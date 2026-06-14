"""Passive scanning — parse HAR/Burp traffic and replay requests through modules.

Supports:
- HAR (HTTP Archive) JSON format — from Chrome DevTools, Burp, etc.
- Burp XML export format (future)

Usage:
  python -m scanner passive capture.har -m sqli,xss -v
"""
import base64
import json
import re
import urllib.parse
from urllib.parse import urlparse, parse_qs, urlencode
from datetime import datetime

from scanner.core.engine import Engine
from scanner.core.request import RequestHandler
from scanner.core.output import Output
from scanner.core.poc import inject_poc_into_finding


def parse_har(filepath):
    """Parse a HAR (HTTP Archive) JSON file.

    Returns:
        List of request dicts: {method, url, headers, cookies, query_params, post_data, mime_type}
    """
    with open(filepath, encoding="utf-8") as f:
        data = json.load(f)

    entries = data.get("log", {}).get("entries", [])
    requests = []

    for entry in entries:
        req = entry.get("request", {})
        method = req.get("method", "GET").upper()

        url = req.get("url", "")
        if not url:
            continue

        # Parse headers into dict
        headers = {}
        for h in req.get("headers", []):
            headers[h["name"]] = h.get("value", "")

        # Parse cookies
        cookies = {}
        for c in req.get("cookies", []):
            cookies[c["name"]] = c.get("value", "")

        # Parse query string
        query_params = {}
        for q in req.get("queryString", []):
            query_params[q["name"]] = q.get("value", "")

        # Parse POST data
        post_data = None
        mime_type = ""
        if "postData" in req:
            post_data = req["postData"].get("text", "")
            mime_type = req["postData"].get("mimeType", "")

        requests.append({
            "method": method,
            "url": url,
            "headers": headers,
            "cookies": cookies,
            "query_params": query_params,
            "post_data": post_data,
            "mime_type": mime_type,
        })

    return requests


def parse_burp_xml(filepath):
    """Parse a Burp Suite XML export file.

    Returns: Same format as parse_har().
    """
    import xml.etree.ElementTree as ET

    try:
        tree = ET.parse(filepath)
    except ET.ParseError as e:
        raise ValueError(f"Invalid Burp XML: {e}")

    root = tree.getroot()
    requests = []

    for item in root.findall("item"):
        url = (item.findtext("url") or "").strip()
        if not url:
            continue

        method = (item.findtext("method") or "GET").strip().upper()
        host = (item.findtext("host") or "").strip()
        protocol = (item.findtext("protocol") or "https").strip()

        # Build full URL if only path
        if not url.startswith("http"):
            url = f"{protocol}://{host}{url}"

        # Decode base64 request
        request_raw = item.findtext("request") or ""
        headers = {}
        post_data = None
        mime_type = ""
        query_params = {}
        cookies = {}

        if request_raw:
            try:
                decoded = base64.b64decode(request_raw).decode("utf-8", errors="replace")
                headers, post_data, mime_type = _parse_raw_request(decoded)
            except Exception:
                pass

        # Parse query string from URL
        parsed = urlparse(url)
        for k, v in parse_qs(parsed.query).items():
            query_params[k] = v[0] if v else ""

        requests.append({
            "method": method,
            "url": url,
            "headers": headers,
            "cookies": cookies,
            "query_params": query_params,
            "post_data": post_data,
            "mime_type": mime_type,
        })

    return requests


def _parse_raw_request(raw_text):
    """Parse raw HTTP request text into headers and body."""
    headers = {}
    body = None
    mime_type = ""

    lines = raw_text.split("\r\n")
    # First line is request line — skip
    i = 1
    while i < len(lines) and lines[i]:
        line = lines[i]
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip()] = v.strip()
        i += 1

    # Body starts after blank line
    if i < len(lines):
        i += 1  # skip blank line
        body = "\r\n".join(lines[i:])

    mime_type = headers.get("Content-Type", "").split(";")[0].strip()
    return headers, body, mime_type


def deduplicate_requests(requests):
    """Deduplicate requests by method + URL (without fragment). Returns unique requests."""
    seen = set()
    unique = []
    for req in requests:
        url = req["url"].split("#")[0]  # strip fragment
        key = (req["method"], url)
        if key not in seen:
            seen.add(key)
            req["url"] = url  # store cleaned
            unique.append(req)
    return unique


def requests_with_params(requests):
    """Filter to requests that have query params or POST data."""
    result = []
    for req in requests:
        has_params = bool(req.get("query_params"))
        has_post = bool(req.get("post_data"))
        if has_params or has_post:
            result.append(req)
    return result


def _build_test_url(req):
    """Build a URL with original params for module testing.

    For GET requests: use the URL as-is (it has query params).
    For POST requests: convert to GET with query params for injection testing.
    """
    method = req["method"]
    url = req["url"]
    query_params = req.get("query_params", {})

    if method in ("GET", "HEAD", "OPTIONS"):
        return url

    # POST with params → build a GET equivalent for injection testing
    if query_params:
        parsed = urlparse(url)
        base = urllib.parse.urlunparse(
            (parsed.scheme, parsed.netloc, parsed.path, "", "", "")
        )
        qs = urlencode(query_params)
        return f"{base}?{qs}"

    # POST with body → return base URL (modules will extract form params)
    return url.split("?")[0]


def run_passive(filepath, module_names, request_handler, output, threads=10):
    """Parse traffic file and replay requests through scanner modules.

    Args:
        filepath: Path to .har or .xml file.
        module_names: Modules to run (list or ["all"]).
        request_handler: RequestHandler instance.
        output: Output instance.
        threads: Concurrency.

    Returns:
        Report dict with source_requests and findings.
    """
    # Parse
    if filepath.endswith(".xml"):
        all_requests = parse_burp_xml(filepath)
        output.log_progress(f"Parsed Burp XML: {len(all_requests)} entries")
    else:
        all_requests = parse_har(filepath)
        output.log_progress(f"Parsed HAR: {len(all_requests)} entries")

    if not all_requests:
        output.log_progress("No requests found in file.")
        return {"scan_time": datetime.now().isoformat(), "findings": {}}

    # Dedup + filter to requests with parameters
    unique = deduplicate_requests(all_requests)
    output.log_progress(f"Deduplicated: {len(unique)} unique requests")

    targets = requests_with_params(unique)
    output.log_progress(
        f"Requests with parameters: {len(targets)}/{len(unique)}"
    )

    if not targets:
        output.log_progress("No requests with parameters to scan.")
        return {
            "scan_time": datetime.now().isoformat(),
            "source_requests": len(unique),
            "findings": {},
        }

    # Build engine with all modules
    engine = Engine()
    from scanner.modules.sqli import SqliModule
    from scanner.modules.xss import XssModule
    from scanner.modules.cmdi import CmdiModule
    from scanner.modules.lfi import LfiModule
    from scanner.modules.ssti import SstiModule
    from scanner.modules.ssrf import SsrfModule
    from scanner.modules.redirect import RedirectModule

    mod_map = {
        "sqli": SqliModule,
        "xss": XssModule,
        "cmdi": CmdiModule,
        "lfi": LfiModule,
        "ssti": SstiModule,
        "ssrf": SsrfModule,
        "redirect": RedirectModule,
    }

    if "all" in module_names:
        names_to_run = list(mod_map.keys())
    else:
        names_to_run = [n for n in module_names if n in mod_map]

    for name in names_to_run:
        engine.register(mod_map[name]())

    # Replay each target URL through modules
    all_findings = {}
    scanned = 0

    for req in targets:
        test_url = _build_test_url(req)
        if not test_url:
            continue

        scanned += 1
        output.log_progress(f"\n[{scanned}/{len(targets)}] {req['method']} {test_url[:100]}")

        # Run each module directly (serial for passive — each target is precious)
        for name in names_to_run:
            mod = engine.modules[name]
            try:
                # Use inspect to pass threads if supported
                import inspect
                sig = inspect.signature(mod.run)
                if "threads" in sig.parameters:
                    result = mod.run(test_url, request_handler, output, threads=threads)
                else:
                    result = mod.run(test_url, request_handler, output)

                # Tag findings with source request context
                for f in result.get("findings", []):
                    f["source_method"] = req["method"]
                    f["source_url"] = req["url"]
                    inject_poc_into_finding(f, name, target=test_url)

                if result["findings"]:
                    all_findings.setdefault(name, []).extend(result["findings"])

            except Exception as e:
                output.log_progress(f"  {name} failed on {test_url[:80]}: {e}")

    report = {
        "scan_time": datetime.now().isoformat(),
        "source_file": filepath,
        "source_requests": len(unique),
        "scanned_targets": scanned,
        "modules": names_to_run,
        "findings": all_findings,
    }

    # Summary
    total = sum(len(v) for v in all_findings.values())
    output.log_progress(
        f"\nPassive scan done: {total} findings from {scanned} targets"
    )
    return report
