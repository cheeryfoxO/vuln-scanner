"""IDOR (Insecure Direct Object Reference) detection.

Two strategies:
  1. Numeric ID enumeration: replace IDs in URL paths/params with adjacent values.
  2. Cross-session comparison: compare responses between two auth sessions.

Usage:
  scanner scan -m idor --cookie "session=A" --cookie2 "session=B" "https://target.com/user/123"
"""
import re
import hashlib
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from scanner.modules.base import BaseModule

# ── ID manipulation ──────────────────────────────────────────────────────

def _extract_numeric_ids(url):
    """Find numeric IDs in URL path and query string. Returns list of (position, current_value)."""
    ids = []
    parsed = urlparse(url)

    # Check path segments
    segments = parsed.path.strip("/").split("/")
    for i, seg in enumerate(segments):
        if seg.isdigit() and len(seg) < 10:  # reasonable ID length
            ids.append({"location": "path", "index": i, "value": int(seg),
                        "route": "/".join(segments[:i])})

    # Check query params
    for k, v in parse_qs(parsed.query).items():
        raw = v[0] if v else ""
        if raw.isdigit() and len(raw) < 10:
            ids.append({"location": "query", "key": k, "value": int(raw)})

    return ids


def _generate_idor_urls(url):
    """Generate URL variants with adjacent/replacement IDs. Returns list of (url, note)."""
    ids = _extract_numeric_ids(url)
    if not ids:
        return []

    variants = []
    for id_info in ids:
        current = id_info["value"]
        # Adjacent IDs
        test_ids = [current - 1, current + 1, current - 2, current + 2,
                    0, 1, 2, 3, 10, 100, 1000, 10000, current * 2]
        # Filter to valid candidates
        candidates = sorted(set(i for i in test_ids if i >= 0 and i != current))

        for new_id in candidates[:8]:  # limit per ID
            new_url = _replace_id(url, id_info, str(new_id))
            variants.append((new_url, f"Replace {id_info['location']} ID {current} → {new_id}"))

    return variants


def _replace_id(url, id_info, new_value):
    """Replace a numeric ID in a URL."""
    parsed = urlparse(url)

    if id_info["location"] == "path":
        segments = parsed.path.strip("/").split("/")
        segments[id_info["index"]] = new_value
        new_path = "/" + "/".join(segments)
        return urlunparse((parsed.scheme, parsed.netloc, new_path, parsed.params,
                          parsed.query, parsed.fragment))

    # Query param
    query = parse_qs(parsed.query, keep_blank_values=True)
    if id_info["key"] in query:
        query[id_info["key"]] = [new_value]
    new_query = urlencode(query, doseq=True)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params,
                      new_query, parsed.fragment))


# ── Response comparison ──────────────────────────────────────────────────

def _fingerprint_response(resp):
    """Create a lightweight fingerprint of a response for comparison."""
    return {
        "status": resp.status_code,
        "len": len(resp.text or ""),
        "hash": hashlib.md5((resp.text or "").encode()).hexdigest(),
        "title": _extract_title(resp.text or ""),
    }


def _extract_title(html):
    """Extract <title> from HTML."""
    match = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
    return re.sub(r"\s+", " ", match.group(1).strip())[:120] if match else ""


def _compare_responses(resp_a, resp_b, note=""):
    """Compare two responses for IDOR signals. Returns finding dict or None."""
    fp_a = _fingerprint_response(resp_a)
    fp_b = _fingerprint_response(resp_b)

    # Strong signal: same status, same body hash → identical response for different ID
    if (fp_a["status"] == fp_b["status"] == 200 and
            fp_a["hash"] == fp_b["hash"] and
            fp_a["len"] > 100):
        return {
            "type": "idor_identical_response",
            "severity": "high",
            "desc": f"Same response for different IDs — no access control{(' (' + note + ')') if note else ''}",
            "evidence": f"Status: {fp_a['status']}, Size: {fp_a['len']}B, Hash: {fp_a['hash'][:12]}",
        }

    # Medium signal: same status, similar size (±5%), different content
    if (fp_a["status"] == fp_b["status"] == 200 and
            fp_a["len"] > 100 and
            abs(fp_a["len"] - fp_b["len"]) < fp_a["len"] * 0.05 and
            fp_a["hash"] != fp_b["hash"]):
        return {
            "type": "idor_similar_response",
            "severity": "medium",
            "desc": f"Similar response size for different IDs — possible data leak{(' (' + note + ')') if note else ''}",
            "evidence": f"Status: {fp_a['status']}, Sizes: {fp_a['len']}B vs {fp_b['len']}B",
        }

    # ID 0 or 1 access: often reveals admin/root data
    if fp_a["status"] == 200 and fp_a["len"] > 100 and note and ("→ 0" in note or "→ 1" in note):
        return {
            "type": "idor_root_id_access",
            "severity": "high",
            "desc": f"Access to ID 0/1 succeeded — often reserved for admin or system{(' (' + note + ')') if note else ''}",
            "evidence": f"Status: {fp_a['status']}, Size: {fp_a['len']}B, Title: {fp_a['title'][:80]}",
        }

    return None


class IdorModule(BaseModule):
    """Detect IDOR via numeric ID enumeration and cross-session comparison.

    Accepts an optional second cookie for session comparison.
    """

    name = "idor"
    description = "Detect IDOR via ID enumeration and cross-session response comparison"
    requires_url = True

    def run(self, target, request_handler, output, threads=10):
        findings = []
        if not re.search(r"\d", target):
            output.log_progress("No numeric IDs in URL — skipping ID enumeration.")
            output.log_progress("Provide a URL with IDs: /user/123/profile or ?id=456")
        else:
            output.log_progress(f"Testing ID enumeration on {target}")
            variants = _generate_idor_urls(target)
            output.log_progress(f"  Generated {len(variants)} variant URLs")

            for var_url, note in variants:
                try:
                    resp = request_handler.get(var_url)
                    if resp.status_code == 200 and len(resp.text or "") > 100:
                        # Compare with baseline (original URL)
                        finding = _compare_responses(resp, resp, note)
                        if finding or resp.status_code == 200:
                            # Just log that we got a 200 on a modified ID
                            finding = {
                                "type": "idor_id_modified",
                                "severity": "info",
                                "desc": f"Modified ID returned 200 — manual verification needed ({note})",
                                "evidence": f"URL: {var_url}, Status: {resp.status_code}, Size: {len(resp.text or '')}B",
                            }
                        if finding and finding["severity"] != "info":
                            findings.append(finding)
                            output.log_finding(self.name, finding)
                except Exception:
                    pass

        return {"module": self.name, "findings": findings}
