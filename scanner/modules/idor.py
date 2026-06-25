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
    """Compare two responses for IDOR signals. Returns finding dict or None.

    resp_a is the baseline (original URL), resp_b is the variant (modified ID).
    """
    fp_a = _fingerprint_response(resp_a)
    fp_b = _fingerprint_response(resp_b)

    # Both must return 200 with meaningful content to compare
    if fp_a["status"] != 200 or fp_b["status"] != 200:
        return None
    if fp_a["len"] <= 100:
        return None

    # ID 0 or 1 access: often reveals admin/root data (check first)
    if note:
        id_match = re.search(r"→\s*(\d+)", note)
        if id_match and int(id_match.group(1)) in (0, 1):
            return {
                "type": "idor_root_id_access",
                "severity": "high",
                "desc": f"Access to ID 0/1 succeeded — often reserved for admin or system ({note})",
                "evidence": f"Status: {fp_b['status']}, Size: {fp_b['len']}B, Title: {fp_b['title'][:80]}",
            }

    # Strong signal: same hash for different IDs → no access control
    if fp_a["hash"] == fp_b["hash"]:
        return {
            "type": "idor_identical_response",
            "severity": "high",
            "desc": f"Same response for different IDs — no access control ({note})",
            "evidence": f"Status: {fp_a['status']}, Size: {fp_a['len']}B, Hash: {fp_a['hash'][:12]}",
        }

    # Medium signal: similar size (±5%) but different content → possible data leak
    if abs(fp_a["len"] - fp_b["len"]) < fp_a["len"] * 0.05:
        return {
            "type": "idor_similar_response",
            "severity": "medium",
            "desc": f"Similar response size for different IDs — possible data leak ({note})",
            "evidence": f"Status: {fp_a['status']}, Sizes: {fp_a['len']}B vs {fp_b['len']}B",
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
            return {"module": self.name, "findings": findings}

        output.log_progress(f"Testing ID enumeration on {target}")

        # Phase 1: fetch original URL as baseline
        output.log_progress("  Fetching baseline (original URL)...")
        try:
            baseline_resp = request_handler.get(target)
        except Exception:
            output.log_progress("  Failed to fetch original URL — aborting IDOR check")
            return {"module": self.name, "findings": findings}

        baseline_len = len(baseline_resp.text or "")
        output.log_progress(f"  Baseline: status={baseline_resp.status_code}, size={baseline_len}B")

        # Phase 2: generate and test variant URLs
        variants = _generate_idor_urls(target)
        output.log_progress(f"  Testing {len(variants)} variant URLs...")

        for var_url, note in variants:
            try:
                resp = request_handler.get(var_url)
                if resp.status_code != 200:
                    continue
                if len(resp.text or "") < 50:
                    continue

                # Compare variant response against baseline
                result = _compare_responses(baseline_resp, resp, note)
                if result:
                    findings.append(result)
                    output.log_finding(self.name, result)

                # Also flag any successful ID modification for manual review
                elif abs(len(resp.text or "") - baseline_len) > baseline_len * 0.1:
                    info_finding = {
                        "type": "idor_different_response",
                        "severity": "medium",
                        "desc": f"Different response for modified ID — possible data leak ({note})",
                        "evidence": f"URL: {var_url}, Status: {resp.status_code}, Sizes: baseline={baseline_len}B vs variant={len(resp.text or '')}B",
                    }
                    findings.append(info_finding)
                    output.log_finding(self.name, info_finding)

            except Exception:
                pass

        output.log_progress(f"IDOR done: {len(findings)} potential issues found")
        return {"module": self.name, "findings": findings}
