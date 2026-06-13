"""DOM XSS detection -- static JavaScript sink/source analysis."""
import re
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed

from scanner.modules.base import BaseModule


# ── Sink & Source Patterns ───────────────────────────────────────────

SINK_PATTERNS = [
    ".innerHTML", ".outerHTML", "document.write", "document.writeln",
    "eval(", "setTimeout(", "setInterval(",
    "location.href", "location.replace(",
]

SOURCE_PATTERNS = [
    "location.hash", "location.search", "location.href",
    "document.URL", "document.documentURI", "window.name",
]


# ── Pure Functions ───────────────────────────────────────────────────

def _find_dom_xss(js_code, source_url):
    """Scan JS code for sink/source pairs indicating DOM XSS.

    Each sink call is checked against sources within ±3 lines.
    """
    lines = js_code.split('\n')
    findings = []

    for i, line in enumerate(lines):
        for sink in SINK_PATTERNS:
            if sink in line:
                window_start = max(0, i - 3)
                window_end = min(len(lines), i + 4)
                window_text = ' '.join(lines[window_start:window_end])
                for source in SOURCE_PATTERNS:
                    if source in window_text:
                        findings.append({
                            "sink": sink,
                            "source": source,
                            "line": i + 1,
                            "snippet": line.strip()[:120],
                            "file": source_url,
                        })
                        break
    return findings


def _extract_scripts(html, base_url):
    """Extract inline and external JavaScript from HTML.

    Returns (inline_blocks, external_urls):
        inline_blocks: list of (label, code) tuples
        external_urls: list of absolute URLs (max 10)
    """
    inline = []
    external = []

    # Inline <script>...</script>
    for match in re.finditer(
        r'<script[^>]*?>([\s\S]*?)</script>', html, re.IGNORECASE
    ):
        attrs = match.group(0)
        code = match.group(1)
        if 'src=' not in attrs and code.strip():
            inline.append(("inline", code.strip()))

    # External <script src="...">
    for match in re.finditer(
        r'<script[^>]*?src=["\']([^"\']+)["\']', html, re.IGNORECASE
    ):
        src = match.group(1)
        full_url = urllib.parse.urljoin(base_url, src)
        external.append(full_url)

    return inline, external[:10]


# ── DomXssModule ─────────────────────────────────────────────────────

class DomXssModule(BaseModule):
    name = "dom_xss"
    description = "Detect DOM XSS via JavaScript sink/source analysis"
    requires_url = True

    def run(self, target, request_handler, output):
        """Run DOM XSS sink/source analysis against the target page."""
        target = target.rstrip("/")
        output.log_progress(f"Fetching {target} for DOM XSS analysis...")

        try:
            resp = request_handler.get(target)
            html = resp.text
        except Exception as e:
            output.log_progress(f"Failed to fetch {target}: {e}")
            return {"module": self.name, "findings": []}

        inline_scripts, external_urls = _extract_scripts(html, target)
        js_sources = [(label, code) for label, code in inline_scripts]

        output.log_progress(
            f"Found {len(inline_scripts)} inline scripts, "
            f"{len(external_urls)} external scripts"
        )

        # Fetch external JS files
        if external_urls:
            with ThreadPoolExecutor(max_workers=5) as pool:
                futures = {}
                for url in external_urls:
                    futures[pool.submit(request_handler.get, url)] = url

                for future in as_completed(futures):
                    url = futures[future]
                    try:
                        resp = future.result()
                        if len(resp.text) < 500_000:
                            js_sources.append((url, resp.text))
                    except Exception:
                        pass

        output.log_progress(f"Analyzing {len(js_sources)} JS sources...")

        findings = []
        seen = set()
        for source_url, code in js_sources:
            for f in _find_dom_xss(code, source_url):
                key = (f["sink"], f["source"], f["file"])
                if key not in seen:
                    seen.add(key)
                    finding = {
                        "type": "dom_xss",
                        "sink": f["sink"],
                        "source": f["source"],
                        "file": f["file"],
                        "line": f["line"],
                        "snippet": f["snippet"],
                        "evidence": (
                            f"sink '{f['sink']}' with source "
                            f"'{f['source']}' at line {f['line']}"
                        ),
                    }
                    if len(findings) < 30:
                        findings.append(finding)
                        output.log_finding(self.name, finding)

        output.log_progress(f"DOM XSS done: {len(findings)} potential sinks found")
        return {"module": self.name, "findings": findings}
