"""XSS detection -- reflected XSS via DOM context analysis."""
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from html.parser import HTMLParser

from scanner.modules.base import BaseModule
from scanner.core.html_utils import _extract_params, _make_test_url


# ── XSS Payloads ─────────────────────────────────────────────────────
XSS_PAYLOADS = [
    {"context": "html_tag", "payload": "<xss>test</xss>",
     "description": "Custom HTML element injection"},
    {"context": "attribute_break", "payload": "\"><script>alert(1)</script>",
     "description": "Double-quote attribute break to script tag"},
    {"context": "attribute_break", "payload": "'><script>alert(1)</script>",
     "description": "Single-quote attribute break to script tag"},
    {"context": "script_tag", "payload": "</script><script>alert(1)</script>",
     "description": "Script tag close and reopen"},
    {"context": "event_handler", "payload": "\" onfocus=\"alert(1)",
     "description": "Event handler injection via double quote"},
    {"context": "url_protocol", "payload": "javascript:alert(1)",
     "description": "JavaScript URL protocol injection"},
    {"context": "svg_event", "payload": "<svg onload=\"alert(1)\">",
     "description": "SVG tag with onload event handler"},
    {"context": "img_event", "payload": "<img src=x onerror=alert(1)>",
     "description": "IMG tag with onerror event handler"},
]


# ── DOM Builder ──────────────────────────────────────────────────────

class _DOMBuilder(HTMLParser):
    """Build a minimal DOM representation for XSS context analysis.

    Tracks elements (tag + attributes) and script text content.
    """

    def __init__(self):
        super().__init__()
        self.elements = []       # List of {"tag": str, "attrs": dict}
        self.script_content = [] # Text inside <script> tags
        self._in_script = False
        self._tag_stack = []

    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)
        self.elements.append({"tag": tag, "attrs": attrs_dict})
        self._tag_stack.append(tag)
        if tag == "script":
            self._in_script = True

    def handle_endtag(self, tag):
        if self._tag_stack and self._tag_stack[-1] == tag:
            self._tag_stack.pop()
        self._in_script = "script" in self._tag_stack

    def handle_data(self, data):
        if self._in_script:
            self.script_content.append(data)


# ── Context Analysis (Pure Function) ─────────────────────────────────

def _analyze_reflection(html, payload):
    """Analyze how a payload is reflected in HTML.

    Returns context string (e.g. "html_tag", "attribute_break", ...)
    or None if payload is not reflected, or "reflected_unsure" if
    reflected in a non-executable context.
    """
    if payload not in html:
        return None

    parser = _DOMBuilder()
    try:
        parser.feed(html)
    except Exception:
        pass

    # ── Context-specific checks ──

    # 1. html_tag: payload <xss>test</xss> — check for <xss> element
    if payload.startswith("<xss>"):
        for elem in parser.elements:
            if elem["tag"] == "xss":
                return "html_tag"
        return "reflected_unsure"

    # 2. attribute_break: payload ">... or '>... — check for new script tag
    if payload.startswith('">') or payload.startswith("'>"):
        if any("alert(1)" in s for s in parser.script_content):
            return "attribute_break"
        return "reflected_unsure"

    # 3. script_tag: payload </script><script>... — check for new script
    if payload.startswith("</script>"):
        if any("alert(1)" in s for s in parser.script_content):
            return "script_tag"
        return "reflected_unsure"

    # 4. event_handler: payload " onfocus=... — check for onfocus attr
    if payload.startswith('" onfocus'):
        for elem in parser.elements:
            if "onfocus" in elem["attrs"]:
                return "event_handler"
        return "reflected_unsure"

    # 5. url_protocol: payload javascript:... — check href/src
    if payload.startswith("javascript:"):
        for elem in parser.elements:
            for attr_name, attr_val in elem["attrs"].items():
                if attr_name in ("href", "src") and "javascript:" in attr_val:
                    return "url_protocol"
        return "reflected_unsure"

    # 6. svg_event: payload <svg onload=... — check svg + onload
    if payload.startswith("<svg"):
        for elem in parser.elements:
            if elem["tag"] == "svg" and "onload" in elem["attrs"]:
                return "svg_event"
        return "reflected_unsure"

    # 7. img_event: payload <img src=x onerror=... — check img + onerror
    if payload.startswith("<img"):
        for elem in parser.elements:
            if elem["tag"] == "img" and "onerror" in elem["attrs"]:
                return "img_event"
        return "reflected_unsure"

    # 8. Case-insensitive event handler (e.g. ONLOAD)
    evt_handlers = {"onfocus", "onload", "onerror", "onclick", "onmouseover"}
    for elem in parser.elements:
        for attr_name in elem["attrs"]:
            if attr_name.lower() in evt_handlers:
                if "alert(1)" in elem["attrs"][attr_name]:
                    return "event_handler"

    return "reflected_unsure"


# ── XssModule ────────────────────────────────────────────────────────

class XssModule(BaseModule):
    name = "xss"
    description = "Detect reflected XSS via DOM context analysis"
    requires_url = True

    def run(self, target, request_handler, output):
        """Run XSS detection against target URL parameters."""
        target = target.rstrip("/")
        output.log_progress(f"Fetching {target} for XSS parameter extraction...")

        try:
            resp = request_handler.get(target)
            html = resp.text
        except Exception as e:
            output.log_progress(f"Failed to fetch {target}: {e}")
            return {"module": self.name, "findings": []}

        param_names = _extract_params(target, html)

        # If URL has no obvious params from HTML, try the URL query itself
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
        total_tests = len(param_names) * len(XSS_PAYLOADS)
        output.log_progress(
            f"Testing {len(param_names)} params x {len(XSS_PAYLOADS)} payloads "
            f"= {total_tests} requests"
        )

        with ThreadPoolExecutor(max_workers=3) as pool:
            futures = {}
            for param_entry in param_names:
                pname = param_entry["name"]
                method = param_entry["method"]
                for xss_entry in XSS_PAYLOADS:
                    payload = xss_entry["payload"]
                    if method == "POST":
                        test_url = target
                        futures[pool.submit(
                            request_handler.post, target,
                            data={pname: payload}
                        )] = (pname, payload, test_url)
                    else:
                        test_url = _make_test_url(target, pname, payload)
                        futures[pool.submit(
                            request_handler.get, test_url
                        )] = (pname, payload, test_url)

            bar = output.create_progress_bar("XSS", len(futures))
            for future in as_completed(futures):
                pname, payload, test_url = futures[future]
                try:
                    resp = future.result()
                    context = _analyze_reflection(resp.text, payload)
                    if context is not None:
                        finding = {
                            "type": "reflected_xss",
                            "parameter": pname,
                            "url": test_url,
                            "payload": payload,
                            "context": context,
                            "evidence": (
                                f"payload reflected as '{context}' "
                                f"in response"
                            ),
                        }
                        findings.append(finding)
                        output.log_finding(self.name, finding)
                except Exception:
                    pass
                output.update_progress(bar)
            bar.close()

        output.log_progress(
            f"XSS scan done: {len(findings)} potential XSS found"
        )
        return {"module": self.name, "findings": findings}
