"""Parameter analysis -- extract input points from HTML forms, JS, and URL query strings."""
import re
from html.parser import HTMLParser
from urllib.parse import urlparse, parse_qs

from scanner.modules.base import BaseModule


class _FormParser(HTMLParser):
    """Extract form actions, input names, and resource links from HTML."""

    def __init__(self):
        super().__init__()
        self.forms = []
        self.links = []
        self.scripts = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "form":
            form_info = {
                "action": attrs.get("action", ""),
                "method": attrs.get("method", "GET").upper(),
                "inputs": [],
            }
            self.forms.append(form_info)
        elif tag == "input" and self.forms:
            name = attrs.get("name", "")
            input_type = attrs.get("type", "text")
            if name:
                self.forms[-1]["inputs"].append({"name": name, "type": input_type})
        elif tag == "a":
            href = attrs.get("href", "")
            if href and not href.startswith("#"):
                self.links.append(href)
        elif tag == "script":
            src = attrs.get("src", "")
            if src:
                self.scripts.append(src)
        elif tag == "link":
            href = attrs.get("href", "")
            if href:
                self.links.append(href)


class ParamsModule(BaseModule):
    name = "params"
    description = "Extract form inputs, JS endpoints, and URL parameters"
    requires_url = True

    JS_API_PATTERNS = [
        re.compile(r"""fetch\s*\(\s*["']([^"']+)["']""", re.I),
        re.compile(r"""axios\.(?:get|post|put|delete|patch)\s*\(\s*["']([^"']+)["']""", re.I),
        re.compile(r"""\$\.(?:ajax|get|post)\s*\(\s*["']([^"']+)["']""", re.I),
        re.compile(r"""XMLHttpRequest[^}]*?\.open\s*\(\s*["']\w+["']\s*,\s*["']([^"']+)["']""", re.I),
    ]

    def _parse_html(self, html):
        parser = _FormParser()
        try:
            parser.feed(html)
        except Exception:
            pass
        return parser

    def _extract_js_endpoints(self, text):
        endpoints = set()
        for pattern in self.JS_API_PATTERNS:
            for match in pattern.finditer(text):
                url = match.group(1)
                if url and not url.startswith("#") and not url.startswith("data:"):
                    endpoints.add(url)
        return list(endpoints)

    def run(self, target, request_handler, output):
        """Extract input points from the target page."""
        target = target.rstrip("/")
        output.log_progress(f"Fetching {target} ...")

        try:
            resp = request_handler.get(target)
            html = resp.text
        except Exception as e:
            output.log_progress(f"Failed to fetch {target}: {e}")
            return {"module": self.name, "findings": []}

        findings = []

        # 1. URL query parameters
        parsed = urlparse(target)
        query_params = parse_qs(parsed.query)
        for param, values in query_params.items():
            findings.append({"type": "URL参数", "source": param, "values": values})
            output.log_finding(self.name, findings[-1])

        # 2. HTML forms and links
        parsed_html = self._parse_html(html)

        for form in parsed_html.forms:
            method = form["method"]
            action = form["action"] or target
            input_names = [inp["name"] for inp in form["inputs"]]
            findings.append({
                "type": f"表单 ({method})",
                "source": action,
                "inputs": input_names,
            })
            output.log_finding(self.name, findings[-1])

        # 3. Interesting links (cap at 30 to limit noise)
        for link in parsed_html.links[:30]:
            findings.append({"type": "链接/资源", "source": link})
            output.log_finding(self.name, findings[-1])

        # 4. JS file URLs (cap at 10)
        for script_src in parsed_html.scripts[:10]:
            findings.append({"type": "JS文件", "source": script_src})
            output.log_finding(self.name, findings[-1])

        # 5. Inline JS API endpoints
        js_endpoints = self._extract_js_endpoints(html)
        for ep in js_endpoints:
            findings.append({"type": "JS端点", "source": ep})
            output.log_finding(self.name, findings[-1])

        output.log_progress(f"Params done: {len(findings)} inputs found")
        return {"module": self.name, "findings": findings}
