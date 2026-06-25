"""Extract API endpoints, secrets, and subdomains from JavaScript files.

Non-invasive: only fetches HTML and JS files, sends no attack payloads.
"""
import re
from urllib.parse import urljoin

from scanner.modules.base import BaseModule

# ── Regex patterns ──────────────────────────────────────────────────────

# API endpoint patterns -- fetch(), axios, $.ajax, XMLHttpRequest, plus URL strings
API_ENDPOINT_PATTERNS = [
    # fetch('/api/...')
    re.compile(r"""fetch\s*\(\s*(['"])((?:https?:)?//[^'"]+|/[^'"]+)\1""", re.IGNORECASE),
    # axios.get('/api/...'), axios.post('/api/...'), axios({url: '/api/...'})
    re.compile(r"""axios\s*\(\s*\{[^}]*url\s*:\s*(['"])([^'"]+)\1""", re.IGNORECASE),
    re.compile(r"""axios\s*\.\s*(?:get|post|put|delete|patch)\s*\(\s*(['"])([^'"]+)\1""", re.IGNORECASE),
    # $.ajax({url: '/api/...'})
    re.compile(r"""\$\.\s*ajax\s*\(\s*\{[^}]*?url\s*:\s*(['"])([^'"]+)\1""", re.IGNORECASE),
    # $.get('/api/...'), $.post('/api/...')
    re.compile(r"""\$\.\s*(?:get|post|getJSON|getScript)\s*\(\s*(['"])([^'"]+)\1""", re.IGNORECASE),
    # XMLHttpRequest.open('GET', '/api/...')
    re.compile(r"""\.\s*open\s*\(\s*(['"])[A-Z]+\1\s*,\s*(['"])([^'"]+)\2""", re.IGNORECASE),
]

# Standalone URL path patterns -- /api/v1/..., /v2/..., /graphql, etc.
URL_PATH_PATTERNS = [
    re.compile(r"""(?<=['"\s])(/api/v\d+/[^\s'"<>]+)"""),
    re.compile(r"""(?<=['"\s])(/v\d+/[^\s'"<>]+)"""),
    re.compile(r"""(?<=['"\s])(/graphql)(?=['"\s])""", re.IGNORECASE),
    re.compile(r"""(?<=['"\s])(/oauth/[^\s'"<>]+)"""),
    re.compile(r"""(?<=['"\s])(/\.well-known/[^\s'"<>]+)"""),
    re.compile(r"""(?<=['"\s])(/api/[^\s'"<>]+)"""),
]

# Secrets / hardcoded credentials
SECRET_PATTERNS = [
    (re.compile(r"""apiKey\s*[:=]\s*(['"])([^'"]{8,})\1""", re.IGNORECASE), "API Key"),
    (re.compile(r"""api[_-]?key\s*[:=]\s*(['"])([^'"]{8,})\1""", re.IGNORECASE), "API Key"),
    (re.compile(r"""api[_-]?secret\s*[:=]\s*(['"])([^'"]{8,})\1""", re.IGNORECASE), "API Secret"),
    (re.compile(r"""secret\s*[:=]\s*(['"])([^'"]{8,})\1""", re.IGNORECASE), "Secret"),
    (re.compile(r"""token\s*[:=]\s*(['"])([^'"]{8,})\1""", re.IGNORECASE), "Token"),
    (re.compile(r"""bearer\s*[:=]\s*(['"])([^'"]{8,})\1""", re.IGNORECASE), "Bearer Token"),
    (re.compile(r"""password\s*[:=]\s*(['"])([^'"]{6,})\1""", re.IGNORECASE), "Password"),
    (re.compile(r"""passwd\s*[:=]\s*(['"])([^'"]{6,})\1""", re.IGNORECASE), "Password"),
    (re.compile(r"""access[_-]?token\s*[:=]\s*(['"])([^'"]{8,})\1""", re.IGNORECASE), "Access Token"),
    (re.compile(r"""auth[_-]?token\s*[:=]\s*(['"])([^'"]{8,})\1""", re.IGNORECASE), "Auth Token"),
    (re.compile(r"""jwt[_-]?secret\s*[:=]\s*(['"])([^'"]{8,})\1""", re.IGNORECASE), "JWT Secret"),
    (re.compile(r"""private[_-]?key\s*[:=]\s*(['"])([^'"]{8,})\1""", re.IGNORECASE), "Private Key"),
    # AWS keys
    (re.compile(r"""AKIA[0-9A-Z]{16}"""), "AWS Access Key"),
    (re.compile(r"""AIza[0-9A-Za-z\-_]{35}"""), "Google API Key"),
    # Generic assignment like const API_KEY = "abc123..."
    (re.compile(r"""\b(?:API|SECRET|TOKEN)_[A-Z0-9_]+\s*=\s*(['"])([^'"]{8,})\1"""), "Generic Secret"),
]

# Subdomain patterns -- extract hostnames from URLs in JS
SUBDOMAIN_PATTERN = re.compile(
    r"""https?://((?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,})(?=[/'"\s<>&#;:]|$)"""
)

# ── Limits ──────────────────────────────────────────────────────────────

MAX_JS_FILES = 20
MAX_FINDINGS_PER_CATEGORY = 30


def _extract_scripts(html, base_url):
    """Parse HTML for <script> tags. Returns (inline_scripts, external_urls).

    inline_scripts: list of (line_number, source_code) tuples
    external_urls: list of resolved absolute URLs
    """
    inline = []
    external = []

    # Find all <script> tags
    tag_pattern = re.compile(
        r"""<script\b([^>]*?)>(.*?)</script\s*>""",
        re.IGNORECASE | re.DOTALL,
    )

    for match in tag_pattern.finditer(html):
        attrs = match.group(1)
        body = match.group(2)

        src_match = re.search(r"""src\s*=\s*(['"])(.*?)\1""", attrs, re.IGNORECASE)
        if src_match:
            src = src_match.group(2)
            if src.strip():
                resolved = urljoin(base_url, src)
                external.append(resolved)
        elif body.strip():
            # Inline script -- determine line number from preceding HTML
            line_num = html[: match.start()].count("\n") + 1
            inline.append((line_num, body.strip()))

    return inline, external


def _find_api_endpoints(js_code, source_name):
    """Extract API endpoints from JS code. Returns list of finding dicts."""
    findings = []
    seen = set()

    for pattern in API_ENDPOINT_PATTERNS:
        for m in pattern.finditer(js_code):
            endpoint = m.group(m.lastindex) if m.lastindex else m.group(0)
            if endpoint in seen:
                continue
            seen.add(endpoint)
            findings.append({
                "type": "api_endpoint",
                "severity": "info",
                "desc": f"API endpoint found in {source_name}",
                "evidence": endpoint,
            })

    return findings[:MAX_FINDINGS_PER_CATEGORY]


def _find_url_paths(js_code, source_name):
    """Extract URL path patterns like /api/v1/... from JS. Returns list of finding dicts."""
    findings = []
    seen = set()

    for pattern in URL_PATH_PATTERNS:
        for m in pattern.finditer(js_code):
            path = m.group(1)
            if path in seen:
                continue
            # Skip paths that look like they're from common libraries
            if any(lib in path.lower() for lib in ("/lib/", "/vendor/", "/node_modules/", "/bower_components/")):
                continue
            seen.add(path)
            findings.append({
                "type": "api_path",
                "severity": "info",
                "desc": f"API path pattern found in {source_name}",
                "evidence": path,
            })

    return findings[:MAX_FINDINGS_PER_CATEGORY]


def _find_secrets(js_code, source_name):
    """Extract hardcoded secrets from JS. Returns list of finding dicts."""
    findings = []
    seen_values = set()

    for pattern, label in SECRET_PATTERNS:
        for m in pattern.finditer(js_code):
            # For patterns with 2 groups, value is group 2; for single-group, value is group 0
            try:
                value = m.group(2) if m.lastindex and m.lastindex >= 2 else m.group(0)
            except (IndexError, AttributeError):
                value = m.group(0)

            value_key = value[:32]
            if value_key in seen_values:
                continue
            seen_values.add(value_key)

            findings.append({
                "type": "secret",
                "severity": "high",
                "desc": f"{label} found in {source_name}",
                "evidence": f"{label}: {value[:40]}{'...' if len(value) > 40 else ''}",
            })

    return findings[:MAX_FINDINGS_PER_CATEGORY]


def _find_subdomains(js_code, source_name, target_domain):
    """Extract subdomains from URLs in JS. Returns list of finding dicts."""
    findings = []
    seen = set()

    for m in SUBDOMAIN_PATTERN.finditer(js_code):
        hostname = m.group(1).lower()

        # Skip the target domain itself and common CDNs
        if hostname in seen:
            continue
        if hostname.endswith("." + target_domain) or hostname == target_domain:
            continue

        # Skip well-known public CDNs and common domains
        skip_domains = {
            "googleapis.com", "gstatic.com", "cloudflare.com", "jsdelivr.net",
            "unpkg.com", "cdnjs.cloudflare.com", "cdn.jsdelivr.net",
            "fonts.googleapis.com", "fonts.gstatic.com", "www.w3.org",
            "ajax.googleapis.com", "code.jquery.com", "maxcdn.bootstrapcdn.com",
            "stackpath.bootstrapcdn.com", "cdnjs.com", "raw.githubusercontent.com",
            "github.com", "gitlab.com", "bitbucket.org", "npmjs.com",
            "polyfill.io", "recaptcha.net", "gstatic.cn",
        }
        if hostname in skip_domains:
            continue
        if any(hostname.endswith("." + d) for d in skip_domains):
            continue

        seen.add(hostname)
        findings.append({
            "type": "subdomain",
            "severity": "info",
            "desc": f"Subdomain/domain found in JS: {source_name}",
            "evidence": hostname,
        })

    return findings[:MAX_FINDINGS_PER_CATEGORY]


class JsEndpointsModule(BaseModule):
    """Extract API endpoints, secrets, and subdomains from JavaScript files.

    Fetches the target page, discovers JS files (inline and external), then
    applies regex patterns to surface interesting strings.
    """

    name = "js_endpoints"
    description = "Extract API endpoints, secrets, and subdomains from JavaScript"
    requires_url = True

    def run(self, target, request_handler, output):
        target = target.rstrip("/")
        output.log_progress(f"JS Endpoints: fetching {target}...")

        findings = []

        # ── 1. Fetch target page ───────────────────────────────────
        try:
            resp = request_handler.get(target)
            html = resp.text or ""
        except Exception as e:
            output.log_progress(f"JS Endpoints: failed to fetch {target}: {e}")
            return {"module": self.name, "findings": []}

        # ── 2. Extract <script> tags ──────────────────────────────
        inline_scripts, external_urls = _extract_scripts(html, target)

        # ── 3. Download external JS files (limited) ───────────────
        js_sources = []
        for line_num, code in inline_scripts:
            js_sources.append((f"{target} (inline L{line_num})", code))

        external_urls = external_urls[:MAX_JS_FILES]
        for url in external_urls:
            try:
                js_resp = request_handler.get(url, timeout=10)
                if js_resp.status_code < 400:
                    js_sources.append((url, js_resp.text or ""))
            except Exception:
                pass

        output.log_progress(
            f"JS Endpoints: {len(js_sources)} JS sources "
            f"({len(inline_scripts)} inline, {len(external_urls)} external)"
        )

        # ── 4. Extract target domain for subdomain filtering ──────
        from urllib.parse import urlparse
        parsed = urlparse(target)
        target_domain = parsed.hostname or target

        # ── 5. Run regex patterns on each JS source ───────────────
        for source_name, js_code in js_sources:
            if not js_code.strip():
                continue

            api_findings = _find_api_endpoints(js_code, source_name)
            for f in api_findings:
                findings.append(f)
                output.log_finding(self.name, f)

            path_findings = _find_url_paths(js_code, source_name)
            for f in path_findings:
                findings.append(f)
                output.log_finding(self.name, f)

            secret_findings = _find_secrets(js_code, source_name)
            for f in secret_findings:
                findings.append(f)
                output.log_finding(self.name, f)

            subdomain_findings = _find_subdomains(js_code, source_name, target_domain)
            for f in subdomain_findings:
                findings.append(f)
                output.log_finding(self.name, f)

        output.log_progress(
            f"JS Endpoints done: {len(findings)} findings "
            f"(from {len(js_sources)} JS sources)"
        )
        return {"module": self.name, "findings": findings}
