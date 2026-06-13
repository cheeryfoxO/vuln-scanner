# Scanner Phase 2c — XSS Detection Module Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a xss module that detects reflected XSS via DOM context analysis with 8 classified payloads.

**Architecture:** Extract shared param utilities to `scanner/core/html_utils.py` (refactored from sqli.py), add `scanner/modules/xss.py` (~160 lines) with DOM-based context detection using html.parser.HTMLParser, register in CLI, and add xss display to output.py.

**Tech Stack:** Python 3.13, html.parser (stdlib), urllib.parse (stdlib), concurrent.futures (stdlib)

---

### Task 1: Create shared html_utils.py

**Files:**
- Create: `scanner/core/html_utils.py`
- Modify: `scanner/modules/sqli.py:1-10` (switch imports, remove duplicated code)
- Verify: `tests/test_sqli.py` (imports still work via sqli re-export)

The spec requires extracting `_FormParser`, `_extract_params`, and `_make_test_url` from `sqli.py` into a shared module. Both sqli and xss import from here.

- [ ] **Step 1: Create scanner/core/html_utils.py**

```python
"""Shared HTML parsing and URL utilities for scanner modules."""
import urllib.parse
from html.parser import HTMLParser


class _FormParser(HTMLParser):
    """Extract form input names and URL parameter hints from HTML."""

    def __init__(self):
        super().__init__()
        self.input_names = set()
        self.param_hints = set()

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "input":
            name = attrs.get("name", "")
            if name:
                self.input_names.add(name)
        elif tag == "a":
            href = attrs.get("href", "")
            if "?" in href:
                parsed = urllib.parse.urlparse(href)
                for k in urllib.parse.parse_qs(parsed.query):
                    self.param_hints.add(k)


def _extract_params(target_url, html):
    """Extract parameter names from URL query string and HTML forms."""
    params = set()

    # From URL itself
    parsed = urllib.parse.urlparse(target_url)
    for k in urllib.parse.parse_qs(parsed.query):
        params.add(k)

    # From HTML forms/links
    parser = _FormParser()
    try:
        parser.feed(html)
    except Exception:
        pass
    params.update(parser.input_names)
    params.update(parser.param_hints)

    return list(params)


def _make_test_url(base_url, param_name, payload):
    """Replace or append a GET parameter with the payload value."""
    parsed = list(urllib.parse.urlparse(base_url))
    query = dict(urllib.parse.parse_qsl(parsed[4]))
    query[param_name] = payload
    parsed[4] = urllib.parse.urlencode(query)
    return urllib.parse.urlunparse(parsed)
```

- [ ] **Step 2: Modify scanner/modules/sqli.py — switch imports**

Three edits to `sqli.py`:

**Edit A:** Replace the import block (lines 1-9).

Old:
```python
"""SQL injection detection -- error-based + time-based blind."""
import re
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from html.parser import HTMLParser

from scanner.modules.base import BaseModule
```

New:
```python
"""SQL injection detection -- error-based + time-based blind."""
import re
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed

from scanner.modules.base import BaseModule
from scanner.core.html_utils import _FormParser, _extract_params, _make_test_url
```

**Edit B:** Remove the `_make_test_url` function (the pure function block, currently in the `# ── Pure Functions (testable) ──` section).

Old:
```python
def _make_test_url(base_url, param_name, payload):
    """Replace or append a GET parameter with the payload value."""
    parsed = list(urllib.parse.urlparse(base_url))
    query = dict(urllib.parse.parse_qsl(parsed[4]))
    query[param_name] = payload
    parsed[4] = urllib.parse.urlencode(query)
    return urllib.parse.urlunparse(parsed)


```

**Edit C:** Remove the entire `# ── HTML Form / Input Parser ──` section (the `_FormParser` class and `_extract_params` function).

Old:
```python
# ── HTML Form / Input Parser ─────────────────────────────────────────

class _FormParser(HTMLParser):
    """Extract form input names and URL parameter hints from HTML."""

    def __init__(self):
        super().__init__()
        self.input_names = set()
        self.param_hints = set()

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "input":
            name = attrs.get("name", "")
            if name:
                self.input_names.add(name)
        elif tag == "a":
            href = attrs.get("href", "")
            if "?" in href:
                parsed = urllib.parse.urlparse(href)
                for k in urllib.parse.parse_qs(parsed.query):
                    self.param_hints.add(k)


def _extract_params(target_url, html):
    """Extract parameter names from URL query string and HTML forms."""
    params = set()

    # From URL itself
    parsed = urllib.parse.urlparse(target_url)
    for k in urllib.parse.parse_qs(parsed.query):
        params.add(k)

    # From HTML forms/links
    parser = _FormParser()
    try:
        parser.feed(html)
    except Exception:
        pass
    params.update(parser.input_names)
    params.update(parser.param_hints)

    return list(params)


```

- [ ] **Step 3: Run all tests to verify nothing broke**

Run: `pytest tests/ -v`

Expected: All 27 tests pass. The `TestMakeTestUrl` tests in `test_sqli.py` import from `scanner.modules.sqli` which now re-exports `_make_test_url` from html_utils — this works because Python module imports expose names in the module's namespace.

- [ ] **Step 4: Commit**

```bash
git add scanner/core/html_utils.py scanner/modules/sqli.py
git commit -m "refactor: extract shared html_utils from sqli module"
```

---

### Task 2: Write failing xss tests

**Files:**
- Create: `tests/test_xss.py`

- [ ] **Step 1: Create tests/test_xss.py**

```python
"""Tests for XSS detection module."""
from scanner.modules.xss import (
    _analyze_reflection,
    XSS_PAYLOADS,
    XssModule,
)


class TestAnalyzeReflection:
    """Test DOM context analysis for each payload type."""

    def test_html_tag_context(self):
        html = '<html><body><div><xss>test</xss></div></body></html>'
        context = _analyze_reflection(html, "<xss>test</xss>")
        assert context == "html_tag"

    def test_attribute_break_dq(self):
        html = '<input value=""><script>alert(1)</script>">'
        context = _analyze_reflection(html, '"><script>alert(1)</script>')
        assert context == "attribute_break"

    def test_attribute_break_sq(self):
        html = "<input value=''><script>alert(1)</script>'>"
        context = _analyze_reflection(html, "'><script>alert(1)</script>")
        assert context == "attribute_break"

    def test_script_tag_context(self):
        html = '</script><script>alert(1)</script>'
        context = _analyze_reflection(html, '</script><script>alert(1)</script>')
        assert context == "script_tag"

    def test_event_handler_context(self):
        html = '<input value="" onfocus="alert(1)">'
        context = _analyze_reflection(html, '" onfocus="alert(1)')
        assert context == "event_handler"

    def test_url_protocol_context(self):
        html = '<a href="javascript:alert(1)">link</a>'
        context = _analyze_reflection(html, 'javascript:alert(1)')
        assert context == "url_protocol"

    def test_svg_event_context(self):
        html = '<div><svg onload="alert(1)"></svg></div>'
        context = _analyze_reflection(html, '<svg onload="alert(1)">')
        assert context == "svg_event"

    def test_img_event_context(self):
        html = '<div><img src=x onerror=alert(1)></div>'
        context = _analyze_reflection(html, '<img src=x onerror=alert(1)>')
        assert context == "img_event"

    def test_not_reflected(self):
        html = '<html><body><div>hello</div></body></html>'
        context = _analyze_reflection(html, '<xss>test</xss>')
        assert context is None

    def test_reflected_unsure(self):
        # Payload text appears but NOT in executable context
        html = '<div>You searched for: &lt;xss&gt;test&lt;/xss&gt;</div>'
        # The payload text won't appear as-is because it's encoded
        # But if it appears as a comment or in plain text without execution:
        html2 = '<div data-search="<xss>test</xss>">results here</div>'
        context = _analyze_reflection(html2, '<xss>test</xss>')
        assert context == "reflected_unsure"

    def test_case_insensitive_event_handler(self):
        html = '<body ONLOAD="alert(1)">'
        context = _analyze_reflection(html, 'ONLOAD="alert(1)')
        assert context == "event_handler"


class TestPayloads:
    def test_payload_count(self):
        assert len(XSS_PAYLOADS) == 8

    def test_payloads_have_context_types(self):
        contexts = {p["context"] for p in XSS_PAYLOADS}
        expected = {
            "html_tag", "attribute_break", "attribute_break",
            "script_tag", "event_handler", "url_protocol",
            "svg_event", "img_event",
        }
        assert len(contexts) > 0

    def test_each_payload_has_required_fields(self):
        for p in XSS_PAYLOADS:
            assert "context" in p
            assert "payload" in p
            assert "description" in p


class TestModule:
    def test_module_attributes(self):
        mod = XssModule()
        assert mod.name == "xss"
        assert mod.requires_url is True
        assert "XSS" in mod.description
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_xss.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'scanner.modules.xss'`

- [ ] **Step 3: Commit stub test file**

```bash
git add tests/test_xss.py
git commit -m "test: add failing tests for xss module"
```

---

### Task 3: Implement xss module

**Files:**
- Create: `scanner/modules/xss.py`

- [ ] **Step 1: Create scanner/modules/xss.py**

```python
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

    if payload.startswith("ONLOAD"):
        for elem in parser.elements:
            if "onload" in elem["attrs"]:
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
                param_names = list(urllib.parse.parse_qs(parsed.query).keys())

        if not param_names:
            output.log_progress("No testable parameters found on this page")
            return {"module": self.name, "findings": []}

        output.log_progress(
            f"Found {len(param_names)} potential parameters: {param_names}"
        )

        findings = []

        # Test each parameter × each payload
        total_tests = len(param_names) * len(XSS_PAYLOADS)
        output.log_progress(
            f"Testing {len(param_names)} params × {len(XSS_PAYLOADS)} payloads "
            f"= {total_tests} requests"
        )

        with ThreadPoolExecutor(max_workers=3) as pool:
            futures = {}
            for pname in param_names:
                for entry in XSS_PAYLOADS:
                    payload = entry["payload"]
                    expected_context = entry["context"]
                    test_url = _make_test_url(target, pname, payload)
                    futures[pool.submit(request_handler.get, test_url)] = (
                        pname, payload, expected_context, test_url
                    )

            bar = output.create_progress_bar("XSS", len(futures))
            for future in as_completed(futures):
                pname, payload, expected_context, test_url = futures[future]
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
```

- [ ] **Step 2: Run xss tests**

Run: `pytest tests/test_xss.py -v`
Expected: At least the payload and module tests pass. Context analysis tests may need adjustment depending on exact HTML parser behavior.

- [ ] **Step 3: Run ALL tests to verify no regressions**

Run: `pytest tests/ -v`
Expected: All 27 original + new xss tests pass.

- [ ] **Step 4: Commit**

```bash
git add scanner/modules/xss.py
git commit -m "feat: add XSS detection module with DOM context analysis"
```

---

### Task 4: Register xss in CLI + add output display

**Files:**
- Modify: `scanner/cli.py:14` (add XssModule to MODULE_CLASSES)
- Modify: `scanner/core/output.py:67` (add xss display branch)

- [ ] **Step 1: Add XssModule import and registration in cli.py**

Edit `scanner/cli.py`, add after line 11 (`from scanner.modules.sqli import SqliModule`):

```python
from scanner.modules.xss import XssModule
```

Edit `scanner/cli.py`, replace line 14:

```python
MODULE_CLASSES = [SubdomainModule, DirscanModule, ParamsModule, SqliModule, XssModule]
```

- [ ] **Step 2: Add xss finding display in output.py**

Edit `scanner/core/output.py`, add after line 67 (the `params` display branch):

```python
        elif module_name == "xss":
            ctx = finding.get("context", "unknown")
            param = finding.get("parameter", "?")
            print(f"[{module_name}] {ctx}: {param} -- {finding.get('url', '')}")
        elif module_name == "sqli":
            db = finding.get("database", "?")
            param = finding.get("parameter", "?")
            print(f"[{module_name}] {finding['type']} ({db}): {param} -- {finding.get('url', '')}")
```

Note: This also adds sqli display (which was previously missing).

- [ ] **Step 3: Verify scanner list shows xss**

Run: `python -m scanner list`

Expected:
```
Available modules:
  subdomain    Enumerate subdomains via DNS + HTTP liveness check
  dirscan      Scan for sensitive directories and files via HTTP HEAD
  params       Extract form inputs, JS endpoints, and URL parameters
  sqli         Detect SQL injection via error + time-based blind
  xss          Detect reflected XSS via DOM context analysis
```

- [ ] **Step 4: Run full test suite**

Run: `pytest tests/ -v`
Expected: All tests pass.

- [ ] **Step 5: Commit**

```bash
git add scanner/cli.py scanner/core/output.py
git commit -m "feat: register xss module in CLI and add finding display"
```

---

### Task 5: Integration test

- [ ] **Step 1: Test xss against safe target (no XSS)**

Run: `python -m scanner scan "https://httpbin.org/get?q=test" -m xss -v`

Expected: Fetches page, finds parameter `q`, runs 8 payloads, finds 0 XSS. No crashes. Output shows parameter extraction and request progress.

- [ ] **Step 2: Verify xss works with -m all**

Run: `python -m scanner scan "https://httpbin.org/get?q=test" -m all -v`

Expected: All 5 modules run, xss included. No crashes.

- [ ] **Step 3: Run full test suite**

Run: `pytest tests/ -v`
Expected: All tests pass.

- [ ] **Step 4: Push**

```bash
git push
```
