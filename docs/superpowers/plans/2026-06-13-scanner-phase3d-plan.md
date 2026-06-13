# Scanner Phase 3d — DOM XSS Sink Analysis Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `dom_xss` module that detects DOM-based XSS via static JavaScript sink/source pairing analysis.

**Architecture:** New module `dom_xss.py` (~130 lines) with pure functions for JS scanning and HTML script extraction. Follows BaseModule pattern. Registers in CLI. Output display added to `output.py`.

**Tech Stack:** Python 3.13, re (stdlib), urllib.parse (stdlib), concurrent.futures (stdlib)

---

### Task 1: Write tests + implement dom_xss.py

**Files:**
- Create: `tests/test_dom_xss.py`
- Create: `scanner/modules/dom_xss.py`

- [ ] **Step 1: Write tests/test_dom_xss.py**

```python
"""Tests for DOM XSS sink analysis module."""
from scanner.modules.dom_xss import (
    _find_dom_xss,
    _extract_scripts,
    SINK_PATTERNS,
    SOURCE_PATTERNS,
    DomXssModule,
)


class TestFindDomXss:
    def test_finds_innerhtml_with_location_hash(self):
        js_code = """
        function update() {
            var hash = location.hash;
            document.getElementById('main').innerHTML = hash;
        }
        """
        results = _find_dom_xss(js_code, "app.js")
        assert len(results) >= 1
        assert any(r["sink"] == ".innerHTML" for r in results)
        assert any(r["source"] == "location.hash" for r in results)

    def test_reports_correct_line_number(self):
        js_code = """
        var x = 1;
        var y = 2;
        document.write(location.search);
        """
        results = _find_dom_xss(js_code, "inline")
        assert len(results) >= 1
        assert results[0]["line"] == 4

    def test_eval_with_document_url(self):
        js_code = 'eval(document.URL.split("#")[1]);'
        results = _find_dom_xss(js_code, "app.js")
        assert len(results) >= 1

    def test_sink_without_source_not_reported(self):
        js_code = 'document.getElementById("x").innerHTML = "safe";'
        results = _find_dom_xss(js_code, "app.js")
        assert len(results) == 0

    def test_source_outside_window_not_reported(self):
        js_code = """
        var url = location.hash;
        // ... 10 lines later ...
        document.getElementById('x').innerHTML = url;
        """
        results = _find_dom_xss(js_code, "app.js")
        assert len(results) == 0  # source more than 3 lines away


class TestExtractScripts:
    def test_extracts_inline_script(self):
        html = '<html><script>var x = 1;</script></html>'
        inline, external = _extract_scripts(html, "http://test.com")
        assert len(inline) >= 1
        assert "var x = 1" in inline[0][1]

    def test_extracts_external_script(self):
        html = '<script src="/app.js"></script>'
        inline, external = _extract_scripts(html, "http://test.com")
        assert "http://test.com/app.js" in external

    def test_ignores_empty_inline_scripts(self):
        html = '<script src="/lib.js"></script><script>  </script>'
        inline, external = _extract_scripts(html, "http://test.com")
        # empty inline script with only whitespace should be skipped
        assert len(inline) == 0

    def test_handles_absolute_external_urls(self):
        html = '<script src="https://cdn.example.com/lib.js"></script>'
        inline, external = _extract_scripts(html, "http://test.com")
        assert "https://cdn.example.com/lib.js" in external


class TestPatterns:
    def test_sinks_non_empty(self):
        assert len(SINK_PATTERNS) >= 8

    def test_sources_non_empty(self):
        assert len(SOURCE_PATTERNS) >= 6


class TestModule:
    def test_module_attributes(self):
        mod = DomXssModule()
        assert mod.name == "dom_xss"
        assert mod.requires_url is True
        assert "DOM" in mod.description
```

- [ ] **Step 2: Run tests — expect FAIL**

Run: `pytest tests/test_dom_xss.py -v`
Expected: `ModuleNotFoundError`

- [ ] **Step 3: Create scanner/modules/dom_xss.py**

```python
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

    Args:
        js_code: JavaScript source as string.
        source_url: Label for the JS source (URL or "inline").

    Returns:
        List of dicts: [{sink, source, line, snippet, file}, ...]
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
```

- [ ] **Step 4: Run tests — expect PASS**

Run: `pytest tests/test_dom_xss.py -v`
Expected: All tests pass.

- [ ] **Step 5: Run ALL tests**

Run: `pytest tests/ -v`
Expected: All pass.

- [ ] **Step 6: Commit**

```bash
git add scanner/modules/dom_xss.py tests/test_dom_xss.py
git commit -m "feat: add DOM XSS sink/source analysis module"
```

---

### Task 2: Register in CLI + output display

**Files:**
- Modify: `scanner/cli.py`
- Modify: `scanner/core/output.py`

- [ ] **Step 1: Register in CLI**

Edit `scanner/cli.py`, add import after XssModule:

```python
from scanner.modules.dom_xss import DomXssModule
```

Edit `scanner/cli.py`, add to MODULE_CLASSES:

```python
MODULE_CLASSES = [SubdomainModule, DirscanModule, ParamsModule, SqliModule, XssModule, DomXssModule]
```

- [ ] **Step 2: Add dom_xss display in output.py**

Edit `scanner/core/output.py`, add after xss display:

```python
        elif module_name == "dom_xss":
            print(f"[{module_name}] {finding['sink']} ← {finding['source']}"
                  f" — {finding['file']}:{finding['line']}")
```

- [ ] **Step 3: Verify scanner list**

Run: `python -m scanner list`
Expected: 6 modules including `dom_xss`

- [ ] **Step 4: Run tests + commit**

```bash
pytest tests/ -v
git add scanner/cli.py scanner/core/output.py
git commit -m "feat: register dom_xss module in CLI and add display"
```

---

### Task 3: Integration test + push

- [ ] **Step 1: Test against real site**

Run: `python -m scanner scan "https://www.baidu.com" -m dom_xss -v`

Expected: Extracts inline + external scripts, scans for sinks, reports any findings. No crashes.

- [ ] **Step 2: Run full test suite**

Run: `pytest tests/ -v`
Expected: All pass.

- [ ] **Step 3: Push**

```bash
git push
```
