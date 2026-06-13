# Scanner Phase 3d — DOM XSS Sink Analysis

**Date:** 2026-06-13
**Status:** Draft → Awaiting review
**Goal:** Add a `dom_xss` module that detects DOM-based XSS vulnerabilities via static JavaScript sink/source pairing analysis.

## 1. Architecture

New file: `scanner/modules/dom_xss.py` (~130 lines). Modify `scanner/cli.py` to register.

```
scanner/modules/dom_xss.py  ← NEW
scanner/cli.py              ← MODIFY: register DomXssModule
```

Independent module, no changes to existing modules. Follows BaseModule pattern.

## 2. Detection Logic

### 2.1 Flow

```
target URL → fetch page → extract JS code sources:
  ├── inline <script> blocks (from HTML)
  └── external <script src="..."> (fetch up to 10 files)
      ↓
  For each JS source:
    scan lines for sink calls
    check ±3 lines for source references
    sink + source in same window → finding
```

### 2.2 Sinks (8 patterns)

```python
SINK_PATTERNS = [
    ".innerHTML", ".outerHTML", "document.write", "document.writeln",
    "eval(", "setTimeout(", "setInterval(",
    "location.href", "location.replace(",
]
```

### 2.3 Sources (6 patterns)

```python
SOURCE_PATTERNS = [
    "location.hash", "location.search", "location.href",
    "document.URL", "document.documentURI", "window.name",
]
```

### 2.4 Core Function

```python
def _find_dom_xss(js_code, source_url):
    """Scan JS code for sink/source pairs indicating DOM XSS.

    Args:
        js_code: JavaScript source as string.
        source_url: URL or label for the JS source (e.g. "inline:main").

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
                        break  # one source per sink is enough
    return findings
```

Duplicate findings for same (sink, source, file) are deduplicated.

### 2.5 HTML Script Extraction

```python
def _extract_scripts(html, base_url):
    """Extract inline and external JavaScript from HTML.

    Returns (inline_blocks, external_urls):
        inline_blocks: list of (label, code) tuples
        external_urls: list of absolute URLs
    """
    import re
    inline = []
    external = []

    # Inline <script>...</script> (without src)
    for match in re.finditer(r'<script[^>]*?>([\s\S]*?)</script>', html, re.I):
        attrs = match.group(0)
        code = match.group(1)
        if 'src=' not in attrs and code.strip():
            inline.append(("inline", code.strip()))

    # External <script src="...">
    for match in re.finditer(r'<script[^>]*?src=["\']([^"\']+)["\']', html, re.I):
        src = match.group(1)
        full_url = urllib.parse.urljoin(base_url, src)
        external.append(full_url)

    return inline, external[:10]  # Cap at 10 external scripts
```

## 3. Module Interface

```python
class DomXssModule(BaseModule):
    name = "dom_xss"
    description = "Detect DOM XSS via JavaScript sink/source analysis"
    requires_url = True

    def run(self, target, request_handler, output):
        target = target.rstrip("/")
        output.log_progress(f"Fetching {target} for DOM XSS analysis...")

        try:
            resp = request_handler.get(target)
            html = resp.text
        except Exception as e:
            output.log_progress(f"Failed to fetch {target}: {e}")
            return {"module": self.name, "findings": []}

        inline_scripts, external_urls = _extract_scripts(html, target)

        # Fetch external JS files (concurrent, 5 threads, 500KB limit)
        js_sources = [(label, code) for label, code in inline_scripts]

        with ThreadPoolExecutor(max_workers=5) as pool:
            futures = {pool.submit(request_handler.get, url): url for url in external_urls}
            for future in as_completed(futures):
                url = futures[future]
                try:
                    resp = future.result()
                    if len(resp.text) < 500_000:
                        js_sources.append((url, resp.text))
                except Exception:
                    pass

        output.log_progress(f"Analyzing {len(js_sources)} JS sources for DOM XSS...")

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
                    findings.append(finding)
                    output.log_finding(self.name, finding)

        output.log_progress(f"DOM XSS done: {len(findings)} potential sinks found")
        return {"module": self.name, "findings": findings}
```

## 4. Output Format

```json
{
  "type": "dom_xss",
  "sink": "innerHTML",
  "source": "location.hash",
  "file": "https://example.com/app.js",
  "line": 42,
  "snippet": "document.getElementById('main').innerHTML = location.hash;",
  "evidence": "sink 'innerHTML' with source 'location.hash' at line 42"
}
```

Output display in `output.py`:

```python
elif module_name == "dom_xss":
    print(f"[{module_name}] {finding['sink']} ← {finding['source']}"
          f" — {finding['file']}:{finding['line']}")
```

## 5. Constraints

- Max 10 external JS files (cap noise)
- Max 500KB per JS file (ignore bundles)
- Max 5 concurrent JS fetches
- Max 30 findings total (cap spam on large apps)
- Deduplicate by (sink, source, file) tuple

## 6. Non-Goals

- Cross-function data flow tracking
- Deobfuscation / minification reversal
- jQuery sink detection (`.html()`, `.append()`, `$()`)
- `eval` argument content analysis
- WebSocket / postMessage / storage source tracking

## 7. Success Criteria

1. `python -m scanner list` shows `dom_xss` module
2. `python -m scanner scan "url" -m dom_xss -v` — extracts scripts, scans for sinks
3. Known vulnerable test case (JS with `location.hash` → `innerHTML`) detected
4. All existing 88 tests pass
5. Output format matches spec
