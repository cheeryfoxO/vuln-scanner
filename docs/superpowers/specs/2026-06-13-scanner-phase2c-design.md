# Scanner Phase 2c — XSS Detection Module

**Date:** 2026-06-13
**Status:** Draft → Awaiting review
**Goal:** Add a xss module that detects reflected XSS via DOM context analysis. Non-destructive, GET-only, 8 classified payloads × 6 context types.

## 1. Architecture

New files: `scanner/core/html_utils.py` (shared param extraction), `scanner/modules/xss.py` (~160 lines).
Modified files: `scanner/modules/sqli.py` (switch import), `scanner/cli.py` (register XssModule).

```
scanner/
├── core/
│   ├── html_utils.py          ← NEW: shared _FormParser + _extract_params
│   ├── engine.py
│   ├── output.py
│   └── request.py
├── modules/
│   ├── base.py
│   ├── subdomain.py
│   ├── dirscan.py
│   ├── params.py
│   ├── sqli.py                ← MODIFY: import _FormParser from html_utils
│   └── xss.py                 ← NEW: XSS detection module
└── cli.py                     ← MODIFY: register XssModule
```

## 2. Detection Logic

### 2.1 Parameter Extraction

Moved to `scanner/core/html_utils.py`:

```python
class _FormParser(HTMLParser):
    """Extract form input names and URL parameter hints from HTML."""
    ...

def _extract_params(target_url, html) -> list[str]:
    """Extract parameter names from URL query string and HTML forms."""
    ...

def _make_test_url(base_url, param_name, payload) -> str:
    """Replace or append a GET parameter with the payload value."""
    ...
```

Both `sqli` and `xss` modules import from here. Identical implementation to current sqli.py version.

### 2.2 Payloads & Context Mapping

8 classified payloads, each targeting a specific injection context:

| # | Payload | Target Context | Detection |
|---|---------|---------------|-----------|
| 1 | `<xss>test</xss>` | html_tag | payload element found in body |
| 2 | `"><script>alert(1)</script>` | attribute_break_dq | double-quote break → script tag in DOM |
| 3 | `'><script>alert(1)</script>` | attribute_break_sq | single-quote break → script tag in DOM |
| 4 | `</script><script>alert(1)</script>` | script_tag | script close → new script in DOM |
| 5 | `" onfocus="alert(1)` | event_handler | onfocus attribute on element |
| 6 | `javascript:alert(1)` | url_protocol | href/src = javascript: URI |
| 7 | `<svg onload="alert(1)">` | svg_event | svg tag + onload in DOM |
| 8 | `<img src=x onerror=alert(1)>` | img_event | img tag + onerror in DOM |

### 2.3 Context Detection Function

Pure function `_analyze_reflection(html: str, payload: str) -> str | None`:

Returns one of: `html_tag`, `attribute_break_dq`, `attribute_break_sq`, `script_tag`, `event_handler`, `url_protocol`, `svg_event`, `img_event`, `reflected_unsure`, or `None` (not reflected).

Detection logic per context:

- **html_tag**: parse HTML → find `xss` element in tag list → check textContent = "test"
- **attribute_break_dq / attribute_break_sq**: payload contains `><script>` → check if a `script` element with text "alert(1)" exists in DOM
- **script_tag**: parse → find `script` element with text "alert(1)" that is NOT inside an attribute
- **event_handler**: search for `onfocus`, `onload`, `onerror` attribute values containing "alert(1)"
- **url_protocol**: search for `href` or `src` attribute value = `javascript:alert(1)`
- **svg_event**: find `svg` element with `onload` attribute
- **img_event**: find `img` element with `onerror` attribute
- **reflected_unsure**: payload text found in HTML but NOT in any executable context
- **None**: payload not found in HTML at all

Implementation uses `html.parser.HTMLParser` to build a simple DOM tree, then inspects it.

### 2.4 Module Flow

```
run(target, request_handler, output):
  1. resp = request_handler.get(target) → html
  2. params = _extract_params(target, html)
  3. If no params → return empty
  4. For each param × each payload (3 threads):
     a. test_url = _make_test_url(target, param, payload)
     b. resp = request_handler.get(test_url)
     c. context = _analyze_reflection(resp.text, payload)
     d. If context → append finding
  5. Return findings
```

## 3. Module Interface

```python
class XssModule(BaseModule):
    name = "xss"
    description = "Detect reflected XSS via DOM context analysis"
    requires_url = True

    def run(self, target, request_handler, output) -> dict:
        ...
        return {"module": self.name, "findings": [...]}
```

CLI registration:

```python
from scanner.modules.xss import XssModule
MODULE_CLASSES = [SubdomainModule, DirscanModule, ParamsModule, SqliModule, XssModule]
```

## 4. Finding Output Format

```json
{
  "type": "reflected_xss",
  "parameter": "q",
  "url": "https://target.com/search?q=%3Cxss%3Etest%3C%2Fxss%3E",
  "payload": "<xss>test</xss>",
  "context": "html_tag",
  "evidence": "payload <xss>test</xss> reflected as HTML element in response"
}
```

Output display in `output.py`:

```python
elif module_name == "xss":
    ctx = finding.get("context", "unknown")
    print(f"[{module_name}] {finding['parameter']}: {ctx} -- {finding['url']}")
```

## 5. Non-Goals

- Stored XSS detection (requires multi-request persistence)
- DOM XSS (sink analysis: innerHTML, document.write, etc.)
- WAF/filter bypass payloads (encoding variants, case mixing)
- POST request support
- Blind XSS (out-of-band callback with external server)

## 6. Success Criteria

1. `python -m scanner list` shows xss module
2. `python -m scanner scan "https://httpbin.org/get?q=test" -m xss -v` — extracts param, 0 XSS found, no crashes
3. All 27 existing tests + new xss tests pass
4. sqli module still works after importpath change
5. Against a page with known reflected XSS, module detects it with correct context
