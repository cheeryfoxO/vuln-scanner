# Scanner Phase 3a — POST Request Support

**Date:** 2026-06-13
**Status:** Draft → Awaiting review
**Goal:** Enable SQLi and XSS modules to automatically send payloads via POST body when the target parameter originates from a POST form.

## 1. Architecture

Three files modified, zero new modules. The change is infrastructural — it touches the shared param extraction layer and the two detection modules that consume it.

```
scanner/core/
├── html_utils.py  ← MODIFY: _FormParser tracks form method, _extract_params returns [{name, method}]
├── request.py     ← MODIFY: +post() method
modules/
├── sqli.py        ← MODIFY: use param["method"] to choose GET/POST
├── xss.py         ← MODIFY: use param["method"] to choose GET/POST
```

## 2. _FormParser Enhancement

Track the current form's method. POST form inputs are collected separately.

```python
class _FormParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.input_names = set()    # GET form inputs + URL params
        self.param_hints = set()    # URL param hints from <a href>
        self.post_params = set()    # NEW: POST form input names
        self._current_form_method = "GET"

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "form":
            self._current_form_method = attrs.get("method", "GET").upper()
        elif tag == "input":
            name = attrs.get("name", "")
            if name:
                if self._current_form_method == "POST":
                    self.post_params.add(name)
                else:
                    self.input_names.add(name)
        elif tag == "a":
            href = attrs.get("href", "")
            if "?" in href:
                parsed = urllib.parse.urlparse(href)
                for k in urllib.parse.parse_qs(parsed.query):
                    self.param_hints.add(k)
```

## 3. _extract_params Return Value

Changed from `list[str]` to `list[dict]`:

```python
def _extract_params(target_url, html):
    """Extract parameters with their HTTP method (GET or POST)."""
    result = {}

    # URL query params → GET
    parsed = urllib.parse.urlparse(target_url)
    for k in urllib.parse.parse_qs(parsed.query):
        result.setdefault(k, "GET")

    # HTML forms/links
    parser = _FormParser()
    try:
        parser.feed(html)
    except Exception:
        pass

    # Dedup: build dict name→method, POST overrides GET
    result = {}
    for name in parser.input_names:
        result.setdefault(name, "GET")
    for name in parser.param_hints:
        result.setdefault(name, "GET")
    for name in parser.post_params:
        result[name] = "POST"  # POST takes precedence

    return [{"name": k, "method": v} for k, v in result.items()]
```

**Deduplication:** param names from multiple sources may duplicate. Each name appears once in output. POST form inputs override URL params of the same name (POST takes precedence).

## 4. RequestHandler.post()

```python
def post(self, url, data=None, **kwargs):
    """Send POST request with form-encoded data."""
    kwargs.setdefault("timeout", self.timeout)
    kwargs.setdefault("headers", {})
    kwargs["headers"].setdefault("User-Agent", self._random_ua())
    return self.session.post(url, data=data, **kwargs)
```

## 5. Module Adaptations

### sqli.py

Every place that constructs a test URL now branches on method:

```python
for entry in param_names:
    pname = entry["name"]
    method = entry["method"]
    for error_payload in ERROR_PAYLOADS:
        if method == "POST":
            url = target  # POST to the form action URL
            future = pool.submit(request_handler.post, url, data={pname: error_payload})
        else:
            test_url = _make_test_url(target, pname, error_payload)
            future = pool.submit(request_handler.get, test_url)
        futures[future] = (pname, error_payload, url_or_test_url)
```

Same pattern for time-based Phase 2.

### xss.py

Same branching pattern — `method == "POST"` → `request_handler.post()`, else `request_handler.get()`.

## 6. Non-Goals

- File upload / multipart POST
- JSON body POST
- Custom POST body format
- CSRF token handling (Phase 3b)

## 7. Success Criteria

1. `pytest tests/ -v` — all 41 existing + new html_utils tests pass
2. `_extract_params` returns `[{name, method}]` format
3. sqli/xss still work with URL-only targets (backward compatible)
4. Against a page with `<form method="POST">`, sqli/xss send POST requests
5. `scanner list` unchanged, all 5 modules load
