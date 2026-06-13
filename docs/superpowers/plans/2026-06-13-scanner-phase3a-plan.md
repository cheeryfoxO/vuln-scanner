# Scanner Phase 3a — POST Request Support Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Enable SQLi and XSS modules to send payloads via POST body when the parameter originates from a POST form, by upgrading the shared param extraction layer.

**Architecture:** Modify `_FormParser` to track form method, change `_extract_params` return from `list[str]` to `list[dict]` (`{name, method}`), add `post()` to `RequestHandler`, then branch on `param["method"]` in both sqli and xss modules.

**Tech Stack:** Python 3.13, html.parser (stdlib), requests, concurrent.futures (stdlib)

---

### Task 1: Upgrade _extract_params + _FormParser

**Files:**
- Modify: `scanner/core/html_utils.py`
- Create: `tests/test_html_utils.py`

- [ ] **Step 1: Write tests for new param format**

Create `tests/test_html_utils.py`:

```python
"""Tests for shared HTML/URL utility functions."""
from scanner.core.html_utils import _FormParser, _extract_params, _make_test_url


class TestFormParser:
    def test_get_form_inputs(self):
        html = '<form method="GET"><input name="q"></form>'
        parser = _FormParser()
        parser.feed(html)
        assert "q" in parser.input_names
        assert len(parser.post_params) == 0

    def test_post_form_inputs(self):
        html = '<form method="POST"><input name="token"></form>'
        parser = _FormParser()
        parser.feed(html)
        assert "token" in parser.post_params
        assert len(parser.input_names) == 0

    def test_default_form_method_is_get(self):
        html = '<form><input name="search"></form>'
        parser = _FormParser()
        parser.feed(html)
        assert "search" in parser.input_names
        assert len(parser.post_params) == 0

    def test_mixed_get_post_forms(self):
        html = '''
            <form method="GET"><input name="q"></form>
            <form method="POST"><input name="password"></form>
        '''
        parser = _FormParser()
        parser.feed(html)
        assert "q" in parser.input_names
        assert "password" in parser.post_params


class TestExtractParams:
    def test_url_params_return_get_method(self):
        params = _extract_params("http://test.com?q=1&page=2", "<html></html>")
        methods = {p["name"]: p["method"] for p in params}
        assert methods["q"] == "GET"
        assert methods["page"] == "GET"

    def test_post_form_params_return_post_method(self):
        html = '<form method="POST"><input name="token"><input name="user"></form>'
        params = _extract_params("http://test.com", html)
        methods = {p["name"]: p["method"] for p in params}
        assert methods["token"] == "POST"
        assert methods["user"] == "POST"

    def test_post_overrides_get_for_same_name(self):
        html = '<form method="POST"><input name="q"></form>'
        params = _extract_params("http://test.com?q=1", html)
        # q appears in both URL (GET) and POST form — POST takes precedence
        result = {p["name"]: p["method"] for p in params}
        assert result["q"] == "POST"

    def test_returns_list_of_dicts(self):
        params = _extract_params("http://test.com?q=1", "<html></html>")
        assert isinstance(params, list)
        assert len(params) > 0
        assert "name" in params[0]
        assert "method" in params[0]

    def test_empty_page_no_params(self):
        params = _extract_params("http://test.com", "<html></html>")
        assert params == []


class TestMakeTestUrl:
    def test_replaces_get_param(self):
        result = _make_test_url("http://example.com/page?id=1", "id", "' OR 1=1--")
        assert "id=%27+OR+1%3D1--" in result

    def test_adds_param_to_url_without_params(self):
        result = _make_test_url("http://example.com/page", "q", "test")
        assert result == "http://example.com/page?q=test"
```

- [ ] **Step 2: Run tests — expect FAIL**

Run: `pytest tests/test_html_utils.py -v`
Expected: `assert len(parser.post_params) == 0` passes (attr missing → AttributeError on first POST test), or some tests fail

- [ ] **Step 3: Implement _FormParser changes**

Edit `scanner/core/html_utils.py`, replace the `_FormParser` class:

```python
class _FormParser(HTMLParser):
    """Extract form input names and URL parameter hints from HTML."""

    def __init__(self):
        super().__init__()
        self.input_names = set()
        self.param_hints = set()
        self.post_params = set()
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

- [ ] **Step 4: Implement _extract_params return format change**

Edit `scanner/core/html_utils.py`, replace the `_extract_params` function:

```python
def _extract_params(target_url, html):
    """Extract parameter names from URL query string and HTML forms.

    Returns list of dicts: [{"name": str, "method": "GET"|"POST"}, ...]
    POST takes precedence when a param appears in both GET and POST contexts.
    """
    result = {}

    # From URL itself → GET
    parsed = urllib.parse.urlparse(target_url)
    for k in urllib.parse.parse_qs(parsed.query):
        result.setdefault(k, "GET")

    # From HTML forms/links
    parser = _FormParser()
    try:
        parser.feed(html)
    except Exception:
        pass

    for name in parser.input_names:
        result.setdefault(name, "GET")
    for name in parser.param_hints:
        result.setdefault(name, "GET")
    for name in parser.post_params:
        result[name] = "POST"  # POST takes precedence

    return [{"name": k, "method": v} for k, v in result.items()]
```

- [ ] **Step 5: Run html_utils tests — expect PASS**

Run: `pytest tests/test_html_utils.py -v`
Expected: All tests pass.

- [ ] **Step 6: Run ALL tests — expect some failures in sqli/xss**

Run: `pytest tests/ -v`
Expected: html_utils tests pass, but sqli/xss tests may fail because `_extract_params` now returns `list[dict]` instead of `list[str]`. The `_make_test_url` tests in `test_sqli.py` should still pass (that function hasn't changed). The main sqli/xss module run tests (if any) will break because they iterate `param_names` expecting strings.

- [ ] **Step 7: Commit**

```bash
git add scanner/core/html_utils.py tests/test_html_utils.py
git commit -m "feat: upgrade _extract_params to return param method (GET/POST)"
```

---

### Task 2: Add post() to RequestHandler

**Files:**
- Modify: `scanner/core/request.py`
- Modify: `tests/test_request.py`

- [ ] **Step 1: Write tests for post()**

Add to `tests/test_request.py` after the existing test class:

```python
class TestPost:
    def test_post_method_exists(self):
        rh = RequestHandler()
        assert hasattr(rh, "post")
        assert callable(rh.post)

    def test_post_accepts_data(self):
        rh = RequestHandler()
        # Verify signature — post(url, data=None, **kwargs)
        import inspect
        sig = inspect.signature(rh.post)
        params = list(sig.parameters.keys())
        assert "url" in params
        assert "data" in params
```

- [ ] **Step 2: Run — expect FAIL**

Run: `pytest tests/test_request.py::TestPost -v`
Expected: FAIL — `hasattr(rh, "post")` returns False

- [ ] **Step 3: Implement post() method**

Edit `scanner/core/request.py`, add after the `head()` method (line 53):

```python
    def post(self, url, data=None, **kwargs):
        """POST request with automatic UA and timeout."""
        return self.session.post(url, data=data, **self._prepare(kwargs))
```

- [ ] **Step 4: Run tests — expect PASS**

Run: `pytest tests/test_request.py::TestPost -v`
Expected: PASS (2 tests)

- [ ] **Step 5: Commit**

```bash
git add scanner/core/request.py tests/test_request.py
git commit -m "feat: add post() method to RequestHandler"
```

---

### Task 3: Adapt sqli.py for GET/POST branching

**Files:**
- Modify: `scanner/modules/sqli.py`

The `_extract_params` now returns `list[dict]`. Everywhere `pname` was a string, it's now an entry dict. Need to branch on `entry["method"]`.

- [ ] **Step 1: Run current sqli tests to see breakage**

Run: `pytest tests/test_sqli.py -v`
Expected: Some tests fail because `_extract_params` returned format changed. (Module tests doing full `run()` are unlikely since they need HTTP mocking. `TestMakeTestUrl` and `TestErrorPatterns` should pass unchanged.)

- [ ] **Step 2: Update sqli.py — adapt all param_name usage**

First, clean up the unused `_FormParser` import (Task 3 also removes the dead import):

Edit line 8:

Old:
```python
from scanner.core.html_utils import _FormParser, _extract_params, _make_test_url
```

New:
```python
from scanner.core.html_utils import _extract_params, _make_test_url
```

Then the key param changes:

**Edit 2a: Update log message (line 125)**

Old:
```python
output.log_progress(f"Found {len(param_names)} potential parameters: {param_names}")
```

New:
```python
param_list = [f"{p['name']}({p['method']})" for p in param_names]
output.log_progress(f"Found {len(param_names)} potential parameters: {param_list}")
```

**Edit 2b: Update fallback block (lines 116-119)**

Old:
```python
        if not param_names:
            parsed = urllib.parse.urlparse(target)
            if parsed.query:
                param_names = list(urllib.parse.parse_qs(parsed.query).keys())
```

New:
```python
        if not param_names:
            parsed = urllib.parse.urlparse(target)
            if parsed.query:
                param_names = [
                    {"name": k, "method": "GET"}
                    for k in urllib.parse.parse_qs(parsed.query).keys()
                ]
```

**Edit 2c: Update Phase 1 futures loop (lines 135-140)**

Old:
```python
            for pname in param_names:
                for error_payload in ERROR_PAYLOADS:
                    test_url = _make_test_url(target, pname, error_payload)
                    futures[pool.submit(request_handler.get, test_url)] = (
                        pname, error_payload, test_url
                    )
```

New:
```python
            for entry in param_names:
                pname = entry["name"]
                method = entry["method"]
                for error_payload in ERROR_PAYLOADS:
                    if method == "POST":
                        test_url = target
                        futures[pool.submit(
                            request_handler.post, target,
                            data={pname: error_payload}
                        )] = (pname, error_payload, test_url)
                    else:
                        test_url = _make_test_url(target, pname, error_payload)
                        futures[pool.submit(
                            request_handler.get, test_url
                        )] = (pname, error_payload, test_url)
```

**Edit 2d: Update Phase 2 target list (lines 169-171)**

Old:
```python
        for pname in param_names:
            if pname not in param_has_error:
                time_based_targets.append(pname)
```

New:
```python
        for entry in param_names:
            if entry["name"] not in param_has_error:
                time_based_targets.append(entry)
```

**Edit 2e: Update Phase 2 baseline computation (lines 182-186)**

Old:
```python
                for pname in time_based_targets:
                    base_url = _make_test_url(target, pname, "1")
                    baseline = _build_baseline_time(base_url, request_handler.get)
                    param_baselines[pname] = baseline
                    output.log_progress(f"  {pname} baseline: {baseline*1000:.0f}ms")
```

New:
```python
                for entry in time_based_targets:
                    pname = entry["name"]
                    if entry["method"] == "POST":
                        baseline = _build_baseline_time(
                            target,
                            lambda u, n=pname: request_handler.post(u, data={n: "1"})
                        )
                    else:
                        base_url = _make_test_url(target, pname, "1")
                        baseline = _build_baseline_time(base_url, request_handler.get)
                    param_baselines[pname] = baseline
                    output.log_progress(f"  {pname} baseline: {baseline*1000:.0f}ms")
```

**Edit 2f: Update Phase 2 sleep payload futures (lines 190-198)**

Old:
```python
                for pname in time_based_targets:
                    for sp in SLEEP_PAYLOADS:
                        test_url = _make_test_url(target, pname, sp["payload"])
                        futures[pool.submit(
                            self._timed_request, request_handler.get, test_url
                        )] = (
                            pname, sp["db"], sp["payload"], test_url,
                            param_baselines[pname],
                        )
```

New:
```python
                for entry in time_based_targets:
                    pname = entry["name"]
                    for sp in SLEEP_PAYLOADS:
                        if entry["method"] == "POST":
                            test_url = target
                            futures[pool.submit(
                                self._timed_request,
                                lambda u, n=pname, pl=sp["payload"]: (
                                    request_handler.post(u, data={n: pl})
                                ),
                                target
                            )] = (
                                pname, sp["db"], sp["payload"], test_url,
                                param_baselines[pname],
                            )
                        else:
                            test_url = _make_test_url(target, pname, sp["payload"])
                            futures[pool.submit(
                                self._timed_request, request_handler.get, test_url
                            )] = (
                                pname, sp["db"], sp["payload"], test_url,
                                param_baselines[pname],
                            )
```

- [ ] **Step 3: Run sqli tests**

Run: `pytest tests/test_sqli.py -v`
Expected: All tests pass (TestErrorPatterns, TestBaselineTime, TestMakeTestUrl, TestPayloads, TestModule).

- [ ] **Step 4: Commit**

```bash
git add scanner/modules/sqli.py
git commit -m "feat: add POST support to sqli module"
```

---

### Task 4: Adapt xss.py for GET/POST branching

**Files:**
- Modify: `scanner/modules/xss.py`

Same pattern as sqli — `param_names` is now `list[dict]`.

- [ ] **Step 1: Update xss.py — adapt param_name usage**

**Edit 1a: Update log message (line 173-175)**

Old:
```python
        output.log_progress(
            f"Found {len(param_names)} potential parameters: {param_names}"
        )
```

New:
```python
        param_list = [f"{p['name']}({p['method']})" for p in param_names]
        output.log_progress(
            f"Found {len(param_names)} potential parameters: {param_list}"
        )
```

**Edit 1b: Update fallback block (lines 164-167)**

Old:
```python
        if not param_names:
            parsed = urllib.parse.urlparse(target)
            if parsed.query:
                param_names = list(urllib.parse.parse_qs(parsed.query).keys())
```

New:
```python
        if not param_names:
            parsed = urllib.parse.urlparse(target)
            if parsed.query:
                param_names = [
                    {"name": k, "method": "GET"}
                    for k in urllib.parse.parse_qs(parsed.query).keys()
                ]
```

**Edit 1c: Update futures loop (lines 186-192)**

Old:
```python
            for pname in param_names:
                for entry in XSS_PAYLOADS:
                    payload = entry["payload"]
                    test_url = _make_test_url(target, pname, payload)
                    futures[pool.submit(request_handler.get, test_url)] = (
                        pname, payload, test_url
                    )
```

New:
```python
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
```

Note: The `for entry in XSS_PAYLOADS` loop variable was `entry`, now renamed to `xss_entry` to avoid shadowing the outer `param_entry`. The `param_entry` and `xss_entry` distinction is important.

- [ ] **Step 2: Run xss tests**

Run: `pytest tests/test_xss.py -v`
Expected: All 14 tests pass.

- [ ] **Step 3: Commit**

```bash
git add scanner/modules/xss.py
git commit -m "feat: add POST support to xss module"
```

---

### Task 5: Integration test + push

- [ ] **Step 1: Run ALL tests**

Run: `pytest tests/ -v`
Expected: All tests pass (41 original + new html_utils + new request tests).

- [ ] **Step 2: Test sqli with GET param (backward compat)**

Run: `python -m scanner scan "https://www.baidu.com/s?wd=test" -m sqli -v`

Expected: Extracts `wd(GET)`, runs Phase 1 + Phase 2 with GET requests. 0 findings, no crashes.

- [ ] **Step 3: Test xss with GET param (backward compat)**

Run: `python -m scanner scan "https://www.baidu.com/s?wd=test" -m xss -v`

Expected: Extracts `wd(GET)`, runs 8 payloads via GET. 0 findings, no crashes.

- [ ] **Step 4: Test -m all**

Run: `python -m scanner scan "https://www.baidu.com" -m all`

Expected: All 5 modules run, no crashes. params output unchanged.

- [ ] **Step 5: Verify scanner list unchanged**

Run: `python -m scanner list`
Expected: 5 modules listed.

- [ ] **Step 6: Push**

```bash
git push
```
