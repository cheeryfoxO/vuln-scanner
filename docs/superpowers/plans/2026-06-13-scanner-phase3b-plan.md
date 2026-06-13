# Scanner Phase 3b — WAF Bypass Encoding Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a shared encoding layer (`scanner/core/encoding.py`) with 7 WAF bypass encoding functions, then wrap sqli/xss payload loops with `generate_variants()` to automatically test encoded variants.

**Architecture:** New pure-function `encoding.py` module (zero dependencies on scanner). Each encoding is a standalone `str → str` function. `generate_variants()` applies all techniques to a payload, returning `[(variant, technique_name), ...]`. Both sqli and xss modules gain a `for encoded, tech in generate_variants(...)` inner loop.

**Tech Stack:** Python 3.13, random (stdlib), urllib.parse (stdlib)

---

### Task 1: Create encoding.py with tests

**Files:**
- Create: `scanner/core/encoding.py`
- Create: `tests/test_encoding.py`

- [ ] **Step 1: Write tests/test_encoding.py**

```python
"""Tests for WAF bypass encoding functions."""
import re
from scanner.core.encoding import (
    _url_encode,
    _case_mix,
    _comment_inject,
    _whitespace_vary,
    _double_url_encode,
    _html_entity,
    _null_byte,
    generate_variants,
    TECHNIQUE_FUNCS,
    SQLI_TECHNIQUES,
    XSS_TECHNIQUES,
)


class TestUrlEncode:
    def test_encodes_single_quote(self):
        result = _url_encode("'")
        assert result == "%27"

    def test_encodes_multiple_chars(self):
        result = _url_encode("1' OR 1=1--")
        assert "%27" in result
        assert "%20" in result
        assert "%3D" in result

    def test_does_not_double_encode(self):
        result = _url_encode("%27")
        assert result.count("25") == 0  # no %25 introduced


class TestCaseMix:
    def test_mixes_case(self):
        result = _case_mix("SELECT")
        # result should differ from original in at least one position most times
        # but with random, just verify it's not empty and same length
        assert len(result) == len("SELECT")
        assert result.upper() == "SELECT"

    def test_preserves_special_chars(self):
        result = _case_mix("' OR 1=1--")
        assert "'" in result
        assert "=" in result
        assert "--" in result


class TestCommentInject:
    def test_replaces_spaces_with_comments(self):
        result = _comment_inject("' OR 1=1")
        assert "/**/" in result
        assert " " not in result

    def test_no_spaces_unchanged(self):
        result = _comment_inject("'OR'")
        assert result == "'OR'"


class TestWhitespaceVary:
    def test_replaces_spaces_with_whitespace(self):
        result = _whitespace_vary("' OR 1=1")
        assert " " not in result
        assert ("\t" in result or "\n" in result)

    def test_no_spaces_unchanged(self):
        result = _whitespace_vary("'OR'")
        assert result == "'OR'"


class TestDoubleUrlEncode:
    def test_double_encodes_percent(self):
        result = _double_url_encode("'")
        assert "%25" in result
        assert "%2527" in result


class TestHtmlEntity:
    def test_encodes_angle_brackets(self):
        result = _html_entity("<script>")
        assert "&#60;" in result
        assert "&#62;" in result
        assert "<" not in result
        assert ">" not in result

    def test_encodes_quotes(self):
        result = _html_entity('"test"')
        assert "&#34;" in result


class TestNullByte:
    def test_prepends_null_byte(self):
        result = _null_byte("<script>")
        assert result.startswith("%00")
        assert "<script>" in result


class TestGenerateVariants:
    def test_always_includes_plain(self):
        variants = generate_variants("test", ["url_encode"])
        methods = [v[1] for v in variants]
        assert "plain" in methods

    def test_uses_specified_techniques(self):
        variants = generate_variants("' OR 1=1--", SQLI_TECHNIQUES)
        methods = {v[1] for v in variants}
        assert "url_encode" in methods
        assert "case_mix" in methods
        assert "comment_inject" in methods
        assert "plain" in methods

    def test_skips_noop(self):
        # Pure digits — case_mix is no-op
        variants = generate_variants("12345", ["case_mix"])
        methods = [v[1] for v in variants]
        assert len(variants) == 1  # only plain, case_mix skipped
        assert methods == ["plain"]

    def test_all_variants_unique(self):
        variants = generate_variants("' OR 1=1--", SQLI_TECHNIQUES)
        payloads = [v[0] for v in variants]
        assert len(payloads) == len(set(payloads))


class TestTechniqueLists:
    def test_sqli_techniques_non_empty(self):
        assert len(SQLI_TECHNIQUES) == 5

    def test_xss_techniques_non_empty(self):
        assert len(XSS_TECHNIQUES) == 5

    def test_all_techniques_in_func_dict(self):
        for name in SQLI_TECHNIQUES + XSS_TECHNIQUES:
            assert name in TECHNIQUE_FUNCS
```

- [ ] **Step 2: Run tests — expect FAIL**

Run: `pytest tests/test_encoding.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'scanner.core.encoding'`

- [ ] **Step 3: Implement scanner/core/encoding.py**

```python
"""WAF bypass encoding functions for payload obfuscation.

Each function takes a plain payload string and returns an encoded variant.
All functions are str -> str, independent of any scanner internals.
"""
import random
import urllib.parse


# ── Encoding Functions ───────────────────────────────────────────────

def _url_encode(payload):
    """URL-encode key SQL/XSS characters.

    Encodes: ' " < > ( ) = ; - and space.
    Does NOT double-encode existing % signs.
    """
    char_map = {
        "'": "%27",
        '"': "%22",
        "<": "%3C",
        ">": "%3E",
        "(": "%28",
        ")": "%29",
        "=": "%3D",
        ";": "%3B",
        "-": "%2D",
        " ": "%20",
    }
    result = []
    for ch in payload:
        result.append(char_map.get(ch, ch))
    return "".join(result)


def _case_mix(payload):
    """Randomly flip case of ASCII letters.

    Each letter has ~50% chance of being upper/lower.
    Non-letters pass through unchanged.
    """
    result = []
    for ch in payload:
        if ch.isalpha():
            result.append(ch.upper() if random.choice([True, False]) else ch.lower())
        else:
            result.append(ch)
    return "".join(result)


def _comment_inject(payload):
    """Replace spaces with SQL inline comments /**/.

    Example: "' OR 1=1" -> "'/**/OR/**/1=1"
    """
    return payload.replace(" ", "/**/")


def _whitespace_vary(payload):
    """Replace spaces with alternative whitespace (tab or newline).

    Randomly chooses \\t or \\n per space.
    """
    result = []
    for ch in payload:
        if ch == " ":
            result.append(random.choice(["\t", "\n"]))
        else:
            result.append(ch)
    return "".join(result)


def _double_url_encode(payload):
    """Double URL-encode: first encode, then encode the % signs.

    Example: "'" -> "%27" -> "%2527"
    """
    single = _url_encode(payload)
    return single.replace("%", "%25")


def _html_entity(payload):
    """Replace HTML-significant characters with decimal entities.

    < -> &#60;   > -> &#62;   " -> &#34;   ' -> &#39;
    """
    char_map = {
        "<": "&#60;",
        ">": "&#62;",
        '"': "&#34;",
        "'": "&#39;",
    }
    result = []
    for ch in payload:
        result.append(char_map.get(ch, ch))
    return "".join(result)


def _null_byte(payload):
    """Prepend a null byte to the payload.

    Some filters stop at null byte but browser processes the rest.
    """
    return "%00" + payload


# ── Technique Registry ───────────────────────────────────────────────

TECHNIQUE_FUNCS = {
    "url_encode": _url_encode,
    "case_mix": _case_mix,
    "comment_inject": _comment_inject,
    "whitespace_vary": _whitespace_vary,
    "double_url_encode": _double_url_encode,
    "html_entity": _html_entity,
    "null_byte": _null_byte,
}

SQLI_TECHNIQUES = [
    "url_encode", "case_mix", "comment_inject",
    "whitespace_vary", "double_url_encode",
]

XSS_TECHNIQUES = [
    "url_encode", "case_mix", "double_url_encode",
    "html_entity", "null_byte",
]


def generate_variants(payload, techniques):
    """Generate plain + all encoded variants of a payload.

    Args:
        payload: Original payload string.
        techniques: List of technique names to apply.

    Returns:
        List of (encoded_payload, technique_name) tuples.
        First is always (payload, "plain").
        Duplicates are skipped (e.g., case_mix on digit-only payload).
    """
    variants = [(payload, "plain")]
    seen = {payload}
    for name in techniques:
        func = TECHNIQUE_FUNCS[name]
        encoded = func(payload)
        if encoded not in seen:
            variants.append((encoded, name))
            seen.add(encoded)
    return variants
```

- [ ] **Step 4: Run encoding tests — expect PASS**

Run: `pytest tests/test_encoding.py -v`
Expected: All tests pass.

- [ ] **Step 5: Commit**

```bash
git add scanner/core/encoding.py tests/test_encoding.py
git commit -m "feat: add WAF bypass encoding layer with 7 techniques"
```

---

### Task 2: Adapt sqli.py to use generate_variants

**Files:**
- Modify: `scanner/modules/sqli.py`

Three locations need `generate_variants()` wrapping: Phase 1 error-based loop, Phase 2 sleep loop. Baseline stays plain.

- [ ] **Step 1: Add import**

Edit `scanner/modules/sqli.py`, add after line 8:

```python
from scanner.core.encoding import generate_variants, SQLI_TECHNIQUES
```

- [ ] **Step 2: Edit Phase 1 error-based loop (lines ~135-158)**

Old:
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

New:
```python
            for entry in param_names:
                pname = entry["name"]
                method = entry["method"]
                for error_payload in ERROR_PAYLOADS:
                    for encoded, tech in generate_variants(error_payload, SQLI_TECHNIQUES):
                        if method == "POST":
                            test_url = target
                            futures[pool.submit(
                                request_handler.post, target,
                                data={pname: encoded}
                            )] = (pname, error_payload, test_url, tech)
                        else:
                            test_url = _make_test_url(target, pname, encoded)
                            futures[pool.submit(
                                request_handler.get, test_url
                            )] = (pname, error_payload, test_url, tech)
```

**Note:** The future result tuple now includes `tech` (encoding name). The completion handler (below) must also be updated.

- [ ] **Step 3: Update Phase 1 completion handler — unpack `tech`**

Old:
```python
            for future in as_completed(futures):
                pname, payload, test_url = futures[future]
                try:
                    resp = future.result()
                    match = _check_error_patterns(resp.text)
                    if match:
                        if pname not in param_has_error:
                            param_has_error.add(pname)
                            finding = {
                                "type": "error_based",
                                "parameter": pname,
                                "url": test_url,
                                "database": match["db"],
                                "evidence": (
                                    f"DB error keyword '{match['keyword']}' "
                                    f"found in response"
                                ),
                            }
```

New:
```python
            for future in as_completed(futures):
                pname, payload, test_url, tech = futures[future]
                try:
                    resp = future.result()
                    match = _check_error_patterns(resp.text)
                    if match:
                        if pname not in param_has_error:
                            param_has_error.add(pname)
                            finding = {
                                "type": "error_based",
                                "parameter": pname,
                                "url": test_url,
                                "database": match["db"],
                                "encoding": tech,
                                "evidence": (
                                    f"DB error keyword '{match['keyword']}' "
                                    f"found in response (encoding: {tech})"
                                ),
                            }
```

- [ ] **Step 4: Edit Phase 2 sleep loop (lines ~190-220)**

Old:
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

New:
```python
                for entry in time_based_targets:
                    pname = entry["name"]
                    for sp in SLEEP_PAYLOADS:
                        for encoded, tech in generate_variants(sp["payload"], SQLI_TECHNIQUES):
                            if entry["method"] == "POST":
                                test_url = target
                                futures[pool.submit(
                                    self._timed_request,
                                    lambda u, n=pname, pl=encoded: (
                                        request_handler.post(u, data={n: pl})
                                    ),
                                    target
                                )] = (
                                    pname, sp["db"], sp["payload"], test_url,
                                    param_baselines[pname], tech,
                                )
                            else:
                                test_url = _make_test_url(target, pname, encoded)
                                futures[pool.submit(
                                    self._timed_request, request_handler.get, test_url
                                )] = (
                                    pname, sp["db"], sp["payload"], test_url,
                                    param_baselines[pname], tech,
                                )
```

- [ ] **Step 5: Update Phase 2 completion handler — unpack and use `tech`**

Old:
```python
                for future in as_completed(futures):
                    pname, db, payload, test_url, baseline = futures[future]
                    try:
                        elapsed = future.result()
                        threshold = max(baseline * 3, DEFAULT_THRESHOLD)
                        if elapsed is not None and elapsed > threshold:
                            finding = {
                                "type": "time_based",
                                "parameter": pname,
                                "url": test_url,
                                "database": db,
                                "baseline_ms": round(baseline * 1000),
                                "response_ms": round(elapsed * 1000),
                                "evidence": (
                                    f"Response delayed {elapsed*1000:.0f}ms "
                                    f"vs baseline {baseline*1000:.0f}ms"
                                ),
                            }
```

New:
```python
                for future in as_completed(futures):
                    pname, db, payload, test_url, baseline, tech = futures[future]
                    try:
                        elapsed = future.result()
                        threshold = max(baseline * 3, DEFAULT_THRESHOLD)
                        if elapsed is not None and elapsed > threshold:
                            finding = {
                                "type": "time_based",
                                "parameter": pname,
                                "url": test_url,
                                "database": db,
                                "encoding": tech,
                                "baseline_ms": round(baseline * 1000),
                                "response_ms": round(elapsed * 1000),
                                "evidence": (
                                    f"Response delayed {elapsed*1000:.0f}ms "
                                    f"vs baseline {baseline*1000:.0f}ms "
                                    f"(encoding: {tech})"
                                ),
                            }
```

- [ ] **Step 6: Run sqli tests**

Run: `pytest tests/test_sqli.py -v`
Expected: All 14 pass.

- [ ] **Step 7: Commit**

```bash
git add scanner/modules/sqli.py
git commit -m "feat: add encoding variants to sqli module"
```

---

### Task 3: Adapt xss.py to use generate_variants

**Files:**
- Modify: `scanner/modules/xss.py`

- [ ] **Step 1: Add import**

Edit `scanner/modules/xss.py`, add after line 7:

```python
from scanner.core.encoding import generate_variants, XSS_TECHNIQUES
```

- [ ] **Step 2: Edit futures loop**

Old:
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

New:
```python
            for param_entry in param_names:
                pname = param_entry["name"]
                method = param_entry["method"]
                for xss_entry in XSS_PAYLOADS:
                    payload = xss_entry["payload"]
                    for encoded, tech in generate_variants(payload, XSS_TECHNIQUES):
                        if method == "POST":
                            test_url = target
                            futures[pool.submit(
                                request_handler.post, target,
                                data={pname: encoded}
                            )] = (pname, payload, test_url, tech)
                        else:
                            test_url = _make_test_url(target, pname, encoded)
                            futures[pool.submit(
                                request_handler.get, test_url
                            )] = (pname, payload, test_url, tech)
```

**Note:** The outer loop variable `payload` is the ORIGINAL payload (for `_analyze_reflection` to search for). The `encoded` variant is sent in the request.

- [ ] **Step 3: Update completion handler — unpack and use `tech`**

Old:
```python
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
```

New:
```python
            for future in as_completed(futures):
                pname, payload, test_url, tech = futures[future]
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
                            "encoding": tech,
                            "evidence": (
                                f"payload reflected as '{context}' "
                                f"in response (encoding: {tech})"
                            ),
                        }
```

- [ ] **Step 4: Update total_tests log message**

Old:
```python
        output.log_progress(
            f"Testing {len(param_names)} params x {len(XSS_PAYLOADS)} payloads "
            f"= {total_tests} requests"
        )
```

`total_tests` needs recalculation:
```python
        # Estimate variant count: 1 plain + ~5 encoded per payload
        variants_per = 1 + len(XSS_TECHNIQUES)
        total_tests = len(param_names) * len(XSS_PAYLOADS) * variants_per
        output.log_progress(
            f"Testing {len(param_names)} params x {len(XSS_PAYLOADS)} payloads "
            f"x ~{variants_per} variants = ~{total_tests} requests"
        )
```

- [ ] **Step 5: Run xss tests**

Run: `pytest tests/test_xss.py -v`
Expected: All 14 pass.

- [ ] **Step 6: Commit**

```bash
git add scanner/modules/xss.py
git commit -m "feat: add encoding variants to xss module"
```

---

### Task 4: Update output.py for encoding display

**Files:**
- Modify: `scanner/core/output.py`

- [ ] **Step 1: Add encoding to xss and sqli display**

Edit the xss display branch:

Old:
```python
        elif module_name == "xss":
            ctx = finding.get("context", "unknown")
            param = finding.get("parameter", "?")
            print(f"[{module_name}] {ctx}: {param} -- {finding.get('url', '')}")
```

New:
```python
        elif module_name == "xss":
            ctx = finding.get("context", "unknown")
            param = finding.get("parameter", "?")
            enc = finding.get("encoding", "")
            enc_str = f" [{enc}]" if enc and enc != "plain" else ""
            print(f"[{module_name}] {ctx}: {param}{enc_str} -- {finding.get('url', '')}")
```

Edit the sqli display branch:

Old:
```python
        elif module_name == "sqli":
            db = finding.get("database", "?")
            param = finding.get("parameter", "?")
            print(f"[{module_name}] {finding['type']} ({db}): {param} -- {finding.get('url', '')}")
```

New:
```python
        elif module_name == "sqli":
            db = finding.get("database", "?")
            param = finding.get("parameter", "?")
            enc = finding.get("encoding", "")
            enc_str = f" [{enc}]" if enc and enc != "plain" else ""
            print(f"[{module_name}] {finding['type']} ({db}): {param}{enc_str} -- {finding.get('url', '')}")
```

- [ ] **Step 2: Run all tests**

Run: `pytest tests/ -v`
Expected: All pass.

- [ ] **Step 3: Commit**

```bash
git add scanner/core/output.py
git commit -m "feat: display encoding technique in sqli/xss findings"
```

---

### Task 5: Integration test + push

- [ ] **Step 1: Run full test suite**

Run: `pytest tests/ -v`
Expected: All tests pass (54 existing + encoding tests).

- [ ] **Step 2: Test sqli with encoding**

Run: `python -m scanner scan "https://www.baidu.com/s?wd=test" -m sqli -v`

Expected: Significantly more requests than before (~12×5=60 error + 4×5=20 time-based). Parameter shows `wd(GET)`. Encoded variants sent. 0 false positives.

- [ ] **Step 3: Test xss with encoding**

Run: `python -m scanner scan "https://www.baidu.com/s?wd=test" -m xss -v`

Expected: ~8×5=40 requests. Encoded variants sent. 0 false positives.

- [ ] **Step 4: Push**

```bash
git push
```
