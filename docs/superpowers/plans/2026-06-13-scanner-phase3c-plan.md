# Scanner Phase 3c — Boolean-Based Blind SQLi Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add Phase 3 boolean-based blind SQLi detection with paired TRUE/FALSE payloads and 3-indicator voting.

**Architecture:** Modifies `sqli.py` only — adds `BOOL_PAYLOADS`, `_strip_dynamic()`, `_compare_responses()`, `NO_RESULT_KEYWORDS`, Phase 3 loop in `run()`. Uses existing `generate_variants()` and `param_has_error`/`param_has_time` tracking sets.

**Tech Stack:** Python 3.13, re (stdlib), concurrent.futures (stdlib)

---

### Task 1: Write failing tests

**Files:**
- Modify: `tests/test_sqli.py`

- [ ] **Step 1: Add boolean blind tests to test_sqli.py**

Append to `tests/test_sqli.py`:

```python
from scanner.modules.sqli import (
    _check_error_patterns,
    _build_baseline_time,
    _make_test_url,
    _strip_dynamic,
    _compare_responses,
    BOOL_PAYLOADS,
    NO_RESULT_KEYWORDS,
    ERROR_PAYLOADS,
    DB_ERROR_PATTERNS,
    SLEEP_PAYLOADS,
    SqliModule,
)


class TestStripDynamic:
    def test_strips_unix_timestamps(self):
        text = "page_1623456789_loaded with token abc123"
        result = _strip_dynamic(text)
        assert "1623456789" not in result

    def test_strips_md5_tokens(self):
        text = "csrf=d41d8cd98f00b204e9800998ecf8427e&ok"
        result = _strip_dynamic(text)
        assert "d41d8cd98f00b204e9800998ecf8427e" not in result

    def test_strips_script_tags(self):
        text = '<div>hi</div><script>var x=1</script><p>bye</p>'
        result = _strip_dynamic(text)
        assert '<script>' not in result
        assert 'var x=1' not in result

    def test_normalizes_whitespace(self):
        text = "hello   world\n\nbye"
        result = _strip_dynamic(text)
        assert "  " not in result
        assert "\n" not in result
        assert result == "hello world bye"

    def test_leaves_normal_text_unchanged(self):
        text = "Search results for: test query"
        result = _strip_dynamic(text)
        assert "Search results" in result


class TestCompareResponses:
    def test_different_length_triggers_positive(self):
        true_html = "<div>Results: item1, item2, item3</div>"
        false_html = "<div>empty</div>"
        verdict, indicators, detail = _compare_responses(true_html, false_html)
        assert verdict is True
        assert "body_length" in indicators

    def test_same_content_triggers_negative(self):
        html = "<div>Welcome</div>"
        verdict, indicators, detail = _compare_responses(html, html)
        assert verdict is False

    def test_no_result_keyword_triggers_positive(self):
        true_html = "<div>100 products found</div>"
        false_html = "<div>no results found</div>"
        verdict, indicators, detail = _compare_responses(true_html, false_html)
        assert verdict is True
        assert "content_keyword" in indicators

    def test_need_two_indicators_for_positive(self):
        # Only body_hash differs (same length, no keywords)
        true_html = "<div>hello world!</div>"
        false_html = "<div>hello world?</div>"
        verdict, indicators, detail = _compare_responses(true_html, false_html)
        # Length same, no keywords, only hash diff → 1/3 votes → False
        assert verdict is False


class TestBoolPayloads:
    def test_three_pairs(self):
        assert len(BOOL_PAYLOADS) == 3

    def test_each_pair_has_true_false_name(self):
        for p in BOOL_PAYLOADS:
            assert "true" in p
            assert "false" in p
            assert "name" in p

    def test_true_false_differ_by_one_char(self):
        for p in BOOL_PAYLOADS:
            diff = sum(1 for a, b in zip(p["true"], p["false"]) if a != b)
            assert diff == 1


class TestNoResultKeywords:
    def test_keywords_non_empty(self):
        assert len(NO_RESULT_KEYWORDS) >= 5

    def test_chinese_keywords_included(self):
        assert any("查" in kw for kw in NO_RESULT_KEYWORDS)
```

- [ ] **Step 2: Run tests — expect FAIL**

Run: `pytest tests/test_sqli.py::TestStripDynamic -v 2>&1 | tail -5`
Expected: `ImportError: cannot import name '_strip_dynamic'`

- [ ] **Step 3: Commit stub tests**

```bash
git add tests/test_sqli.py
git commit -m "test: add failing tests for boolean-based blind sqli"
```

---

### Task 2: Implement pure functions + payloads

**Files:**
- Modify: `scanner/modules/sqli.py`

- [ ] **Step 1: Add BOOL_PAYLOADS and NO_RESULT_KEYWORDS**

Add after `SLEEP_PAYLOADS` definition (after line 63):

```python
# ── Boolean-Based Payloads ──────────────────────────────────────────
BOOL_PAYLOADS = [
    {"name": "numeric", "true": " AND 1=1", "false": " AND 1=2"},
    {"name": "string", "true": " AND 'a'='a", "false": " AND 'a'='b"},
    {"name": "subquery", "true": " AND (SELECT 1)=1", "false": " AND (SELECT 1)=2"},
]

NO_RESULT_KEYWORDS = [
    "no results", "not found", "no records", "0 results",
    "nothing found", "查询结果为空", "没有找到", "暂无数据",
    "找不到", "未找到", "无结果",
]
```

- [ ] **Step 2: Add _strip_dynamic and _compare_responses functions**

Add after `_build_baseline_time` (after line 91):

```python
def _strip_dynamic(text):
    """Remove dynamic content for reliable comparison.

    Strips: Unix timestamps (10-13 digits), hex tokens (32+ chars),
    script tag content, normalizes whitespace.
    """
    import re
    text = re.sub(r'\b\d{10,13}\b', '', text)
    text = re.sub(r'\b[0-9a-f]{32,}\b', '', text)
    text = re.sub(r'\b[0-9a-f]{64,}\b', '', text)
    text = re.sub(r'<script[^>]*>.*?</script>', '', text, flags=re.S | re.I)
    text = re.sub(r'\s+', ' ', text)
    return text.strip()


def _compare_responses(true_html, false_html):
    """Compare TRUE vs FALSE responses using 3 indicators.

    Returns (verdict: bool, indicators: list, detail: str).
    Verdict is True when >= 2 of 3 indicators trigger.
    """
    votes = 0
    indicators = []
    ratio = 0.0

    # Indicator 1: body length ratio > 5%
    len_true = len(true_html)
    len_false = len(false_html)
    max_len = max(len_true, len_false)
    if max_len > 0:
        ratio = abs(len_true - len_false) / max_len
        if ratio > 0.05:
            votes += 1
            indicators.append("body_length")

    # Indicator 2: stripped content hash
    clean_true = _strip_dynamic(true_html)
    clean_false = _strip_dynamic(false_html)
    if clean_true != clean_false:
        votes += 1
        indicators.append("body_hash")

    # Indicator 3: no-result keywords in FALSE but not TRUE
    false_lower = false_html.lower()
    true_lower = true_html.lower()
    for kw in NO_RESULT_KEYWORDS:
        if kw in false_lower and kw not in true_lower:
            votes += 1
            indicators.append("content_keyword")
            break

    detail_parts = []
    if "body_length" in indicators:
        detail_parts.append(f"length diff {ratio*100:.1f}%")
    if "body_hash" in indicators:
        detail_parts.append("hash mismatch")
    if "content_keyword" in indicators:
        detail_parts.append("no-result keyword")

    return votes >= 2, indicators, ", ".join(detail_parts)
```

- [ ] **Step 3: Run boolean tests — expect PASS**

Run: `pytest tests/test_sqli.py::TestStripDynamic tests/test_sqli.py::TestCompareResponses tests/test_sqli.py::TestBoolPayloads tests/test_sqli.py::TestNoResultKeywords -v`
Expected: All new tests pass.

- [ ] **Step 4: Run ALL tests**

Run: `pytest tests/ -v`
Expected: All pass (74 existing + new boolean tests).

- [ ] **Step 5: Commit**

```bash
git add scanner/modules/sqli.py
git commit -m "feat: add boolean-based blind payloads and comparison functions"
```

---

### Task 3: Integrate Phase 3 into SqliModule.run()

**Files:**
- Modify: `scanner/modules/sqli.py`

- [ ] **Step 0: Update encoding import**

Old:
```python
from scanner.core.encoding import generate_variants, SQLI_TECHNIQUES
```

New:
```python
from scanner.core.encoding import generate_variants, SQLI_TECHNIQUES, TECHNIQUE_FUNCS
```

- [ ] **Step 1: Add param_has_time tracking set**

Replace `time_based_targets = []` (around line 132) with tracking set:

Old:
```python
        findings = []
        time_based_targets = []
        param_has_error = set()
```

New:
```python
        findings = []
        param_has_error = set()
        param_has_time = set()
```

- [ ] **Step 2: Update Phase 2 to populate param_has_time**

In Phase 2 completion handler, when a time-based finding is discovered, add to `param_has_time`. Also replace all `time_based_targets` with computing from params:

The Phase 1→Phase 2 transition (lines 181-184 currently) — replace:

Old:
```python
        for entry in param_names:
            if entry["name"] not in param_has_error:
                time_based_targets.append(entry)
```

New:
```python
        time_based_targets = [
            entry for entry in param_names
            if entry["name"] not in param_has_error
        ]
```

Then in Phase 2 completion handler, where finding is appended (after `output.log_finding`), add:
```python
                            param_has_time.add(pname)
```

- [ ] **Step 3: Add Phase 3 boolean-based detection block**

Add after Phase 2's `bar.close()` (after line ~259), before the final log message:

```python
        # Phase 3: Boolean-based blind for params without error or time hits
        bool_targets = [
            entry for entry in param_names
            if entry["name"] not in param_has_error
            and entry["name"] not in param_has_time
        ]

        if bool_targets:
            output.log_progress(
                f"Phase 3: Boolean-based blind ({len(bool_targets)} params, "
                f"{len(BOOL_PAYLOADS)} pairs)"
            )
            with ThreadPoolExecutor(max_workers=3) as pool:
                futures = {}
                for entry in bool_targets:
                    pname = entry["name"]
                    method = entry["method"]
                    for pair in BOOL_PAYLOADS:
                        for encoded, tech in generate_variants(pair["true"], SQLI_TECHNIQUES):
                            # TRUE request → get response
                            if method == "POST":
                                true_url = target
                                futures[pool.submit(
                                    request_handler.post, target,
                                    data={pname: encoded}
                                )] = (pname, pair, True, true_url, tech)
                            else:
                                true_url = _make_test_url(target, pname, encoded)
                                futures[pool.submit(
                                    request_handler.get, true_url
                                )] = (pname, pair, True, true_url, tech)

                            # FALSE request — encode with same technique
                            if tech == "plain":
                                false_encoded = pair["false"]
                            else:
                                false_encoded = TECHNIQUE_FUNCS[tech](pair["false"])
                            if method == "POST":
                                false_url = target
                                futures[pool.submit(
                                    request_handler.post, target,
                                    data={pname: false_encoded}
                                )] = (pname, pair, False, false_url, tech)
                            else:
                                false_url = _make_test_url(target, pname, false_encoded)
                                futures[pool.submit(
                                    request_handler.get, false_url
                                )] = (pname, pair, False, false_url, tech)

                # Collect TRUE/FALSE response pairs and compare
                bar = output.create_progress_bar("Boolean-Blind", len(futures))
                pairs_cache = {}  # (pname, pair["name"], tech) → {True: html, False: html, true_url, false_url}
                for future in as_completed(futures):
                    pname, pair, is_true, url, tech = futures[future]
                    key = (pname, pair["name"], tech)
                    try:
                        resp = future.result()
                        if key not in pairs_cache:
                            pairs_cache[key] = {
                                "true_html": None, "false_html": None,
                                "true_url": None, "false_url": None,
                            }
                        if is_true:
                            pairs_cache[key]["true_html"] = resp.text
                            pairs_cache[key]["true_url"] = url
                        else:
                            pairs_cache[key]["false_html"] = resp.text
                            pairs_cache[key]["false_url"] = url

                        # If both present, compare
                        cache = pairs_cache[key]
                        if cache["true_html"] is not None and cache["false_html"] is not None:
                            verdict, indicators, detail = _compare_responses(
                                cache["true_html"], cache["false_html"]
                            )
                            if verdict:
                                finding = {
                                    "type": "boolean_based",
                                    "parameter": pname,
                                    "true_url": cache["true_url"],
                                    "false_url": cache["false_url"],
                                    "payload_pair": pair["name"],
                                    "encoding": tech,
                                    "indicators": indicators,
                                    "evidence": (
                                        f"TRUE/FALSE response differ: {detail} "
                                        f"(encoding: {tech})"
                                    ),
                                }
                                findings.append(finding)
                                output.log_finding(self.name, finding)
                                param_has_time.add(pname)
                            del pairs_cache[key]
                    except Exception:
                        if key in pairs_cache:
                            pairs_cache.pop(key, None)
                    output.update_progress(bar)
                bar.close()
```

- [ ] **Step 4: Run sqli tests**

Run: `pytest tests/test_sqli.py -v`
Expected: All tests pass.

- [ ] **Step 5: Run ALL tests**

Run: `pytest tests/ -v`
Expected: All pass.

- [ ] **Step 6: Commit**

```bash
git add scanner/modules/sqli.py
git commit -m "feat: add Phase 3 boolean-based blind SQLi detection"
```

---

### Task 4: Integration test + push

- [ ] **Step 1: Test sqli with all three phases**

Run: `python -m scanner scan "https://www.baidu.com/s?wd=test" -m sqli -v`

Expected: Phase 1 runs, Phase 2 runs (with encoding), Phase 3 runs (3 pairs × ~6 encoding variants = ~36 requests). 0 false positives.

- [ ] **Step 2: Run full test suite**

Run: `pytest tests/ -v`
Expected: All pass.

- [ ] **Step 3: Push**

```bash
git push
```
