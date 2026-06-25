# Scanner Phase 2b — SQL Injection Module Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a sqli module that detects SQL injection via error-based + time-based blind techniques. Non-destructive, GET-only, inherits BaseModule.

**Architecture:** Single new file `scanner/modules/sqli.py` (~200 lines). Reuses `_FormParser` pattern from params module for input extraction. Two-phase detection: error keyword matching (Phase 1), then time-based sleep with baseline comparison (Phase 2). Per-parameter decision — skip time-based for params that already triggered errors. Registered in `cli.py` with new `--sqli-threshold` option.

**Tech Stack:** Python 3.13, re (stdlib), html.parser (stdlib), time (stdlib), concurrent.futures (stdlib)

---

### Task 1: Write sqli module tests

**Files:**
- Create: `tests/test_sqli.py`

- [ ] **Step 1: Create test file with testable pure functions**

Create `tests/test_sqli.py`:
```python
"""Tests for SQL injection detection module."""
import re
import time
from unittest.mock import Mock, patch
from scanner.modules.sqli import (
    _check_error_patterns,
    _build_baseline_time,
    _make_test_url,
    ERROR_PAYLOADS,
    DB_ERROR_PATTERNS,
    SLEEP_PAYLOADS,
    SqliModule,
)


class TestErrorPatterns:
    def test_mysql_error_detected(self):
        text = "You have an error in your SQL syntax; check the manual"
        result = _check_error_patterns(text)
        assert result is not None
        assert result["db"] == "MySQL"
        assert "SQL syntax" in result["keyword"]

    def test_postgresql_error_detected(self):
        text = "ERROR: 42601: syntax error at or near \"'\" at character 15. PostgreSQL query failed"
        result = _check_error_patterns(text)
        assert result is not None
        assert result["db"] in ("PostgreSQL",)

    def test_mssql_error_detected(self):
        text = "Microsoft OLE DB Provider for SQL Server error '80040e14'. Unclosed quotation mark"
        result = _check_error_patterns(text)
        assert result is not None
        assert result["db"] in ("MSSQL", "MySQL")

    def test_oracle_error_detected(self):
        text = "ORA-01756: quoted string not properly terminated"
        result = _check_error_patterns(text)
        assert result is not None
        assert result["db"] in ("Oracle", "MySQL")

    def test_no_error_in_normal_page(self):
        text = "<html><body>Welcome to our site</body></html>"
        result = _check_error_patterns(text)
        assert result is None

    def test_check_error_patterns_is_case_insensitive(self):
        text = "you have an error in your sql syntax near"
        result = _check_error_patterns(text)
        assert result is not None
        assert result["db"] is not None


class TestBaselineTime:
    def test_baseline_returns_average(self):
        """send_request is called 3 times, baseline = average of all 3."""
        call_times = [0.1, 0.2, 0.3]
        call_count = [0]

        def mock_request(url):
            idx = min(call_count[0], 2)
            call_count[0] += 1
            time.sleep(call_times[idx])  # won't actually sleep in test if we mock
            return Mock(status_code=200, text="")

        # We mock time.perf_counter to return controlled values
        with patch("time.perf_counter") as mock_time:
            mock_time.side_effect = [0.0, 0.1, 0.1, 0.2, 0.2, 0.3]
            baseline = _build_baseline_time("http://test.com?id=1", mock_request)
            assert 0.09 < baseline < 0.11  # ~0.1s average


class TestMakeTestUrl:
    def test_replaces_get_param(self):
        result = _make_test_url("http://example.com/page?id=1", "id", "' OR 1=1--")
        assert result == "http://example.com/page?id=1%27+OR+1%3D1--"

    def test_adds_param_to_url_without_params(self):
        result = _make_test_url("http://example.com/page", "q", "test")
        assert result == "http://example.com/page?q=test"

    def test_adds_param_to_url_with_existing_params(self):
        result = _make_test_url("http://example.com/page?a=1&b=2", "b", "injected")
        assert "b=injected" in result


class TestPayloads:
    def test_error_payloads_non_empty(self):
        assert len(ERROR_PAYLOADS) == 12

    def test_sleep_payloads_have_four_dbs(self):
        assert len(SLEEP_PAYLOADS) == 4
        dbs = {p["db"] for p in SLEEP_PAYLOADS}
        assert dbs == {"MySQL", "PostgreSQL", "MSSQL", "Oracle"}

    def test_db_error_patterns_have_all_four(self):
        dbs = set(DB_ERROR_PATTERNS.keys())
        assert dbs == {"MySQL", "PostgreSQL", "MSSQL", "Oracle"}


class TestModule:
    def test_module_attributes(self):
        mod = SqliModule()
        assert mod.name == "sqli"
        assert mod.requires_url is True
        assert "SQL" in mod.description
```

- [ ] **Step 2: Verify tests fail**

Run: `pytest tests/test_sqli.py -v`

Expected: FAIL — `ModuleNotFoundError: No module named 'scanner.modules.sqli'`

- [ ] **Step 3: Commit stub test file**

```bash
git add tests/test_sqli.py
git commit -m "test: add failing tests for sqli module"
```

---

### Task 2: Implement sqli module

**Files:**
- Create: `scanner/modules/sqli.py`

- [ ] **Step 1: Implement the full sqli.py module**

Create `scanner/modules/sqli.py`:
```python
"""SQL injection detection -- error-based + time-based blind."""
import re
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from html.parser import HTMLParser

from scanner.modules.base import BaseModule


# ── Error-Based Payloads ────────────────────────────────────────────
ERROR_PAYLOADS = [
    "'",
    '"',
    "')",
    '")',
    "\\",
    "1' AND '1'='1",
    "1' AND '1'='2",
    "1 AND 1=1",
    "1 AND 1=2",
    "1' OR 1=1--",
    "1' UNION SELECT NULL--",
    "1; SELECT 1--",
]

# ── DB Error Keyword Patterns ───────────────────────────────────────
DB_ERROR_PATTERNS = {
    "MySQL": [
        r"SQL syntax",
        r"mysql_fetch",
        r"MySQL Error",
        r"Warning.*mysql",
        r"valid MySQL",
    ],
    "PostgreSQL": [
        r"PostgreSQL",
        r"psql",
        r"pg_query",
        r"ERROR:\s+syntax error",
    ],
    "MSSQL": [
        r"SQL Server",
        r"ODBC",
        r"mssql",
        r"SqlException",
        r"Unclosed quotation mark",
    ],
    "Oracle": [
        r"ORA-\d+",
        r"Oracle",
        r"PL/SQL",
        r"quoted string not properly terminated",
    ],
}

# ── Time-Based Sleep Payloads ────────────────────────────────────────
SLEEP_PAYLOADS = [
    {"db": "MySQL", "payload": "' OR IF(1=1,SLEEP(5),0)--"},
    {"db": "PostgreSQL", "payload": "'; SELECT pg_sleep(5)--"},
    {"db": "MSSQL", "payload": "'; WAITFOR DELAY '00:00:05'--"},
    {"db": "Oracle", "payload": "'; BEGIN DBMS_LOCK.SLEEP(5); END;--"},
]

DEFAULT_THRESHOLD = 5  # seconds


# ── Pure Functions (testable) ────────────────────────────────────────

def _check_error_patterns(text):
    """Scan response text for DB error keywords. Returns {db, keyword} or None."""
    text_lower = text.lower()
    for db, patterns in DB_ERROR_PATTERNS.items():
        for pat in patterns:
            if re.search(pat, text_lower):
                return {"db": db, "keyword": pat}
    return None


def _build_baseline_time(url, send_request):
    """Send 3 normal requests, return average response time in seconds."""
    times = []
    for _ in range(3):
        start = time.perf_counter()
        try:
            send_request(url)
        except Exception:
            pass
        elapsed = time.perf_counter() - start
        times.append(elapsed)
    return sum(times) / len(times) if times else 0.0


def _make_test_url(base_url, param_name, payload):
    """Replace or append a GET parameter with the payload value."""
    parsed = list(urllib.parse.urlparse(base_url))
    query = dict(urllib.parse.parse_qsl(parsed[4]))
    query[param_name] = payload
    parsed[4] = urllib.parse.urlencode(query)
    return urllib.parse.urlunparse(parsed)


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


# ── SqliModule ───────────────────────────────────────────────────────

class SqliModule(BaseModule):
    name = "sqli"
    description = "Detect SQL injection via error + time-based blind"
    requires_url = True

    def run(self, target, request_handler, output):
        """Run error-based and time-based SQLi detection."""
        target = target.rstrip("/")
        output.log_progress(f"Fetching {target} for parameter extraction...")

        try:
            resp = request_handler.get(target)
            html = resp.text
        except Exception as e:
            output.log_progress(f"Failed to fetch {target}: {e}")
            return {"module": self.name, "findings": []}

        param_names = _extract_params(target, html)

        # If URL has no obvious params, try injecting into the URL path itself
        if not param_names:
            parsed = urllib.parse.urlparse(target)
            if parsed.query:
                param_names = list(urllib.parse.parse_qs(parsed.query).keys())

        if not param_names:
            output.log_progress("No testable parameters found on this page")
            return {"module": self.name, "findings": []}

        output.log_progress(f"Found {len(param_names)} potential parameters: {param_names}")

        findings = []
        time_based_targets = []  # (param_name, test_url) pairs for Phase 2

        # Phase 1: Error-based (fast, 3 concurrent requests)
        output.log_progress(f"Phase 1: Error-based testing ({len(ERROR_PAYLOADS)} payloads)")
        with ThreadPoolExecutor(max_workers=3) as pool:
            futures = {}
            for pname in param_names:
                for error_payload in ERROR_PAYLOADS:
                    test_url = _make_test_url(target, pname, error_payload)
                    futures[pool.submit(request_handler.get, test_url)] = (pname, error_payload, test_url)

            bar = output.create_progress_bar("Error-Based", len(futures))
            param_has_error = set()
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
                                "evidence": f"DB error keyword '{match['keyword']}' found in response",
                            }
                            findings.append(finding)
                            output.log_finding(self.name, finding)
                except Exception:
                    pass
                output.update_progress(bar)
            bar.close()

        # Determine which params need Phase 2
        for pname in param_names:
            if pname not in param_has_error:
                time_based_targets.append(pname)

        # Phase 2: Time-based blind for params without error matches
        if time_based_targets:
            output.log_progress(
                f"Phase 2: Time-based blind ({len(time_based_targets)} params, "
                f"{len(SLEEP_PAYLOADS)} DB types)"
            )
            with ThreadPoolExecutor(max_workers=3) as pool:
                # First, compute baseline for each parameter
                param_baselines = {}
                for pname in time_based_targets:
                    base_url = _make_test_url(target, pname, "1")
                    baseline = _build_baseline_time(base_url, request_handler.get)
                    param_baselines[pname] = baseline
                    output.log_progress(f"  {pname} baseline: {baseline*1000:.0f}ms")

                # Then test sleep payloads
                futures = {}
                for pname in time_based_targets:
                    for sp in SLEEP_PAYLOADS:
                        test_url = _make_test_url(target, pname, sp["payload"])
                        futures[pool.submit(self._timed_request, request_handler.get, test_url)] = (
                            pname, sp["db"], sp["payload"], test_url, param_baselines[pname]
                        )

                bar = output.create_progress_bar("Time-Based", len(futures))
                for future in as_completed(futures):
                    pname, db, payload, test_url, baseline = futures[future]
                    try:
                        elapsed = future.result()
                        if elapsed is not None and elapsed > max(baseline * 3, DEFAULT_THRESHOLD):
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
                            findings.append(finding)
                            output.log_finding(self.name, finding)
                    except Exception:
                        pass
                    output.update_progress(bar)
                bar.close()

        output.log_progress(f"SQLi scan done: {len(findings)} potential injections found")
        return {"module": self.name, "findings": findings}

    def _timed_request(self, get_func, url):
        """Make a request and return elapsed time in seconds, or None on failure."""
        start = time.perf_counter()
        try:
            get_func(url)
            return time.perf_counter() - start
        except Exception:
            return None
```

- [ ] **Step 2: Run tests — error pattern tests should pass**

Run: `pytest tests/test_sqli.py -v -k "TestErrorPatterns or TestPayloads or TestModule or TestMakeTestUrl"`

Expected: Most test classes pass (TestBaselineTime may need adjustment)

- [ ] **Step 3: Verify module loads and smoke test**

Run: `python -c "from scanner.modules.sqli import SqliModule; m = SqliModule(); print(m.name, m.description)"`

Expected: `sqli Detect SQL injection via error + time-based blind`

- [ ] **Step 4: Commit**

```bash
git add scanner/modules/sqli.py
git commit -m "feat: add SQL injection detection module (error-based + time-based blind)"
```

---

### Task 3: Register in CLI + add --sqli-threshold

**Files:**
- Modify: `scanner/cli.py`

- [ ] **Step 1: Add SqliModule to MODULE_CLASSES and add --sqli-threshold arg**

Edit `scanner/cli.py`, add import after line 10:
```python
from scanner.modules.sqli import SqliModule
```

Edit `scanner/cli.py` line 13, replace:
```python
MODULE_CLASSES = [SubdomainModule, DirscanModule, ParamsModule]
```
with:
```python
MODULE_CLASSES = [SubdomainModule, DirscanModule, ParamsModule, SqliModule]
```

Edit `scanner/cli.py`, add after `--dirscan-wordlist` line:
```python
    scan.add_argument("--sqli-threshold", type=int, default=5,
                      help="SQLi time-based threshold in seconds (default: 5)")
```

- [ ] **Step 2: Verify scanner list shows sqli**

Run: `python -m scanner list`

Expected:
```
Available modules:
  subdomain    Enumerate subdomains via DNS + HTTP liveness check
  dirscan      Scan for sensitive directories and files via HTTP HEAD
  params       Extract form inputs, JS endpoints, and URL parameters
  sqli         Detect SQL injection via error + time-based blind
```

- [ ] **Step 3: Run all tests**

Run: `pytest tests/ -v`

Expected: All tests pass

- [ ] **Step 4: Commit**

```bash
git add scanner/cli.py
git commit -m "feat: register sqli module in CLI with --sqli-threshold option"
```

---

### Task 4: Integration test

- [ ] **Step 1: Test against safe target (no SQLi)**

Run: `python -m scanner scan https://httpbin.org/get?id=1 -m sqli -v`

Expected: Fetches page, finds parameter `id`, runs error-based and time-based, finds 0 injections. No crashes.

- [ ] **Step 2: Verify sqli works with -m all**

Run: `python -m scanner scan https://httpbin.org -m all`

Expected: All 4 modules run, sqli included

- [ ] **Step 3: Run full test suite**

Run: `pytest tests/ -v`

Expected: All tests pass (13 original + sqli tests)

- [ ] **Step 4: Push**

```bash
git push
```
