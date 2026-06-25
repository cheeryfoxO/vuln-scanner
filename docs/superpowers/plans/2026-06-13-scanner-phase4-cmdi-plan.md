# Command Injection Detection (Phase 4) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `cmdi` module that detects OS command injection via error-based output matching (12 payloads) and time-based blind detection (4 sleep payloads × 5 encoding techniques).

**Architecture:** New module `scanner/modules/cmdi.py` (~220 lines) following the exact same pattern as `sqli.py` — pure functions for error pattern matching and timing, module class with two-phase `run()`. Reuses `_extract_params` from `html_utils.py`, `generate_variants`/`TECHNIQUE_FUNCS` from `encoding.py`. Registers in CLI with display in output.

**Tech Stack:** Python 3.13, re (stdlib), time (stdlib), urllib.parse (stdlib), concurrent.futures (stdlib)

---

### File Structure

| File | Action | Purpose |
|------|--------|---------|
| `scanner/modules/cmdi.py` | Create | Module: error patterns, time payloads, CmdiModule class |
| `tests/test_cmdi.py` | Create | Tests for pure functions + module attributes |
| `scanner/cli.py` | Modify | Import + register CmdiModule in MODULE_CLASSES |
| `scanner/core/output.py` | Modify | Add `cmdi` display in `log_finding()` |

### Encoding Techniques

Command injection uses 5 of the 7 encoding techniques (excluding `comment_inject` which is SQL-specific and `html_entity` which targets HTML parsing, not shell):

```python
CMDI_TECHNIQUES = [
    "url_encode", "case_mix", "whitespace_vary",
    "double_url_encode", "null_byte",
]
```

### Error Payloads (12)

Covers 4 command separators (`;`, `|`, `` ` ``, `$()`) across Unix and Windows targets:

```python
CMD_ERROR_PAYLOADS = [
    "; id",
    "| id",
    "`id`",
    "$(id)",
    "; whoami",
    "| whoami",
    "; cat /etc/passwd",
    "; uname -a",
    "| dir",
    "; type %SystemRoot%\\win.ini",
    "& whoami",
    "|| whoami",
]
```

### Error Detection Patterns

Organized by OS to give context in findings:

```python
CMD_ERROR_PATTERNS = {
    "Unix": [
        r"uid=\d+\([^)]+\)\s+gid=\d+\([^)]+\)",  # id output
        r"root:x:0:0:",                              # /etc/passwd
        r"(?:www-data|nobody|daemon):x:",            # system users
        r"Linux\s+\S+\s+\d+\.\d+",                   # uname -a
        r"Darwin\s+\S+\s+\d+\.\d+",                  # uname macOS
    ],
    "Windows": [
        r"Volume\sin\sdrive",                         # dir output
        r"Directory\sof\s",                           # dir output
        r"<DIR>\s+",                                  # dir listing
        r"nt\s+authority\\",                          # whoami
        r"\\\\windows\\\\",                           # path leak
        r"\[Version\s+\d+\.\d+",                     # ver output
    ],
}
```

### Time-Based Sleep Payloads (4)

Four command separators, all using `sleep 5`:

```python
CMD_SLEEP_PAYLOADS = [
    {"os": "Unix", "payload": "; sleep 5"},
    {"os": "Unix", "payload": "| sleep 5"},
    {"os": "Unix", "payload": "|| sleep 5"},
    {"os": "Unix", "payload": "&& sleep 5"},
]
```

### Finding Structure

```python
{
    "type": "error_based",        # or "time_based"
    "parameter": "q",
    "url": "http://example.com?q=%3B+id",
    "os": "Unix",                  # from CMD_ERROR_PATTERNS or CMD_SLEEP_PAYLOADS
    "encoding": "url_encode",
    "evidence": "OS command output 'uid=33(www-data)' found (encoding: url_encode)",
    # time_based adds:
    "baseline_ms": 120,
    "response_ms": 5340,
}
```

---

### Task 1: Write tests + implement cmdi.py

**Files:**
- Create: `tests/test_cmdi.py`
- Create: `scanner/modules/cmdi.py`

- [ ] **Step 1: Write tests/test_cmdi.py**

```python
"""Tests for command injection detection module."""
import time
from unittest.mock import Mock, patch
from scanner.modules.cmdi import (
    _check_cmd_error_patterns,
    _build_baseline_time,
    CMD_ERROR_PAYLOADS,
    CMD_SLEEP_PAYLOADS,
    CMD_ERROR_PATTERNS,
    CmdiModule,
)


class TestCmdErrorPatterns:
    def test_unix_id_output_detected(self):
        text = "uid=33(www-data) gid=33(www-data) groups=33(www-data)"
        result = _check_cmd_error_patterns(text)
        assert result is not None
        assert result["os"] == "Unix"

    def test_passwd_entry_detected(self):
        text = "/etc/passwd contents: root:x:0:0:root:/root:/bin/bash"
        result = _check_cmd_error_patterns(text)
        assert result is not None
        assert result["os"] == "Unix"

    def test_uname_output_detected(self):
        text = "Linux server01 5.15.0-91-generic #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023"
        result = _check_cmd_error_patterns(text)
        assert result is not None
        assert result["os"] == "Unix"

    def test_windows_dir_output_detected(self):
        text = " Volume in drive C has no label."
        result = _check_cmd_error_patterns(text)
        assert result is not None
        assert result["os"] == "Windows"

    def test_windows_whoami_detected(self):
        text = "nt authority\\system"
        result = _check_cmd_error_patterns(text)
        assert result is not None
        assert result["os"] == "Windows"

    def test_no_command_in_normal_page(self):
        text = "<html><body>Welcome to our site</body></html>"
        result = _check_cmd_error_patterns(text)
        assert result is None

    def test_case_insensitive_matching(self):
        text = "VOLUME IN DRIVE C IS SYSTEM"
        result = _check_cmd_error_patterns(text)
        assert result is not None
        assert result["os"] == "Windows"


class TestBaselineTime:
    def test_baseline_returns_average(self):
        call_times = [0.1, 0.2, 0.3]
        call_count = [0]

        def mock_request(url):
            idx = min(call_count[0], 2)
            call_count[0] += 1
            time.sleep(call_times[idx])
            return Mock(status_code=200, text="")

        with patch("time.perf_counter") as mock_time:
            mock_time.side_effect = [0.0, 0.1, 0.1, 0.2, 0.2, 0.3]
            baseline = _build_baseline_time("http://test.com?id=1", mock_request)
            assert 0.09 < baseline < 0.11


class TestPayloads:
    def test_error_payloads_count(self):
        assert len(CMD_ERROR_PAYLOADS) == 12

    def test_error_payloads_have_separators(self):
        payloads_str = " ".join(CMD_ERROR_PAYLOADS)
        assert ";" in payloads_str or "|" in payloads_str

    def test_sleep_payloads_have_four(self):
        assert len(CMD_SLEEP_PAYLOADS) == 4

    def test_sleep_payloads_all_use_sleep_5(self):
        for sp in CMD_SLEEP_PAYLOADS:
            assert "sleep 5" in sp["payload"]

    def test_error_patterns_have_both_os(self):
        assert "Unix" in CMD_ERROR_PATTERNS
        assert "Windows" in CMD_ERROR_PATTERNS
        assert len(CMD_ERROR_PATTERNS["Unix"]) >= 3
        assert len(CMD_ERROR_PATTERNS["Windows"]) >= 3


class TestModule:
    def test_module_attributes(self):
        mod = CmdiModule()
        assert mod.name == "cmdi"
        assert mod.requires_url is True
        assert "command" in mod.description.lower()
```

- [ ] **Step 2: Run tests — expect FAIL**

Run: `pytest tests/test_cmdi.py -v`
Expected: `ModuleNotFoundError: No module named 'scanner.modules.cmdi'`

- [ ] **Step 3: Create scanner/modules/cmdi.py**

```python
"""Command injection detection -- error-based + time-based blind."""
import re
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed

from scanner.modules.base import BaseModule
from scanner.core.html_utils import _extract_params, _make_test_url
from scanner.core.encoding import generate_variants, TECHNIQUE_FUNCS


# ── Command Injection Techniques ─────────────────────────────────────
# SQL-specific (comment_inject) and HTML-specific (html_entity) excluded

CMDI_TECHNIQUES = [
    "url_encode", "case_mix", "whitespace_vary",
    "double_url_encode", "null_byte",
]

# ── Error-Based Payloads ────────────────────────────────────────────

CMD_ERROR_PAYLOADS = [
    "; id",
    "| id",
    "`id`",
    "$(id)",
    "; whoami",
    "| whoami",
    "; cat /etc/passwd",
    "; uname -a",
    "| dir",
    "; type %SystemRoot%\\win.ini",
    "& whoami",
    "|| whoami",
]

# ── OS Command Output Patterns ──────────────────────────────────────

CMD_ERROR_PATTERNS = {
    "Unix": [
        r"uid=\d+\([^)]+\)\s+gid=\d+\([^)]+\)",
        r"root:x:0:0:",
        r"(?:www-data|nobody|daemon):x:",
        r"Linux\s+\S+\s+\d+\.\d+",
        r"Darwin\s+\S+\s+\d+\.\d+",
    ],
    "Windows": [
        r"Volume\sin\sdrive",
        r"Directory\sof\s",
        r"<DIR>\s+",
        r"nt\s+authority\\",
        r"\\\\windows\\\\",
        r"\[Version\s+\d+\.\d+",
    ],
}

# ── Time-Based Sleep Payloads ───────────────────────────────────────

CMD_SLEEP_PAYLOADS = [
    {"os": "Unix", "payload": "; sleep 5"},
    {"os": "Unix", "payload": "| sleep 5"},
    {"os": "Unix", "payload": "|| sleep 5"},
    {"os": "Unix", "payload": "&& sleep 5"},
]

DEFAULT_THRESHOLD = 5  # seconds


# ── Pure Functions (testable) ───────────────────────────────────────

def _check_cmd_error_patterns(text):
    """Scan response text for OS command output patterns.

    Returns {"os": str, "pattern": str} or None.
    """
    for os_name, patterns in CMD_ERROR_PATTERNS.items():
        for pat in patterns:
            if re.search(pat, text, re.IGNORECASE):
                return {"os": os_name, "pattern": pat}
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


# ── CmdiModule ──────────────────────────────────────────────────────

class CmdiModule(BaseModule):
    name = "cmdi"
    description = "Detect command injection via error output + time-based blind"
    requires_url = True

    def run(self, target, request_handler, output):
        """Run error-based and time-based command injection detection."""
        target = target.rstrip("/")
        output.log_progress(f"Fetching {target} for parameter extraction...")

        try:
            resp = request_handler.get(target)
            html = resp.text
        except Exception as e:
            output.log_progress(f"Failed to fetch {target}: {e}")
            return {"module": self.name, "findings": []}

        param_names = _extract_params(target, html)

        # If URL has no obvious params, try the URL query itself
        if not param_names:
            parsed = urllib.parse.urlparse(target)
            if parsed.query:
                param_names = [
                    {"name": k, "method": "GET"}
                    for k in urllib.parse.parse_qs(parsed.query).keys()
                ]

        if not param_names:
            output.log_progress("No testable parameters found on this page")
            return {"module": self.name, "findings": []}

        param_list = [f"{p['name']}({p['method']})" for p in param_names]
        output.log_progress(
            f"Found {len(param_names)} potential parameters: {param_list}"
        )

        findings = []
        param_has_error = set()

        # Phase 1: Error-based (fast, 3 concurrent requests)
        output.log_progress(
            f"Phase 1: Error-based testing ({len(CMD_ERROR_PAYLOADS)} payloads)"
        )
        with ThreadPoolExecutor(max_workers=3) as pool:
            futures = {}
            for entry in param_names:
                pname = entry["name"]
                method = entry["method"]
                for error_payload in CMD_ERROR_PAYLOADS:
                    for encoded, tech in generate_variants(
                        error_payload, CMDI_TECHNIQUES
                    ):
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

            bar = output.create_progress_bar("Error-Based", len(futures))
            for future in as_completed(futures):
                pname, payload, test_url, tech = futures[future]
                try:
                    resp = future.result()
                    match = _check_cmd_error_patterns(resp.text)
                    if match:
                        if pname not in param_has_error:
                            param_has_error.add(pname)
                            finding = {
                                "type": "error_based",
                                "parameter": pname,
                                "url": test_url,
                                "os": match["os"],
                                "encoding": tech,
                                "evidence": (
                                    f"OS command output matching "
                                    f"'{match['pattern']}' found "
                                    f"(encoding: {tech})"
                                ),
                            }
                            findings.append(finding)
                            output.log_finding(self.name, finding)
                except Exception:
                    pass
                output.update_progress(bar)
            bar.close()

        # Determine which params need Phase 2
        time_based_targets = [
            entry for entry in param_names
            if entry["name"] not in param_has_error
        ]

        # Phase 2: Time-based blind for params without error matches
        if time_based_targets:
            output.log_progress(
                f"Phase 2: Time-based blind ({len(time_based_targets)} params, "
                f"{len(CMD_SLEEP_PAYLOADS)} payloads)"
            )
            with ThreadPoolExecutor(max_workers=3) as pool:
                # Compute baseline for each parameter
                param_baselines = {}
                for entry in time_based_targets:
                    pname = entry["name"]
                    if entry["method"] == "POST":
                        baseline = _build_baseline_time(
                            target,
                            lambda u, n=pname: request_handler.post(
                                u, data={n: "1"}
                            )
                        )
                    else:
                        base_url = _make_test_url(target, pname, "1")
                        baseline = _build_baseline_time(
                            base_url, request_handler.get
                        )
                    param_baselines[pname] = baseline
                    output.log_progress(
                        f"  {pname} baseline: {baseline*1000:.0f}ms"
                    )

                # Test sleep payloads
                futures = {}
                for entry in time_based_targets:
                    pname = entry["name"]
                    for sp in CMD_SLEEP_PAYLOADS:
                        for encoded, tech in generate_variants(
                            sp["payload"], CMDI_TECHNIQUES
                        ):
                            if entry["method"] == "POST":
                                test_url = target
                                futures[pool.submit(
                                    self._timed_request,
                                    lambda u, n=pname, pl=encoded: (
                                        request_handler.post(u, data={n: pl})
                                    ),
                                    target
                                )] = (
                                    pname, sp["os"], sp["payload"], test_url,
                                    param_baselines[pname], tech,
                                )
                            else:
                                test_url = _make_test_url(
                                    target, pname, encoded
                                )
                                futures[pool.submit(
                                    self._timed_request,
                                    request_handler.get, test_url
                                )] = (
                                    pname, sp["os"], sp["payload"], test_url,
                                    param_baselines[pname], tech,
                                )

                bar = output.create_progress_bar("Time-Based", len(futures))
                for future in as_completed(futures):
                    pname, os_name, payload, test_url, baseline, tech = (
                        futures[future]
                    )
                    try:
                        elapsed = future.result()
                        threshold = max(baseline * 3, DEFAULT_THRESHOLD)
                        if elapsed is not None and elapsed > threshold:
                            finding = {
                                "type": "time_based",
                                "parameter": pname,
                                "url": test_url,
                                "os": os_name,
                                "encoding": tech,
                                "baseline_ms": round(baseline * 1000),
                                "response_ms": round(elapsed * 1000),
                                "evidence": (
                                    f"Response delayed {elapsed*1000:.0f}ms "
                                    f"vs baseline {baseline*1000:.0f}ms "
                                    f"(encoding: {tech})"
                                ),
                            }
                            findings.append(finding)
                            output.log_finding(self.name, finding)
                    except Exception:
                        pass
                    output.update_progress(bar)
                bar.close()

        output.log_progress(
            f"Command injection done: {len(findings)} potential injections found"
        )
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

- [ ] **Step 4: Run tests — expect PASS**

Run: `pytest tests/test_cmdi.py -v`
Expected: All 13 tests pass.

- [ ] **Step 5: Commit**

```bash
git add scanner/modules/cmdi.py tests/test_cmdi.py
git commit -m "feat: add command injection detection module"
```

---

### Task 2: Register in CLI + output display

**Files:**
- Modify: `scanner/cli.py:14-17` (add import + to MODULE_CLASSES)
- Modify: `scanner/core/output.py:79-81` (add display before `log_progress`)

- [ ] **Step 1: Register in CLI**

Edit `scanner/cli.py`, add import after the stored_xss import:

```python
from scanner.modules.cmdi import CmdiModule
```

Edit `scanner/cli.py`, MODULE_CLASSES list:

```python
MODULE_CLASSES = [SubdomainModule, DirscanModule, ParamsModule, SqliModule, XssModule, DomXssModule, StoredXssModule, CmdiModule]
```

- [ ] **Step 2: Add display in output.py**

Add before `log_progress` method (after the `stored_xss` elif block):

```python
        elif module_name == "cmdi":
            os_name = finding.get("os", "?")
            param = finding.get("parameter", "?")
            enc = finding.get("encoding", "")
            enc_str = f" [{enc}]" if enc and enc != "plain" else ""
            if finding.get("type") == "time_based":
                print(f"[{module_name}] {finding['type']} ({os_name}): {param}{enc_str} "
                      f"-- {finding.get('response_ms', '?')}ms -- {finding.get('url', '')}")
            else:
                print(f"[{module_name}] {finding['type']} ({os_name}): {param}{enc_str} "
                      f"-- {finding.get('url', '')}")
```

- [ ] **Step 3: Verify list + tests**

```bash
python -m scanner list
pytest tests/ -v
```

Expected: `cmdi` appears in module list. All tests pass (113 + 13 = 126).

- [ ] **Step 4: Commit**

```bash
git add scanner/cli.py scanner/core/output.py
git commit -m "feat: register cmdi module and add display"
```

---

### Task 3: Integration test + push

- [ ] **Step 1: Test against target**

Run: `python -m scanner scan "https://www.baidu.com" -m cmdi -v`

Expected: Finds parameters, runs error-based and time-based phases. No crashes. May find nothing (Baidu is well-filtered), but must not error.

- [ ] **Step 2: Run full test suite**

Run: `pytest tests/ -v`
Expected: All 126 tests pass.

- [ ] **Step 3: Push**

```bash
git push
```
