# Scanner Phase 3e — Stored XSS Detection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `stored_xss` module that detects persistent XSS via form submission with unique UUID payloads and re-check.

**Architecture:** New module `stored_xss.py` (~150 lines) with pure functions for form extraction, link extraction, form data building, and UUID payload generation. Two-phase detection: submit → re-check. Registers in CLI.

**Tech Stack:** Python 3.13, re (stdlib), urllib.parse (stdlib), uuid (stdlib), concurrent.futures (stdlib)

---

### Task 1: Write tests + implement stored_xss.py

**Files:**
- Create: `tests/test_stored_xss.py`
- Create: `scanner/modules/stored_xss.py`

- [ ] **Step 1: Write tests/test_stored_xss.py**

```python
"""Tests for stored XSS detection module."""
from scanner.modules.stored_xss import (
    _make_stored_payload,
    _extract_post_forms,
    _extract_links,
    _build_form_data,
    StoredXssModule,
)


class TestMakeStoredPayload:
    def test_returns_payload_and_uid(self):
        payload, uid = _make_stored_payload()
        assert uid in payload
        assert payload.startswith("<xss_store_")
        assert len(uid) == 8

    def test_unique_per_call(self):
        uids = [_make_stored_payload()[1] for _ in range(10)]
        assert len(set(uids)) == 10


class TestExtractPostForms:
    def test_extracts_post_form(self):
        html = '<form method="POST" action="/submit"><input name="msg"></form>'
        forms = _extract_post_forms(html, "http://test.com")
        assert len(forms) == 1
        assert forms[0]["action"] == "http://test.com/submit"
        assert forms[0]["inputs"][0]["name"] == "msg"

    def test_ignores_get_forms(self):
        html = '<form method="GET" action="/search"><input name="q"></form>'
        forms = _extract_post_forms(html, "http://test.com")
        assert len(forms) == 0

    def test_resolves_relative_action(self):
        html = '<form method="post" action="comment"><input name="text"></form>'
        forms = _extract_post_forms(html, "http://test.com/page")
        assert forms[0]["action"] == "http://test.com/comment"

    def test_caps_at_five(self):
        html = '<form method="POST"><input name="x"></form>' * 10
        forms = _extract_post_forms(html, "http://test.com")
        assert len(forms) == 5


class TestExtractLinks:
    def test_extracts_href_links(self):
        html = '<a href="/page1">1</a><a href="/page2">2</a>'
        links = _extract_links(html, "http://test.com")
        assert len(links) >= 2

    def test_skips_anchor_and_javascript(self):
        html = '<a href="#">top</a><a href="javascript:void(0)">x</a>'
        links = _extract_links(html, "http://test.com")
        assert len(links) == 0

    def test_resolves_relative_urls(self):
        html = '<a href="/about">About</a>'
        links = _extract_links(html, "http://test.com")
        assert "http://test.com/about" in links


class TestBuildFormData:
    def test_payload_goes_to_first_text_input(self):
        inputs = [
            {"name": "email", "type": "email"},
            {"name": "msg", "type": "text"},
        ]
        data, used = _build_form_data(inputs, "<xss>")
        assert data["email"] == "<xss>"
        assert data["msg"] == "test"
        assert used is True

    def test_other_inputs_get_default(self):
        inputs = [
            {"name": "name", "type": "text"},
            {"name": "hidden", "type": "hidden"},
            {"name": "submit", "type": "submit"},
        ]
        data, used = _build_form_data(inputs, "<xss>")
        assert data["name"] == "<xss>"
        assert data["hidden"] == "test"
        assert data["submit"] == "test"

    def test_no_text_input_returns_unused(self):
        inputs = [{"name": "hidden", "type": "hidden"}]
        data, used = _build_form_data(inputs, "<xss>")
        assert used is False


class TestModule:
    def test_module_attributes(self):
        mod = StoredXssModule()
        assert mod.name == "stored_xss"
        assert mod.requires_url is True
        assert "stored" in mod.description.lower()
```

- [ ] **Step 2: Run tests — expect FAIL**

Run: `pytest tests/test_stored_xss.py -v`
Expected: `ModuleNotFoundError`

- [ ] **Step 3: Create scanner/modules/stored_xss.py**

```python
"""Stored XSS detection -- form submission + persistence re-check."""
import re
import time
import uuid
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed

from scanner.modules.base import BaseModule


# ── Payload Generation ───────────────────────────────────────────────

def _make_stored_payload():
    """Generate unique XSS payload with traceable UUID."""
    uid = uuid.uuid4().hex[:8]
    return f"<xss_store_{uid}>", uid


# ── Form & Link Extraction ───────────────────────────────────────────

def _extract_post_forms(html, base_url):
    """Extract POST forms from HTML. Returns list of dicts (max 5)."""
    forms = []

    for match in re.finditer(
        r'<form[^>]*?method=["\']?post["\']?[^>]*?>([\s\S]*?)</form>',
        html, re.IGNORECASE
    ):
        form_html = match.group(0)
        action_match = re.search(r'action=["\']([^"\']+)["\']', form_html, re.I)
        action = action_match.group(1) if action_match else ""
        action = urllib.parse.urljoin(base_url, action)

        inputs = []
        for inp in re.finditer(r'<input[^>]*?>', form_html, re.I):
            attrs = inp.group(0)
            name_match = re.search(r'name=["\']([^"\']+)["\']', attrs, re.I)
            type_match = re.search(r'type=["\']([^"\']+)["\']', attrs, re.I)
            if name_match:
                inputs.append({
                    "name": name_match.group(1),
                    "type": type_match.group(1).lower() if type_match else "text",
                })

        if inputs:
            forms.append({"action": action, "inputs": inputs})

    return forms[:5]


def _extract_links(html, base_url):
    """Extract page links for stored XSS re-check (max 15)."""
    links = set()
    for match in re.finditer(r'<a[^>]*?href=["\']([^"\']+)["\']', html, re.I):
        href = match.group(1)
        if href.startswith('#') or href.startswith('javascript:'):
            continue
        full = urllib.parse.urljoin(base_url, href)
        if full.startswith(('http://', 'https://')):
            links.add(full)
    links.discard(base_url)
    return list(links)[:15]


def _build_form_data(inputs, payload):
    """Build form data dict. Payload goes to first text-type input."""
    text_types = {"text", "search", "url", "email", ""}
    data = {}
    payload_used = False
    for inp in inputs:
        if inp["type"] in text_types and not payload_used:
            data[inp["name"]] = payload
            payload_used = True
        else:
            data[inp["name"]] = "test"
    return data, payload_used


# ── StoredXssModule ─────────────────────────────────────────────────

class StoredXssModule(BaseModule):
    name = "stored_xss"
    description = "Detect stored XSS via form submission and re-check"
    requires_url = True

    def run(self, target, request_handler, output):
        """Run stored XSS detection: submit payloads, then re-check."""
        target = target.rstrip("/")
        output.log_progress(f"Fetching {target} for stored XSS analysis...")

        try:
            resp = request_handler.get(target)
            html = resp.text
        except Exception as e:
            output.log_progress(f"Failed to fetch {target}: {e}")
            return {"module": self.name, "findings": []}

        forms = _extract_post_forms(html, target)
        links = _extract_links(html, target)

        output.log_progress(
            f"Found {len(forms)} POST forms, {len(links)} links to re-check"
        )

        if not forms:
            output.log_progress("No POST forms found — skipping")
            return {"module": self.name, "findings": []}

        # Phase 1: Submit payloads
        submissions = []
        for form in forms:
            payload, uid = _make_stored_payload()
            data, used = _build_form_data(form["inputs"], payload)
            if not used:
                continue

            try:
                request_handler.post(form["action"], data=data)
                submissions.append((uid, payload, form, data))
                output.log_progress(
                    f"Submitted {uid} to {form['action']}"
                )
            except Exception as e:
                output.log_progress(f"Failed to submit to {form['action']}: {e}")

        if not submissions:
            output.log_progress("No forms could be submitted")
            return {"module": self.name, "findings": []}

        # Phase 2: Re-check
        check_urls = [target] + links

        output.log_progress(
            f"Re-checking {len(check_urls)} URLs for stored payloads..."
        )

        findings = []
        for uid, payload, form, data in submissions:
            for check_url in check_urls:
                try:
                    resp = request_handler.get(check_url)
                    if payload in resp.text:
                        injected_field = next(
                            (k for k, v in data.items() if v == payload), "unknown"
                        )
                        finding = {
                            "type": "stored_xss",
                            "form_action": form["action"],
                            "payload_uid": uid,
                            "payload": payload,
                            "injected_field": injected_field,
                            "found_on": check_url,
                            "evidence": (
                                f"payload {uid} submitted to "
                                f"{form['action']} found on {check_url}"
                            ),
                        }
                        findings.append(finding)
                        output.log_finding(self.name, finding)
                        break
                except Exception:
                    pass

        output.log_progress(
            f"Stored XSS done: {len(findings)} persistent injections found"
        )
        return {"module": self.name, "findings": findings}
```

- [ ] **Step 4: Run tests — expect PASS**

Run: `pytest tests/test_stored_xss.py -v`
Expected: All tests pass.

- [ ] **Step 5: Run ALL tests**

Run: `pytest tests/ -v`
Expected: All pass.

- [ ] **Step 6: Commit**

```bash
git add scanner/modules/stored_xss.py tests/test_stored_xss.py
git commit -m "feat: add stored XSS detection module"
```

---

### Task 2: Register in CLI + output display

**Files:**
- Modify: `scanner/cli.py`
- Modify: `scanner/core/output.py`

- [ ] **Step 1: Register in CLI**

Edit `scanner/cli.py`, add import:

```python
from scanner.modules.stored_xss import StoredXssModule
```

Edit `scanner/cli.py`, MODULE_CLASSES:

```python
MODULE_CLASSES = [SubdomainModule, DirscanModule, ParamsModule, SqliModule, XssModule, DomXssModule, StoredXssModule]
```

- [ ] **Step 2: Add display in output.py**

Add before `log_progress` method:

```python
        elif module_name == "stored_xss":
            print(f"[{module_name}] {finding['payload_uid']}: "
                  f"{finding['injected_field']} → {finding['found_on']}")
```

- [ ] **Step 3: Verify list + tests**

```bash
python -m scanner list
pytest tests/ -v
```

- [ ] **Step 4: Commit**

```bash
git add scanner/cli.py scanner/core/output.py
git commit -m "feat: register stored_xss module and add display"
```

---

### Task 3: Integration test + push

- [ ] **Step 1: Test against target with POST forms**

Run: `python -m scanner scan "https://www.baidu.com" -m stored_xss -v`

Expected: Finds POST forms (if any), submits, re-checks. No crashes.

- [ ] **Step 2: Run full test suite**

Run: `pytest tests/ -v`
Expected: All pass.

- [ ] **Step 3: Push**

```bash
git push
```
