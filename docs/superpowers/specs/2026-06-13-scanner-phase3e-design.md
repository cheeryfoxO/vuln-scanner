# Scanner Phase 3e — Stored XSS Detection

**Date:** 2026-06-13
**Status:** Draft → Awaiting review
**Goal:** Add a `stored_xss` module that detects persistent XSS by submitting unique payloads to POST forms, then re-visiting the page and related links to check if the payload persisted in the HTML.

## 1. Architecture

New file: `scanner/modules/stored_xss.py` (~150 lines).

```
scanner/modules/stored_xss.py  ← NEW
scanner/cli.py                 ← MODIFY: register StoredXssModule
scanner/core/output.py         ← MODIFY: add display
```

Independent module. Follows BaseModule pattern. Reuses `RequestHandler.post()` (Phase 3a) and conceptual `_FormParser` from html_utils.

## 2. Detection Flow

```
target URL → GET page → extract:
  ├── POST forms with action + inputs
  └── page links for re-check
      ↓
  For each POST form (max 5):
    1. Generate unique payload: <xss_store_<8-char-uuid>>
    2. Fill form: payload in first text-type input, defaults elsewhere
    3. POST to form action URL
      ↓
  Wait 1 second
      ↓
  Re-check URLs (original target + up to 15 links):
    GET each → search HTML for UUID payloads
    Found → stored XSS confirmed
    Report: payload_uid, form_action, injected_field, found_on
```

## 3. Unique Payload Generation

```python
import uuid

def _make_stored_payload():
    """Generate unique XSS payload with traceable UUID."""
    uid = uuid.uuid4().hex[:8]
    return f"<xss_store_{uid}>", uid
```

Each form submission gets its own UUID. When payload is found on re-check, the UUID identifies which form/injection was responsible.

## 4. Form Extraction

```python
def _extract_post_forms(html, base_url):
    """Extract POST forms from HTML. Returns list of dicts."""
    import re
    forms = []

    # Match <form ...>...</form>
    for match in re.finditer(
        r'<form[^>]*?method=["\']?post["\']?[^>]*?>([\s\S]*?)</form>',
        html, re.IGNORECASE
    ):
        form_html = match.group(0)
        action_match = re.search(r'action=["\']([^"\']+)["\']', form_html, re.I)
        action = urllib.parse.urljoin(base_url, action_match.group(1) if action_match else "")

        inputs = []
        for inp in re.finditer(r'<input[^>]*?>', form_html, re.I):
            attrs = inp.group(0)
            name_match = re.search(r'name=["\']([^"\']+)["\']', attrs, re.I)
            type_match = re.search(r'type=["\']([^"\']+)["\']', attrs, re.I)
            if name_match:
                inputs.append({
                    "name": name_match.group(1),
                    "type": type_match.group(1) if type_match else "text",
                })

        if inputs:  # Only forms with at least one input
            forms.append({"action": action, "inputs": inputs})

    return forms[:5]
```

## 5. Link Extraction for Re-Check

```python
def _extract_links(html, base_url):
    """Extract page links for stored XSS re-check."""
    import re
    links = set()
    for match in re.finditer(r'<a[^>]*?href=["\']([^"\']+)["\']', html, re.I):
        href = match.group(1)
        if not href.startswith('#') and not href.startswith('javascript:'):
            full = urllib.parse.urljoin(base_url, href)
            if full.startswith(('http://', 'https://')):
                links.add(full)
    links.discard(base_url)  # will add back as first check
    return list(links)[:15]
```

## 6. Form Submission

For each form, fill inputs:
- First `text`/`search`/`url`/`email` input → XSS payload
- All other inputs → default safe value (`"test"`)

```python
def _build_form_data(inputs, payload):
    """Build form data dict. Payload goes to first text-type input."""
    data = {}
    payload_used = False
    for inp in inputs:
        if inp["type"] in ("text", "search", "url", "email", "") and not payload_used:
            data[inp["name"]] = payload
            payload_used = True
        else:
            data[inp["name"]] = "test"
    return data, payload_used
```

## 7. Module Interface

```python
class StoredXssModule(BaseModule):
    name = "stored_xss"
    description = "Detect stored XSS via form submission and re-check"
    requires_url = True

    def run(self, target, request_handler, output):
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
        submissions = []  # [(uid, payload, form, injected_field), ...]
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
                                f"payload {uid} submitted to {form['action']} "
                                f"found on {check_url}"
                            ),
                        }
                        findings.append(finding)
                        output.log_finding(self.name, finding)
                        break  # Found on one URL is enough
                except Exception:
                    pass

        output.log_progress(
            f"Stored XSS done: {len(findings)} persistent injections found"
        )
        return {"module": self.name, "findings": findings}
```

## 8. Output Format

```json
{
  "type": "stored_xss",
  "form_action": "https://target.com/comments",
  "payload_uid": "a1b2c3d4",
  "payload": "<xss_store_a1b2c3d4>",
  "injected_field": "message",
  "found_on": "https://target.com/",
  "evidence": "payload a1b2c3d4 submitted to /comments found on /"
}
```

Output display:

```python
elif module_name == "stored_xss":
    print(f"[{module_name}] {finding['payload_uid']}: "
          f"{finding['injected_field']} → {finding['found_on']}")
```

## 9. Constraints

- Max 5 POST forms
- Max 15 re-check links
- 1 second delay between submission and re-check (handled by order of operations)
- Non-payload form fields filled with "test"
- Only POST forms with text-type inputs are targeted

## 10. Non-Goals

- Authentication / session handling
- CSRF token extraction and replay
- File upload stored XSS
- Multi-step form wizard
- Repeated re-check (check once, not recurring)

## 11. Success Criteria

1. `python -m scanner list` shows `stored_xss` module
2. `python -m scanner scan "url" -m stored_xss -v` — extracts forms, submits payloads, re-checks
3. All existing 100 tests pass
4. UUID payload generation is unique per call
5. Against a page with POST form, module submits and re-checks without error
