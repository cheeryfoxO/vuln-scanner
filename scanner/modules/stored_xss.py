"""Stored XSS detection -- form submission + persistence re-check."""
import re
import urllib.parse
import uuid

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
