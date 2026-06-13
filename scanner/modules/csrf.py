"""CSRF detection -- passive form token analysis."""
import re
import urllib.parse

from scanner.modules.base import BaseModule


_CSRF_TOKEN_NAMES = {
    "csrf", "_csrf", "csrf_token", "csrf-token",
    "_token", "token", "authenticity_token",
    "xsrf", "_xsrf", "xsrf_token",
    "__RequestVerificationToken", "__csrf",
    "nonce", "_nonce", "form_token",
    "csrfmiddlewaretoken",
}


def _find_forms(html, base_url):
    """Extract POST forms from HTML.

    Returns list of dicts: [{action, method, inputs: [{name, type, value}]}]
    """
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
            value_match = re.search(r'value=["\']([^"\']*)["\']', attrs, re.I)
            if name_match:
                inputs.append({
                    "name": name_match.group(1),
                    "type": type_match.group(1).lower() if type_match else "text",
                    "value": value_match.group(1) if value_match else "",
                })

        if inputs:
            forms.append({"action": action, "method": "POST", "inputs": inputs})

    return forms


def _has_csrf_token(inputs):
    """Check if any hidden input looks like a CSRF token.

    A CSRF token is either:
    - A hidden input with a known CSRF token name
    - A hidden input with a token-like value (hex string >= 32 chars)
    """
    for inp in inputs:
        # Check known CSRF token names (case-insensitive)
        if inp["name"].lower() in _CSRF_TOKEN_NAMES:
            return True

        # Check token-like values in hidden inputs
        if inp["type"] == "hidden" and inp["value"]:
            val = inp["value"]
            # Looks like a hex token (32+ hex chars)
            if re.fullmatch(r'[0-9a-fA-F]{32,}', val):
                return True
            # Looks like base64 (mix of alphanumeric + possible +/=/long)
            if len(val) >= 24 and re.match(r'^[A-Za-z0-9+/=_-]{24,}$', val):
                return True

    return False


class CsrfModule(BaseModule):
    name = "csrf"
    description = "Detect missing CSRF tokens in POST forms"
    requires_url = True

    def run(self, target, request_handler, output):
        """Analyze page forms for CSRF protection."""
        target = target.rstrip("/")
        output.log_progress(f"Fetching {target} for CSRF analysis...")

        try:
            resp = request_handler.get(target)
            html = resp.text
        except Exception as e:
            output.log_progress(f"Failed to fetch {target}: {e}")
            return {"module": self.name, "findings": []}

        forms = _find_forms(html, target)

        if not forms:
            output.log_progress("No POST forms found — nothing to check")
            return {"module": self.name, "findings": []}

        output.log_progress(f"Found {len(forms)} POST forms to analyze")

        findings = []
        for form in forms:
            input_names = [inp["name"] for inp in form["inputs"]]
            if _has_csrf_token(form["inputs"]):
                output.log_progress(
                    f"  OK: {form['action']} — CSRF token present"
                )
            else:
                finding = {
                    "type": "csrf_missing",
                    "form_action": form["action"],
                    "form_method": form["method"],
                    "inputs": input_names,
                    "evidence": (
                        f"No CSRF token found in form with "
                        f"{len(form['inputs'])} inputs: {input_names}"
                    ),
                }
                findings.append(finding)
                output.log_finding(self.name, finding)

        output.log_progress(
            f"CSRF done: {len(findings)} forms lack CSRF protection"
        )
        return {"module": self.name, "findings": findings}
