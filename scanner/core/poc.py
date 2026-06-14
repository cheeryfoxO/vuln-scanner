"""PoC generation — produce reproducible curl commands from scanner findings."""
import shlex
import urllib.parse


def _escape_shell(val):
    """Shell-escape a value for safe curl usage."""
    if not isinstance(val, str):
        val = str(val)
    return shlex.quote(val)


def build_curl(finding, module_name, cookies=None, extra_headers=None, target=None):
    """Build a reproducible curl command from a finding.

    Args:
        finding: The finding dict from a module.
        module_name: Module that produced the finding.
        cookies: Optional cookie string (e.g., 'session=abc').
        extra_headers: Optional dict of extra headers.
        target: Override target URL.

    Returns:
        curl command string, or "" if insufficient data.
    """
    url = target or finding.get("url", finding.get("host", ""))
    if not url:
        return ""

    parts = ["curl", "-s", "-i"]

    # Cookies
    if cookies:
        parts.extend(["-b", _escape_shell(cookies)])

    # Headers
    all_headers = dict(extra_headers or {})
    parts.append("-H 'User-Agent: Mozilla/5.0'")

    # Module-specific curl construction
    if module_name == "sqli":
        param = finding.get("parameter", "")
        payload = finding.get("payload", "")
        if param:
            inj_url = _inject_param(url, param, payload)
            parts.append(_escape_shell(inj_url))
            if finding.get("type") == "time_based":
                parts.insert(1, "-m 15")  # timeout for time-based
        else:
            parts.append(_escape_shell(url))

    elif module_name == "xss":
        param = finding.get("parameter", "")
        payload = finding.get("payload", "")
        if param:
            inj_url = _inject_param(url, param, payload)
            parts.append(_escape_shell(inj_url))
        else:
            parts.append(_escape_shell(url))

    elif module_name in ("cmdi", "lfi", "ssti"):
        param = finding.get("parameter", "")
        payload = finding.get("payload", "")
        if param and payload:
            inj_url = _inject_param(url, param, payload)
            parts.append(_escape_shell(inj_url))
        else:
            parts.append(_escape_shell(url))

    elif module_name == "redirect":
        param = finding.get("parameter", "")
        payload = finding.get("payload", "")
        if param and payload:
            inj_url = _inject_param(url, param, payload)
            parts.append(_escape_shell(inj_url))
        else:
            parts.append(_escape_shell(url))
        parts.insert(1, "-L")  # follow redirect

    elif module_name == "ssrf":
        param = finding.get("parameter", "")
        payload = finding.get("payload", "")
        if param and payload:
            inj_url = _inject_param(url, param, payload)
            parts.append(_escape_shell(inj_url))
        else:
            parts.append(_escape_shell(url))

    elif module_name == "dirscan":
        parts.append(_escape_shell(url))
        parts.insert(1, "-I")  # HEAD first

    elif module_name == "subdomain":
        host = finding.get("host", url)
        parts.append(_escape_shell(f"https://{host}"))

    elif module_name == "csrf":
        action = finding.get("form_action", url)
        parts.extend(["-X", "POST", _escape_shell(action)])
        parts.append("-H 'Content-Type: application/x-www-form-urlencoded'")
        inputs = finding.get("inputs", [])
        if inputs:
            data = "&".join(f"{i.get('name','')}=test" for i in inputs)
            parts.extend(["-d", _escape_shell(data)])

    elif module_name == "headers":
        parts.append(_escape_shell(url))

    elif module_name == "cors":
        origin = finding.get("origin", "https://evil.com")
        parts.extend(["-H", _escape_shell(f"Origin: {origin}")])
        parts.append(_escape_shell(url))

    elif module_name == "stored_xss":
        parts.append(_escape_shell(url))

    elif module_name == "fingerprint":
        parts.append(_escape_shell(url))

    else:
        # Generic fallback
        param = finding.get("parameter", "")
        payload = finding.get("payload", "")
        if param and payload:
            inj_url = _inject_param(url, param, payload)
            parts.append(_escape_shell(inj_url))
        else:
            parts.append(_escape_shell(url))

    return " \\\n  ".join(parts)


def _inject_param(url, param, payload):
    """Inject a payload into a URL parameter."""
    parsed = urllib.parse.urlparse(url)
    query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    # Set or replace the parameter with payload
    query[param] = [payload if payload else "PAYLOAD"]
    new_query = urllib.parse.urlencode(query, doseq=True)
    return urllib.parse.urlunparse(parsed._replace(query=new_query))


def inject_poc_into_finding(finding, module_name, cookies=None, extra_headers=None, target=None):
    """Mutate finding dict to include a 'poc' field with the curl command."""
    curl = build_curl(finding, module_name, cookies, extra_headers, target)
    if curl:
        finding["poc"] = curl
    return finding
