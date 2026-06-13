"""Security header analysis -- check for missing/insecure HTTP headers."""
from scanner.modules.base import BaseModule


_SECURITY_HEADERS = [
    {
        "name": "Strict-Transport-Security",
        "description": "Enforce HTTPS connections (HSTS)",
        "check": "present",
    },
    {
        "name": "Content-Security-Policy",
        "description": "Prevent XSS and data injection (CSP)",
        "check": "present",
    },
    {
        "name": "X-Frame-Options",
        "description": "Prevent clickjacking via iframes",
        "check": "present",
    },
    {
        "name": "X-Content-Type-Options",
        "description": "Prevent MIME type sniffing",
        "check": "present",
    },
    {
        "name": "Referrer-Policy",
        "description": "Control referrer information leakage",
        "check": "present",
    },
    {
        "name": "Permissions-Policy",
        "description": "Restrict browser feature usage",
        "check": "present",
    },
    {
        "name": "Access-Control-Allow-Origin",
        "description": "CORS — wildcard allows any origin to read responses",
        "check": "no_wildcard",
    },
]


def _check_headers(response):
    """Check response for security headers.

    Returns list of findings for missing or insecure headers.
    """
    results = []
    resp_headers = {k.lower(): v for k, v in response.headers.items()}

    for entry in _SECURITY_HEADERS:
        name = entry["name"]
        key = name.lower()

        if key not in resp_headers:
            results.append({
                "header": name,
                "status": "missing",
                "description": entry["description"],
                "evidence": f"Header '{name}' is missing",
            })
        elif entry["check"] == "no_wildcard" and resp_headers[key] == "*":
            results.append({
                "header": name,
                "status": "insecure",
                "value": "*",
                "description": entry["description"],
                "evidence": f"Header '{name}' is set to wildcard '*'",
            })
        else:
            results.append({
                "header": name,
                "status": "present",
                "value": resp_headers[key][:80],
                "description": entry["description"],
            })

    return results


class HeadersModule(BaseModule):
    name = "headers"
    description = "Check for missing or misconfigured security headers"
    requires_url = True

    def run(self, target, request_handler, output):
        """Analyze security headers on the target."""
        target = target.rstrip("/")
        output.log_progress(f"Fetching {target} for header analysis...")

        try:
            resp = request_handler.get(target)
        except Exception as e:
            output.log_progress(f"Failed to fetch {target}: {e}")
            return {"module": self.name, "findings": []}

        header_results = _check_headers(resp)

        findings = []
        for result in header_results:
            if result["status"] in ("missing", "insecure"):
                findings.append(result)
                output.log_finding(self.name, result)

        ok_count = sum(1 for r in header_results if r["status"] == "present")
        missing_count = sum(1 for r in header_results if r["status"] == "missing")
        insecure_count = sum(1 for r in header_results if r["status"] == "insecure")

        output.log_progress(
            f"Headers done: {ok_count} OK, "
            f"{missing_count} missing, {insecure_count} insecure"
        )
        return {"module": self.name, "findings": findings}
