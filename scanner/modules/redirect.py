"""Open redirect detection -- Location header analysis."""
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed

from scanner.modules.base import BaseModule
from scanner.core.html_utils import _extract_params, _make_test_url
from scanner.core.encoding import generate_variants


# No encoding needed for redirect payloads
REDIRECT_TECHNIQUES = []

_REDIRECT_PAYLOADS = [
    "//evil.com",
    "https://evil.com",
    "%2F%2Fevil.com",
    "/\\evil.com",
    "//google.com%40evil.com",
    "https:evil.com",
]


def _is_external_redirect(response, target_domain):
    """Check if response is a 3xx redirect to an external domain.

    Args:
        response: requests.Response object
        target_domain: netloc of the target (e.g., 'example.com')

    Returns: bool
    """
    if not (300 <= response.status_code < 400):
        return False
    location = response.headers.get("Location", "")
    if not location:
        return False
    try:
        parsed = urllib.parse.urlparse(location)
    except Exception:
        return False
    if not parsed.netloc:
        return False  # relative redirect, not interesting
    return parsed.netloc != target_domain


class RedirectModule(BaseModule):
    name = "redirect"
    description = "Detect open redirect via Location header analysis"
    requires_url = True

    def run(self, target, request_handler, output):
        """Run open redirect detection."""
        target = target.rstrip("/")
        parsed_target = urllib.parse.urlparse(target)
        target_domain = parsed_target.netloc

        output.log_progress(f"Fetching {target} for parameter extraction...")

        try:
            resp = request_handler.get(target)
            html = resp.text
        except Exception as e:
            output.log_progress(f"Failed to fetch {target}: {e}")
            return {"module": self.name, "findings": []}

        param_names = _extract_params(target, html)

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
            f"Testing {len(_REDIRECT_PAYLOADS)} redirect payloads across "
            f"{len(param_names)} parameters"
        )

        with ThreadPoolExecutor(max_workers=3) as pool:
            futures = {}
            for entry in param_names:
                pname = entry["name"]
                method = entry["method"]
                for payload in _REDIRECT_PAYLOADS:
                    for encoded, tech in generate_variants(payload, REDIRECT_TECHNIQUES):
                        if method == "POST":
                            test_url = target
                            futures[pool.submit(
                                request_handler.post, target,
                                data={pname: encoded},
                                allow_redirects=False,
                            )] = (pname, payload, test_url, tech)
                        else:
                            test_url = _make_test_url(target, pname, encoded)
                            futures[pool.submit(
                                request_handler.get, test_url,
                                allow_redirects=False,
                            )] = (pname, payload, test_url, tech)

            bar = output.create_progress_bar("Redirect", len(futures))
            for future in as_completed(futures):
                pname, payload, test_url, tech = futures[future]
                try:
                    resp = future.result()
                    if _is_external_redirect(resp, target_domain):
                        location = resp.headers.get("Location", "")
                        if pname not in param_has_finding:
                            param_has_finding.add(pname)
                            finding = {
                                "type": "open_redirect",
                                "parameter": pname,
                                "url": test_url,
                                "status_code": resp.status_code,
                                "location": location,
                                "encoding": tech,
                                "evidence": (
                                    f"HTTP {resp.status_code} redirect to "
                                    f"external host: {location}"
                                ),
                            }
                            findings.append(finding)
                            output.log_finding(self.name, finding)
                except Exception:
                    pass
                output.update_progress(bar)
            bar.close()

        output.log_progress(
            f"Redirect done: {len(findings)} open redirects found"
        )
        return {"module": self.name, "findings": findings}
