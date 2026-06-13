"""SSRF detection -- internal service fingerprint matching."""
import re
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed

from scanner.modules.base import BaseModule
from scanner.core.html_utils import _extract_params, _make_test_url
from scanner.core.encoding import generate_variants


SSRF_TECHNIQUES = []

_SSRF_PAYLOADS = [
    {"url": "http://169.254.169.254/latest/meta-data/", "target": "AWS"},
    {"url": "http://127.0.0.1/", "target": "Localhost"},
    {"url": "http://localhost/", "target": "Localhost"},
    {"url": "http://[::1]/", "target": "Localhost"},
    {"url": "http://0x7f000001/", "target": "Localhost"},
    {"url": "http://2130706433/", "target": "Localhost"},
    {"url": "http://127.0.0.1:22", "target": "SSH"},
    {"url": "file:///etc/passwd", "target": "File"},
]

_SSRF_FINGERPRINTS = {
    "AWS Metadata": [
        r"ami-id",
        r"instance-id",
        r"instance-type",
        r"security-groups",
        r"placement",
        r"local-hostname",
    ],
    "Local Web Server": [
        r"Apache2\s+(?:Ubuntu\s+)?Default\s+Page",
        r"Welcome to nginx",
        r"IIS\s+Windows\s+Server",
        r"<title>phpinfo\(\)</title>",
        r"phpMyAdmin",
    ],
    "SSH Service": [
        r"SSH-\d+\.\d+-OpenSSH",
        r"Protocol mismatch",
    ],
}


def _check_ssrf_fingerprints(text):
    """Scan response text for internal service fingerprints.

    Returns {"service": str, "pattern": str} or None.
    """
    for service, patterns in _SSRF_FINGERPRINTS.items():
        for pat in patterns:
            if re.search(pat, text, re.IGNORECASE):
                return {"service": service, "pattern": pat}
    return None


class SsrfModule(BaseModule):
    name = "ssrf"
    description = "Detect SSRF via internal service fingerprint matching"
    requires_url = True

    def run(self, target, request_handler, output):
        """Run SSRF detection."""
        target = target.rstrip("/")
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
            f"Testing {len(_SSRF_PAYLOADS)} SSRF payloads across "
            f"{len(param_names)} parameters"
        )

        with ThreadPoolExecutor(max_workers=3) as pool:
            futures = {}
            for entry in param_names:
                pname = entry["name"]
                method = entry["method"]
                for ssrf_entry in _SSRF_PAYLOADS:
                    payload = ssrf_entry["url"]
                    for encoded, tech in generate_variants(payload, SSRF_TECHNIQUES):
                        if method == "POST":
                            test_url = target
                            futures[pool.submit(
                                request_handler.post, target,
                                data={pname: encoded}
                            )] = (pname, ssrf_entry, test_url, tech)
                        else:
                            test_url = _make_test_url(target, pname, encoded)
                            futures[pool.submit(
                                request_handler.get, test_url
                            )] = (pname, ssrf_entry, test_url, tech)

            bar = output.create_progress_bar("SSRF", len(futures))
            for future in as_completed(futures):
                pname, ssrf_entry, test_url, tech = futures[future]
                try:
                    resp = future.result()
                    match = _check_ssrf_fingerprints(resp.text)
                    if match:
                        if pname not in param_has_finding:
                            param_has_finding.add(pname)
                            finding = {
                                "type": "ssrf",
                                "parameter": pname,
                                "url": test_url,
                                "ssrf_target": ssrf_entry["target"],
                                "service": match["service"],
                                "encoding": tech,
                                "evidence": (
                                    f"Internal service fingerprint "
                                    f"'{match['pattern']}' matched — "
                                    f"possible SSRF to {ssrf_entry['url']}"
                                ),
                            }
                            findings.append(finding)
                            output.log_finding(self.name, finding)
                except Exception:
                    pass
                output.update_progress(bar)
            bar.close()

        output.log_progress(
            f"SSRF done: {len(findings)} potential SSRF targets found"
        )
        return {"module": self.name, "findings": findings}
