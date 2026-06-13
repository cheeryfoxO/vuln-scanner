"""CORS misconfiguration detection — origin reflection + credentials."""
import re
import urllib.parse

from scanner.modules.base import BaseModule


_TEST_ORIGINS = [
    "https://evil.com",
    "null",
    "https://evil.target.com",  # subdomain bypass attempt
]


def _check_cors(response, origin):
    """Check if the response reflects the Origin header.

    Args:
        response: requests.Response object.
        origin: The Origin value that was sent.

    Returns: dict with finding details or None.
    """
    acao = response.headers.get("Access-Control-Allow-Origin", "")
    acac = response.headers.get("Access-Control-Allow-Credentials", "").lower()

    # Origin is reflected back
    if acao == origin:
        if acac == "true":
            return {
                "acao_reflected": True,
                "acao_value": acao,
                "acac": True,
                "severity": "critical",
                "evidence": (
                    f"Origin '{origin}' reflected in ACAO "
                    f"with Access-Control-Allow-Credentials: true"
                ),
            }
        return {
            "acao_reflected": True,
            "acao_value": acao,
            "acac": False,
            "severity": "high",
            "evidence": f"Origin '{origin}' reflected in ACAO header",
        }

    # echo-based reflection: if origin appears anywhere in ACAO
    # (some servers echo back with prefix/suffix variations)
    if origin != "*" and origin in acao:
        return {
            "acao_reflected": True,
            "acao_value": acao,
            "acac": acac == "true",
            "severity": "medium",
            "evidence": f"Origin '{origin}' found in ACAO value '{acao}'",
        }

    return None


class CorsModule(BaseModule):
    name = "cors"
    description = "Detect CORS misconfigurations via Origin reflection"
    requires_url = True

    def run(self, target, request_handler, output):
        """Test CORS configuration on the target."""
        target = target.rstrip("/")
        parsed_target = urllib.parse.urlparse(target)
        target_domain = parsed_target.netloc

        output.log_progress(f"Fetching {target} for CORS analysis...")

        try:
            resp = request_handler.get(target)
            html = resp.text
        except Exception as e:
            output.log_progress(f"Failed to fetch {target}: {e}")
            return {"module": self.name, "findings": []}

        findings = []

        # Collect URLs to test: main target + same-origin links/scripts
        test_urls = {target}
        for match in re.finditer(
            r'(?:src|href)=["\']([^"\']+)["\']', html, re.I
        ):
            url = urllib.parse.urljoin(target, match.group(1))
            parsed = urllib.parse.urlparse(url)
            if parsed.netloc == target_domain and parsed.scheme in ("http", "https"):
                test_urls.add(url)

        # Cap test URLs
        test_urls = list(test_urls)[:20]
        output.log_progress(
            f"Testing CORS on {len(test_urls)} URLs ({len(_TEST_ORIGINS)} origins)"
        )

        for test_url in test_urls:
            for origin in _TEST_ORIGINS:
                try:
                    resp = request_handler.get(
                        test_url,
                        headers={"Origin": origin},
                    )
                    result = _check_cors(resp, origin)
                    if result:
                        finding = {
                            "type": "cors_misconfig",
                            "url": test_url,
                            "origin": origin,
                            "acao": result["acao_value"],
                            "acac": result["acac"],
                            "severity": result["severity"],
                            "evidence": result["evidence"],
                        }
                        findings.append(finding)
                        output.log_finding(self.name, finding)
                        # One finding per URL is enough
                        break
                except Exception:
                    pass

        critical_count = sum(1 for f in findings if f["severity"] == "critical")
        output.log_progress(
            f"CORS done: {len(findings)} misconfigs "
            f"({critical_count} critical with credentials)"
        )
        return {"module": self.name, "findings": findings}
