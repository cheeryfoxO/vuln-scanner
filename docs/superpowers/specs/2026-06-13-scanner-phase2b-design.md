# Scanner Phase 2b — SQL Injection Detection Module

**Date:** 2026-06-13
**Status:** Draft → Awaiting review
**Goal:** Add a sqli module that detects SQL injection via error-based + time-based blind techniques. Non-destructive, no data extraction.

## 1. Module Architecture

New file: `scanner/modules/sqli.py` (~200 lines), independent module — takes a URL, finds its own inputs, tests them.

```
sqli.py
├── ERROR_PAYLOADS: 12 error-triggering payloads
├── DB_ERROR_PATTERNS: MySQL/PG/MSSQL/Oracle error keywords
├── SLEEP_PAYLOADS: 4 DB-specific sleep payloads
├── run(target, request_handler, output)
│   1. Fetch page + extract input points (reuse _FormParser pattern)
│   2. Phase 1: Error-based detection (fast, all inputs)
│   3. Phase 2: Time-based blind (baseline + confirmation)
│   4. Report positives
```

**Constraints:**
- Max 3 threads (time-based needs stable timing)
- Total timeout 60s per target
- Pure detection — no `UNION SELECT`, no data extraction

## 2. Detection Logic

### Phase 1: Error-Based (Fast Screening)

12 error-triggering payloads per input point:

| # | Payload | Purpose |
|---|---------|---------|
| 1 | `'` | Single quote break |
| 2 | `"` | Double quote break |
| 3 | `')` | Parenthesis + quote |
| 4 | `")` | Parenthesis + double quote |
| 5 | `\` | Escape char |
| 6 | `1' AND '1'='1` | Always-true condition |
| 7 | `1' AND '1'='2` | Always-false condition |
| 8 | `1 AND 1=1` | Numeric always-true |
| 9 | `1 AND 1=2` | Numeric always-false |
| 10 | `1' OR 1=1--` | OR injection |
| 11 | `1' UNION SELECT NULL--` | UNION probe |
| 12 | `1; SELECT 1--` | Stacked query probe |

DB error keyword patterns (case-insensitive regex):
- MySQL: `SQL syntax`, `mysql_fetch`, `MySQL Error`, `Warning.*mysql`
- PostgreSQL: `PostgreSQL`, `psql`, `pg_query`, `ERROR:`
- MSSQL: `SQL Server`, `ODBC`, `mssql`, `SqlException`
- Oracle: `ORA-\d+`, `Oracle`, `PL/SQL`

**Verdict:** Any match → "疑似错误型注入"

### Phase 2: Time-Based Blind (Confirmation)

Per-input decision: if Phase 1 found error on this specific parameter, report it and skip time-based for this parameter only. Other parameters without error matches still proceed to time-based testing. No redundant testing on the same parameter.

Sleep payloads (one per DB):

| DB | Payload |
|----|---------|
| MySQL | `' OR IF(1=1,SLEEP(5),0)--` |
| PostgreSQL | `'; SELECT pg_sleep(5)--` |
| MSSQL | `'; WAITFOR DELAY '00:00:05'--` |
| Oracle | `'; BEGIN DBMS_LOCK.SLEEP(5); END;--` |

**Procedure:**
1. Send 3 normal requests → compute average response time `baseline`
2. For each sleep payload → send request → measure `actual_time`
3. `actual_time > max(baseline * 3, threshold)` → positive (threshold default = 5s)
4. Any of 4 DB payloads positive → "疑似时间盲注 (DB: MySQL/...)"

## 3. Module Integration

Follows existing BaseModule pattern:
```python
class SqliModule(BaseModule):
    name = "sqli"
    description = "Detect SQL injection via error + time-based blind"
    requires_url = True

    def run(self, target, request_handler, output):
        # ... implementation
        return {"module": self.name, "findings": [...]}
```

Register in `scanner/cli.py` by adding `SqliModule` to `MODULE_CLASSES`.

CLI usage:
```bash
scanner scan https://target.com/page?id=1 -m sqli -v
scanner scan https://target.com -m all -v -o report.json
```

New CLI option:
```
--sqli-threshold <n>   Time-based threshold in seconds (default: 5)
```

## 4. Finding Output Format

```json
{
  "type": "error_based | time_based",
  "parameter": "id",
  "method": "GET",
  "url": "https://target.com/page?id=1'",
  "payload": "' OR IF(1=1,SLEEP(5),0)--",
  "baseline_ms": 120,
  "response_ms": 5230,
  "database": "MySQL",
  "evidence": "Response delayed 5110ms vs baseline 120ms"
}
```

## 5. Non-Goals

- Boolean-based blind (AND 1=1 vs AND 1=2) → Phase 3
- UNION-based data extraction → Never (destructive)
- WAF bypass payloads → Phase 3
- GET-only for Phase 2b (POST support → Phase 3)

## 6. Success Criteria

1. `python -m scanner list` shows sqli module
2. Against a local test target with known SQLi (e.g., DVWA), module detects it
3. Against httpbin.org (no SQLi), module finds nothing (no false positives)
4. Output format matches spec
5. All existing 13 tests + new sqli tests pass
