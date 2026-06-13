# Scanner Phase 3c — Boolean-Based Blind SQLi Detection

**Date:** 2026-06-13
**Status:** Draft → Awaiting review
**Goal:** Add Phase 3 (boolean-based blind) to the sqli module, using paired TRUE/FALSE payloads and multi-indicator voting to detect blind SQL injection.

## 1. Architecture

Single file modified: `scanner/modules/sqli.py`. New pure functions for dynamic content stripping and response comparison are added to the module's testable functions section.

```
scanner/modules/sqli.py  ← MODIFY: +3 boolean payload pairs, +_strip_dynamic(), +_compare_responses(), +Phase 3 in run()
```

No new files. No CLI changes. Output format extended with `boolean_based` type.

## 2. Payload Pairs

Three TRUE/FALSE pairs. Each pair differs by exactly one character.

```python
BOOL_PAYLOADS = [
    {"name": "numeric", "true": " AND 1=1", "false": " AND 1=2"},
    {"name": "string",  "true": " AND 'a'='a", "false": " AND 'a'='b"},
    {"name": "subquery","true": " AND (SELECT 1)=1", "false": " AND (SELECT 1)=2"},
]
```

Payloads APPEND to existing parameter values (not replace), keeping the original query intact:
- TRUE: `?id=1 AND 1=1`
- FALSE: `?id=1 AND 1=2`

## 3. Dynamic Content Stripping

```python
def _strip_dynamic(text):
    """Remove dynamic content that causes false positives in comparison.

    Strips: Unix timestamps, hex tokens, script content, normalizes whitespace.
    """
    import re
    text = re.sub(r'\b\d{10,13}\b', '', text)           # Unix timestamps
    text = re.sub(r'\b[0-9a-f]{32,}\b', '', text)       # MD5+ hex tokens
    text = re.sub(r'\b[0-9a-f]{64,}\b', '', text)       # SHA-256 tokens
    text = re.sub(r'<script[^>]*>.*?</script>', '', text, flags=re.S | re.I)  # script tags
    text = re.sub(r'\s+', ' ', text)                     # normalize whitespace
    return text.strip()
```

## 4. No-Result Keywords

```python
NO_RESULT_KEYWORDS = [
    "no results", "not found", "no records", "0 results",
    "nothing found", "查询结果为空", "没有找到", "暂无数据",
    "找不到", "未找到", "无结果",
]
```

## 5. Multi-Indicator Comparison

```python
def _compare_responses(true_html, false_html):
    """Compare TRUE vs FALSE responses using 3 indicators.

    Returns (verdict: bool, indicators: list[str], detail: str)
    """
    votes = 0
    indicators = []

    # Indicator 1: body length ratio
    len_true = len(true_html)
    len_false = len(false_html)
    max_len = max(len_true, len_false)
    if max_len > 0:
        ratio = abs(len_true - len_false) / max_len
        if ratio > 0.05:
            votes += 1
            indicators.append("body_length")

    # Indicator 2: stripped hash
    clean_true = _strip_dynamic(true_html)
    clean_false = _strip_dynamic(false_html)
    if clean_true != clean_false:
        votes += 1
        indicators.append("body_hash")

    # Indicator 3: no-result keywords
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
```

## 6. Phase 3 Flow

Added to `SqliModule.run()` after Phase 2.

```
Phase 1 → error-based (existing)
Phase 2 → time-based  (existing)
Phase 3 → boolean-based (NEW — only for params not caught by Phase 1 or 2)
```

Logic per parameter:

```python
# Only params that passed both Phase 1 and Phase 2 without findings
bool_targets = [entry for entry in param_names
                if entry["name"] not in param_has_error
                and entry["name"] not in param_has_time]

for entry in bool_targets:
    for pair in BOOL_PAYLOADS:
        for encoded, tech in generate_variants(...):
            # 1. Send TRUE request
            # 2. Send FALSE request
            # 3. _compare_responses(true_html, false_html)
            # 4. If verdict → finding
```

Uses existing `generate_variants()` for WAF bypass. 3 thread concurrency (TRUE/FALSE fetched concurrently per pair).

## 7. Integration with Existing Phases

Phase 2's `time_based_targets` tracker renamed to `param_has_time` (matching `param_has_error`):

```python
param_has_error = set()   # Phase 1 hits
param_has_time = set()    # Phase 2 hits
```

Phase 3 runs on: `param_names - param_has_error - param_has_time`

## 8. Output Format

```json
{
  "type": "boolean_based",
  "parameter": "id",
  "true_url": "https://target.com/page?id=1 AND 1=1",
  "false_url": "https://target.com/page?id=1 AND 1=2",
  "payload_pair": "numeric",
  "encoding": "plain",
  "indicators": ["body_length", "body_hash"],
  "evidence": "length diff 5.2%, hash mismatch"
}
```

## 9. Non-Goals

- Content-based diff (line-by-line HTML comparison) → too much false positives
- Extracting data bit-by-bit via boolean (real blind exploitation) → destructive
- Heuristic page structure analysis (DOM tree diff) → Phase 4

## 10. Success Criteria

1. `pytest tests/` — all existing 74 + new boolean-blinds tests pass
2. `python -m scanner scan "url?id=1" -m sqli -v` — three phases run in order, Phase 3 only for uncatched params
3. Paired TRUE/FALSE requests sent with encoding variants
4. `_strip_dynamic` correctly removes timestamps and tokens
5. `_compare_responses` voting correctly classifies TRUE/FALSE pairs
