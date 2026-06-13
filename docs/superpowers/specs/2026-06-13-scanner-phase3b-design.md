# Scanner Phase 3b — WAF Bypass Payload Encoding

**Date:** 2026-06-13
**Status:** Draft → Awaiting review
**Goal:** Add a shared encoding layer that generates WAF-bypass variants of existing payloads via 7 encoding techniques, expanding SQLi and XSS payload sets at runtime without duplicating payload definitions.

## 1. Architecture

One new file, two modified module files:

```
scanner/core/
├── encoding.py    ← NEW: 7 encoding functions + generate_variants()
modules/
├── sqli.py        ← MODIFY: wrap payload loops with generate_variants
├── xss.py         ← MODIFY: wrap payload loops with generate_variants
```

No changes to cli.py, output.py, or any other files. Existing detection logic unchanged — only the payloads sent are different.

## 2. Encoding Functions

All pure functions: `str → str`. Each produces one encoding variant.

```python
TECHNIQUE_FUNCS = {
    "url_encode": _url_encode,
    "case_mix": _case_mix,
    "comment_inject": _comment_inject,
    "whitespace_vary": _whitespace_vary,
    "double_url_encode": _double_url_encode,
    "html_entity": _html_entity,
    "null_byte": _null_byte,
}
```

### 2.1 url_encode

URL-encode key characters while leaving alphanumerics as-is:
- `'` → `%27`, `"` → `%22`, `<` → `%3C`, `>` → `%3E`
- space → `%20`, `(` → `%28`, `)` → `%29`, `=` → `%3D`, `;` → `%3B`, `-` → `%2D`
- Important: do NOT encode `%` that already exists (avoid double-encoding here)

### 2.2 case_mix

Randomly mix case of alphabetic characters:
- Each ASCII letter flips case with ~50% probability via `random.choice`
- e.g., `AND` → `aNd`, `select` → `SeLeCt`, `<Script>` → `<ScRiPt>`
- Must NOT touch SQL keywords inside XML/HTML tags — but since we encode the whole payload string, treat all ASCII letters uniformly

### 2.3 comment_inject (SQLi-only)

Replace spaces with SQL comment sequences:
- Space → `/**/`
- Multiple spaces collapsed to single `/**/`
- e.g., `' OR 1=1--` → `'/**/OR/**/1=1--`

### 2.4 whitespace_vary (SQLi-only)

Replace spaces with alternative whitespace characters:
- Space → `\t` (0x09) or `\n` (0x0a), randomly chosen per space
- e.g., `' OR 1=1--` → `'\tOR\n1=1--`

### 2.5 double_url_encode

Double-encode: re-encode the `%` signs in an already URL-encoded string.
- `%27` → `%2537` (because `%` → `%25`, so `%27` → `%2527`)
- First URL-encode, then replace each `%` with `%25`

### 2.6 html_entity (XSS-only)

Replace HTML-significant characters with decimal entities:
- `<` → `&#60;`, `>` → `&#62;`, `"` → `&#34;`, `'` → `&#39;`
- Do NOT encode `=` in attributes (keep `onload="..."` valid)

### 2.7 null_byte (XSS-only)

Prepend a null byte to the payload:
- Prefix the entire payload with `%00`
- Some filters stop at null byte but the browser processes the rest

## 3. Technique Assignment

```python
SQLI_TECHNIQUES = [
    "url_encode", "case_mix", "comment_inject",
    "whitespace_vary", "double_url_encode",
]

XSS_TECHNIQUES = [
    "url_encode", "case_mix", "double_url_encode",
    "html_entity", "null_byte",
]
```

## 4. generate_variants

```python
def generate_variants(payload, techniques):
    """Generate plain + all encoded variants.

    Args:
        payload: The original payload string.
        techniques: List of technique names to apply.

    Returns:
        List of (encoded_payload, technique_name) tuples.
        First tuple is always (payload, "plain").
    """
    variants = [(payload, "plain")]
    for name in techniques:
        func = TECHNIQUE_FUNCS[name]
        encoded = func(payload)
        if encoded != payload:  # Skip no-op (e.g., case_mix on digits)
            variants.append((encoded, name))
    return variants
```

## 5. Module Adaptations

### 5.1 sqli.py

Every payload loop gains an inner `generate_variants()` loop. Uses `SQLI_TECHNIQUES`.

**Phase 1 (error-based):**
```
for entry in param_names:
    for error_payload in ERROR_PAYLOADS:
        for encoded, tech in generate_variants(error_payload, SQLI_TECHNIQUES):
            → GET/POST with encoded payload
```

**Phase 2 baseline:** Only use plain payload (no encoding on baseline).

**Phase 2 (time-based):**
```
for entry in time_based_targets:
    for sp in SLEEP_PAYLOADS:
        for encoded, tech in generate_variants(sp["payload"], SQLI_TECHNIQUES):
            → GET/POST with encoded payload
```

**Note:** `_timed_request` continues to work unchanged — it receives the lambda/function and URL.

### 5.2 xss.py

Same pattern with `XSS_TECHNIQUES`:

```
for param_entry in param_names:
    for xss_entry in XSS_PAYLOADS:
        for encoded, tech in generate_variants(xss_entry["payload"], XSS_TECHNIQUES):
            → GET/POST with encoded payload
```

**Note:** `_analyze_reflection` still checks if the original payload (not the encoded variant) appears in the response HTML. The encoded variant is sent; the decoder function searches for the original payload text in the HTML. This is correct because if the WAF passes the encoded payload but the app decodes it before reflecting, the original payload text will appear.

## 6. Output Format

Findings gain an `encoding` field:

```json
{
  "type": "error_based",
  "parameter": "id",
  "url": "https://target.com/page?id=%27%20OR%201%3D1--",
  "database": "MySQL",
  "encoding": "url_encode",
  "evidence": "DB error keyword 'SQL syntax' found"
}
```

Output display for sqli/xss adds encoding info.

## 7. Non-Goals

- Filter detection (determining which WAF is present)
- Adaptive encoding (only sending variants after confirming WAF)
- Custom user-supplied encoding rules
- Chaining multiple encodings (e.g., URL-encode THEN case-mix) — one technique at a time

## 8. Success Criteria

1. `pytest tests/ -v` — all tests pass (existing 54 + new encoding tests)
2. `python -m scanner scan "url?id=1" -m sqli -v` — sends encoded variants, displays encoding type
3. `python -m scanner scan "url?q=test" -m xss -v` — sends encoded variants
4. `_analyze_reflection` still correctly identifies contexts (XSS detection works with encoded payloads)
5. Plain payloads still sent alongside encoded variants (backward compatible)
