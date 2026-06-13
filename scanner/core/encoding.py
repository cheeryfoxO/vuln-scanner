"""WAF bypass encoding functions for payload obfuscation.

Each function takes a plain payload string and returns an encoded variant.
All functions are str -> str, independent of any scanner internals.
"""
import random
import urllib.parse


# ── Encoding Functions ───────────────────────────────────────────────

def _url_encode(payload):
    """URL-encode key SQL/XSS characters.

    Encodes: ' " < > ( ) = ; - and space.
    Does NOT double-encode existing % signs.
    """
    char_map = {
        "'": "%27",
        '"': "%22",
        "<": "%3C",
        ">": "%3E",
        "(": "%28",
        ")": "%29",
        "=": "%3D",
        ";": "%3B",
        "-": "%2D",
        " ": "%20",
    }
    result = []
    for ch in payload:
        result.append(char_map.get(ch, ch))
    return "".join(result)


def _case_mix(payload):
    """Randomly flip case of ASCII letters.

    Each letter has ~50% chance of being upper/lower.
    Non-letters pass through unchanged.
    """
    result = []
    for ch in payload:
        if ch.isalpha():
            result.append(ch.upper() if random.choice([True, False]) else ch.lower())
        else:
            result.append(ch)
    return "".join(result)


def _comment_inject(payload):
    """Replace spaces with SQL inline comments /**/.

    Example: "' OR 1=1" -> "'/**/OR/**/1=1"
    """
    return payload.replace(" ", "/**/")


def _whitespace_vary(payload):
    """Replace spaces with alternative whitespace (tab or newline).

    Randomly chooses \\t or \\n per space.
    """
    result = []
    for ch in payload:
        if ch == " ":
            result.append(random.choice(["\t", "\n"]))
        else:
            result.append(ch)
    return "".join(result)


def _double_url_encode(payload):
    """Double URL-encode: first encode, then encode the % signs.

    Example: "'" -> "%27" -> "%2527"
    """
    single = _url_encode(payload)
    return single.replace("%", "%25")


def _html_entity(payload):
    """Replace HTML-significant characters with decimal entities.

    < -> &#60;   > -> &#62;   " -> &#34;   ' -> &#39;
    """
    char_map = {
        "<": "&#60;",
        ">": "&#62;",
        '"': "&#34;",
        "'": "&#39;",
    }
    result = []
    for ch in payload:
        result.append(char_map.get(ch, ch))
    return "".join(result)


def _null_byte(payload):
    """Prepend a null byte to the payload.

    Some filters stop at null byte but browser processes the rest.
    """
    return "%00" + payload


# ── Technique Registry ───────────────────────────────────────────────

TECHNIQUE_FUNCS = {
    "url_encode": _url_encode,
    "case_mix": _case_mix,
    "comment_inject": _comment_inject,
    "whitespace_vary": _whitespace_vary,
    "double_url_encode": _double_url_encode,
    "html_entity": _html_entity,
    "null_byte": _null_byte,
}

SQLI_TECHNIQUES = [
    "url_encode", "case_mix", "comment_inject",
    "whitespace_vary", "double_url_encode",
]

XSS_TECHNIQUES = [
    "url_encode", "case_mix", "double_url_encode",
    "html_entity", "null_byte",
]


def generate_variants(payload, techniques):
    """Generate plain + all encoded variants of a payload.

    Args:
        payload: Original payload string.
        techniques: List of technique names to apply.

    Returns:
        List of (encoded_payload, technique_name) tuples.
        First is always (payload, "plain").
        Duplicates are skipped (e.g., case_mix on digit-only payload).
    """
    variants = [(payload, "plain")]
    seen = {payload}
    for name in techniques:
        func = TECHNIQUE_FUNCS[name]
        encoded = func(payload)
        if encoded not in seen:
            variants.append((encoded, name))
            seen.add(encoded)
    return variants
