"""JWT token analysis — parse, detect misconfigurations, test attacks.

Checks: none alg bypass, weak HMAC secret, alg confusion, kid injection,
        expired tokens, missing claims, JWK injection.
"""
import base64
import hashlib
import hmac
import json
import re
import time

from scanner.modules.base import BaseModule

# ── JWT Utilities ────────────────────────────────────────────────────────

# Common weak HMAC secrets
_WEAK_SECRETS = [
    "secret", "password", "123456", "admin", "changeme",
    "key", "private", "jwt_secret", "jwt-secret", "jwtsecret",
    "secret_key", "secretkey", "secret-key",
    "your-256-bit-secret", "your_secret_key",
    "super_secret", "super-secret", "supersecret",
    "default", "test", "dev", "development",
    "production", "prod", "staging",
    "flask-secret", "django-secret-key", "django-insecure",
    "rails-secret", "laravel-key",
    "api_secret", "api-secret-key", "api_key",
    "access_token_secret", "token_secret",
    "hmac_secret", "hmac_key",
]


def _b64url_decode(data):
    """Decode base64url-encoded string."""
    data = data.replace("-", "+").replace("_", "/")
    # Add padding
    rem = len(data) % 4
    if rem:
        data += "=" * (4 - rem)
    try:
        return base64.b64decode(data)
    except Exception:
        return None


def _b64url_encode(data):
    """Encode bytes to base64url string."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _parse_jwt(token):
    """Parse a JWT into header, payload, signature. Returns dict or None."""
    parts = token.strip().split(".")
    if len(parts) != 3:
        return None
    header_raw, payload_raw, sig_raw = parts[0], parts[1], parts[2]
    header = _b64url_decode(header_raw)
    payload = _b64url_decode(payload_raw)
    if not header or not payload:
        return None
    try:
        header = json.loads(header)
        payload = json.loads(payload)
    except (json.JSONDecodeError, TypeError):
        return None
    return {
        "header": header,
        "payload": payload,
        "signature_b64": sig_raw,
        "signing_input": f"{header_raw}.{payload_raw}",
    }


def _hmac_sign(data, secret, algo="HS256"):
    """Sign data with HMAC using the given algorithm."""
    hash_map = {"HS256": "sha256", "HS384": "sha384", "HS512": "sha512"}
    hash_name = hash_map.get(algo, "sha256")
    return hmac.new(
        secret.encode() if isinstance(secret, str) else secret,
        data.encode() if isinstance(data, str) else data,
        hash_name
    ).digest()


def _try_none_alg(token):
    """Test if 'none' algorithm bypass works."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        # Create none-alg token: set alg to none in header
        header_b64 = parts[0]
        decoded = _b64url_decode(header_b64)
        if not decoded:
            return None
        header = json.loads(decoded)
        header["alg"] = "none"
        new_header = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
        payload = parts[1]
        # Remove signature
        return {"modified_token": f"{new_header}.{payload}.", "note": "alg=none, no signature"}
    except Exception:
        return None


def _try_weak_secrets(token):
    """Test common weak HMAC secrets against JWT signature."""
    parsed = _parse_jwt(token)
    if not parsed:
        return []
    alg = parsed["header"].get("alg", "")
    if alg not in ("HS256", "HS384", "HS512"):
        return []

    found = []
    for secret in _WEAK_SECRETS[:15]:  # limit to avoid slowdown
        try:
            computed = _hmac_sign(parsed["signing_input"], secret, alg)
            computed_b64 = _b64url_encode(computed)
            if computed_b64 == parsed["signature_b64"]:
                found.append(secret)
        except Exception:
            pass
    return found


def _check_kid_injection(header):
    """Check if kid (Key ID) parameter could be exploited."""
    kid = header.get("kid", "")
    findings = []
    if not kid:
        return findings
    # Path traversal in kid
    if "../" in kid or "..\\" in kid:
        findings.append({"type": "kid_path_traversal", "kid": kid,
                         "desc": "kid contains path traversal — may read arbitrary files"})
    # kid pointing to /dev/null or known static files
    if kid in ("/dev/null", "/dev/zero", "/dev/random"):
        findings.append({"type": "kid_static_file", "kid": kid,
                         "desc": f"kid points to {kid} — predictable key material"})
    # SQL injection in kid
    if re.search(r"['\"]\s*(?:OR|UNION|SELECT|--|;)", kid, re.I):
        findings.append({"type": "kid_sqli", "kid": kid,
                         "desc": "kid may be vulnerable to SQL injection"})
    return findings


def _check_jwk_header(header):
    """Check for JWK (JSON Web Key) header — may allow key injection."""
    if "jwk" in header:
        return {"type": "jwk_injection", "desc": "jwk header present — attacker may inject own key"}
    if "jku" in header:
        return {"type": "jku_header", "desc": "jku header present — fetch attacker-controlled JWK set"}
    return None


def _check_claims(payload):
    """Check for missing or suspicious claims."""
    issues = []
    now = int(time.time())

    # Expiration
    if "exp" not in payload:
        issues.append("missing exp claim — token never expires")
    else:
        exp = payload["exp"]
        if exp < now:
            issues.append(f"token expired at {exp} ({time.ctime(exp)})")
        elif exp - now > 365 * 86400:
            issues.append(f"token expiry > 1 year ({exp})")

    # Not-before
    if "nbf" in payload and payload["nbf"] > now:
        issues.append(f"token not yet valid until {payload['nbf']}")

    # Issued-at
    if "iat" in payload and payload["iat"] > now:
        issues.append(f"iat in the future ({payload['iat']})")

    # Issuer
    if "iss" not in payload:
        issues.append("missing iss (issuer) claim")

    # Subject
    if "sub" not in payload:
        issues.append("missing sub (subject) claim")

    # JWT ID
    if "jti" not in payload:
        issues.append("missing jti (JWT ID) — no replay protection")

    # Audience
    if "aud" not in payload:
        issues.append("missing aud (audience) claim")

    # Sensitive data in payload
    sensitive_keys = []
    for key in ("password", "passwd", "secret", "token", "apikey", "api_key",
                "credit_card", "ssn", "pin", "admin"):
        if key in payload:
            sensitive_keys.append(key)
    if sensitive_keys:
        issues.append(f"sensitive data in payload: {', '.join(sensitive_keys)}")

    return issues


def _detect_alg_confusion(header):
    """Detect potential algorithm confusion (RS→HS)."""
    alg = header.get("alg", "")
    if alg in ("RS256", "RS384", "RS512"):
        return {"type": "alg_confusion_rs_to_hs",
                "desc": f"Uses {alg}. If the server accepts HS{algo[-3:]} with the public key as secret, "
                        f"an attacker can forge tokens."}
    return None


def analyze_token(token, token_source=""):
    """Run all JWT checks against a token. Returns list of findings.

    Args:
        token: JWT string.
        token_source: description of where the token was found.

    Returns:
        List of finding dicts.
    """
    findings = []

    parsed = _parse_jwt(token)
    if not parsed:
        return []

    header = parsed["header"]
    payload = parsed["payload"]
    alg = header.get("alg", "unknown")

    finding = {
        "token_source": token_source,
        "header": header,
        "payload": payload,
        "algorithm": alg,
    }

    # Check algorithm
    if alg == "none":
        findings.append({**finding, "type": "alg_none",
                         "severity": "critical",
                         "desc": "Token uses 'none' algorithm — trivial signature bypass"})

    # None bypass test
    none_token = _try_none_alg(token)
    if none_token:
        findings.append({**finding, "type": "alg_none_bypass",
                         "severity": "critical",
                         "modified_token": none_token["modified_token"],
                         "desc": "Try submitting token with alg=none and no signature"})

    # Weak HMAC
    weak = _try_weak_secrets(token)
    if weak:
        findings.append({**finding, "type": "weak_hmac_secret",
                         "severity": "critical",
                         "secrets_found": weak,
                         "desc": f"HMAC secret is weak/common: {', '.join(weak)}"})

    # Algorithm confusion
    confusion = _detect_alg_confusion(header)
    if confusion:
        findings.append({**finding, "type": confusion["type"],
                         "severity": "high",
                         "desc": confusion["desc"]})

    # KID injection
    kid_findings = _check_kid_injection(header)
    for kf in kid_findings:
        findings.append({**finding, "type": kf["type"],
                         "severity": "high",
                         "kid": kf["kid"],
                         "desc": kf["desc"]})

    # JWK injection
    jwk = _check_jwk_header(header)
    if jwk:
        findings.append({**finding, "type": jwk["type"],
                         "severity": "high",
                         "desc": jwk["desc"]})

    # Claim issues
    claim_issues = _check_claims(payload)
    if claim_issues:
        findings.append({**finding, "type": "weak_claims",
                         "severity": "medium",
                         "issues": claim_issues,
                         "desc": f"Claim issues: {'; '.join(claim_issues[:3])}"})

    # If no issues found, report healthy token
    if not findings:
        findings.append({**finding, "type": "healthy",
                         "severity": "info",
                         "desc": f"Token appears well-configured (alg={alg})"})

    return findings


def _extract_jwts_from_response(resp, target_url):
    """Extract JWT tokens from HTTP response."""
    tokens = []

    # Check Authorization header
    auth = resp.headers.get("Authorization", "")
    match = re.search(r"Bearer\s+([A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+)",
                      auth)
    if match:
        tokens.append({"token": match.group(1), "source": "Authorization header"})

    # Check Set-Cookie headers
    for hdr_name in ("Set-Cookie", "set-cookie"):
        if hdr_name in resp.headers:
            cookies = resp.headers[hdr_name]
            # Common JWT cookie names
            jwt_cookie = re.search(
                r"(?:token|jwt|access_token|id_token|auth|session)=([A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+)",
                cookies
            )
            if jwt_cookie:
                tokens.append({"token": jwt_cookie.group(1),
                               "source": f"Cookie ({hdr_name})"})

    # Check for JWT in HTML/JS
    body = resp.text or ""
    jwt_in_body = re.findall(
        r'["\']?(eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+)["\']?',
        body
    )
    for tok in jwt_in_body[:5]:  # limit
        if not any(t["token"] == tok for t in tokens):
            tokens.append({"token": tok, "source": "HTML/JS body"})

    return tokens


class JwtModule(BaseModule):
    """Analyze JWT tokens for misconfigurations and vulnerabilities."""

    name = "jwt"
    description = "Analyze JWT tokens: none-alg, weak secrets, alg confusion, kid injection"
    requires_url = True

    def run(self, target, request_handler, output):
        output.log_progress(f"Fetching {target} for JWT analysis...")
        findings = []

        try:
            resp = request_handler.get(target)
        except Exception:
            output.log_progress(f"Failed to fetch {target}")
            return {"module": self.name, "findings": []}

        tokens = _extract_jwts_from_response(resp, target)

        # Also check request cookies if provided
        if hasattr(request_handler, "cookies_str") and request_handler.cookies_str:
            # Check for JWT in cookies
            for cookie in request_handler.cookies_str.split(";"):
                cookie = cookie.strip()
                if "." in cookie and "=" in cookie:
                    k, v = cookie.split("=", 1)
                    if v.count(".") >= 2 and len(v) > 20:
                        if not any(t["token"] == v for t in tokens):
                            tokens.append({"token": v, "source": f"Provided cookie ({k})"})

        if not tokens:
            output.log_progress("No JWT tokens found in response headers, cookies, or body.")
            findings.append({
                "type": "no_token", "severity": "info",
                "desc": "No JWT tokens detected on this endpoint"
            })
        else:
            output.log_progress(f"Found {len(tokens)} JWT token(s)")
            for tok_info in tokens:
                token_findings = analyze_token(tok_info["token"], tok_info["source"])
                for f in token_findings:
                    findings.append(f)
                    sev = f.get("severity", "info")
                    output.log_progress(f"  [{sev.upper()}] {f['type']}: {f.get('desc', '')[:80]}")
                output.log_finding(self.name, {"token_source": tok_info["source"],
                                                "findings": token_findings})

        return {"module": self.name, "findings": findings}
