"""Tests for JWT analysis."""
from scanner.modules.jwt import (
    _parse_jwt, _b64url_decode, _b64url_encode,
    _try_none_alg, _try_weak_secrets, _check_claims,
    _check_kid_injection, analyze_token, _extract_jwts_from_response,
)
from unittest.mock import Mock


class TestBase64Url:
    def test_roundtrip(self):
        data = b'{"alg":"HS256"}'
        encoded = _b64url_encode(data)
        decoded = _b64url_decode(encoded)
        assert decoded == data


class TestParseJwt:
    def test_valid_hs256(self):
        # Test token: {"alg":"HS256","typ":"JWT"}.{"sub":"123"}.sig
        header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        payload = "eyJzdWIiOiIxMjMifQ"
        token = f"{header}.{payload}.fakesig"
        parsed = _parse_jwt(token)
        assert parsed is not None
        assert parsed["header"]["alg"] == "HS256"
        assert parsed["payload"]["sub"] == "123"

    def test_invalid_token(self):
        assert _parse_jwt("not-a-jwt") is None
        assert _parse_jwt("a.b") is None

    def test_none_alg_bypass(self):
        # Token with HS256 → generates none-alg variant
        header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        payload = "eyJzdWIiOiIxMjMifQ"
        token = f"{header}.{payload}.sig"
        result = _try_none_alg(token)
        assert result is not None
        assert result["modified_token"].endswith(".")


class TestWeakSecrets:
    def test_known_weak_secret(self):
        import hashlib, hmac, base64, json
        secret = "secret"
        header = base64.urlsafe_b64encode(json.dumps({"alg":"HS256","typ":"JWT"}).encode()).rstrip(b"=").decode()
        payload = base64.urlsafe_b64encode(json.dumps({"sub":"123"}).encode()).rstrip(b"=").decode()
        sig_input = f"{header}.{payload}"
        sig = hmac.new(secret.encode(), sig_input.encode(), hashlib.sha256).digest()
        sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
        token = f"{header}.{payload}.{sig_b64}"
        found = _try_weak_secrets(token)
        assert "secret" in found


class TestClaims:
    def test_missing_claims(self):
        issues = _check_claims({"sub": "123"})
        assert any("exp" in i for i in issues)

    def test_sensitive_data(self):
        issues = _check_claims({"sub": "123", "password": "hunter2"})
        assert any("sensitive" in i for i in issues)


class TestKidInjection:
    def test_path_traversal(self):
        findings = _check_kid_injection({"kid": "../../etc/passwd"})
        assert len(findings) > 0

    def test_safe_kid(self):
        findings = _check_kid_injection({"kid": "key-1"})
        assert len(findings) == 0


class TestAnalyzeToken:
    def test_returns_findings(self):
        header = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0"
        payload = "eyJzdWIiOiIxMjMifQ"
        token = f"{header}.{payload}."
        findings = analyze_token(token)
        assert len(findings) > 0
