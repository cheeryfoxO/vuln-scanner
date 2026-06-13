"""Tests for CORS misconfiguration detection."""
from unittest.mock import Mock
from scanner.modules.cors import (
    _check_cors,
    CorsModule,
)


class TestCheckCors:
    def test_detects_reflected_origin(self):
        resp = Mock(
            status_code=200,
            headers={"Access-Control-Allow-Origin": "https://evil.com"},
        )
        result = _check_cors(resp, "https://evil.com")
        assert result is not None
        assert result["acao_reflected"] is True
        assert result["severity"] == "high"

    def test_detects_reflected_with_credentials(self):
        resp = Mock(
            status_code=200,
            headers={
                "Access-Control-Allow-Origin": "https://evil.com",
                "Access-Control-Allow-Credentials": "true",
            },
        )
        result = _check_cors(resp, "https://evil.com")
        assert result is not None
        assert result["severity"] == "critical"

    def test_returns_none_for_no_cors_headers(self):
        resp = Mock(status_code=200, headers={})
        result = _check_cors(resp, "https://evil.com")
        assert result is None

    def test_returns_none_for_fixed_origin(self):
        resp = Mock(
            status_code=200,
            headers={"Access-Control-Allow-Origin": "https://target.com"},
        )
        result = _check_cors(resp, "https://evil.com")
        assert result is None

    def test_returns_none_for_wildcard_without_credentials(self):
        resp = Mock(
            status_code=200,
            headers={"Access-Control-Allow-Origin": "*"},
        )
        result = _check_cors(resp, "https://evil.com")
        assert result is None  # wildcard alone is not a misconfig, just low risk


class TestModule:
    def test_module_attributes(self):
        mod = CorsModule()
        assert mod.name == "cors"
        assert mod.requires_url is True
        assert "cors" in mod.description.lower()
