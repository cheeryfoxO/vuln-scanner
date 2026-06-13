"""Tests for security headers module."""
from unittest.mock import Mock
from scanner.modules.headers import (
    _check_headers,
    _SECURITY_HEADERS,
    HeadersModule,
)


class TestCheckHeaders:
    def test_reports_missing_headers(self):
        resp = Mock(status_code=200, headers={})
        results = _check_headers(resp)
        assert len(results) > 0
        assert any(r["status"] == "missing" for r in results)

    def test_detects_present_headers(self):
        resp = Mock(status_code=200, headers={
            "Strict-Transport-Security": "max-age=31536000",
            "X-Frame-Options": "DENY",
        })
        results = _check_headers(resp)
        hsts = next(r for r in results if r["header"] == "Strict-Transport-Security")
        assert hsts["status"] == "present"

    def test_flags_wildcard_cors(self):
        resp = Mock(status_code=200, headers={
            "Access-Control-Allow-Origin": "*",
        })
        results = _check_headers(resp)
        cors = next(r for r in results if r["header"] == "Access-Control-Allow-Origin")
        assert cors["status"] == "insecure"


class TestHeaderList:
    def test_covers_critical_headers(self):
        names = {h["name"] for h in _SECURITY_HEADERS}
        assert "Strict-Transport-Security" in names
        assert "Content-Security-Policy" in names
        assert "X-Frame-Options" in names
        assert "X-Content-Type-Options" in names

    def test_each_header_has_description(self):
        for h in _SECURITY_HEADERS:
            assert "name" in h
            assert "description" in h
            assert len(h["description"]) > 5


class TestModule:
    def test_module_attributes(self):
        mod = HeadersModule()
        assert mod.name == "headers"
        assert mod.requires_url is True
        assert "header" in mod.description.lower()
