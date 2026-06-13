"""Tests for open redirect detection module."""
from unittest.mock import Mock
from scanner.modules.redirect import (
    _is_external_redirect,
    _REDIRECT_PAYLOADS,
    RedirectModule,
)


class TestIsExternalRedirect:
    def test_302_to_external_is_detected(self):
        resp = Mock(status_code=302, headers={"Location": "https://evil.com"})
        assert _is_external_redirect(resp, "example.com") is True

    def test_301_to_external_is_detected(self):
        resp = Mock(status_code=301, headers={"Location": "//evil.com"})
        assert _is_external_redirect(resp, "example.com") is True

    def test_relative_redirect_is_ignored(self):
        resp = Mock(status_code=302, headers={"Location": "/login"})
        assert _is_external_redirect(resp, "example.com") is False

    def test_same_domain_is_ignored(self):
        resp = Mock(status_code=302, headers={"Location": "https://example.com/page"})
        assert _is_external_redirect(resp, "example.com") is False

    def test_non_3xx_is_ignored(self):
        resp = Mock(status_code=200, headers={"Location": "https://evil.com"})
        assert _is_external_redirect(resp, "example.com") is False

    def test_no_location_header_is_ignored(self):
        resp = Mock(status_code=302, headers={})
        assert _is_external_redirect(resp, "example.com") is False


class TestPayloads:
    def test_has_six_payloads(self):
        assert len(_REDIRECT_PAYLOADS) == 6

    def test_includes_protocol_relative(self):
        assert any("//evil.com" in p for p in _REDIRECT_PAYLOADS)

    def test_includes_url_encoded(self):
        assert any("%2F" in p for p in _REDIRECT_PAYLOADS)


class TestModule:
    def test_module_attributes(self):
        mod = RedirectModule()
        assert mod.name == "redirect"
        assert mod.requires_url is True
        assert "redirect" in mod.description.lower()
