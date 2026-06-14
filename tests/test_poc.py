"""Tests for PoC generation."""
import urllib.parse
from scanner.core.poc import (
    build_curl,
    inject_poc_into_finding,
    _inject_param,
    _escape_shell,
)


class TestInjectParam:
    def test_injects_into_query_string(self):
        url = "https://example.com/search?q=test"
        result = _inject_param(url, "q", "' OR 1=1--")
        parsed = urllib.parse.urlparse(result)
        assert "q=%27+OR+1%3D1--" in parsed.query or "OR+1%3D1" in parsed.query

    def test_adds_param_if_missing(self):
        url = "https://example.com/page"
        result = _inject_param(url, "id", "1'")
        assert "id=1%27" in result

    def test_preserves_existing_params(self):
        url = "https://example.com/search?q=test&page=1"
        result = _inject_param(url, "q", "PAYLOAD")
        assert "page=1" in result


class TestBuildCurl:
    def test_basic_sqli(self):
        finding = {
            "url": "https://example.com/search?q=test",
            "parameter": "q",
            "payload": "' OR 1=1--",
            "type": "error_based",
        }
        curl = build_curl(finding, "sqli")
        assert "curl" in curl
        assert "example.com" in curl

    def test_subdomain(self):
        finding = {"host": "admin.example.com", "type": "dns_resolve"}
        curl = build_curl(finding, "subdomain")
        assert "admin.example.com" in curl

    def test_unknown_module_fallback(self):
        finding = {
            "url": "https://example.com/test",
            "parameter": "x",
            "payload": "test",
        }
        curl = build_curl(finding, "unknown_module")
        assert "curl" in curl

    def test_missing_url_returns_empty(self):
        finding = {"type": "info"}
        curl = build_curl(finding, "headers")
        assert curl == ""


class TestInjectPoc:
    def test_adds_poc_to_finding(self):
        finding = {"url": "https://example.com/test", "type": "info"}
        result = inject_poc_into_finding(finding, "headers")
        assert "poc" in result
        assert "curl" in result["poc"]


class TestEscapeShell:
    def test_escapes_special_chars(self):
        result = _escape_shell("hello'world")
        assert result != "hello'world"  # should be quoted
