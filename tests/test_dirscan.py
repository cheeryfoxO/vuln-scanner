"""Tests for directory scanning module with content fingerprinting."""
import re
from unittest.mock import Mock
from scanner.modules.dirscan import (
    _check_content,
    _SENSITIVE_PATTERNS,
    DirscanModule,
)


class TestCheckContent:
    def test_returns_none_for_normal_page(self):
        mock_request = Mock()
        mock_request.get.return_value = Mock(text="<html>Hello World</html>")
        result = _check_content("http://example.com/.env", mock_request)
        assert result is None

    def test_detects_db_password_in_env(self):
        mock_request = Mock()
        mock_request.get.return_value = Mock(text='DB_PASSWORD="secret123"')
        result = _check_content("http://example.com/.env", mock_request)
        assert result is not None
        assert result["severity"] == "high"
        assert "DB" in result["label"]

    def test_detects_private_key(self):
        mock_request = Mock()
        mock_request.get.return_value = Mock(
            text="-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA..."
        )
        result = _check_content("http://example.com/id_rsa", mock_request)
        assert result is not None
        assert result["severity"] == "critical"

    def test_detects_aws_key(self):
        mock_request = Mock()
        mock_request.get.return_value = Mock(
            text="AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
        )
        result = _check_content("http://example.com/.env", mock_request)
        assert result is not None
        assert result["severity"] == "critical"

    def test_detects_connection_string(self):
        mock_request = Mock()
        mock_request.get.return_value = Mock(
            text="mongodb://admin:password123@localhost:27017/db"
        )
        result = _check_content("http://example.com/config.js", mock_request)
        assert result is not None
        assert result["severity"] == "critical"

    def test_handles_request_exception(self):
        mock_request = Mock()
        mock_request.get.side_effect = Exception("Connection refused")
        result = _check_content("http://example.com/.env", mock_request)
        assert result is None


class TestPatterns:
    def test_has_at_least_eight_patterns(self):
        assert len(_SENSITIVE_PATTERNS) >= 8

    def test_includes_critical_and_high(self):
        severities = {p[2] for p in _SENSITIVE_PATTERNS}
        assert "critical" in severities
        assert "high" in severities


class TestModule:
    def test_module_attributes(self):
        mod = DirscanModule()
        assert mod.name == "dirscan"
        assert mod.requires_url is True
