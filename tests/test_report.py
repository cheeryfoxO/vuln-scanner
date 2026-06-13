"""Tests for HTML report generation."""
import os
import tempfile
from scanner.core.report import _infer_severity, generate_html


class TestInferSeverity:
    def test_sqli_is_critical(self):
        assert _infer_severity("sqli", {"type": "error_based"}) == "critical"

    def test_headers_is_low(self):
        assert _infer_severity("headers", {"type": "missing"}) == "low"

    def test_params_is_info(self):
        assert _infer_severity("params", {"type": "url"}) == "info"

    def test_respects_finding_override(self):
        finding = {"type": "lfi", "severity": "critical"}
        assert _infer_severity("dirscan", finding) == "critical"


class TestGenerateHtml:
    def test_generates_valid_html_file(self):
        report = {
            "scan_time": "2025-01-01T00:00:00",
            "target": "example.com",
            "modules": ["sqli", "headers"],
            "findings": {
                "sqli": [{"type": "error_based", "parameter": "id",
                          "evidence": "SQL syntax error"}],
                "headers": [{"header": "CSP", "status": "missing",
                             "description": "Missing CSP"}],
            },
        }
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as f:
            path = f.name
        try:
            result = generate_html("example.com", report, path)
            assert result == path
            assert os.path.getsize(path) > 500
            with open(path, encoding="utf-8") as f:
                content = f.read()
            assert "Scan Report" in content
            assert "example.com" in content
            assert "SQL syntax error" in content
            assert "CRITICAL" in content
            assert "LOW" in content
        finally:
            os.unlink(path)

    def test_discovered_urls_show(self):
        report = {
            "scan_time": "2025-01-01T00:00:00",
            "target": "test.com",
            "modules": [],
            "findings": {},
            "discovered_urls": 42,
        }
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as f:
            path = f.name
        try:
            generate_html("test.com", report, path)
            with open(path, encoding="utf-8") as f:
                content = f.read()
            assert "42" in content
        finally:
            os.unlink(path)
