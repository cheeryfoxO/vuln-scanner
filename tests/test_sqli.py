"""Tests for SQL injection detection module."""
import re
import time
from unittest.mock import Mock, patch
from scanner.modules.sqli import (
    _check_error_patterns,
    _build_baseline_time,
    _make_test_url,
    ERROR_PAYLOADS,
    DB_ERROR_PATTERNS,
    SLEEP_PAYLOADS,
    SqliModule,
)


class TestErrorPatterns:
    def test_mysql_error_detected(self):
        text = "You have an error in your SQL syntax; check the manual"
        result = _check_error_patterns(text)
        assert result is not None
        assert result["db"] == "MySQL"
        assert "SQL syntax" in result["keyword"]

    def test_postgresql_error_detected(self):
        text = "ERROR: 42601: syntax error at or near \"'\" at character 15. PostgreSQL query failed"
        result = _check_error_patterns(text)
        assert result is not None

    def test_mssql_error_detected(self):
        text = "Microsoft OLE DB Provider for SQL Server error '80040e14'. Unclosed quotation mark"
        result = _check_error_patterns(text)
        assert result is not None

    def test_oracle_error_detected(self):
        text = "ORA-01756: quoted string not properly terminated"
        result = _check_error_patterns(text)
        assert result is not None

    def test_no_error_in_normal_page(self):
        text = "<html><body>Welcome to our site</body></html>"
        result = _check_error_patterns(text)
        assert result is None

    def test_check_error_patterns_is_case_insensitive(self):
        text = "you have an error in your sql syntax near"
        result = _check_error_patterns(text)
        assert result is not None


class TestBaselineTime:
    def test_baseline_returns_average(self):
        call_times = [0.1, 0.2, 0.3]
        call_count = [0]

        def mock_request(url):
            idx = min(call_count[0], 2)
            call_count[0] += 1
            time.sleep(call_times[idx])
            return Mock(status_code=200, text="")

        with patch("time.perf_counter") as mock_time:
            mock_time.side_effect = [0.0, 0.1, 0.1, 0.2, 0.2, 0.3]
            baseline = _build_baseline_time("http://test.com?id=1", mock_request)
            assert 0.09 < baseline < 0.11


class TestMakeTestUrl:
    def test_replaces_get_param(self):
        result = _make_test_url("http://example.com/page?id=1", "id", "' OR 1=1--")
        assert "id=%27+OR+1%3D1--" in result

    def test_adds_param_to_url_without_params(self):
        result = _make_test_url("http://example.com/page", "q", "test")
        assert result == "http://example.com/page?q=test"

    def test_adds_param_to_url_with_existing_params(self):
        result = _make_test_url("http://example.com/page?a=1&b=2", "b", "injected")
        assert "b=injected" in result


class TestPayloads:
    def test_error_payloads_non_empty(self):
        assert len(ERROR_PAYLOADS) == 12

    def test_sleep_payloads_have_four_dbs(self):
        assert len(SLEEP_PAYLOADS) == 4
        dbs = {p["db"] for p in SLEEP_PAYLOADS}
        assert dbs == {"MySQL", "PostgreSQL", "MSSQL", "Oracle"}

    def test_db_error_patterns_have_all_four(self):
        dbs = set(DB_ERROR_PATTERNS.keys())
        assert dbs == {"MySQL", "PostgreSQL", "MSSQL", "Oracle"}


class TestModule:
    def test_module_attributes(self):
        mod = SqliModule()
        assert mod.name == "sqli"
        assert mod.requires_url is True
        assert "SQL" in mod.description
