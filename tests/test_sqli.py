"""Tests for SQL injection detection module."""
import re
import time
from unittest.mock import Mock, patch
from scanner.modules.sqli import (
    _check_error_patterns,
    _build_baseline_time,
    _make_test_url,
    _strip_dynamic,
    _compare_responses,
    BOOL_PAYLOADS,
    NO_RESULT_KEYWORDS,
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


class TestStripDynamic:
    def test_strips_unix_timestamps(self):
        text = "page_1623456789_loaded with token abc123"
        result = _strip_dynamic(text)
        assert "1623456789" not in result

    def test_strips_md5_tokens(self):
        text = "csrf=d41d8cd98f00b204e9800998ecf8427e&ok"
        result = _strip_dynamic(text)
        assert "d41d8cd98f00b204e9800998ecf8427e" not in result

    def test_strips_script_tags(self):
        text = '<div>hi</div><script>var x=1</script><p>bye</p>'
        result = _strip_dynamic(text)
        assert "<script>" not in result
        assert "var x=1" not in result

    def test_normalizes_whitespace(self):
        text = "hello   world\n\nbye"
        result = _strip_dynamic(text)
        assert "  " not in result
        assert "\n" not in result
        assert result == "hello world bye"

    def test_leaves_normal_text_unchanged(self):
        text = "Search results for: test query"
        result = _strip_dynamic(text)
        assert "Search results" in result


class TestCompareResponses:
    def test_different_length_triggers_positive(self):
        true_html = "<div>Results: item1, item2, item3</div>"
        false_html = "<div>empty</div>"
        verdict, indicators, detail = _compare_responses(true_html, false_html)
        assert verdict is True
        assert "body_length" in indicators

    def test_same_content_triggers_negative(self):
        html = "<div>Welcome</div>"
        verdict, indicators, detail = _compare_responses(html, html)
        assert verdict is False

    def test_no_result_keyword_triggers_positive(self):
        true_html = "<div>100 products found</div>"
        false_html = "<div>no results found</div>"
        verdict, indicators, detail = _compare_responses(true_html, false_html)
        assert verdict is True
        assert "content_keyword" in indicators

    def test_need_two_indicators_for_positive(self):
        true_html = "<div>hello world!</div>"
        false_html = "<div>hello world?</div>"
        verdict, indicators, detail = _compare_responses(true_html, false_html)
        assert verdict is False


class TestBoolPayloads:
    def test_three_pairs(self):
        assert len(BOOL_PAYLOADS) == 3

    def test_each_pair_has_true_false_name(self):
        for p in BOOL_PAYLOADS:
            assert "true" in p
            assert "false" in p
            assert "name" in p

    def test_true_false_differ_by_one_char(self):
        for p in BOOL_PAYLOADS:
            diff = sum(1 for a, b in zip(p["true"], p["false"]) if a != b)
            assert diff == 1


class TestNoResultKeywords:
    def test_keywords_non_empty(self):
        assert len(NO_RESULT_KEYWORDS) >= 5

    def test_chinese_keywords_included(self):
        assert any("查" in kw for kw in NO_RESULT_KEYWORDS)
