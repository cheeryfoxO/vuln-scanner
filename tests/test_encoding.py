"""Tests for WAF bypass encoding functions."""
import re
from scanner.core.encoding import (
    _url_encode,
    _case_mix,
    _comment_inject,
    _whitespace_vary,
    _double_url_encode,
    _html_entity,
    _null_byte,
    generate_variants,
    TECHNIQUE_FUNCS,
    SQLI_TECHNIQUES,
    XSS_TECHNIQUES,
)


class TestUrlEncode:
    def test_encodes_single_quote(self):
        result = _url_encode("'")
        assert result == "%27"

    def test_encodes_multiple_chars(self):
        result = _url_encode("1' OR 1=1--")
        assert "%27" in result
        assert "%20" in result
        assert "%3D" in result

    def test_does_not_double_encode(self):
        result = _url_encode("%27")
        assert result.count("25") == 0


class TestCaseMix:
    def test_output_length_unchanged(self):
        result = _case_mix("SELECT")
        assert len(result) == len("SELECT")
        assert result.upper() == "SELECT"

    def test_preserves_special_chars(self):
        result = _case_mix("' OR 1=1--")
        assert "'" in result
        assert "=" in result
        assert "--" in result


class TestCommentInject:
    def test_replaces_spaces_with_comments(self):
        result = _comment_inject("' OR 1=1")
        assert "/**/" in result
        assert " " not in result

    def test_no_spaces_unchanged(self):
        result = _comment_inject("'OR'")
        assert result == "'OR'"


class TestWhitespaceVary:
    def test_replaces_spaces_with_whitespace(self):
        result = _whitespace_vary("' OR 1=1")
        assert " " not in result
        assert ("\t" in result or "\n" in result)

    def test_no_spaces_unchanged(self):
        result = _whitespace_vary("'OR'")
        assert result == "'OR'"


class TestDoubleUrlEncode:
    def test_double_encodes_percent(self):
        result = _double_url_encode("'")
        assert "%25" in result
        assert "%2527" in result


class TestHtmlEntity:
    def test_encodes_angle_brackets(self):
        result = _html_entity("<script>")
        assert "&#60;" in result
        assert "&#62;" in result
        assert "<" not in result
        assert ">" not in result

    def test_encodes_quotes(self):
        result = _html_entity('"test"')
        assert "&#34;" in result


class TestNullByte:
    def test_prepends_null_byte(self):
        result = _null_byte("<script>")
        assert result.startswith("%00")
        assert "<script>" in result


class TestGenerateVariants:
    def test_always_includes_plain(self):
        variants = generate_variants("test", ["url_encode"])
        methods = [v[1] for v in variants]
        assert "plain" in methods

    def test_uses_specified_techniques(self):
        variants = generate_variants("' OR 1=1--", SQLI_TECHNIQUES)
        methods = {v[1] for v in variants}
        assert "url_encode" in methods
        assert "comment_inject" in methods
        assert "plain" in methods
        # case_mix may collide with plain for short payloads — verify count
        assert len(variants) >= 5  # at least 5 of 6 possible (plain + 5 techniques)

    def test_skips_noop(self):
        variants = generate_variants("12345", ["case_mix"])
        assert len(variants) == 1
        assert variants[0][1] == "plain"

    def test_all_variants_unique(self):
        variants = generate_variants("' OR 1=1--", SQLI_TECHNIQUES)
        payloads = [v[0] for v in variants]
        assert len(payloads) == len(set(payloads))


class TestTechniqueLists:
    def test_sqli_techniques_count(self):
        assert len(SQLI_TECHNIQUES) == 5

    def test_xss_techniques_count(self):
        assert len(XSS_TECHNIQUES) == 5

    def test_all_techniques_in_func_dict(self):
        for name in SQLI_TECHNIQUES + XSS_TECHNIQUES:
            assert name in TECHNIQUE_FUNCS
