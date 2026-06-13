"""Tests for CSRF detection module."""
from scanner.modules.csrf import (
    _find_forms,
    _has_csrf_token,
    _CSRF_TOKEN_NAMES,
    CsrfModule,
)


class TestFindForms:
    def test_finds_post_form(self):
        html = '<form method="POST" action="/submit"><input name="msg"></form>'
        forms = _find_forms(html, "http://test.com")
        assert len(forms) == 1
        assert forms[0]["method"] == "POST"
        assert forms[0]["action"] == "http://test.com/submit"

    def test_ignores_get_forms(self):
        html = '<form method="GET" action="/search"><input name="q"></form>'
        forms = _find_forms(html, "http://test.com")
        assert len(forms) == 0

    def test_includes_all_inputs(self):
        html = (
            '<form method="POST" action="/signup">'
            '<input name="user"><input name="pass" type="password">'
            '<input type="submit"></form>'
        )
        forms = _find_forms(html, "http://test.com")
        assert len(forms[0]["inputs"]) == 2
        names = [i["name"] for i in forms[0]["inputs"]]
        assert "user" in names
        assert "pass" in names

    def test_resolves_relative_action(self):
        html = '<form method="POST" action="login"><input name="u"></form>'
        forms = _find_forms(html, "http://test.com/page")
        assert forms[0]["action"] == "http://test.com/login"


class TestHasCsrfToken:
    def test_csrf_name_detected(self):
        inputs = [
            {"name": "csrf_token", "type": "hidden", "value": "abc123"},
            {"name": "msg", "type": "text", "value": ""},
        ]
        assert _has_csrf_token(inputs) is True

    def test_authenticity_token_detected(self):
        inputs = [
            {"name": "authenticity_token", "type": "hidden",
             "value": "abcdef1234567890abcdef1234567890"},
        ]
        assert _has_csrf_token(inputs) is True

    def test_token_like_value_detected(self):
        inputs = [
            {"name": "sec", "type": "hidden",
             "value": "d41d8cd98f00b204e9800998ecf8427e"},
            {"name": "msg", "type": "text", "value": ""},
        ]
        assert _has_csrf_token(inputs) is True

    def test_no_token_detected(self):
        inputs = [
            {"name": "user", "type": "text", "value": ""},
            {"name": "pass", "type": "password", "value": ""},
        ]
        assert _has_csrf_token(inputs) is False

    def test_short_value_not_considered_token(self):
        inputs = [
            {"name": "mode", "type": "hidden", "value": "1"},
        ]
        assert _has_csrf_token(inputs) is False


class TestTokenNames:
    def test_includes_common_names(self):
        assert "csrf" in _CSRF_TOKEN_NAMES
        assert "authenticity_token" in _CSRF_TOKEN_NAMES
        assert "_token" in _CSRF_TOKEN_NAMES


class TestModule:
    def test_module_attributes(self):
        mod = CsrfModule()
        assert mod.name == "csrf"
        assert mod.requires_url is True
        assert "csrf" in mod.description.lower()
