"""Tests for shared HTML/URL utility functions."""
from scanner.core.html_utils import _FormParser, _extract_params, _make_test_url


class TestFormParser:
    def test_get_form_inputs(self):
        html = '<form method="GET"><input name="q"></form>'
        parser = _FormParser()
        parser.feed(html)
        assert "q" in parser.input_names
        assert len(parser.post_params) == 0

    def test_post_form_inputs(self):
        html = '<form method="POST"><input name="token"></form>'
        parser = _FormParser()
        parser.feed(html)
        assert "token" in parser.post_params
        assert len(parser.input_names) == 0

    def test_default_form_method_is_get(self):
        html = '<form><input name="search"></form>'
        parser = _FormParser()
        parser.feed(html)
        assert "search" in parser.input_names
        assert len(parser.post_params) == 0

    def test_mixed_get_post_forms(self):
        html = '''
            <form method="GET"><input name="q"></form>
            <form method="POST"><input name="password"></form>
        '''
        parser = _FormParser()
        parser.feed(html)
        assert "q" in parser.input_names
        assert "password" in parser.post_params


class TestExtractParams:
    def test_url_params_return_get_method(self):
        params = _extract_params("http://test.com?q=1&page=2", "<html></html>")
        methods = {p["name"]: p["method"] for p in params}
        assert methods["q"] == "GET"
        assert methods["page"] == "GET"

    def test_post_form_params_return_post_method(self):
        html = '<form method="POST"><input name="token"><input name="user"></form>'
        params = _extract_params("http://test.com", html)
        methods = {p["name"]: p["method"] for p in params}
        assert methods["token"] == "POST"
        assert methods["user"] == "POST"

    def test_post_overrides_get_for_same_name(self):
        html = '<form method="POST"><input name="q"></form>'
        params = _extract_params("http://test.com?q=1", html)
        result = {p["name"]: p["method"] for p in params}
        assert result["q"] == "POST"

    def test_returns_list_of_dicts(self):
        params = _extract_params("http://test.com?q=1", "<html></html>")
        assert isinstance(params, list)
        assert len(params) > 0
        assert "name" in params[0]
        assert "method" in params[0]

    def test_empty_page_no_params(self):
        params = _extract_params("http://test.com", "<html></html>")
        assert params == []


class TestMakeTestUrl:
    def test_replaces_get_param(self):
        result = _make_test_url("http://example.com/page?id=1", "id", "' OR 1=1--")
        assert "id=%27+OR+1%3D1--" in result

    def test_adds_param_to_url_without_params(self):
        result = _make_test_url("http://example.com/page", "q", "test")
        assert result == "http://example.com/page?q=test"
