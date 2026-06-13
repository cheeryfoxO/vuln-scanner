"""Tests for stored XSS detection module."""
from scanner.modules.stored_xss import (
    _make_stored_payload,
    _extract_post_forms,
    _extract_links,
    _build_form_data,
    StoredXssModule,
)


class TestMakeStoredPayload:
    def test_returns_payload_and_uid(self):
        payload, uid = _make_stored_payload()
        assert uid in payload
        assert payload.startswith("<xss_store_")
        assert len(uid) == 8

    def test_unique_per_call(self):
        uids = [_make_stored_payload()[1] for _ in range(10)]
        assert len(set(uids)) == 10


class TestExtractPostForms:
    def test_extracts_post_form(self):
        html = '<form method="POST" action="/submit"><input name="msg"></form>'
        forms = _extract_post_forms(html, "http://test.com")
        assert len(forms) == 1
        assert forms[0]["action"] == "http://test.com/submit"
        assert forms[0]["inputs"][0]["name"] == "msg"

    def test_ignores_get_forms(self):
        html = '<form method="GET" action="/search"><input name="q"></form>'
        forms = _extract_post_forms(html, "http://test.com")
        assert len(forms) == 0

    def test_resolves_relative_action(self):
        html = '<form method="post" action="comment"><input name="text"></form>'
        forms = _extract_post_forms(html, "http://test.com/page")
        assert forms[0]["action"] == "http://test.com/comment"

    def test_caps_at_five(self):
        html = '<form method="POST"><input name="x"></form>' * 10
        forms = _extract_post_forms(html, "http://test.com")
        assert len(forms) == 5


class TestExtractLinks:
    def test_extracts_href_links(self):
        html = '<a href="/page1">1</a><a href="/page2">2</a>'
        links = _extract_links(html, "http://test.com")
        assert len(links) >= 2

    def test_skips_anchor_and_javascript(self):
        html = '<a href="#">top</a><a href="javascript:void(0)">x</a>'
        links = _extract_links(html, "http://test.com")
        assert len(links) == 0

    def test_resolves_relative_urls(self):
        html = '<a href="/about">About</a>'
        links = _extract_links(html, "http://test.com")
        assert "http://test.com/about" in links


class TestBuildFormData:
    def test_payload_goes_to_first_text_input(self):
        inputs = [
            {"name": "email", "type": "email"},
            {"name": "msg", "type": "text"},
        ]
        data, used = _build_form_data(inputs, "<xss>")
        assert data["email"] == "<xss>"
        assert data["msg"] == "test"
        assert used is True

    def test_other_inputs_get_default(self):
        inputs = [
            {"name": "name", "type": "text"},
            {"name": "hidden", "type": "hidden"},
            {"name": "submit", "type": "submit"},
        ]
        data, used = _build_form_data(inputs, "<xss>")
        assert data["name"] == "<xss>"
        assert data["hidden"] == "test"
        assert data["submit"] == "test"

    def test_no_text_input_returns_unused(self):
        inputs = [{"name": "hidden", "type": "hidden"}]
        data, used = _build_form_data(inputs, "<xss>")
        assert used is False


class TestModule:
    def test_module_attributes(self):
        mod = StoredXssModule()
        assert mod.name == "stored_xss"
        assert mod.requires_url is True
        assert "stored" in mod.description.lower()
