"""Tests for XSS detection module."""
from scanner.modules.xss import (
    _analyze_reflection,
    XSS_PAYLOADS,
    XssModule,
)


class TestAnalyzeReflection:
    """Test DOM context analysis for each payload type."""

    def test_html_tag_context(self):
        html = '<html><body><div><xss>test</xss></div></body></html>'
        context = _analyze_reflection(html, "<xss>test</xss>")
        assert context == "html_tag"

    def test_attribute_break_dq(self):
        html = '<input value=""><script>alert(1)</script>">'
        context = _analyze_reflection(html, '"><script>alert(1)</script>')
        assert context == "attribute_break"

    def test_attribute_break_sq(self):
        html = "<input value=''><script>alert(1)</script>'>"
        context = _analyze_reflection(html, "'><script>alert(1)</script>")
        assert context == "attribute_break"

    def test_script_tag_context(self):
        html = '</script><script>alert(1)</script>'
        context = _analyze_reflection(html, '</script><script>alert(1)</script>')
        assert context == "script_tag"

    def test_event_handler_context(self):
        html = '<input value="" onfocus="alert(1)">'
        context = _analyze_reflection(html, '" onfocus="alert(1)')
        assert context == "event_handler"

    def test_url_protocol_context(self):
        html = '<a href="javascript:alert(1)">link</a>'
        context = _analyze_reflection(html, 'javascript:alert(1)')
        assert context == "url_protocol"

    def test_svg_event_context(self):
        html = '<div><svg onload="alert(1)"></svg></div>'
        context = _analyze_reflection(html, '<svg onload="alert(1)">')
        assert context == "svg_event"

    def test_img_event_context(self):
        html = '<div><img src=x onerror=alert(1)></div>'
        context = _analyze_reflection(html, '<img src=x onerror=alert(1)>')
        assert context == "img_event"

    def test_not_reflected(self):
        html = '<html><body><div>hello</div></body></html>'
        context = _analyze_reflection(html, '<xss>test</xss>')
        assert context is None

    def test_reflected_unsure(self):
        html = '<div data-search="<xss>test</xss>">results here</div>'
        context = _analyze_reflection(html, '<xss>test</xss>')
        assert context == "reflected_unsure"

    def test_case_insensitive_event_handler(self):
        html = '<body ONLOAD="alert(1)">'
        context = _analyze_reflection(html, 'ONLOAD="alert(1)')
        assert context == "event_handler"


class TestPayloads:
    def test_payload_count(self):
        assert len(XSS_PAYLOADS) == 8

    def test_each_payload_has_required_fields(self):
        for p in XSS_PAYLOADS:
            assert "context" in p
            assert "payload" in p
            assert "description" in p


class TestModule:
    def test_module_attributes(self):
        mod = XssModule()
        assert mod.name == "xss"
        assert mod.requires_url is True
        assert "XSS" in mod.description
