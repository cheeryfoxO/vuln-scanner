"""Tests for SSTI detection module."""
from unittest.mock import Mock, patch
from scanner.modules.ssti import (
    _check_ssti_output,
    _check_object_leak,
    SstiModule,
)


class TestCheckSstiOutput:
    def test_detects_49_from_expression(self):
        text = "Result: 49 items found"
        result = _check_ssti_output(text, "49")
        assert result is True

    def test_surrounded_by_tags(self):
        text = "<div>49</div>"
        result = _check_ssti_output(text, "49")
        assert result is True

    def test_no_match_when_absent(self):
        text = "No results found"
        result = _check_ssti_output(text, "49")
        assert result is False

    def test_exact_word_boundary(self):
        text = "Result: 1490 items"
        result = _check_ssti_output(text, "49")
        assert result is False  # 49 is inside 1490

    def test_detects_repeated_string(self):
        text = "Value: 7777777"
        result = _check_ssti_output(text, "7777777")
        assert result is True


class TestCheckObjectLeak:
    def test_detects_config_object(self):
        text = "<Config {'DEBUG': True, 'SECRET_KEY': 'xxx'}>"
        result = _check_object_leak(text)
        assert result is True

    def test_detects_template_reference(self):
        text = "Error: <TemplateReference 'index.html'> not found"
        result = _check_object_leak(text)
        assert result is True

    def test_no_match_on_normal_page(self):
        text = "<html><body>Welcome</body></html>"
        result = _check_object_leak(text)
        assert result is False


class TestModule:
    def test_module_attributes(self):
        mod = SstiModule()
        assert mod.name == "ssti"
        assert mod.requires_url is True
        assert "template" in mod.description.lower() or "ssti" in mod.description.lower()
