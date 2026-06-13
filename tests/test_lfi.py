"""Tests for LFI detection module."""
import re
from scanner.modules.lfi import (
    _check_lfi_patterns,
    _is_base64,
    _decode_if_base64,
    _LFI_PAYLOADS,
    _LFI_PATTERNS,
    LfiModule,
)


class TestCheckLfiPatterns:
    def test_detects_passwd_content(self):
        text = "root:x:0:0:root:/root:/bin/bash\n daemon:x:1:1:daemon:/usr/sbin"
        result = _check_lfi_patterns(text)
        assert result is not None
        assert result["file"] == "/etc/passwd"

    def test_detects_win_ini_content(self):
        text = "[fonts]\n[extensions]\n[files]"
        result = _check_lfi_patterns(text)
        assert result is not None
        assert result["file"] == "win.ini"

    def test_detects_php_source_in_plain_text(self):
        text = '<?php echo "hello"; ?>'
        result = _check_lfi_patterns(text)
        assert result is not None
        assert result["file"] == "index.php"

    def test_no_match_on_normal_html(self):
        text = "<html><body><h1>Welcome</h1></body></html>"
        result = _check_lfi_patterns(text)
        assert result is None


class TestBase64Detection:
    def test_is_base64_for_valid_b64(self):
        assert _is_base64("PD9waHAgZWNobyAiaGVsbG8iOyA/Pg==") is True

    def test_is_base64_rejects_plain_text(self):
        assert _is_base64("hello world") is False

    def test_decode_if_base64_decodes_valid(self):
        result = _decode_if_base64("PD9waHAgZWNobyAiaGVsbG8iOyA/Pg==")
        assert "<?php" in result

    def test_decode_if_base64_returns_original_for_non_b64(self):
        text = "<html>normal content</html>"
        result = _decode_if_base64(text)
        assert result == text


class TestPayloads:
    def test_has_eight_payloads(self):
        assert len(_LFI_PAYLOADS) == 8

    def test_payloads_cover_both_os(self):
        os_set = {p["os"] for p in _LFI_PAYLOADS}
        assert "Unix" in os_set
        assert "Windows" in os_set

    def test_payloads_have_required_fields(self):
        for p in _LFI_PAYLOADS:
            assert "path" in p
            assert "os" in p
            assert "file" in p


class TestPatterns:
    def test_patterns_cover_three_file_types(self):
        assert "/etc/passwd" in _LFI_PATTERNS
        assert "win.ini" in _LFI_PATTERNS
        assert "index.php" in _LFI_PATTERNS

    def test_each_file_has_multiple_patterns(self):
        for patterns in _LFI_PATTERNS.values():
            assert len(patterns) >= 2


class TestModule:
    def test_module_attributes(self):
        mod = LfiModule()
        assert mod.name == "lfi"
        assert mod.requires_url is True
        assert "lfi" in mod.description.lower() or "file" in mod.description.lower()
