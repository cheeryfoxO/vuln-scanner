"""Tests for command injection detection module."""
import time
from unittest.mock import Mock, patch
from scanner.modules.cmdi import (
    _check_cmd_error_patterns,
    _build_baseline_time,
    CMD_ERROR_PAYLOADS,
    CMD_SLEEP_PAYLOADS,
    CMD_ERROR_PATTERNS,
    CmdiModule,
)


class TestCmdErrorPatterns:
    def test_unix_id_output_detected(self):
        text = "uid=33(www-data) gid=33(www-data) groups=33(www-data)"
        result = _check_cmd_error_patterns(text)
        assert result is not None
        assert result["os"] == "Unix"

    def test_passwd_entry_detected(self):
        text = "/etc/passwd contents: root:x:0:0:root:/root:/bin/bash"
        result = _check_cmd_error_patterns(text)
        assert result is not None
        assert result["os"] == "Unix"

    def test_uname_output_detected(self):
        text = "Linux server01 5.15.0-91-generic #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023"
        result = _check_cmd_error_patterns(text)
        assert result is not None
        assert result["os"] == "Unix"

    def test_windows_dir_output_detected(self):
        text = " Volume in drive C has no label."
        result = _check_cmd_error_patterns(text)
        assert result is not None
        assert result["os"] == "Windows"

    def test_windows_whoami_detected(self):
        text = "nt authority\\system"
        result = _check_cmd_error_patterns(text)
        assert result is not None
        assert result["os"] == "Windows"

    def test_no_command_in_normal_page(self):
        text = "<html><body>Welcome to our site</body></html>"
        result = _check_cmd_error_patterns(text)
        assert result is None

    def test_case_insensitive_matching(self):
        text = "VOLUME IN DRIVE C IS SYSTEM"
        result = _check_cmd_error_patterns(text)
        assert result is not None
        assert result["os"] == "Windows"


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


class TestPayloads:
    def test_error_payloads_count(self):
        assert len(CMD_ERROR_PAYLOADS) == 12

    def test_error_payloads_have_separators(self):
        payloads_str = " ".join(CMD_ERROR_PAYLOADS)
        assert ";" in payloads_str or "|" in payloads_str

    def test_sleep_payloads_have_four(self):
        assert len(CMD_SLEEP_PAYLOADS) == 4

    def test_sleep_payloads_all_use_sleep_5(self):
        for sp in CMD_SLEEP_PAYLOADS:
            assert "sleep 5" in sp["payload"]

    def test_error_patterns_have_both_os(self):
        assert "Unix" in CMD_ERROR_PATTERNS
        assert "Windows" in CMD_ERROR_PATTERNS
        assert len(CMD_ERROR_PATTERNS["Unix"]) >= 3
        assert len(CMD_ERROR_PATTERNS["Windows"]) >= 3


class TestModule:
    def test_module_attributes(self):
        mod = CmdiModule()
        assert mod.name == "cmdi"
        assert mod.requires_url is True
        assert "command" in mod.description.lower()
