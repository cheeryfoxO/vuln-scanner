"""Tests for SSRF detection module."""
from scanner.modules.ssrf import (
    _check_ssrf_fingerprints,
    _SSRF_PAYLOADS,
    _SSRF_FINGERPRINTS,
    SsrfModule,
)


class TestCheckSsrfFingerprints:
    def test_detects_aws_metadata(self):
        text = '{"ami-id": "ami-12345", "instance-type": "t2.micro"}'
        result = _check_ssrf_fingerprints(text)
        assert result is not None
        assert result["service"] == "AWS Metadata"

    def test_detects_instance_id(self):
        text = "instance-id: i-0abcd1234efgh5678"
        result = _check_ssrf_fingerprints(text)
        assert result is not None
        assert result["service"] == "AWS Metadata"

    def test_detects_apache_default(self):
        text = "<title>Apache2 Ubuntu Default Page</title>"
        result = _check_ssrf_fingerprints(text)
        assert result is not None
        assert result["service"] == "Local Web Server"

    def test_detects_nginx_default(self):
        text = "<title>Welcome to nginx!</title>"
        result = _check_ssrf_fingerprints(text)
        assert result is not None

    def test_detects_phpinfo(self):
        text = "<title>phpinfo()</title>"
        result = _check_ssrf_fingerprints(text)
        assert result is not None

    def test_detects_ssh_banner(self):
        text = "SSH-2.0-OpenSSH_8.9p1 Ubuntu"
        result = _check_ssrf_fingerprints(text)
        assert result is not None
        assert result["service"] == "SSH Service"

    def test_no_match_on_normal_html(self):
        text = "<html><body><h1>Welcome to our site</h1></body></html>"
        result = _check_ssrf_fingerprints(text)
        assert result is None


class TestPayloads:
    def test_has_eight_payloads(self):
        assert len(_SSRF_PAYLOADS) == 8

    def test_includes_aws_metadata(self):
        assert any("169.254.169.254" in p["url"] for p in _SSRF_PAYLOADS)

    def test_includes_localhost(self):
        assert any("127.0.0.1" in p["url"] for p in _SSRF_PAYLOADS)

    def test_includes_ip_obfuscation(self):
        urls = [p["url"] for p in _SSRF_PAYLOADS]
        assert any("0x7f" in u for u in urls) or any("2130706433" in u for u in urls)


class TestFingerprints:
    def test_covers_three_categories(self):
        assert "AWS Metadata" in _SSRF_FINGERPRINTS
        assert "Local Web Server" in _SSRF_FINGERPRINTS
        assert "SSH Service" in _SSRF_FINGERPRINTS

    def test_each_category_has_patterns(self):
        for patterns in _SSRF_FINGERPRINTS.values():
            assert len(patterns) >= 1


class TestModule:
    def test_module_attributes(self):
        mod = SsrfModule()
        assert mod.name == "ssrf"
        assert mod.requires_url is True
        assert "ssrf" in mod.description.lower()
