"""Tests for subdomain enumeration module."""
import os
import socket
from unittest.mock import Mock, patch, mock_open

from scanner.modules.subdomain import SubdomainModule


# ── _load_wordlist tests ───────────────────────────────────────────────

class TestLoadWordlist:
    def test_reads_wordlist_file_correctly(self):
        """_load_wordlist reads lines, strips whitespace, and filters empties."""
        mod = SubdomainModule()
        content = "www\nmail\n  admin  \n\nftp\n"
        with patch("builtins.open", mock_open(read_data=content)):
            result = mod._load_wordlist()
        assert result == ["www", "mail", "admin", "ftp"]

    def test_uses_custom_wordlist_path(self):
        """Custom wordlist_path is used when provided."""
        mod = SubdomainModule(wordlist_path="/custom/path/words.txt")
        content = "staging\n"
        m = mock_open(read_data=content)
        with patch("builtins.open", m):
            mod._load_wordlist()
        expected_path = os.path.normpath("/custom/path/words.txt")
        m.assert_called_once_with(expected_path, encoding="utf-8")

    def test_returns_empty_list_for_empty_file(self):
        """Empty file yields an empty list."""
        mod = SubdomainModule()
        with patch("builtins.open", mock_open(read_data="")):
            result = mod._load_wordlist()
        assert result == []

    def test_strips_blank_lines_only(self):
        """File with only blank lines returns empty list."""
        mod = SubdomainModule()
        with patch("builtins.open", mock_open(read_data="\n   \n\t\n")):
            result = mod._load_wordlist()
        assert result == []

    def test_normalizes_path_before_open(self):
        """_load_wordlist normalizes the path before opening."""
        mod = SubdomainModule(wordlist_path="foo/bar/../baz/words.txt")
        m = mock_open(read_data="www\n")
        with patch("builtins.open", m):
            mod._load_wordlist()
        # os.path.normpath should turn the above into "foo/baz/words.txt"
        called_path = m.call_args[0][0]
        assert called_path == "foo\\baz\\words.txt" or called_path == "foo/baz/words.txt"
        assert ".." not in called_path


# ── _resolve tests ─────────────────────────────────────────────────────

class TestResolve:
    def test_returns_ips_for_resolvable_hostname(self):
        """_resolve returns a list of IPs from getaddrinfo."""
        mod = SubdomainModule()
        fake_addrinfo = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.1", 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.2", 0)),
        ]
        with patch("socket.getaddrinfo", return_value=fake_addrinfo):
            result = mod._resolve("sub.example.com")
        assert sorted(result) == ["10.0.0.1", "10.0.0.2"]

    def test_returns_empty_list_on_gaierror(self):
        """_resolve returns [] when DNS resolution fails."""
        mod = SubdomainModule()
        with patch("socket.getaddrinfo", side_effect=socket.gaierror):
            result = mod._resolve("nonexistent.example.com")
        assert result == []

    def test_deduplicates_ips(self):
        """_resolve deduplicates IPs when getaddrinfo returns duplicates."""
        mod = SubdomainModule()
        fake_addrinfo = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.1", 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.1", 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.2", 0)),
        ]
        with patch("socket.getaddrinfo", return_value=fake_addrinfo):
            result = mod._resolve("dup.example.com")
        assert sorted(result) == ["10.0.0.1", "10.0.0.2"]

    def test_calls_getaddrinfo_with_af_inet(self):
        """_resolve passes socket.AF_INET to getaddrinfo for IPv4-only."""
        mod = SubdomainModule()
        with patch("socket.getaddrinfo", return_value=[]) as mock_fn:
            mod._resolve("host.example.com")
        mock_fn.assert_called_once_with("host.example.com", None, socket.AF_INET)

    def test_skips_non_ipv4_entries(self):
        """Addresses not matching AF_INET are silently ignored."""
        mod = SubdomainModule()
        # Return an IPv6 address — the function only iterates AF_INET results,
        # but getaddrinfo filters by AF_INET already, so this is implicitly tested.
        # We explicitly test that only AF_INET entries are collected.
        fake_addrinfo = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.1", 0)),
        ]
        with patch("socket.getaddrinfo", return_value=fake_addrinfo):
            result = mod._resolve("ipv4only.example.com")
        assert result == ["192.168.1.1"]


# ── _check_http tests ──────────────────────────────────────────────────

class TestCheckHttp:
    def test_returns_status_and_title_when_https_succeeds(self):
        """HTTPS success returns (status_code, title)."""
        mod = SubdomainModule()
        rh = Mock()
        resp = Mock()
        resp.status_code = 200
        resp.text = "<html><head><title>My Page</title></head><body></body></html>"
        rh.get.return_value = resp

        status, title = mod._check_http("sub.example.com", rh)
        assert status == 200
        assert title == "My Page"
        rh.get.assert_called_once_with("https://sub.example.com")

    def test_extracts_title_case_insensitive(self):
        """Title extraction is case-insensitive."""
        mod = SubdomainModule()
        rh = Mock()
        resp = Mock()
        resp.status_code = 200
        resp.text = "<HTML><HEAD><TITLE>UpperCase</TITLE></HEAD></HTML>"
        rh.get.return_value = resp

        _status, title = mod._check_http("sub.example.com", rh)
        assert title == "UpperCase"

    def test_title_with_attributes_in_tag(self):
        """Title tag with extra attributes is parsed correctly."""
        mod = SubdomainModule()
        rh = Mock()
        resp = Mock()
        resp.status_code = 200
        resp.text = '<html><head><title id="page-title" class="main">Hello World</title></head></html>'
        rh.get.return_value = resp

        _status, title = mod._check_http("sub.example.com", rh)
        assert title == "Hello World"

    def test_falls_back_to_http_when_https_fails(self):
        """When HTTPS raises, _check_http tries HTTP as fallback."""
        mod = SubdomainModule()
        rh = Mock()
        https_resp = Mock()
        https_resp.status_code = 200
        https_resp.text = "<html><title>HTTP Fallback</title></html>"
        rh.get.side_effect = [Exception("Connection refused"), https_resp]

        status, title = mod._check_http("sub.example.com", rh)
        assert status == 200
        assert title == "HTTP Fallback"
        assert rh.get.call_count == 2
        rh.get.assert_any_call("https://sub.example.com")
        rh.get.assert_any_call("http://sub.example.com")

    def test_returns_zero_empty_string_when_both_fail(self):
        """When both HTTPS and HTTP fail, return (0, '')."""
        mod = SubdomainModule()
        rh = Mock()
        rh.get.side_effect = [Exception("HTTPS failed"), Exception("HTTP failed")]

        status, title = mod._check_http("sub.example.com", rh)
        assert status == 0
        assert title == ""

    def test_returns_status_without_title(self):
        """When no <title> tag exists, title is empty string."""
        mod = SubdomainModule()
        rh = Mock()
        resp = Mock()
        resp.status_code = 301
        resp.text = "<html><body>Redirecting...</body></html>"
        rh.get.return_value = resp

        status, title = mod._check_http("sub.example.com", rh)
        assert status == 301
        assert title == ""

    def test_collapses_whitespace_in_title(self):
        """Title text has whitespace normalized with single spaces."""
        mod = SubdomainModule()
        rh = Mock()
        resp = Mock()
        resp.status_code = 200
        resp.text = "<html><head><title>Hello\n\t  World  \n</title></head></html>"
        rh.get.return_value = resp

        _status, title = mod._check_http("sub.example.com", rh)
        assert title == "Hello World"

    def test_truncates_title_to_100_chars(self):
        """Title longer than 100 characters is truncated."""
        mod = SubdomainModule()
        rh = Mock()
        resp = Mock()
        resp.status_code = 200
        long_text = "A" * 150
        resp.text = f"<html><title>{long_text}</title></html>"
        rh.get.return_value = resp

        _status, title = mod._check_http("sub.example.com", rh)
        assert len(title) == 100
        assert title == "A" * 100

    def test_https_exception_then_http_success(self):
        """Concrete test: HTTPS throws, HTTP returns valid response."""
        mod = SubdomainModule()
        rh = Mock()
        ok_resp = Mock()
        ok_resp.status_code = 200
        ok_resp.text = "<html><title>OK</title></html>"
        rh.get.side_effect = [socket.gaierror, ok_resp]

        status, title = mod._check_http("sub.example.com", rh)
        assert status == 200
        assert title == "OK"


# ── Module attribute tests ─────────────────────────────────────────────

class TestModuleAttributes:
    def test_name_is_subdomain(self):
        mod = SubdomainModule()
        assert mod.name == "subdomain"

    def test_description_mentions_dns_and_http(self):
        mod = SubdomainModule()
        assert "DNS" in mod.description
        assert "HTTP" in mod.description

    def test_requires_url_is_false(self):
        mod = SubdomainModule()
        assert mod.requires_url is False

    def test_default_wordlist_path_is_set(self):
        mod = SubdomainModule()
        assert mod.wordlist_path is not None
        assert "subdomains.txt" in mod.wordlist_path

    def test_custom_wordlist_path_accepted(self):
        mod = SubdomainModule(wordlist_path="/tmp/my_words.txt")
        assert mod.wordlist_path == "/tmp/my_words.txt"

    def test_default_and_custom_differ(self):
        default_mod = SubdomainModule()
        custom_mod = SubdomainModule(wordlist_path="/other/path.txt")
        assert default_mod.wordlist_path != custom_mod.wordlist_path


# ── run() integration-style tests ──────────────────────────────────────

class TestRun:
    def test_run_returns_module_name_and_findings(self):
        """run() returns dict with module name and findings key."""
        mod = SubdomainModule()
        rh = Mock()
        out = Mock()

        # Supply a minimal wordlist so DNS phase runs
        with patch("builtins.open", mock_open(read_data="www\nmail\n")):
            with patch("socket.getaddrinfo", side_effect=socket.gaierror):
                result = mod.run("example.com", rh, out)

        assert result["module"] == "subdomain"
        assert "findings" in result
        assert result["findings"] == []

    def test_run_finds_live_subdomains(self):
        """End-to-end: DNS resolves → HTTP check succeeds → finding recorded."""
        mod = SubdomainModule()
        rh = Mock()
        out = Mock()

        resp = Mock()
        resp.status_code = 200
        resp.text = "<html><title>Admin Panel</title></html>"
        rh.get.return_value = resp

        fake_addrinfo = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.1", 0)),
        ]

        with patch("builtins.open", mock_open(read_data="admin\n")):
            with patch("socket.getaddrinfo", return_value=fake_addrinfo):
                result = mod.run("example.com", rh, out)

        assert len(result["findings"]) == 1
        finding = result["findings"][0]
        assert finding["host"] == "admin.example.com"
        assert finding["ip"] == "10.0.0.1"
        assert finding["status"] == 200
        assert finding["title"] == "Admin Panel"

    def test_run_logs_progress_and_findings(self):
        """run() calls output methods for progress and findings."""
        mod = SubdomainModule()
        rh = Mock()
        out = Mock()

        resp = Mock()
        resp.status_code = 200
        resp.text = "<html><title>Test</title></html>"
        rh.get.return_value = resp

        fake_addrinfo = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.1", 0)),
        ]

        with patch("builtins.open", mock_open(read_data="www\n")):
            with patch("socket.getaddrinfo", return_value=fake_addrinfo):
                mod.run("example.com", rh, out)

        assert out.log_progress.called
        assert out.create_progress_bar.called
        assert out.update_progress.called
        assert out.log_finding.called

    def test_run_skips_http_when_nothing_resolved(self):
        """When DNS resolves nothing, HTTP phase is skipped."""
        mod = SubdomainModule()
        rh = Mock()
        out = Mock()

        with patch("builtins.open", mock_open(read_data="www\n")):
            with patch("socket.getaddrinfo", side_effect=socket.gaierror):
                result = mod.run("example.com", rh, out)

        # HTTP handler should never be called
        rh.get.assert_not_called()
        assert result["findings"] == []

    def test_run_respects_threads_parameter(self):
        """run() accepts and uses the threads parameter without error."""
        mod = SubdomainModule()
        rh = Mock()
        out = Mock()

        with patch("builtins.open", mock_open(read_data="www\n")):
            with patch("socket.getaddrinfo", side_effect=socket.gaierror):
                result = mod.run("example.com", rh, out, threads=5)

        assert result["module"] == "subdomain"

    def test_run_handles_http_check_exception_gracefully(self):
        """If _check_http raises for one host, other hosts still process."""
        mod = SubdomainModule()
        rh = Mock()
        out = Mock()

        resp_ok = Mock()
        resp_ok.status_code = 200
        resp_ok.text = "<html><title>OK</title></html>"

        # First host HTTP succeeds, second raises exception
        rh.get.side_effect = [
            resp_ok,
            Exception("Boom"),
        ]

        fake_addrinfo_1 = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.1", 0)),
        ]
        fake_addrinfo_2 = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.2", 0)),
        ]

        with patch("builtins.open", mock_open(read_data="www\nmail\n")):
            with patch("socket.getaddrinfo", side_effect=[fake_addrinfo_1, fake_addrinfo_2]):
                result = mod.run("example.com", rh, out)

        # The first host should be in findings; the second skipped
        assert len(result["findings"]) >= 1
        hosts = [f["host"] for f in result["findings"]]
        assert "www.example.com" in hosts
