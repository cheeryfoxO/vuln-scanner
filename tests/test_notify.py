"""Tests for the Notifier notification module."""
from unittest.mock import patch, MagicMock

from scanner.core.notify import Notifier, TELEGRAM_MAX_LENGTH


# ── Sample report fixture ──────────────────────────────────────────────

def _make_report():
    return {
        "target": "example.com",
        "scan_time": "2026-06-25T12:00:00",
        "modules": ["fingerprint", "headers", "cors", "sqli", "xss"],
        "findings": {
            "cors": [
                {"type": "cors_misconfig", "severity": "critical", "url": "https://example.com/api", "evidence": "Origin reflected"},
                {"type": "cors_misconfig", "severity": "high", "url": "https://example.com/other", "evidence": "Loose ACAO"},
            ],
            "sqli": [
                {"type": "error_based", "severity": "critical", "parameter": "id", "evidence": "SQL error", "desc": "Error-based SQLi in id param"},
            ],
            "xss": [
                {"type": "reflected", "severity": "medium", "parameter": "q", "evidence": "<script>alert(1)"},
                {"type": "reflected", "severity": "low", "parameter": "p", "evidence": "onerror="},
            ],
            "headers": [
                {"type": "missing_hsts", "severity": "high", "header": "Strict-Transport-Security", "status": "missing"},
                {"type": "missing_xfo", "severity": "info", "header": "X-Frame-Options", "status": "missing"},
            ],
        },
    }


# ── Tests ──────────────────────────────────────────────────────────────

class TestNotifierInit:
    def test_empty_channels_on_init(self):
        n = Notifier()
        assert n.channels == []


class TestAddTelegram:
    def test_registers_telegram_channel(self):
        n = Notifier()
        n.add_telegram("mytoken", "123456")
        assert len(n.channels) == 1
        assert n.channels[0]["type"] == "telegram"
        assert n.channels[0]["bot_token"] == "mytoken"
        assert n.channels[0]["chat_id"] == "123456"


class TestAddWebhook:
    def test_registers_webhook_channel_with_defaults(self):
        n = Notifier()
        n.add_webhook("https://hooks.example.com/slack")
        assert len(n.channels) == 1
        assert n.channels[0]["type"] == "webhook"
        assert n.channels[0]["url"] == "https://hooks.example.com/slack"
        assert n.channels[0]["method"] == "POST"
        assert n.channels[0]["headers"] == {}

    def test_registers_webhook_channel_with_custom_method_and_headers(self):
        n = Notifier()
        n.add_webhook("https://hooks.example.com/custom", method="PUT", headers={"X-Api-Key": "abc"})
        ch = n.channels[0]
        assert ch["method"] == "PUT"
        assert ch["headers"] == {"X-Api-Key": "abc"}


class TestBuildPayload:
    def test_severity_breakdown(self):
        report = _make_report()
        payload = Notifier._build_payload("example.com", report, "2026-06-25T12:00:00")
        sb = payload["severity_breakdown"]
        assert sb["critical"] == 2
        assert sb["high"] == 2
        assert sb["medium"] == 1
        assert sb["low"] == 1
        assert sb["info"] == 1

    def test_total_findings_and_modules_ran(self):
        report = _make_report()
        payload = Notifier._build_payload("example.com", report)
        assert payload["total_findings"] == 7
        assert payload["modules_ran"] == 5

    def test_top_findings_critical_and_high_only(self):
        report = _make_report()
        payload = Notifier._build_payload("example.com", report)
        top = payload["top_findings"]
        severities = [f["severity"] for f in top]
        for s in severities:
            assert s in ("critical", "high")
        assert len(top) <= 5

    def test_empty_findings(self):
        report = {"target": "x.com", "scan_time": "", "modules": [], "findings": {}}
        payload = Notifier._build_payload("x.com", report)
        assert payload["total_findings"] == 0
        assert payload["severity_breakdown"]["critical"] == 0
        assert payload["top_findings"] == []

    def test_scan_time_defaults_to_now(self):
        report = _make_report()
        payload = Notifier._build_payload("example.com", report)
        assert "T" in payload["scan_time"]


class TestTelegramFormatting:
    def test_includes_key_info(self):
        payload = Notifier._build_payload("example.com", _make_report(), "2026-06-25T12:00:00")
        text = Notifier._format_telegram_message(payload)
        assert "example.com" in text
        assert "2026-06-25T12:00:00" in text
        assert "Total findings: 7" in text
        assert "Critical: 2" in text
        assert "High:     2" in text

    def test_truncates_long_message(self):
        payload = Notifier._build_payload("example.com", _make_report())
        # Artificially blow up payload to exceed 4096
        long_payload = dict(payload)
        long_payload["top_findings"] = [
            {"type": "test", "severity": "critical", "desc": "X" * 150}
            for _ in range(100)
        ]
        text = Notifier._format_telegram_message(long_payload)
        assert len(text) <= TELEGRAM_MAX_LENGTH


class TestSend:
    @patch("scanner.core.notify.requests.post")
    def test_sends_to_telegram(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_post.return_value = mock_resp

        n = Notifier()
        n.add_telegram("token", "chat")
        results = n.send("example.com", _make_report())

        assert len(results) == 1
        assert results[0] == ("telegram", True, "ok")
        mock_post.assert_called_once()
        call_args = mock_post.call_args
        assert call_args[1]["json"]["chat_id"] == "chat"

    @patch("scanner.core.notify.requests.request")
    def test_sends_to_webhook(self, mock_request):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_request.return_value = mock_resp

        n = Notifier()
        n.add_webhook("https://hooks.example.com")
        results = n.send("example.com", _make_report(), scan_time="2026-06-25T12:00:00")

        assert len(results) == 1
        assert results[0] == ("webhook", True, "HTTP 200")
        mock_request.assert_called_once()
        call_args, call_kwargs = mock_request.call_args
        assert call_args[0] == "POST"
        assert call_args[1] == "https://hooks.example.com"
        assert call_kwargs["headers"] == {}
        assert call_kwargs["timeout"] == 15
        assert call_kwargs["json"]["target"] == "example.com"
        assert call_kwargs["json"]["total_findings"] == 7

    @patch("scanner.core.notify.requests.post")
    def test_telegram_failure_does_not_block_webhook(self, mock_post):
        mock_post.side_effect = __import__("requests").ConnectionError("network down")

        n = Notifier()
        n.add_telegram("token", "chat")
        n.add_webhook("https://hooks.example.com")

        with patch("scanner.core.notify.requests.request") as mock_request:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_request.return_value = mock_resp

            results = n.send("example.com", _make_report())

        assert len(results) == 2
        assert results[0] == ("telegram", False, "network down")
        assert results[1] == ("webhook", True, "HTTP 200")

    def test_empty_channels_returns_empty_list(self):
        n = Notifier()
        results = n.send("example.com", _make_report())
        assert results == []


class TestWebhookPayloadStructure:
    def test_payload_keys(self):
        payload = Notifier._build_payload("example.com", _make_report(), "2026-06-25T12:00:00")
        expected_keys = {"target", "scan_time", "total_findings", "severity_breakdown", "modules_ran", "top_findings"}
        assert set(payload.keys()) == expected_keys

    def test_webhook_payload_is_json_serializable(self):
        payload = Notifier._build_payload("example.com", _make_report())
        import json
        json.dumps(payload)  # should not raise
