"""Notification module -- send scan results via Telegram Bot or generic webhook."""
import json
from datetime import datetime

import requests


TELEGRAM_MAX_LENGTH = 4096


class Notifier:
    """Send scan completion notifications via various channels."""

    def __init__(self):
        self.channels = []

    def add_telegram(self, bot_token, chat_id):
        """Add Telegram notification channel."""
        self.channels.append({
            "type": "telegram",
            "bot_token": bot_token,
            "chat_id": chat_id,
        })

    def add_webhook(self, url, method="POST", headers=None):
        """Add generic webhook notification channel."""
        self.channels.append({
            "type": "webhook",
            "url": url,
            "method": method,
            "headers": headers or {},
        })

    @staticmethod
    def _build_payload(target, report, scan_time=None):
        """Build the JSON payload from a report dict.

        Expected report structure (from engine.run):
          {"target": ..., "scan_time": ..., "modules": [...], "findings": {...}}
        """
        findings_dict = report.get("findings", {})
        all_findings = []
        for mod_findings in findings_dict.values():
            all_findings.extend(mod_findings)

        severity_breakdown = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in all_findings:
            sev = f.get("severity", "info")
            if sev in severity_breakdown:
                severity_breakdown[sev] += 1

        # Top 5 critical/high findings
        top = [f for f in all_findings if f.get("severity") in ("critical", "high")]
        top.sort(key=lambda f: {"critical": 0, "high": 1}.get(f.get("severity"), 99))
        top_findings = []
        for f in top[:5]:
            top_findings.append({
                "type": f.get("type", "unknown"),
                "severity": f.get("severity", "info"),
                "desc": f.get("desc", f.get("evidence", "")),
            })

        return {
            "target": target,
            "scan_time": scan_time or datetime.now().isoformat(),
            "total_findings": len(all_findings),
            "severity_breakdown": severity_breakdown,
            "modules_ran": len(report.get("modules", [])),
            "top_findings": top_findings,
        }

    @staticmethod
    def _format_telegram_message(payload):
        """Format payload as a readable text message for Telegram."""
        sb = payload["severity_breakdown"]
        lines = [
            f"Scan complete: {payload['target']}",
            f"Time: {payload['scan_time']}",
            f"Total findings: {payload['total_findings']} ({payload['modules_ran']} modules)",
            "",
            "Severity breakdown:",
            f"  Critical: {sb['critical']}",
            f"  High:     {sb['high']}",
            f"  Medium:   {sb['medium']}",
            f"  Low:      {sb['low']}",
            f"  Info:     {sb['info']}",
        ]
        if payload["top_findings"]:
            lines.append("")
            lines.append("Top findings:")
            for i, f in enumerate(payload["top_findings"], 1):
                sev = f["severity"].upper()
                desc = f.get("desc", "")
                if desc:
                    desc = desc[:120]
                lines.append(f"  {i}. [{sev}] {f['type']}: {desc}")

        message = "\n".join(lines)
        if len(message) > TELEGRAM_MAX_LENGTH:
            message = message[:TELEGRAM_MAX_LENGTH - 4] + "\n..."
        return message

    def _send_telegram(self, channel, payload):
        """Send notification to a Telegram channel. Returns (success, message)."""
        text = self._format_telegram_message(payload)
        url = f"https://api.telegram.org/bot{channel['bot_token']}/sendMessage"
        try:
            resp = requests.post(
                url,
                json={"chat_id": channel["chat_id"], "text": text},
                timeout=15,
            )
            resp.raise_for_status()
            return True, "ok"
        except requests.RequestException as e:
            return False, str(e)

    def _send_webhook(self, channel, payload):
        """Send notification to a webhook. Returns (success, message)."""
        try:
            resp = requests.request(
                channel["method"],
                channel["url"],
                json=payload,
                headers=channel.get("headers", {}),
                timeout=15,
            )
            resp.raise_for_status()
            return True, f"HTTP {resp.status_code}"
        except requests.RequestException as e:
            return False, str(e)

    def send(self, target, report, scan_time=None):
        """Send notification to all registered channels.

        Returns list of (channel_type, success, message).
        Failures on one channel do not prevent other channels from sending.
        """
        payload = self._build_payload(target, report, scan_time)
        results = []
        for ch in self.channels:
            if ch["type"] == "telegram":
                success, msg = self._send_telegram(ch, payload)
            elif ch["type"] == "webhook":
                success, msg = self._send_webhook(ch, payload)
            else:
                success, msg = False, f"unknown channel type: {ch['type']}"
            results.append((ch["type"], success, msg))
        return results
