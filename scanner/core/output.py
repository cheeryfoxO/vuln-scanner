"""Output formatting: colored terminal and JSON report."""
import json
import sys
from datetime import datetime

try:
    from colorama import init, Fore, Style
    init()
    HAS_COLOR = True
except ImportError:
    HAS_COLOR = False
    class _Dummy:
        def __getattr__(self, _):
            return ""
    Fore = _Dummy()
    Style = _Dummy()


class Output:
    """Handles all output: colored terminal + JSON report generation."""

    def __init__(self, verbose=False, use_color=True, json_path=None):
        self.verbose = verbose
        self.use_color = use_color and HAS_COLOR
        self.json_path = json_path
        self.results = {}

    def _color(self, code):
        if not self.use_color:
            return ""
        if 200 <= code < 300:
            return Fore.GREEN
        if 300 <= code < 400:
            return Fore.YELLOW
        if code in (401, 403):
            return Fore.RED
        if code == 404:
            return Fore.LIGHTBLACK_EX
        return ""

    def _reset(self):
        return Style.RESET_ALL if self.use_color else ""

    def log_finding(self, module_name, finding):
        """Record and display a finding."""
        self.results.setdefault(module_name, []).append(finding)

        if module_name == "subdomain":
            code = finding.get("status", 0)
            print(f"[{module_name}] {self._color(code)}{finding['host']}{self._reset()} - {code} - {finding.get('title', '')}")
        elif module_name == "dirscan":
            code = finding.get("status", 0)
            print(f"[{module_name}] {self._color(code)}{code}{self._reset()} - {finding['url']} ({finding.get('size', 0)}B)")
        elif module_name == "params":
            print(f"[{module_name}] {finding['type']}: {finding['source']}")

    def log_progress(self, message):
        """Print progress (verbose mode only)."""
        if self.verbose:
            print(f"[*] {message}", file=sys.stderr)

    def write_report(self, target, modules_used):
        """Build and optionally save JSON report."""
        report = {
            "scan_time": datetime.now().isoformat(),
            "target": target,
            "modules": modules_used,
            "findings": self.results,
        }
        if self.json_path:
            with open(self.json_path, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
        return report
