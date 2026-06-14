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


class _DummyBar:
    def update(self, n=1):
        pass
    def close(self):
        pass


class Output:
    """Handles all output: colored terminal + JSON report generation."""

    def __init__(self, verbose=False, use_color=True, json_path=None):
        self.verbose = verbose
        self.use_color = use_color and HAS_COLOR
        self.json_path = json_path
        self.results = {}
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except Exception:
            pass

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
            severity = finding.get("severity")
            if severity:
                sev_color = Fore.RED if severity == "critical" else Fore.YELLOW
                print(f"[{module_name}] {self._color(code)}{code}{self._reset()} - "
                      f"{finding['url']} {sev_color}[{severity}]{self._reset()} — "
                      f"{finding.get('sensitive', '')}")
            else:
                print(f"[{module_name}] {self._color(code)}{code}{self._reset()} - "
                      f"{finding['url']} ({finding.get('size', 0)}B)")
        elif module_name == "params":
            print(f"[{module_name}] {finding['type']}: {finding['source']}")
        elif module_name == "xss":
            ctx = finding.get("context", "unknown")
            param = finding.get("parameter", "?")
            enc = finding.get("encoding", "")
            enc_str = f" [{enc}]" if enc and enc != "plain" else ""
            print(f"[{module_name}] {ctx}: {param}{enc_str} -- {finding.get('url', '')}")
        elif module_name == "sqli":
            db = finding.get("database", "?")
            param = finding.get("parameter", "?")
            enc = finding.get("encoding", "")
            enc_str = f" [{enc}]" if enc and enc != "plain" else ""
            print(f"[{module_name}] {finding['type']} ({db}): {param}{enc_str} -- {finding.get('url', '')}")
        elif module_name == "dom_xss":
            print(f"[{module_name}] {finding['sink']} ← {finding['source']}"
                  f" — {finding['file']}:{finding['line']}")
        elif module_name == "stored_xss":
            print(f"[{module_name}] {finding['payload_uid']}: "
                  f"{finding['injected_field']} → {finding['found_on']}")
        elif module_name == "cmdi":
            os_name = finding.get("os", "?")
            param = finding.get("parameter", "?")
            enc = finding.get("encoding", "")
            enc_str = f" [{enc}]" if enc and enc != "plain" else ""
            if finding.get("type") == "time_based":
                print(f"[{module_name}] {finding['type']} ({os_name}): {param}{enc_str} "
                      f"-- {finding.get('response_ms', '?')}ms -- {finding.get('url', '')}")
            else:
                print(f"[{module_name}] {finding['type']} ({os_name}): {param}{enc_str} "
                      f"-- {finding.get('url', '')}")
        elif module_name == "lfi":
            os_name = finding.get("os", "?")
            file_name = finding.get("file", "?")
            param = finding.get("parameter", "?")
            print(f"[{module_name}] {finding['type']} ({os_name}): {param} "
                  f"— {file_name} — {finding.get('url', '')}")
        elif module_name == "redirect":
            code = finding.get("status_code", 0)
            param = finding.get("parameter", "?")
            location = finding.get("location", "?")
            print(f"[{module_name}] {code} → {location} "
                  f"— param: {param}")
        elif module_name == "ssrf":
            service = finding.get("service", "?")
            ssrf_target = finding.get("ssrf_target", "?")
            param = finding.get("parameter", "?")
            print(f"[{module_name}] {service} ({ssrf_target}): "
                  f"param={param} — {finding.get('url', '')}")
        elif module_name == "csrf":
            action = finding.get("form_action", "?")
            num_inputs = len(finding.get("inputs", []))
            print(f"[{module_name}] No token: {action} "
                  f"({num_inputs} inputs)")
        elif module_name == "headers":
            status = finding.get("status", "?")
            header = finding.get("header", "?")
            value = finding.get("value", "")
            val_str = f" = {value}" if value else ""
            print(f"[{module_name}] {status}: {header}{val_str}")
        elif module_name == "cors":
            sev = finding.get("severity", "?")
            sev_color = Fore.RED if sev == "critical" else Fore.YELLOW
            print(f"[{module_name}] {sev_color}{sev}{self._reset()} — "
                  f"{finding.get('origin', '?')} → {finding.get('url', '')}"
                  f"{' [creds]' if finding.get('acac') else ''}")
        elif module_name == "ssti":
            engine = finding.get("engine", "?")
            param = finding.get("parameter", "?")
            enc = finding.get("encoding", "")
            enc_str = f" [{enc}]" if enc and enc != "plain" else ""
            if finding.get("type") == "time_based":
                print(f"[{module_name}] {finding['type']} ({engine}): {param}{enc_str} "
                      f"-- {finding.get('response_ms', '?')}ms")
            else:
                print(f"[{module_name}] {finding['type']} ({engine}): {param}{enc_str} "
                      f"-- {finding.get('url', '')}")
        elif module_name == "fingerprint":
            techs = finding.get("all_techs", [])
            cdn = finding.get("cdn", "")
            wafs = finding.get("wafs", [])
            status = finding.get("status_code", "?")
            tech_str = ", ".join(techs) if techs else "generic"
            cdn_str = f" | CDN: {cdn}" if cdn else ""
            waf_str = f" | WAF: {', '.join(w['waf'] for w in wafs)}" if wafs else ""
            print(f"[{module_name}] {Fore.CYAN}{status}{self._reset()} — "
                  f"{tech_str}{cdn_str}{waf_str}")

        # PoC display (verbose or if available)
        poc = finding.get("poc", "")
        if poc and self.verbose:
            print(f"    ↳ {Fore.LIGHTBLACK_EX}PoC: {poc}{self._reset()}")

    def log_progress(self, message):
        """Print progress (verbose mode only)."""
        if self.verbose:
            print(f"[*] {message}", file=sys.stderr)

    def create_progress_bar(self, desc, total):
        """Create a progress bar. Returns tqdm or dummy if !verbose."""
        if self.verbose:
            try:
                from tqdm import tqdm
                return tqdm(total=total, desc=desc, unit="req", ncols=80)
            except ImportError:
                pass
        return _DummyBar()

    def update_progress(self, bar, n=1):
        """Update progress bar. No-op for dummy bars."""
        bar.update(n)

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
