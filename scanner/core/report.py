"""HTML report generation with severity grouping."""
import json
from datetime import datetime

# ── Severity Inference ──────────────────────────────────────────────

# Mapping: module_name → (default_severity, type_overrides)
_SEVERITY_MAP = {
    "sqli": ("critical", {}),
    "cmdi": ("critical", {}),
    "ssti": ("critical", {}),
    "lfi": ("high", {}),
    "xss": ("high", {}),
    "dom_xss": ("high", {}),
    "stored_xss": ("high", {}),
    "ssrf": ("high", {}),
    "cors": ("high", {}),  # individual findings may override
    "csrf": ("medium", {}),
    "redirect": ("medium", {}),
    "headers": ("low", {}),
    "dirscan": ("low", {}),
    "params": ("info", {}),
    "subdomain": ("info", {}),
}

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_SEVERITY_COLORS = {
    "critical": "#dc3545",
    "high": "#fd7e14",
    "medium": "#ffc107",
    "low": "#17a2b8",
    "info": "#6c757d",
}


def _infer_severity(module_name, finding):
    """Determine severity for a finding. Checks finding-level override first."""
    # Direct severity on finding (e.g. cors, dirscan elevated)
    if "severity" in finding:
        return finding["severity"]

    # Module default
    default, _ = _SEVERITY_MAP.get(module_name, ("info", {}))
    return default


def _escape_html(text):
    """Minimal HTML escaping."""
    return (text
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;"))


def generate_html(target, report, output_path):
    """Generate a self-contained HTML report.

    Args:
        target: Scan target string.
        report: Report dict from engine.run().
        output_path: Path to write HTML file.
    """
    findings_by_severity = {s: [] for s in _SEVERITY_ORDER}

    total = 0
    for module_name, findings in report.get("findings", {}).items():
        for f in findings:
            severity = _infer_severity(module_name, f)
            findings_by_severity.setdefault(severity, []).append(
                (module_name, f)
            )
            total += 1

    # Build stats row
    stats_html = ""
    for sev in ["critical", "high", "medium", "low", "info"]:
        count = len(findings_by_severity.get(sev, []))
        stats_html += (
            f'<div class="stat" style="background:{_SEVERITY_COLORS[sev]}">'
            f'{sev.upper()}<br><b>{count}</b></div>'
        )

    # Build findings HTML
    findings_html = ""
    for sev in ["critical", "high", "medium", "low", "info"]:
        group = findings_by_severity.get(sev, [])
        if not group:
            continue
        findings_html += (
            f'<div class="severity-group">'
            f'<h2 style="color:{_SEVERITY_COLORS[sev]}">'
            f'{sev.upper()} ({len(group)})</h2>'
        )
        for module_name, finding in group:
            evidence = _escape_html(finding.get("evidence", str(finding)))
            # Build compact key-value display
            detail_items = []
            skip_keys = {"evidence"}
            for k, v in finding.items():
                if k not in skip_keys:
                    val = str(v)[:120]
                    detail_items.append(f'<span class="kv"><b>{k}:</b> {_escape_html(val)}</span>')
            details = " &nbsp;|&nbsp; ".join(detail_items)

            findings_html += (
                f'<div class="finding">'
                f'<div class="finding-header">'
                f'<span class="module-tag">{module_name}</span>'
                f'<span class="finding-type">{_escape_html(finding.get("type", ""))}</span>'
                f'</div>'
                f'<div class="finding-details">{details}</div>'
                f'<div class="finding-evidence">{evidence}</div>'
                f'</div>'
            )
        findings_html += '</div>'

    scan_time = report.get("scan_time", datetime.now().isoformat())
    discovered = report.get("discovered_urls", 0)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Scan Report — {_escape_html(target)}</title>
<style>
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
       background: #0d1117; color: #c9d1d9; padding: 24px; }}
.header {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px;
          padding: 24px; margin-bottom: 24px; }}
.header h1 {{ color: #58a6ff; font-size: 22px; margin-bottom: 8px; }}
.header .meta {{ color: #8b949e; font-size: 13px; }}
.stats {{ display: flex; gap: 12px; margin-bottom: 24px; flex-wrap: wrap; }}
.stat {{ color: #fff; padding: 10px 18px; border-radius: 6px; text-align: center;
        font-size: 12px; min-width: 70px; }}
.severity-group {{ margin-bottom: 24px; }}
.severity-group h2 {{ font-size: 16px; margin-bottom: 12px; border-bottom: 1px solid #30363d;
                     padding-bottom: 6px; }}
.finding {{ background: #161b22; border: 1px solid #30363d; border-radius: 6px;
           padding: 14px; margin-bottom: 8px; }}
.finding-header {{ display: flex; align-items: center; gap: 10px; margin-bottom: 6px; }}
.module-tag {{ background: #21262d; color: #58a6ff; padding: 2px 8px; border-radius: 4px;
              font-size: 11px; font-weight: 600; }}
.finding-type {{ color: #c9d1d9; font-size: 13px; }}
.finding-details {{ color: #8b949e; font-size: 12px; margin-bottom: 6px; }}
.finding-details .kv {{ margin-right: 4px; }}
.finding-evidence {{ color: #e6edf3; font-size: 12px; background: #0d1117;
                    padding: 8px; border-radius: 4px; border-left: 3px solid #30363d;
                    font-family: monospace; word-break: break-all; }}
.footer {{ text-align: center; color: #484f58; font-size: 11px; margin-top: 32px; }}
</style>
</head>
<body>
<div class="header">
  <h1>Scan Report</h1>
  <div class="meta">
    Target: {_escape_html(target)} &nbsp;|&nbsp;
    Time: {scan_time} &nbsp;|&nbsp;
    Modules: {len(report.get('modules', []))} &nbsp;|&nbsp;
    Discovered URLs: {discovered}
  </div>
</div>
<div class="stats">{stats_html}</div>
{findings_html}
<div class="footer">Generated by vuln-scanner</div>
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
    return output_path
