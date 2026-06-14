"""Flask-based web UI for the vulnerability scanner.

Launch: python -m scanner web [--host 127.0.0.1] [--port 8080]
"""
import json
import queue
import sys
import threading
import time
import webbrowser
from datetime import datetime

from scanner.core.engine import Engine
from scanner.core.request import RequestHandler
from scanner.core.output import Output
from scanner.core.report import generate_html

# ── HTML template (embedded to avoid template directory) ─────────────────

PAGE = r'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Vuln Scanner</title>
<style>
:root {
  --bg: #0d1117; --card: #161b22; --border: #30363d;
  --text: #c9d1d9; --muted: #8b949e; --accent: #58a6ff;
  --green: #238636; --red: #da3633; --orange: #d29922;
  --cyan: #39c5cf; --purple: #a371f7;
}
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
       background: var(--bg); color: var(--text); min-height: 100vh; }
.header { background: var(--card); border-bottom: 1px solid var(--border);
          padding: 12px 24px; display: flex; align-items: center; gap: 12px; }
.header h1 { font-size: 18px; color: var(--accent); }
.header .ver { color: var(--muted); font-size: 11px; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 10px;
         font-size: 11px; font-weight: 600; }
.badge-ok { background: #1a3a2a; color: #3fb950; }
.badge-err { background: #3a1a1a; color: #f85149; }
.main { display: flex; gap: 0; height: calc(100vh - 50px); }
/* Sidebar */
.sidebar { width: 320px; min-width: 320px; background: var(--card);
           border-right: 1px solid var(--border); padding: 16px;
           overflow-y: auto; }
.sidebar h3 { font-size: 13px; color: var(--muted); margin-bottom: 8px;
              text-transform: uppercase; letter-spacing: 1px; }
.sidebar label { display: block; font-size: 12px; color: var(--text);
                 margin-bottom: 4px; }
.sidebar input[type="text"], .sidebar input[type="number"], .sidebar select {
  width: 100%; padding: 6px 10px; background: var(--bg);
  border: 1px solid var(--border); border-radius: 4px; color: var(--text);
  font-size: 13px; margin-bottom: 12px; }
.sidebar input:focus, .sidebar select:focus {
  outline: none; border-color: var(--accent); }
.mod-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 4px;
            margin-bottom: 12px; max-height: 320px; overflow-y: auto; }
.mod-grid label { display: flex; align-items: center; gap: 6px;
                  font-size: 11px; padding: 3px 6px; border-radius: 4px;
                  cursor: pointer; }
.mod-grid label:hover { background: #21262d; }
.mod-grid input[type="checkbox"] { accent-color: var(--accent); }
.btn { display: inline-block; padding: 8px 20px; border: none; border-radius: 6px;
       font-size: 13px; font-weight: 600; cursor: pointer; transition: .2s; }
.btn-start { background: var(--green); color: #fff; width: 100%; }
.btn-start:hover { filter: brightness(1.2); }
.btn-start:disabled { background: #1a3a2a; color: #484f58; cursor: not-allowed; }
.btn-stop { background: var(--red); color: #fff; width: 100%; margin-top: 8px; }
.btn-small { padding: 4px 12px; font-size: 11px; }
/* Content area */
.content { flex: 1; display: flex; flex-direction: column; overflow: hidden; }
.tabs { display: flex; border-bottom: 1px solid var(--border); background: var(--card); }
.tab { padding: 8px 18px; font-size: 12px; color: var(--muted); cursor: pointer;
       border-bottom: 2px solid transparent; }
.tab.active { color: var(--accent); border-bottom-color: var(--accent); }
.tab-content { flex: 1; overflow-y: auto; display: none; }
.tab-content.active { display: block; }
/* Log */
#log { padding: 16px; font-family: 'SF Mono', 'Cascadia Code', 'Consolas', monospace;
       font-size: 11px; line-height: 1.6; white-space: pre-wrap; word-break: break-all; }
.log-time { color: var(--muted); }
.log-info { color: var(--text); }
.log-find { color: var(--orange); }
.log-done { color: #3fb950; }
.log-err  { color: var(--red); }
/* Findings table */
.findings-toolbar { padding: 10px 16px; display: flex; gap: 8px; align-items: center;
                    border-bottom: 1px solid var(--border); }
.filt { padding: 4px 10px; border-radius: 10px; font-size: 11px; cursor: pointer;
        border: 1px solid var(--border); background: transparent; color: var(--muted); }
.filt.active, .filt:hover { border-color: var(--accent); color: var(--accent); }
.filt-c { color: #f85149; } .filt-h { color: #d29922; }
.filt-m { color: #d29922; } .filt-l { color: var(--cyan); }
.filt-i { color: var(--muted); }
#findings-table { width: 100%; font-size: 12px; border-collapse: collapse; }
#findings-table th { text-align: left; padding: 8px 16px; color: var(--muted);
                     font-size: 11px; border-bottom: 1px solid var(--border);
                     position: sticky; top: 0; background: var(--bg); }
#findings-table td { padding: 6px 16px; border-bottom: 1px solid #21262d; }
#findings-table tr:hover td { background: #161b22; }
.sev { display: inline-block; padding: 1px 6px; border-radius: 3px;
       font-size: 10px; font-weight: 700; text-transform: uppercase; }
.sev-critical { background: #3a1a1a; color: #f85149; }
.sev-high { background: #3a2a1a; color: #d29922; }
.sev-medium { background: #2a2a1a; color: #d29922; }
.sev-low { background: #1a2a3a; color: #39c5cf; }
.sev-info { background: #1a1a2a; color: #8b949e; }
.poc-cell { max-width: 320px; overflow: hidden; text-overflow: ellipsis;
            font-family: monospace; font-size: 10px; color: #3fb950; cursor: pointer; }
/* Report download */
.report-bar { padding: 10px 16px; border-top: 1px solid var(--border);
              display: flex; gap: 8px; align-items: center; }
@media (max-width: 768px) {
  .main { flex-direction: column; }
  .sidebar { width: 100%; min-width: auto; max-height: 40vh; }
}
</style>
</head>
<body>
<div class="header">
  <h1>🛡️ Vuln Scanner</h1>
  <span class="ver">16 modules · 258 tests</span>
  <span id="conn-status" class="badge badge-ok" style="margin-left:auto">● connected</span>
</div>
<div class="main">
  <div class="sidebar">
    <h3>Target</h3>
    <input type="text" id="target" placeholder="https://example.com" value="">

    <h3>Modules</h3>
    <div class="mod-grid" id="mod-checks">
    </div>
    <label style="cursor:pointer; font-size:11px; margin-bottom:12px">
      <input type="checkbox" id="select-all" checked onchange="toggleAll(this.checked)">
      Select / deselect all
    </label>

    <h3>Options</h3>
    <label>Threads</label>
    <input type="number" id="threads" value="10" min="1" max="50">
    <label>Delay (ms)</label>
    <input type="number" id="delay" value="100" min="0" max="5000">
    <label>Timeout (s)</label>
    <input type="number" id="timeout" value="10" min="1" max="60">
    <label>Depth (crawler)</label>
    <input type="number" id="depth" value="1" min="1" max="5">
    <label>Scope</label>
    <input type="text" id="scope" placeholder="*.example.com">
    <label>Cookie</label>
    <input type="text" id="cookie" placeholder="session=abc; token=xyz">
    <label>Proxy</label>
    <input type="text" id="proxy" placeholder="http://127.0.0.1:8080">

    <button class="btn btn-start" id="btn-start" onclick="startScan()">▶ Start Scan</button>
    <button class="btn btn-stop" id="btn-stop" onclick="stopScan()" style="display:none">■ Stop</button>

    <h3 style="margin-top:16px">Passive Scan</h3>
    <label>HAR / Burp XML file</label>
    <input type="file" id="har-file" accept=".har,.xml" style="margin-bottom:8px">
    <button class="btn btn-start" style="background:var(--purple)" onclick="startPassive()">📥 Import & Scan</button>
  </div>

  <div class="content">
    <div class="tabs">
      <div class="tab active" onclick="switchTab('log')">📋 Log</div>
      <div class="tab" onclick="switchTab('findings')">🔍 Findings (<span id="find-count">0</span>)</div>
    </div>

    <div id="tab-log" class="tab-content active">
      <div id="log"><span class="log-info">Ready. Enter a target and click Start Scan.</span></div>
    </div>

    <div id="tab-findings" class="tab-content">
      <div class="findings-toolbar">
        <span style="font-size:12px;color:var(--muted)">Filter:</span>
        <button class="filt active" onclick="filterFindings('all')" data-f="all">All</button>
        <button class="filt filt-c" onclick="filterFindings('critical')" data-f="critical">Critical</button>
        <button class="filt filt-h" onclick="filterFindings('high')" data-f="high">High</button>
        <button class="filt filt-m" onclick="filterFindings('medium')" data-f="medium">Medium</button>
        <button class="filt filt-l" onclick="filterFindings('low')" data-f="low">Low</button>
        <button class="filt filt-i" onclick="filterFindings('info')" data-f="info">Info</button>
      </div>
      <div style="overflow-y:auto;flex:1">
        <table id="findings-table">
          <thead><tr>
            <th>Severity</th><th>Module</th><th>Type</th><th>Target</th><th>Evidence</th><th>PoC</th>
          </tr></thead>
          <tbody id="findings-body"></tbody>
        </table>
      </div>
      <div class="report-bar" id="report-bar" style="display:none">
        <button class="btn btn-small" style="background:var(--accent);color:#000"
                onclick="downloadReport('json')">📥 JSON Report</button>
        <button class="btn btn-small" style="background:var(--purple);color:#fff"
                onclick="downloadReport('html')">📄 HTML Report</button>
      </div>
    </div>
  </div>
</div>

<script>
const MODULES = [
  "subdomain","dirscan","params",
  "sqli","xss","dom_xss","stored_xss",
  "cmdi","lfi","redirect",
  "ssrf","csrf","headers","cors","ssti","fingerprint"
];

// Init module checkboxes
const grid = document.getElementById('mod-checks');
MODULES.forEach((m, i) => {
  const checked = (m !== 'stored_xss'); // default all except slow ones
  grid.innerHTML += `<label><input type="checkbox" value="${m}" ${checked?'checked':''}> ${m}</label>`;
});

function getCheckedModules() {
  return [...document.querySelectorAll('#mod-checks input:checked')].map(c => c.value);
}

function toggleAll(on) {
  document.querySelectorAll('#mod-checks input').forEach(c => c.checked = on);
}

let currentFilter = 'all';
let allFindings = [];
let evtSource = null;
let scanRunning = false;

function switchTab(name) {
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
  document.querySelector(`.tab:nth-child(${name==='log'?1:2})`).classList.add('active');
  document.getElementById(`tab-${name}`).classList.add('active');
}

function log(msg, cls='log-info') {
  const el = document.getElementById('log');
  const time = new Date().toLocaleTimeString();
  el.innerHTML += `<div class="${cls}"><span class="log-time">[${time}]</span> ${msg}</div>`;
  el.scrollTop = el.scrollHeight;
}

function startScan() {
  if (scanRunning) return;
  const target = document.getElementById('target').value.trim();
  if (!target) { log('Please enter a target URL', 'log-err'); return; }

  const modules = getCheckedModules();
  if (!modules.length) { log('Please select at least one module', 'log-err'); return; }

  scanRunning = true;
  allFindings = [];
  document.getElementById('btn-start').style.display = 'none';
  document.getElementById('btn-stop').style.display = 'block';
  document.getElementById('find-count').textContent = '0';
  document.getElementById('findings-body').innerHTML = '';
  document.getElementById('report-bar').style.display = 'none';
  document.getElementById('log').innerHTML = '';

  const params = new URLSearchParams({
    target, modules: modules.join(','),
    threads: document.getElementById('threads').value || 10,
    delay: document.getElementById('delay').value || 100,
    timeout: document.getElementById('timeout').value || 10,
    depth: document.getElementById('depth').value || 1,
    scope: document.getElementById('scope').value,
    cookie: document.getElementById('cookie').value,
    proxy: document.getElementById('proxy').value,
  });

  evtSource = new EventSource('/api/scan?' + params.toString());
  evtSource.onmessage = function(e) {
    const data = JSON.parse(e.data);
    if (data.type === 'log') {
      log(data.msg, data.cls || 'log-info');
    } else if (data.type === 'finding') {
      allFindings.push(data.finding);
      document.getElementById('find-count').textContent = allFindings.length;
      renderFindings();
    } else if (data.type === 'done') {
      log('✓ Scan complete — ' + data.total + ' findings', 'log-done');
      document.getElementById('report-bar').style.display = 'flex';
      scanDone();
    } else if (data.type === 'report') {
      window._lastReport = data.report;
    } else if (data.type === 'error') {
      log(data.msg, 'log-err');
      scanDone();
    }
  };
  evtSource.onerror = function() {
    if (scanRunning) log('Connection lost', 'log-err');
    scanDone();
  };

  log('Starting scan: ' + target + ' [' + modules.length + ' modules]');
}

function stopScan() {
  if (evtSource) { evtSource.close(); evtSource = null; }
  scanDone();
  log('Scan stopped by user', 'log-err');
}

function scanDone() {
  scanRunning = false;
  document.getElementById('btn-start').style.display = 'block';
  document.getElementById('btn-stop').style.display = 'none';
  if (evtSource) { evtSource.close(); evtSource = null; }
}

function startPassive() {
  const file = document.getElementById('har-file').files[0];
  if (!file) { log('Please select a HAR or XML file', 'log-err'); return; }

  const modules = getCheckedModules();
  if (!modules.length) { log('Please select at least one module', 'log-err'); return; }

  scanRunning = true;
  allFindings = [];
  document.getElementById('btn-start').style.display = 'none';
  document.getElementById('btn-stop').style.display = 'block';
  document.getElementById('find-count').textContent = '0';
  document.getElementById('findings-body').innerHTML = '';
  document.getElementById('report-bar').style.display = 'none';
  document.getElementById('log').innerHTML = '';

  const formData = new FormData();
  formData.append('file', file);
  formData.append('modules', modules.join(','));
  formData.append('threads', document.getElementById('threads').value || 10);
  formData.append('delay', document.getElementById('delay').value || 100);
  formData.append('timeout', document.getElementById('timeout').value || 10);
  formData.append('cookie', document.getElementById('cookie').value);
  formData.append('proxy', document.getElementById('proxy').value);

  // Use fetch + polling for passive (file upload + SSE is tricky)
  fetch('/api/passive', { method: 'POST', body: formData })
    .then(r => r.json())
    .then(data => {
      if (data.error) { log(data.error, 'log-err'); return; }
      allFindings = data.findings || [];
      document.getElementById('find-count').textContent = allFindings.length;
      renderFindings();
      log('Passive scan complete — ' + allFindings.length + ' findings from ' + (data.scanned||0) + ' targets', 'log-done');
      if (data.report) window._lastReport = data.report;
      document.getElementById('report-bar').style.display = 'flex';
    })
    .catch(err => log('Error: ' + err, 'log-err'))
    .finally(scanDone);
}

const SEV_ORDER = {critical:0, high:1, medium:2, low:3, info:4};
const SEV_COLORS = {critical:'sev-critical', high:'sev-high', medium:'sev-medium', low:'sev-low', info:'sev-info'};

function getSeverity(finding, mod) {
  if (finding.severity) return finding.severity;
  const map = {sqli:'critical', cmdi:'critical', ssti:'critical',
               lfi:'high', xss:'high', dom_xss:'high', stored_xss:'high',
               ssrf:'high', cors:'high',
               csrf:'medium', redirect:'medium',
               headers:'low', dirscan:'low',
               params:'info', subdomain:'info', fingerprint:'info'};
  return map[mod] || 'info';
}

function renderFindings() {
  const tbody = document.getElementById('findings-body');
  let filtered = allFindings;
  if (currentFilter !== 'all') {
    filtered = allFindings.filter(f => getSeverity(f.finding, f.module) === currentFilter);
  }
  // Sort newest first
  filtered = [...filtered].reverse();

  tbody.innerHTML = filtered.map(({finding, module}) => {
    const sev = getSeverity(finding, module);
    const type = finding.type || finding.get ? finding.get('type', '') : '';
    const target = finding.url || finding.host || finding.form_action || '';
    const evidence = (finding.evidence || finding.description || '').substring(0, 100);
    const poc = finding.poc || '';
    return `<tr>
      <td><span class="sev ${SEV_COLORS[sev]||''}">${sev}</span></td>
      <td>${module}</td>
      <td>${type}</td>
      <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis" title="${target}">${target}</td>
      <td style="max-width:180px;overflow:hidden;text-overflow:ellipsis" title="${evidence}">${evidence}</td>
      <td class="poc-cell" title="Click to copy" onclick="copyPoC(this)">${poc}</td>
    </tr>`;
  }).join('');
}

function filterFindings(sev) {
  currentFilter = sev;
  document.querySelectorAll('.filt').forEach(b => b.classList.remove('active'));
  document.querySelector(`.filt[data-f="${sev}"]`).classList.add('active');
  renderFindings();
}

function copyPoC(el) {
  const poc = el.textContent;
  navigator.clipboard.writeText(poc).then(() => {
    el.style.color = '#3fb950';
    setTimeout(() => el.style.color = '', 1000);
  });
}

function downloadReport(format) {
  if (format === 'json') {
    const blob = new Blob([JSON.stringify(window._lastReport || {findings:[]}, null, 2)], {type:'application/json'});
    const a = document.createElement('a'); a.href = URL.createObjectURL(blob);
    a.download = 'scan_report.json'; a.click();
  } else {
    // Request HTML from server
    const params = new URLSearchParams({target: document.getElementById('target').value || 'passive'});
    fetch('/api/report?' + params.toString())
      .then(r => r.blob())
      .then(blob => {
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = 'scan_report.html'; a.click();
      });
  }
}

// Connection indicator
setInterval(() => {
  document.getElementById('conn-status').className = evtSource && evtSource.readyState === 1
    ? 'badge badge-ok' : 'badge badge-err';
  document.getElementById('conn-status').textContent = evtSource && evtSource.readyState === 1
    ? '● connected' : '● disconnected';
}, 3000);
</script>
</body>
</html>'''


# ── Flask app ────────────────────────────────────────────────────────────

def create_app():
    """Create the Flask app (delayed import so Flask is only needed for web cmd)."""
    from flask import Flask, request, Response, jsonify, stream_with_context

    app = Flask(__name__)

    @app.route("/")
    def index():
        return PAGE, 200, {"Content-Type": "text/html; charset=utf-8"}

    @app.route("/api/scan")
    def api_scan():
        """Run scan with SSE progress streaming via thread-safe queue."""
        target = request.args.get("target", "")
        modules = request.args.get("modules", "all")
        threads = int(request.args.get("threads", 10))
        delay = int(request.args.get("delay", 100))
        timeout = int(request.args.get("timeout", 10))
        depth = int(request.args.get("depth", 1))
        scope = request.args.get("scope") or None
        cookie = request.args.get("cookie") or None
        proxy = request.args.get("proxy") or None

        if not target:
            return Response(
                "data: " + json.dumps({"type": "error", "msg": "No target specified"}) + "\n\n",
                mimetype="text/event-stream"
            )

        module_names = [m.strip() for m in modules.split(",") if m.strip()]
        if not module_names or module_names == ["all"]:
            module_names = ["all"]

        rh = RequestHandler(
            timeout=timeout, delay=delay, cookies=cookie,
            extra_headers=None, proxy=proxy,
        )

        # Thread-safe event queue
        event_queue = queue.Queue()
        STOP_SENTINEL = object()

        class QueueOutput(Output):
            """Output that pushes events to a thread-safe queue."""
            def __init__(self):
                super().__init__(verbose=True, use_color=False)
            def log_finding(self, module_name, finding):
                sev_map = {"sqli":"critical", "cmdi":"critical", "ssti":"critical",
                           "lfi":"high", "xss":"high", "dom_xss":"high", "stored_xss":"high",
                           "ssrf":"high", "cors":"high",
                           "csrf":"medium", "redirect":"medium",
                           "headers":"low", "dirscan":"low",
                           "params":"info", "subdomain":"info", "fingerprint":"info"}
                severity = finding.get("severity", sev_map.get(module_name, "info"))
                event_queue.put({
                    "type": "finding",
                    "finding": {"finding": finding, "module": module_name, "severity": severity},
                })
                # Also show as log
                typ = finding.get("type", "")
                url = finding.get("url", finding.get("host", ""))
                event_queue.put({
                    "type": "log", "msg": f"[{module_name}] {severity}: {typ} — {url}",
                    "cls": "log-find",
                })
            def log_progress(self, message):
                event_queue.put({"type": "log", "msg": str(message), "cls": "log-info"})
            def create_progress_bar(self, desc, total):
                return _DummyBar()
            def update_progress(self, bar, n=1):
                pass

        class _DummyBar:
            def update(self, n=1): pass
            def close(self): pass

        output = QueueOutput()

        # Register engine
        engine = Engine()
        from scanner.cli import MODULE_CLASSES
        for cls in MODULE_CLASSES:
            engine.register(cls())

        report_data = {}

        def run_scan_thread():
            """Run scan in background thread, push results to queue."""
            try:
                result = engine.run(
                    target, module_names, rh, output,
                    threads=threads, scope=scope, depth=depth,
                )
                total = sum(len(v) for v in result.get("findings", {}).values())
                event_queue.put({
                    "type": "done", "total": total,
                    "report": result,
                })
            except Exception as e:
                event_queue.put({"type": "error", "msg": str(e)})
            finally:
                event_queue.put(STOP_SENTINEL)

        thread = threading.Thread(target=run_scan_thread, daemon=True)
        thread.start()

        def generate():
            while True:
                try:
                    item = event_queue.get(timeout=30)
                except queue.Empty:
                    # Keep-alive ping
                    yield ": keepalive\n\n"
                    continue

                if item is STOP_SENTINEL:
                    break

                yield f"data: {json.dumps(item, default=str)}\n\n"

        return Response(
            stream_with_context(generate()),
            mimetype="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no",
                "Access-Control-Allow-Origin": "*",
            }
        )

    @app.route("/api/report")
    def api_report():
        """Generate and return HTML report."""
        target = request.args.get("target", "unknown")
        report_json = request.args.get("report", "{}")
        try:
            report = json.loads(report_json)
        except json.JSONDecodeError:
            report = {"scan_time": datetime.now().isoformat(), "target": target,
                      "modules": [], "findings": {}}

        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as f:
            path = f.name
        try:
            generate_html(target, report, path)
            with open(path, encoding="utf-8") as f:
                html = f.read()
        finally:
            import os
            if os.path.exists(path):
                os.unlink(path)

        return Response(html, mimetype="text/html; charset=utf-8")

    @app.route("/api/passive", methods=["POST"])
    def api_passive():
        """Handle passive scan file upload."""
        if "file" not in request.files:
            return jsonify({"error": "No file uploaded"}), 400

        file = request.files["file"]
        modules = request.form.get("modules", "all")
        threads = int(request.form.get("threads", 10))
        delay = int(request.form.get("delay", 100))
        timeout = int(request.form.get("timeout", 10))
        cookie = request.form.get("cookie") or None
        proxy = request.form.get("proxy") or None

        import tempfile, os
        suffix = ".xml" if file.filename.endswith(".xml") else ".har"
        with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as f:
            file.save(f.name)
            tmp_path = f.name

        try:
            from scanner.core.passive import run_passive
            module_names = [m.strip() for m in modules.split(",")] if modules != "all" else ["all"]
            rh = RequestHandler(timeout=timeout, delay=delay, cookies=cookie, proxy=proxy)
            out = Output(verbose=False, use_color=False)

            report = run_passive(tmp_path, module_names, rh, out, threads=threads)

            # Flatten findings for frontend
            findings = []
            for mod_name, mod_findings in report.get("findings", {}).items():
                for f in mod_findings:
                    findings.append({"finding": f, "module": mod_name})

            return jsonify({
                "findings": findings,
                "scanned": report.get("scanned_targets", 0),
                "report": report,
            })
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

    return app


def run_web(host="127.0.0.1", port=8080, open_browser=True):
    """Launch the web server."""
    try:
        from flask import Flask
    except ImportError:
        print("Flask is required for the Web UI. Install it:")
        print("  pip install flask")
        sys.exit(1)

    app = create_app()

    if open_browser:
        url = f"http://{host}:{port}"
        print(f"Opening {url} ...")
        webbrowser.open(url)

    print(f"\n  Vuln Scanner Web UI")
    print(f"  http://{host}:{port}")
    print(f"  Press Ctrl+C to stop\n")

    app.run(host=host, port=port, debug=False, threaded=True)
