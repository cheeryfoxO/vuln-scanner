# Vulnerability Scanner v1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a modular Python CLI vulnerability scanner with 3 reconnaissance modules (subdomain enumeration, directory scanning, parameter analysis), plugin architecture, ThreadPoolExecutor concurrency, colored terminal output, and JSON reporting.

**Architecture:** Plugin-based CLI tool. Each module inherits `BaseModule` and implements `run(target, request_handler, output)`. Modules manage their own internal concurrency via `ThreadPoolExecutor`. The engine orchestrates module execution order. Output is decoupled from scanning logic — modules call `output.log_finding()` and `output.log_progress()`.

**Tech Stack:** Python 3.13, requests, colorama, concurrent.futures, argparse, socket, html.parser, pytest

**Design decisions:**
- Each module creates its own `ThreadPoolExecutor` (DNS needs 50 workers, HTTP needs 20) — simpler than a shared pool
- `output` object is passed into modules — they call `log_finding()` directly for real-time display
- `request_handler` wraps all HTTP — modules never call `requests` directly
- Wordlists are embedded in `scanner/data/` as plain text files, read at module init

---

### Task 1: Project scaffolding

**Files:**
- Create: `scanner/__init__.py`
- Create: `scanner/__main__.py`
- Create: `scanner/core/__init__.py`
- Create: `scanner/modules/__init__.py`
- Create: `setup.py`

- [ ] **Step 1: Create directory structure and init files**

```bash
mkdir -p scanner/core scanner/modules scanner/data tests
```

Create `scanner/__init__.py`:
```python
"""Vulnerability Scanner - Modular reconnaissance tool."""
__version__ = "0.1.0"
```

Create `scanner/core/__init__.py`:
```python
```

Create `scanner/modules/__init__.py`:
```python
```

- [ ] **Step 2: Create __main__.py**

Create `scanner/__main__.py`:
```python
"""Allow running as: python -m scanner"""
from scanner.cli import main

if __name__ == "__main__":
    main()
```

- [ ] **Step 3: Create setup.py**

Create `setup.py`:
```python
from setuptools import setup, find_packages

setup(
    name="scanner",
    version="0.1.0",
    packages=find_packages(),
    include_package_data=True,
    install_requires=["requests", "colorama"],
    entry_points={
        "console_scripts": [
            "scanner=scanner.cli:main",
        ],
    },
)
```

- [ ] **Step 4: Install in development mode**

Run: `pip install -e "F:/talk_with_claude/all_achievement"`

Expected: `Successfully installed scanner-0.1.0`

- [ ] **Step 5: Commit**

```bash
git add scanner/__init__.py scanner/__main__.py scanner/core/__init__.py scanner/modules/__init__.py setup.py
git commit -m "chore: project scaffolding with package structure"
```

---

### Task 2: Wordlist data files

**Files:**
- Create: `scanner/data/subdomains.txt`
- Create: `scanner/data/dirs.txt`
- Create: `scanner/modules/__init__.py` (modify to add module registry)

- [ ] **Step 1: Create subdomain wordlist (~200 entries)**

Create `scanner/data/subdomains.txt`:
```
www
mail
smtp
pop
imap
webmail
email
ftp
sftp
ssh
dns
ns1
ns2
dev
test
staging
prod
uat
qa
demo
beta
alpha
api
api2
app
apps
m
mobile
blog
forum
community
support
help
docs
wiki
kb
status
monitor
admin
administrator
cpanel
whm
webdisk
autodiscover
remote
vpn
gateway
portal
login
sso
auth
ldap
sql
db
database
mysql
redis
mongo
elastic
search
kibana
grafana
jenkins
ci
cd
git
gitlab
docker
k8s
kubernetes
proxy
cdn
static
assets
media
images
img
files
download
dl
s3
storage
backup
log
logs
mx
mx1
shop
store
pay
payment
billing
invoice
chat
crm
erp
hr
intranet
internal
partner
partners
reseller
affiliate
press
news
career
careers
jobs
upload
uploads
sandbox
new
old
v2
v1
en
cn
us
eu
dashboard
panel
control
service
services
my
account
accounts
profile
user
users
member
client
customer
order
orders
checkout
cart
secure
ssl
origin
edge
cache
lb
loadbalancer
ns3
ns4
dns1
dns2
www2
cdn1
cdn2
stage
test2
dev2
lab
labs
research
analytics
metrics
stats
data
feed
rss
atom
newsletter
webinar
event
events
live
stream
video
videos
gallery
photo
photos
survey
poll
messenger
sms
notification
notify
alerts
alert
```

- [ ] **Step 2: Create directory/file wordlist (~300 entries)**

Create `scanner/data/dirs.txt`:
```
.git/HEAD
.env
.env.local
.env.production
.env.backup
backup.zip
backup.tar.gz
backup.sql
dump.sql
wp-admin/
wp-content/
wp-includes/
wp-login.php
xmlrpc.php
admin/
administrator/
login/
phpmyadmin/
pma/
phpinfo.php
info.php
test.php
server-status
server-info
.htaccess
.htpasswd
robots.txt
sitemap.xml
crossdomain.xml
.DS_Store
config.json
config.yml
config.yaml
config.xml
config.php
config.inc.php
configuration.php
settings.py
settings.json
settings.yml
debug/
dev/
development/
test/
testing/
staging/
Dockerfile
docker-compose.yml
docker-compose.yaml
Makefile
Gruntfile.js
package.json
yarn.lock
composer.json
composer.lock
Gemfile
requirements.txt
Pipfile
.gitignore
.gitattributes
swagger.json
swagger.yaml
openapi.json
api-docs/
api/docs
api/v1/
api/v2/
graphql
graphiql
playground
console/
shell.php
cmd.php
upload.php
install.php
setup.php
upgrade.php
migrate.php
adminer.php
log/
logs/
tmp/
temp/
cache/
backup/
backups/
old/
new/
bak/
inc/
include/
includes/
src/
source/
assets/
static/
public/
private/
protected/
vendor/
node_modules/
storage/
uploads/
download/
downloads/
files/
images/
img/
css/
js/
fonts/
media/
feed/
rss/
atom/
api/rest/
rest/
soap/
wcf/
webservice/
service/
services/
endpoint/
endpoints/
cron/
worker/
task/
tasks/
queue/
jobs/
health
healthcheck
ping
status
version
info
metrics
metrics/
prometheus
.env.example
.env.sample
.env.dev
.env.test
.env.staging
.aws/credentials
.docker/config.json
.bash_history
.mysql_history
.gitconfig
.npmrc
.eslintrc
.babelrc
.editorconfig
.prettierrc
nginx.conf
nginx-status
nginx/
apache/
httpd/
lighttpd/
web.config
app.config
application.properties
application.yml
application.json
bootstrap.yml
database.yml
database.json
secrets.yml
secrets.json
credentials.json
credentials.yml
password.txt
passwords.txt
users.txt
access.log
error.log
debug.log
trace.log
web.log
app.log
auth.log
laravel.log
production.log
db/
database/
sql/
mysql/
dump/
export/
import/
data/
downloads/
upload/
file/
files/
doc/
docs/
documentation/
manual/
guide/
readme.html
readme.md
changelog.txt
changelog.md
license.txt
license.md
security.txt
humans.txt
trace.axd
elmah.axd
web.config.bak
global.asax
default.aspx
default.asp
index.php
index.html
index.htm
home.html
home.php
main.html
main.php
page/
pages/
post/
posts/
article/
articles/
news/
blog/
category/
categories/
tag/
tags/
archive/
archives/
search/
sitemap/
rss/
contact/
about/
faq/
help/
terms/
privacy/
policy/
tos/
legal/
```

- [ ] **Step 3: Verify wordlist line counts**

Run: `wc -l scanner/data/subdomains.txt scanner/data/dirs.txt`

Expected: ~198 subdomains, ~236 dirs (approximate)

- [ ] **Step 4: Commit**

```bash
git add scanner/data/subdomains.txt scanner/data/dirs.txt
git commit -m "feat: add built-in wordlists for subdomain and directory scanning"
```

---

### Task 3: Base module interface

**Files:**
- Create: `scanner/modules/base.py`
- Create: `tests/__init__.py`
- Create: `tests/test_base.py`

- [ ] **Step 1: Write failing test**

Create `tests/__init__.py`:
```python
```

Create `tests/test_base.py`:
```python
"""Tests for base module interface."""
from scanner.modules.base import BaseModule


def test_cannot_instantiate_abstract():
    """Instantiating BaseModule directly should raise TypeError."""
    try:
        BaseModule()
        assert False, "Should have raised TypeError"
    except TypeError:
        pass


def test_concrete_subclass_works():
    """A subclass that implements run() should work."""
    class TestMod(BaseModule):
        name = "test"
        description = "Test module"
        requires_url = False

        def run(self, target, request_handler, output):
            return {"module": self.name, "findings": []}

    mod = TestMod()
    assert mod.name == "test"
    assert mod.requires_url is False
    result = mod.run("example.com", None, None)
    assert result == {"module": "test", "findings": []}
```

- [ ] **Step 2: Verify test fails**

Run: `pytest tests/test_base.py -v`

Expected: FAIL — `ModuleNotFoundError: No module named 'scanner.modules.base'`

- [ ] **Step 3: Implement BaseModule**

Create `scanner/modules/base.py`:
```python
"""Base module interface for the scanner plugin architecture."""
from abc import ABC, abstractmethod


class BaseModule(ABC):
    """Abstract base for all scanner modules.

    Subclasses must define: name, description, requires_url, run().
    """

    name: str = ""
    description: str = ""
    requires_url: bool = False

    @abstractmethod
    def run(self, target: str, request_handler, output) -> dict:
        """Execute the module and return findings.

        Args:
            target: Domain name or full URL (see requires_url)
            request_handler: RequestHandler instance
            output: Output instance

        Returns:
            {"module": self.name, "findings": [<dict>, ...]}
        """
        ...
```

- [ ] **Step 4: Verify test passes**

Run: `pytest tests/test_base.py -v`

Expected: 2 passed

- [ ] **Step 5: Commit**

```bash
git add scanner/modules/base.py tests/__init__.py tests/test_base.py
git commit -m "feat: add BaseModule abstract class with tests"
```

---

### Task 4: HTTP request wrapper

**Files:**
- Create: `scanner/core/request.py`
- Create: `tests/test_request.py`

- [ ] **Step 1: Write failing test**

Create `tests/test_request.py`:
```python
"""Tests for HTTP request wrapper."""
from scanner.core.request import RequestHandler, USER_AGENTS


def test_default_timeout_is_10():
    rh = RequestHandler()
    assert rh.timeout == 10


def test_custom_timeout():
    rh = RequestHandler(timeout=5)
    assert rh.timeout == 5


def test_user_agents_non_empty():
    assert len(USER_AGENTS) >= 3
    for ua in USER_AGENTS:
        assert isinstance(ua, str)
        assert len(ua) > 20


def test_session_created():
    rh = RequestHandler()
    assert rh.session is not None
```

- [ ] **Step 2: Verify test fails**

Run: `pytest tests/test_request.py -v`

Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Implement RequestHandler**

Create `scanner/core/request.py`:
```python
"""HTTP request wrapper with UA rotation, retry, and timeout."""
import random

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:126.0) Gecko/20100101 Firefox/126.0",
]

DEFAULT_TIMEOUT = 10


class RequestHandler:
    """Wraps requests.Session with UA rotation, retry, and default timeout."""

    def __init__(self, timeout=DEFAULT_TIMEOUT, max_retries=1):
        self.timeout = timeout
        self.session = requests.Session()

        retry_strategy = Retry(
            total=max_retries,
            backoff_factor=0.5,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "HEAD"],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

    def _random_ua(self):
        return random.choice(USER_AGENTS)

    def _prepare(self, kwargs):
        headers = kwargs.pop("headers", {})
        headers.setdefault("User-Agent", self._random_ua())
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("allow_redirects", True)
        kwargs["headers"] = headers
        return kwargs

    def get(self, url, **kwargs):
        """GET request with automatic UA and timeout."""
        return self.session.get(url, **self._prepare(kwargs))

    def head(self, url, **kwargs):
        """HEAD request with automatic UA and timeout."""
        return self.session.head(url, **self._prepare(kwargs))
```

- [ ] **Step 4: Verify test passes**

Run: `pytest tests/test_request.py -v`

Expected: 4 passed

- [ ] **Step 5: Commit**

```bash
git add scanner/core/request.py tests/test_request.py
git commit -m "feat: add HTTP request wrapper with UA rotation and retry"
```

---

### Task 5: Output formatter

**Files:**
- Create: `scanner/core/output.py`
- Create: `tests/test_output.py`

- [ ] **Step 1: Write failing test**

Create `tests/test_output.py`:
```python
"""Tests for output formatter."""
import json
import os
import tempfile
from scanner.core.output import Output


def test_log_finding_stores_result():
    out = Output(verbose=False, use_color=False)
    finding = {"host": "admin.example.com", "ip": "1.2.3.4", "status": 200, "title": "Admin"}
    out.log_finding("subdomain", finding)
    assert "subdomain" in out.results
    assert out.results["subdomain"] == [finding]


def test_json_report_structure():
    out = Output(verbose=False, use_color=False)
    out.log_finding("dirscan", {"url": "http://x.com/.git/HEAD", "status": 200, "size": 41, "content_type": "text/plain"})

    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as f:
        path = f.name

    try:
        out.json_path = path
        report = out.write_report("example.com", ["dirscan"])
        assert report["target"] == "example.com"
        assert report["modules"] == ["dirscan"]
        assert "scan_time" in report
        assert "dirscan" in report["findings"]
        assert len(report["findings"]["dirscan"]) == 1

        with open(path) as f:
            saved = json.load(f)
        assert saved == report
    finally:
        os.unlink(path)


def test_multiple_modules_isolated():
    out = Output(verbose=False, use_color=False)
    out.log_finding("subdomain", {"host": "a.example.com", "status": 200, "title": "A"})
    out.log_finding("dirscan", {"url": "http://x.com/admin/", "status": 403, "size": 0, "content_type": "text/html"})
    assert len(out.results["subdomain"]) == 1
    assert len(out.results["dirscan"]) == 1
```

- [ ] **Step 2: Verify test fails**

Run: `pytest tests/test_output.py -v`

Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Implement Output**

Create `scanner/core/output.py`:
```python
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
```

- [ ] **Step 4: Verify test passes**

Run: `pytest tests/test_output.py -v`

Expected: 3 passed

- [ ] **Step 5: Commit**

```bash
git add scanner/core/output.py tests/test_output.py
git commit -m "feat: add output formatter with terminal color and JSON report"
```

---

### Task 6: Subdomain enumeration module

**Files:**
- Create: `scanner/modules/subdomain.py`

- [ ] **Step 1: Implement SubdomainModule**

Create `scanner/modules/subdomain.py`:
```python
"""Subdomain enumeration — DNS resolution + HTTP liveness check."""
import os
import re
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

from scanner.modules.base import BaseModule

_WORDLIST = os.path.join(os.path.dirname(__file__), "..", "data", "subdomains.txt")


class SubdomainModule(BaseModule):
    name = "subdomain"
    description = "Enumerate subdomains via DNS + HTTP liveness check"
    requires_url = False

    def _load_wordlist(self):
        path = os.path.normpath(_WORDLIST)
        with open(path, encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip()]

    def _resolve(self, hostname):
        """Return set of IPv4 addresses for a hostname."""
        ips = set()
        try:
            for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
                ips.add(info[4][0])
        except socket.gaierror:
            pass
        return list(ips)

    def _check_http(self, hostname, request_handler):
        """Try HTTPS then HTTP, return (status_code, title) or (0, '')."""
        for scheme in ("https", "http"):
            url = f"{scheme}://{hostname}"
            try:
                resp = request_handler.get(url)
                match = re.search(r"<title[^>]*>(.*?)</title>", resp.text, re.I | re.S)
                title = re.sub(r"\s+", " ", match.group(1).strip())[:100] if match else ""
                return resp.status_code, title
            except Exception:
                continue
        return 0, ""

    def run(self, target, request_handler, output):
        """Enumerate subdomains for the given domain."""
        prefixes = self._load_wordlist()
        output.log_progress(f"Loaded {len(prefixes)} subdomain prefixes, resolving DNS...")

        # Phase 1: DNS resolution (50 concurrent workers)
        resolved = []
        with ThreadPoolExecutor(max_workers=50) as pool:
            futures = {pool.submit(self._resolve, f"{p}.{target}"): p for p in prefixes}
            done = 0
            for future in as_completed(futures):
                done += 1
                ips = future.result()
                if ips:
                    prefix = futures[future]
                    resolved.append((f"{prefix}.{target}", ips[0]))
                if done % 50 == 0:
                    output.log_progress(f"DNS: {done}/{len(prefixes)} done, {len(resolved)} resolved")

        output.log_progress(f"DNS complete: {len(resolved)} subdomains resolved, checking HTTP...")

        # Phase 2: HTTP liveness (20 concurrent workers)
        findings = []
        if resolved:
            with ThreadPoolExecutor(max_workers=20) as pool:
                futures = {pool.submit(self._check_http, host, request_handler): (host, ip)
                           for host, ip in resolved}
                done = 0
                for future in as_completed(futures):
                    host, ip = futures[future]
                    done += 1
                    try:
                        status, title = future.result()
                        if status:
                            finding = {"host": host, "ip": ip, "status": status, "title": title}
                            findings.append(finding)
                            output.log_finding(self.name, finding)
                    except Exception:
                        pass
                    if done % 20 == 0:
                        output.log_progress(f"HTTP: {done}/{len(resolved)} checked, {len(findings)} live")

        output.log_progress(f"Subdomain scan done: {len(findings)} live subdomains found")
        return {"module": self.name, "findings": findings}
```

- [ ] **Step 2: Quick smoke test (requires internet)**

Run: `python -c "from scanner.modules.subdomain import SubdomainModule; m = SubdomainModule(); print(f'Module: {m.name}, prefixes: {len(m._load_wordlist())}')"`

Expected: `Module: subdomain, prefixes: ~198`

- [ ] **Step 3: Commit**

```bash
git add scanner/modules/subdomain.py
git commit -m "feat: add subdomain enumeration module"
```

---

### Task 7: Directory/file scanning module

**Files:**
- Create: `scanner/modules/dirscan.py`

- [ ] **Step 1: Implement DirscanModule**

Create `scanner/modules/dirscan.py`:
```python
"""Directory/file scanning — HTTP HEAD probe with 404 baseline filtering."""
import os
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin

from scanner.modules.base import BaseModule

_WORDLIST = os.path.join(os.path.dirname(__file__), "..", "data", "dirs.txt")


class DirscanModule(BaseModule):
    name = "dirscan"
    description = "Scan for sensitive directories and files via HTTP HEAD"
    requires_url = True

    def _load_wordlist(self):
        path = os.path.normpath(_WORDLIST)
        with open(path, encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip()]

    def _build_baseline(self, base_url, request_handler):
        """Request a random non-existent path to find the server's 404 behavior."""
        random_path = f"nonexistent-{uuid.uuid4().hex[:8]}.html"
        url = urljoin(base_url, random_path)
        try:
            resp = request_handler.head(url)
            return resp.status_code, len(resp.text or "")
        except Exception:
            return None, None

    def _probe(self, url, request_handler, baseline_status, baseline_length):
        """Probe a single path. Returns finding dict or None."""
        try:
            resp = request_handler.head(url)
            code = resp.status_code

            # Filter 404-like responses using baseline
            if code == baseline_status:
                if code == 404 and len(resp.text or "") == baseline_length:
                    return None
            if code == 404 and baseline_status is None:
                pass  # No baseline — can't filter, include all

            content_type = resp.headers.get("Content-Type", "")
            content_length = resp.headers.get("Content-Length", "")
            try:
                size = int(content_length) if content_length else 0
            except ValueError:
                size = 0

            return {"url": url, "status": code, "size": size, "content_type": content_type}
        except Exception:
            return None

    def run(self, target, request_handler, output):
        """Scan directories and files on the target URL."""
        target = target.rstrip("/")
        paths = self._load_wordlist()
        output.log_progress(f"Loaded {len(paths)} paths, establishing 404 baseline...")

        baseline_status, baseline_length = self._build_baseline(target, request_handler)
        output.log_progress(f"Baseline: status={baseline_status}, body_len={baseline_length}")

        findings = []
        with ThreadPoolExecutor(max_workers=20) as pool:
            futures = {}
            for path in paths:
                # Build URL — path from wordlist may already have leading /
                clean_path = path if path.startswith("/") else f"/{path}"
                url = f"{target}{clean_path}"
                futures[pool.submit(self._probe, url, request_handler, baseline_status, baseline_length)] = url

            done = 0
            for future in as_completed(futures):
                done += 1
                try:
                    result = future.result()
                    if result:
                        findings.append(result)
                        output.log_finding(self.name, result)
                except Exception:
                    pass
                if done % 50 == 0:
                    output.log_progress(f"Dirscan: {done}/{len(paths)} probed, {len(findings)} found")

        output.log_progress(f"Dirscan done: {len(findings)} accessible paths found")
        return {"module": self.name, "findings": findings}
```

- [ ] **Step 2: Quick smoke test**

Run: `python -c "from scanner.modules.dirscan import DirscanModule; m = DirscanModule(); print(f'Module: {m.name}, paths: {len(m._load_wordlist())}')"`

Expected: `Module: dirscan, paths: ~236`

- [ ] **Step 3: Commit**

```bash
git add scanner/modules/dirscan.py
git commit -m "feat: add directory/file scanning module with 404 baseline"
```

---

### Task 8: Parameter analysis module

**Files:**
- Create: `scanner/modules/params.py`

- [ ] **Step 1: Implement ParamsModule**

Create `scanner/modules/params.py`:
```python
"""Parameter analysis — extract input points from HTML, JS, and URL query strings."""
import re
from html.parser import HTMLParser
from urllib.parse import urlparse, parse_qs

from scanner.modules.base import BaseModule


class _FormParser(HTMLParser):
    """Extract form actions, input names, and resource links from HTML."""

    def __init__(self):
        super().__init__()
        self.forms = []
        self.links = []
        self.scripts = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "form":
            form_info = {
                "action": attrs.get("action", ""),
                "method": attrs.get("method", "GET").upper(),
                "inputs": [],
            }
            self.forms.append(form_info)
        elif tag == "input" and self.forms:
            name = attrs.get("name", "")
            input_type = attrs.get("type", "text")
            if name:
                self.forms[-1]["inputs"].append({"name": name, "type": input_type})
        elif tag == "a":
            href = attrs.get("href", "")
            if href and not href.startswith("#"):
                self.links.append(href)
        elif tag == "script":
            src = attrs.get("src", "")
            if src:
                self.scripts.append(src)
        elif tag == "link":
            href = attrs.get("href", "")
            if href:
                self.links.append(href)


class ParamsModule(BaseModule):
    name = "params"
    description = "Extract form inputs, JS endpoints, and URL parameters"
    requires_url = True

    # Regex patterns for API calls in JavaScript
    JS_API_PATTERNS = [
        re.compile(r"""fetch\s*\(\s*["']([^"']+)["']""", re.I),
        re.compile(r"""axios\.(?:get|post|put|delete|patch)\s*\(\s*["']([^"']+)["']""", re.I),
        re.compile(r"""\$\.(?:ajax|get|post)\s*\(\s*["']([^"']+)["']""", re.I),
        re.compile(r"""XMLHttpRequest[^}]*?\.open\s*\(\s*["']\w+["']\s*,\s*["']([^"']+)["']""", re.I),
    ]

    def _parse_html(self, html):
        parser = _FormParser()
        try:
            parser.feed(html)
        except Exception:
            pass
        return parser

    def _extract_js_endpoints(self, text):
        """Find API endpoints in JavaScript code using regex patterns."""
        endpoints = set()
        for pattern in self.JS_API_PATTERNS:
            for match in pattern.finditer(text):
                url = match.group(1)
                # Filter out obviously non-API URLs
                if url and not url.startswith("#") and not url.startswith("data:"):
                    endpoints.add(url)
        return list(endpoints)

    def run(self, target, request_handler, output):
        """Extract input points from the target page."""
        target = target.rstrip("/")
        output.log_progress(f"Fetching {target} ...")

        try:
            resp = request_handler.get(target)
            html = resp.text
        except Exception as e:
            output.log_progress(f"Failed to fetch {target}: {e}")
            return {"module": self.name, "findings": []}

        findings = []

        # 1. URL query parameters
        parsed = urlparse(target)
        query_params = parse_qs(parsed.query)
        for param, values in query_params.items():
            findings.append({"type": "URL参数", "source": param, "values": values})
            output.log_finding(self.name, findings[-1])

        # 2. HTML forms and links
        parsed_html = self._parse_html(html)

        for form in parsed_html.forms:
            method = form["method"]
            action = form["action"] or target
            input_names = [inp["name"] for inp in form["inputs"]]
            findings.append({
                "type": f"表单 ({method})",
                "source": action,
                "inputs": input_names,
            })
            output.log_finding(self.name, findings[-1])

        # 3. Interesting links (relative paths, API-looking)
        for link in parsed_html.links[:30]:  # Cap at 30 to avoid noise
            findings.append({"type": "链接/资源", "source": link})
            output.log_finding(self.name, findings[-1])

        # 4. JS file URLs
        for script_src in parsed_html.scripts[:10]:
            findings.append({"type": "JS文件", "source": script_src})
            output.log_finding(self.name, findings[-1])

        # 5. Inline JS endpoints
        js_endpoints = self._extract_js_endpoints(html)
        for ep in js_endpoints:
            findings.append({"type": "JS端点", "source": ep})
            output.log_finding(self.name, findings[-1])

        output.log_progress(f"Params done: {len(findings)} inputs found")
        return {"module": self.name, "findings": findings}
```

- [ ] **Step 2: Verify module loads**

Run: `python -c "from scanner.modules.params import ParamsModule; m = ParamsModule(); print(m.name, m.description)"`

Expected: `params Extract form inputs, JS endpoints, and URL parameters`

- [ ] **Step 3: Commit**

```bash
git add scanner/modules/params.py
git commit -m "feat: add parameter analysis module"
```

---

### Task 9: Engine

**Files:**
- Create: `scanner/core/engine.py`
- Create: `tests/test_engine.py`

- [ ] **Step 1: Write failing test**

Create `tests/test_engine.py`:
```python
"""Tests for the scan engine."""
from scanner.core.engine import Engine
from scanner.modules.base import BaseModule


class FakeOutput:
    """Minimal Output stub for testing the engine."""
    def __init__(self):
        self.results = {}
        self.progress = []

    def log_finding(self, module_name, finding):
        self.results.setdefault(module_name, []).append(finding)

    def log_progress(self, message):
        self.progress.append(message)

    def write_report(self, target, modules):
        pass


class FakeRequestHandler:
    """Stub request handler."""
    pass


class FakeModule(BaseModule):
    name = "fake"
    description = "A test module"
    requires_url = False

    def run(self, target, request_handler, output):
        output.log_finding(self.name, {"key": "value"})
        return {"module": self.name, "findings": [{"key": "value"}]}


def test_engine_registers_module():
    engine = Engine()
    mod = FakeModule()
    engine.register(mod)
    assert mod.name in engine.modules


def test_engine_runs_single_module():
    engine = Engine()
    mod = FakeModule()
    engine.register(mod)

    output = FakeOutput()
    req = FakeRequestHandler()

    results = engine.run("example.com", ["fake"], req, output, threads=10)
    assert results["target"] == "example.com"
    assert "fake" in results["findings"]
    assert results["findings"]["fake"] == [{"key": "value"}]


def test_engine_skips_unknown_module():
    engine = Engine()
    mod = FakeModule()
    engine.register(mod)

    output = FakeOutput()
    req = FakeRequestHandler()

    results = engine.run("example.com", ["nonexistent"], req, output, threads=10)
    assert results["findings"] == {}


def test_engine_lists_registered_modules():
    engine = Engine()
    engine.register(FakeModule())
    info = engine.list_modules()
    assert "fake" in info
    assert info["fake"] == "A test module"
```

- [ ] **Step 2: Verify tests fail**

Run: `pytest tests/test_engine.py -v`

Expected: FAIL — `ModuleNotFoundError: No module named 'scanner.core.engine'`

- [ ] **Step 3: Implement Engine**

Create `scanner/core/engine.py`:
```python
"""Scan engine — module registry, execution orchestration, result aggregation."""
from datetime import datetime


class Engine:
    """Orchestrates module execution, collecting results."""

    def __init__(self):
        self.modules = {}  # name -> module instance

    def register(self, module):
        """Register a module instance. Called once per module at startup."""
        self.modules[module.name] = module

    def list_modules(self):
        """Return {name: description} for all registered modules."""
        return {name: mod.description for name, mod in self.modules.items()}

    def _normalize_target(self, target, module):
        """Ensure target has http:// prefix if module requires a URL."""
        if module.requires_url and not target.startswith("http"):
            return f"http://{target}"
        # Strip protocol for subdomain enumeration
        if not module.requires_url:
            return target.replace("https://", "").replace("http://", "").rstrip("/")
        return target

    def run(self, target, module_names, request_handler, output, threads=10):
        """Execute the specified modules against the target.

        Args:
            target: Domain or URL string
            module_names: List of module names to run, or ["all"]
            request_handler: RequestHandler instance
            output: Output instance
            threads: Unused (each module manages its own pool)

        Returns:
            Report dict with target, scan_time, modules, findings
        """
        if "all" in module_names:
            names_to_run = list(self.modules.keys())
        else:
            names_to_run = [n for n in module_names if n in self.modules]

        output.log_progress(f"Modules to run: {names_to_run}")

        all_findings = {}
        modules_ran = []

        # Execution order: subdomain first, then dirscan + params in parallel
        # For simplicity in phase 1, run sequentially
        for name in names_to_run:
            mod = self.modules[name]
            normalized = self._normalize_target(target, mod)
            output.log_progress(f"Running module: {mod.name} against {normalized}")
            try:
                result = mod.run(normalized, request_handler, output)
                all_findings[result["module"]] = result["findings"]
                modules_ran.append(name)
            except Exception as e:
                output.log_progress(f"Module {mod.name} failed: {e}")

        return {
            "scan_time": datetime.now().isoformat(),
            "target": target,
            "modules": modules_ran,
            "findings": all_findings,
        }
```

- [ ] **Step 4: Verify tests pass**

Run: `pytest tests/test_engine.py -v`

Expected: 4 passed

- [ ] **Step 5: Commit**

```bash
git add scanner/core/engine.py tests/test_engine.py
git commit -m "feat: add scan engine with module registry and orchestration"
```

---

### Task 10: CLI entry point

**Files:**
- Create: `scanner/cli.py`

- [ ] **Step 1: Implement CLI**

Create `scanner/cli.py`:
```python
"""CLI entry point — argument parsing and wiring."""
import argparse
import sys

from scanner.core.engine import Engine
from scanner.core.request import RequestHandler
from scanner.core.output import Output
from scanner.modules.subdomain import SubdomainModule
from scanner.modules.dirscan import DirscanModule
from scanner.modules.params import ParamsModule


MODULE_CLASSES = [SubdomainModule, DirscanModule, ParamsModule]


def _build_parser():
    parser = argparse.ArgumentParser(
        prog="scanner",
        description="Modular vulnerability reconnaissance tool",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # scan command
    scan = subparsers.add_parser("scan", help="Run scan against a target")
    scan.add_argument("target", help="Target domain or URL (e.g., example.com or https://example.com)")
    scan.add_argument("-m", "--modules", default="all",
                      help="Comma-separated module names (subdomain,dirscan,params) or 'all'")
    scan.add_argument("-t", "--threads", type=int, default=10,
                      help="Concurrency hint (default: 10)")
    scan.add_argument("-o", "--output", help="Save JSON report to file")
    scan.add_argument("-v", "--verbose", action="store_true", help="Verbose progress output")
    scan.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds")
    scan.add_argument("--no-color", action="store_true", help="Disable colored output")

    # list command
    list_cmd = subparsers.add_parser("list", help="List available modules")

    return parser


def main():
    parser = _build_parser()
    args = parser.parse_args()

    # Build engine and register all modules
    engine = Engine()
    for cls in MODULE_CLASSES:
        mod = cls()
        engine.register(mod)

    if args.command == "list":
        print("Available modules:")
        for name, desc in engine.list_modules().items():
            print(f"  {name:12} {desc}")
        return

    # Parse module names
    if args.modules == "all":
        module_names = ["all"]
    else:
        module_names = [m.strip() for m in args.modules.split(",")]

    # Build dependencies
    request_handler = RequestHandler(timeout=args.timeout)
    output = Output(
        verbose=args.verbose,
        use_color=not args.no_color,
        json_path=args.output,
    )

    # Run
    output.log_progress(f"Starting scan against {args.target}")
    report = engine.run(args.target, module_names, request_handler, output, threads=args.threads)

    # Write JSON report (even if -o not specified, write_report handles that)
    if args.output:
        output.write_report(args.target, report["modules"])
        print(f"\nReport saved to {args.output}")

    # Summary
    total = sum(len(v) for v in report["findings"].values())
    print(f"\nScan complete. {total} findings across {len(report['modules'])} modules.")


if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Verify CLI works**

Run: `python -m scanner list`

Expected:
```
Available modules:
  subdomain    Enumerate subdomains via DNS + HTTP liveness check
  dirscan      Scan for sensitive directories and files via HTTP HEAD
  params       Extract form inputs, JS endpoints, and URL parameters
```

- [ ] **Step 3: Verify scan help**

Run: `python -m scanner scan --help`

Expected: Shows usage with target, -m, -t, -o, -v, --timeout, --no-color flags

- [ ] **Step 4: Commit**

```bash
git add scanner/cli.py
git commit -m "feat: add CLI entry point with scan and list subcommands"
```

---

### Task 11: Integration test

- [ ] **Step 1: Run against a test domain (subdomain only)**

Run: `python -m scanner scan example.com -m subdomain -v`

Expected: Should run without crashing. Likely finds some subdomains via DNS resolution. Verbose mode shows progress.

- [ ] **Step 2: Run parameter analysis against a real site**

Run: `python -m scanner scan https://httpbin.org -m params -v`

Expected: Extracts form inputs from httpbin.org. Should find URL parameters and form elements.

- [ ] **Step 3: Run with JSON output**

Run: `python -m scanner scan https://httpbin.org -m params -o report.json`

Expected: Creates `report.json` in current directory. Verify with `python -c "import json; print(json.load(open('report.json')))"` — should show valid JSON with findings.

- [ ] **Step 4: Run all modules**

Run: `python -m scanner scan example.com -m all -v -o full_report.json`

Expected: All three modules run, no crashes, JSON report is valid.

- [ ] **Step 5: Commit**

```bash
git commit -m "test: integration test passes for all three modules"
```

---

## Verification Checklist

After all tasks complete:

1. `python -m scanner list` — shows 3 modules
2. `python -m scanner scan example.com -m subdomain` — finds subdomains, doesn't crash
3. `python -m scanner scan https://httpbin.org -m params -o test.json` — creates valid JSON
4. `python -m scanner scan example.com -m all` — runs all modules
5. `python -m scanner scan --help` — shows help
6. `pytest tests/ -v` — all tests pass
