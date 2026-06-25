# Scanner Phase 2a — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Three UX improvements: fix Chinese encoding, add custom wordlist support via CLI flags, add tqdm progress bars.

**Architecture:** Each change is independent and touches 1-3 files. Encoding: one-line fix in Output.__init__. Wordlists: CLI args flow through engine.run() to module constructors. tqdm: Output gets two progress bar methods; modules call them instead of text progress.

**Tech Stack:** Python 3.13, tqdm (new dependency)

---

### Task 1: Chinese encoding fix

**Files:**
- Modify: `scanner/core/output.py:22-26`

- [ ] **Step 1: Add UTF-8 stdout reconfigure in Output.__init__**

Edit `scanner/core/output.py`, replace `__init__` (lines 22-26):

```python
def __init__(self, verbose=False, use_color=True, json_path=None):
    self.verbose = verbose
    self.use_color = use_color and HAS_COLOR
    self.json_path = json_path
    self.results = {}
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
```

The `try/except` handles edge cases where stdout doesn't support reconfigure (piped output, old terminals).

- [ ] **Step 2: Verify encoding fix**

Run: `python -m scanner scan https://httpbin.org -m params`

Expected: Chinese text like "链接/资源" and "JS文件" displays correctly (no garbled characters)

- [ ] **Step 3: Verify existing tests still pass**

Run: `pytest tests/ -v`

Expected: 13 passed

- [ ] **Step 4: Commit**

```bash
git add scanner/core/output.py
git commit -m "fix: force UTF-8 stdout encoding for Chinese text on Windows"
```

---

### Task 2: Custom wordlist support

**Files:**
- Modify: `scanner/cli.py:30-33` (add 2 args)
- Modify: `scanner/cli.py:49-53` (pass wordlists to module constructors)
- Modify: `scanner/cli.py:77` (pass wordlists to engine.run)
- Modify: `scanner/core/engine.py:28` (run signature + forward to modules)
- Modify: `scanner/modules/subdomain.py:12-15` (add __init__)

- [ ] **Step 1: Add `__init__` to SubdomainModule and DirscanModule**

Edit `scanner/modules/subdomain.py`, add after line 15 (`requires_url = False`):

```python
def __init__(self, wordlist_path=None):
    self.wordlist_path = wordlist_path or _WORDLIST
```

Replace line 17-20 (`_load_wordlist` method — change `_WORDLIST` to `self.wordlist_path`):

Current:
```python
    def _load_wordlist(self):
        path = os.path.normpath(_WORDLIST)
        with open(path, encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip()]
```

Replace with:
```python
    def _load_wordlist(self):
        path = os.path.normpath(self.wordlist_path)
        with open(path, encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip()]
```

Edit `scanner/modules/dirscan.py`, add after line 15 (`requires_url = True`):

```python
def __init__(self, wordlist_path=None):
    self.wordlist_path = wordlist_path or _WORDLIST
```

Replace line 17-20 (`_load_wordlist` method):

Current:
```python
    def _load_wordlist(self):
        path = os.path.normpath(_WORDLIST)
        with open(path, encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip()]
```

Replace with:
```python
    def _load_wordlist(self):
        path = os.path.normpath(self.wordlist_path)
        with open(path, encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip()]
```

- [ ] **Step 2: Add CLI arguments**

Edit `scanner/cli.py`, add after line 33 (`--no-color`):

```python
    scan.add_argument("--subdomain-wordlist", help="Custom subdomain wordlist file")
    scan.add_argument("--dirscan-wordlist", help="Custom directory wordlist file")
```

- [ ] **Step 3: Pass wordlists to module constructors in cli.py**

Edit `scanner/cli.py`, replace lines 49-53:

Current:
```python
    engine = Engine()
    for cls in MODULE_CLASSES:
        mod = cls()
        engine.register(mod)
```

Replace with:
```python
    engine = Engine()
    for cls in MODULE_CLASSES:
        kwargs = {}
        if cls is SubdomainModule and args.subdomain_wordlist:
            kwargs["wordlist_path"] = args.subdomain_wordlist
        if cls is DirscanModule and args.dirscan_wordlist:
            kwargs["wordlist_path"] = args.dirscan_wordlist
        mod = cls(**kwargs)
        engine.register(mod)
```

- [ ] **Step 4: Verify custom wordlist works**

First create a small test wordlist:

```bash
echo "www" > /tmp/test_subs.txt
echo "mail" >> /tmp/test_subs.txt
```

Run: `python -m scanner scan example.com -m subdomain --subdomain-wordlist /tmp/test_subs.txt -v`

Expected: `Loaded 2 subdomain prefixes` (uses custom file, not 183 built-in)

- [ ] **Step 5: Verify fallback to built-in works**

Run: `python -m scanner scan example.com -m subdomain -v`

Expected: `Loaded 183 subdomain prefixes` (uses built-in when flag omitted)

- [ ] **Step 6: Verify all tests still pass**

Run: `pytest tests/ -v`

Expected: 13 passed

- [ ] **Step 7: Commit**

```bash
git add scanner/cli.py scanner/modules/subdomain.py scanner/modules/dirscan.py
git commit -m "feat: add --subdomain-wordlist and --dirscan-wordlist CLI options"
```

---

### Task 3: tqdm progress bars

**Files:**
- Modify: `scanner/core/output.py` (add `create_progress_bar`, `update_progress`)
- Modify: `scanner/modules/subdomain.py:45-88` (replace text progress with bars)
- Modify: `scanner/modules/dirscan.py:56-87` (same)
- Modify: `setup.py` (add tqdm dependency)

- [ ] **Step 1: Install tqdm**

Run: `pip install tqdm`

Expected: `Successfully installed tqdm-x.x.x`

- [ ] **Step 2: Add tqdm to setup.py dependencies**

Edit `setup.py`, line 9:

Current:
```python
    install_requires=["requests", "colorama"],
```

Replace with:
```python
    install_requires=["requests", "colorama", "tqdm"],
```

- [ ] **Step 3: Add progress bar methods to Output**

Edit `scanner/core/output.py`, add after `log_progress` (line 60):

```python
    def create_progress_bar(self, desc, total):
        """Create a progress bar. Returns tqdm instance or dummy if !verbose."""
        if self.verbose:
            try:
                from tqdm import tqdm
                return tqdm(total=total, desc=desc, unit="req", ncols=80)
            except ImportError:
                pass
        return _DummyBar()

    def update_progress(self, bar, n=1):
        """Update progress bar by n steps. No-op for dummy bars."""
        bar.update(n)
```

Add the `_DummyBar` class at the top of the file (after `Style = _Dummy()` line 16):

```python
class _DummyBar:
    def update(self, n=1):
        pass
    def close(self):
        pass
```

- [ ] **Step 4: Replace text progress in subdomain.py with tqdm bars**

Edit `scanner/modules/subdomain.py`, replace the `run` method (lines 45-88):

```python
    def run(self, target, request_handler, output):
        """Enumerate subdomains for the given domain."""
        prefixes = self._load_wordlist()
        output.log_progress(f"Loaded {len(prefixes)} subdomain prefixes, resolving DNS...")

        # Phase 1: DNS resolution
        resolved = []
        with ThreadPoolExecutor(max_workers=50) as pool:
            futures = {pool.submit(self._resolve, f"{p}.{target}"): p for p in prefixes}
            bar = output.create_progress_bar("DNS Resolving", len(prefixes))
            for future in as_completed(futures):
                ips = future.result()
                if ips:
                    prefix = futures[future]
                    resolved.append((f"{prefix}.{target}", ips[0]))
                output.update_progress(bar)
            bar.close()

        output.log_progress(f"DNS complete: {len(resolved)} subdomains resolved, checking HTTP...")

        # Phase 2: HTTP liveness
        findings = []
        if resolved:
            with ThreadPoolExecutor(max_workers=20) as pool:
                futures = {pool.submit(self._check_http, host, request_handler): (host, ip)
                           for host, ip in resolved}
                bar = output.create_progress_bar("HTTP Checking", len(resolved))
                for future in as_completed(futures):
                    host, ip = futures[future]
                    try:
                        status, title = future.result()
                        if status:
                            finding = {"host": host, "ip": ip, "status": status, "title": title}
                            findings.append(finding)
                            output.log_finding(self.name, finding)
                    except Exception:
                        pass
                    output.update_progress(bar)
                bar.close()

        output.log_progress(f"Subdomain scan done: {len(findings)} live subdomains found")
        return {"module": self.name, "findings": findings}
```

- [ ] **Step 5: Replace text progress in dirscan.py with tqdm bar**

Edit `scanner/modules/dirscan.py`, replace the `run` method (lines 56-87):

```python
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
                clean_path = path if path.startswith("/") else f"/{path}"
                url = f"{target}{clean_path}"
                futures[pool.submit(self._probe, url, request_handler, baseline_status, baseline_length)] = url

            bar = output.create_progress_bar("Dirscan", len(paths))
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        findings.append(result)
                        output.log_finding(self.name, result)
                except Exception:
                    pass
                output.update_progress(bar)
            bar.close()

        output.log_progress(f"Dirscan done: {len(findings)} accessible paths found")
        return {"module": self.name, "findings": findings}
```

- [ ] **Step 6: Verify tqdm bars in verbose mode**

Run: `python -m scanner scan example.com -m subdomain -v`

Expected: tqdm progress bars shown for DNS and HTTP phases

- [ ] **Step 7: Verify no bars in non-verbose mode**

Run: `python -m scanner scan example.com -m subdomain`

Expected: No progress bars, only findings printed

- [ ] **Step 8: Verify all tests still pass**

Run: `pytest tests/ -v`

Expected: 13 passed

- [ ] **Step 9: Commit**

```bash
git add scanner/core/output.py scanner/modules/subdomain.py scanner/modules/dirscan.py setup.py
git commit -m "feat: add tqdm progress bars for subdomain and dirscan modules"
```

---

### Task 4: Full integration verification

- [ ] **Step 1: Run all modules with verbose + custom wordlist + JSON output**

```bash
echo "www" > /tmp/mini_subs.txt
python -m scanner scan example.com -m subdomain,dirscan,params \
  --subdomain-wordlist /tmp/mini_subs.txt \
  -v -o phase2a_test.json
```

Expected: All three modules complete without error, progress bars shown for subdomain and dirscan, JSON file written

- [ ] **Step 2: Verify Chinese text displays correctly**

Run: `python -m scanner scan https://httpbin.org -m params`

Expected: "链接/资源", "JS文件", "JS端点" display correctly

- [ ] **Step 3: Final test suite**

Run: `pytest tests/ -v`

Expected: 13 passed

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "test: Phase 2a integration verification passed"
```
