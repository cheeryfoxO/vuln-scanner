# Scanner Phase 2a — Polish & UX Improvements

**Date:** 2026-06-13
**Status:** Draft → Awaiting review
**Goal:** 修复中文编码、支持自定义字典、添加进度条，提升工具可用性

## 1. Chinese Encoding Fix

**Problem:** Windows 终端默认 GBK，`print()` 中文显示乱码

**Solution:** `output.py` 的 `Output.__init__` 开头加一行：
```python
sys.stdout.reconfigure(encoding="utf-8")
```

**Files changed:** `scanner/core/output.py` (+1 line)

**Risk:** 老 cmd.exe 可能抛异常，用 `try/except` 包裹降级

## 2. Custom Wordlist Support

**Problem:** 字典硬编码在 `scanner/data/`，用户不能用自己的

**Solution:** 加两个 CLI 参数：
```
--subdomain-wordlist PATH   自定义子域名字典
--dirscan-wordlist PATH     自定义路径字典
```

**Data flow:**
```
cli.py (argparse)
  → engine.py (run() 接收 wordlist_paths)
    → SubdomainModule(wordlist_path=...) / DirscanModule(wordlist_path=...)
```

**Existing interface already supports this:**
```python
class SubdomainModule(BaseModule):
    def __init__(self, wordlist_path=None):  # already exists
        self.wordlist_path = wordlist_path or _WORDLIST
```

**Files changed:**
- `scanner/cli.py` — add 2 arguments
- `scanner/core/engine.py` — `run()` signature adds `wordlists: dict`

## 3. tqdm Progress Bars

**Problem:** Text progress (`[*] DNS: 50/183 done`) not intuitive

**Solution:** Use tqdm library for progress bars in `-v` mode

**Design:**

`Output` gets two new methods:
```python
def create_progress_bar(self, desc, total):  # returns tqdm or dummy
def update_progress(self, bar, n=1):         # bar.update(n) or noop
```

Modules call:
```python
bar = output.create_progress_bar("DNS Resolving", len(prefixes))
for future in as_completed(futures):
    ...
    output.update_progress(bar)
bar.close()
```

**When `-v` is off or tqdm not installed:** `create_progress_bar` returns a dummy with `.update()` and `.close()` as no-ops. Current `[*] text` output keeps working.

**Files changed:**
- `scanner/core/output.py` — add `create_progress_bar`, `update_progress`
- `scanner/modules/subdomain.py` — replace `done % 50 == 0` prints
- `scanner/modules/dirscan.py` — same
- `setup.py` — add `tqdm` dependency

## 4. Non-Goals

- params module uses only 1 HTTP request so no progress bar needed
- tqdm is optional — if not installed, fall back to text progress
- Custom wordlist validation (check file exists, readable) — yes, basic check

## 5. Success Criteria

1. Chinese text displays correctly in Windows Terminal / Git Bash
2. `--subdomain-wordlist custom.txt` uses custom file, falls back to built-in
3. `--dirscan-wordlist custom.txt` same
4. `-v` shows tqdm progress bars; without `-v` shows nothing extra
5. All 13 existing tests still pass
