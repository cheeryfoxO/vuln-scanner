"""Scan engine -- module registry, concurrent execution, checkpoint/resume."""
import inspect
import json
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

from scanner.core.crawler import Crawler
from scanner.core.poc import inject_poc_into_finding

# Modules that don't send attack payloads — safe to run in parallel
NON_INVASIVE = {"subdomain", "dirscan", "params", "headers", "cors", "csrf", "fingerprint", "js_endpoints", "s3"}


class Engine:
    """Orchestrates module execution and collects results."""

    def __init__(self):
        self.modules = {}
        self.discovered_urls = []

    def register(self, module):
        """Register a module instance."""
        self.modules[module.name] = module

    def list_modules(self):
        """Return {name: description} for all registered modules."""
        return {name: mod.description for name, mod in self.modules.items()}

    def _normalize_target(self, target, module):
        """Ensure target has http:// if module needs a URL, strip protocol otherwise."""
        has_scheme = target.startswith("http://") or target.startswith("https://")
        if module.requires_url and not has_scheme:
            return f"http://{target}"
        if not module.requires_url:
            return target.replace("https://", "").replace("http://", "").rstrip("/")
        return target

    @staticmethod
    def _checkpoint_path(output_path):
        """Derive checkpoint file path from JSON output path."""
        if not output_path:
            return None
        base = os.path.splitext(output_path)[0]
        return f"{base}.checkpoint.json"

    def _load_checkpoint(self, checkpoint_path):
        """Load completed module names from checkpoint file. Returns set or empty set."""
        if not checkpoint_path or not os.path.exists(checkpoint_path):
            return set()
        try:
            with open(checkpoint_path, encoding="utf-8") as f:
                data = json.load(f)
            completed = set(data.get("completed_modules", []))
            self.discovered_urls = data.get("discovered_urls", [])
            return completed
        except (json.JSONDecodeError, KeyError):
            return set()

    def _save_checkpoint(self, checkpoint_path, completed_modules):
        """Save progress checkpoint so scan can be resumed."""
        if not checkpoint_path:
            return
        data = {
            "saved_at": datetime.now().isoformat(),
            "completed_modules": sorted(completed_modules),
            "discovered_urls": self.discovered_urls,
        }
        os.makedirs(os.path.dirname(checkpoint_path) or ".", exist_ok=True)
        with open(checkpoint_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    def _run_module(self, mod, normalized, request_handler, output, threads):
        """Execute a single module, passing threads if supported."""
        sig = inspect.signature(mod.run)
        if "threads" in sig.parameters:
            return mod.run(normalized, request_handler, output, threads=threads)
        return mod.run(normalized, request_handler, output)

    def _run_group(self, names, target, request_handler, output, threads,
                   skipped, all_findings, modules_ran, checkpoint_path):
        """Run a group of modules concurrently."""
        if not names:
            return

        # Cookie/header context for PoC generation
        cookies = getattr(request_handler, 'cookies_str', None) or getattr(request_handler, 'extra_headers', {})
        extra_hdrs = getattr(request_handler, 'extra_headers', {}) or {}

        # Build future → name map
        futures_map = {}
        with ThreadPoolExecutor(max_workers=min(threads, len(names))) as pool:
            for name in names:
                mod = self.modules[name]
                normalized = self._normalize_target(target, mod)
                futures_map[pool.submit(
                    self._run_module, mod, normalized, request_handler, output, threads
                )] = name

            for future in as_completed(futures_map):
                name = futures_map[future]
                try:
                    result = future.result()
                    findings = result["findings"]
                    # Inject reproducible PoC into each finding
                    for f in findings:
                        inject_poc_into_finding(
                            f, name,
                            cookies=cookies if isinstance(cookies, str) else None,
                            extra_headers=extra_hdrs,
                            target=target,
                        )
                    all_findings[result["module"]] = findings
                    modules_ran.append(name)
                    output.log_progress(f"[OK] {name} complete")
                except Exception as e:
                    output.log_progress(f"Module {name} failed: {e}")

                # Checkpoint after each module
                self._save_checkpoint(checkpoint_path, set(modules_ran))

    def run(self, target, module_names, request_handler, output, threads=10,
            scope=None, depth=1, resume=None):
        """Execute specified modules against the target.

        Args:
            target: Domain or URL string.
            module_names: List of module names, or ["all"].
            request_handler: RequestHandler instance.
            output: Output instance.
            threads: Concurrency — max concurrent modules.
            scope: Domain scope pattern (e.g., '*.example.com').
            depth: Crawl depth (default 1, no recursion).
            resume: Path to JSON output for checkpoint resume.

        Returns:
            Report dict with target, scan_time, modules, findings.
        """
        if "all" in module_names:
            names_to_run = list(self.modules.keys())
        else:
            names_to_run = [n for n in module_names if n in self.modules]

        # ── Resume logic ──────────────────────────────────────────
        checkpoint_path = self._checkpoint_path(resume or getattr(output, "json_path", None))
        completed = self._load_checkpoint(checkpoint_path)

        skipped = [n for n in names_to_run if n in completed]
        pending = [n for n in names_to_run if n not in completed]
        if skipped:
            output.log_progress(
                f"Resume: skipping {len(skipped)} completed modules: {skipped}"
            )
        output.log_progress(f"Modules to run: {pending}")

        # ── Phase 0: Crawl (skip if resuming with urls already) ──
        if not self.discovered_urls and depth > 1:
            crawler = Crawler()
            normalized_target = target.rstrip("/")
            if not normalized_target.startswith("http"):
                normalized_target = f"http://{normalized_target}"
            self.discovered_urls = crawler.crawl(
                normalized_target, depth, scope, request_handler, output
            )

        all_findings = {}
        modules_ran = list(skipped)  # credit previously completed modules

        # ── Phase 1: Non-invasive modules (concurrent) ────────────
        non_invasive = [n for n in pending if n in NON_INVASIVE]
        invasive = [n for n in pending if n not in NON_INVASIVE]

        output.log_progress(
            f"Phase 1: non-invasive modules ({len(non_invasive)} concurrent)"
        )
        self._run_group(
            non_invasive, target, request_handler, output, threads,
            skipped, all_findings, modules_ran, checkpoint_path
        )

        # ── Phase 2: Invasive modules (concurrent) ────────────────
        output.log_progress(
            f"Phase 2: invasive modules ({len(invasive)} concurrent)"
        )
        self._run_group(
            invasive, target, request_handler, output, threads,
            skipped, all_findings, modules_ran, checkpoint_path
        )

        report = {
            "scan_time": datetime.now().isoformat(),
            "target": target,
            "modules": modules_ran,
            "findings": all_findings,
        }
        if self.discovered_urls:
            report["discovered_urls"] = len(self.discovered_urls)

        # Clean checkpoint on successful full run
        if checkpoint_path and os.path.exists(checkpoint_path):
            os.remove(checkpoint_path)

        return report
