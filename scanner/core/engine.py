"""Scan engine -- module registry, execution orchestration, result aggregation."""
from datetime import datetime


class Engine:
    """Orchestrates module execution and collects results."""

    def __init__(self):
        self.modules = {}

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

    def run(self, target, module_names, request_handler, output, threads=10,
            scope=None, depth=1):
        """Execute specified modules against the target.

        Args:
            target: Domain or URL string
            module_names: List of module names, or ["all"]
            request_handler: RequestHandler instance
            output: Output instance
            threads: Concurrency hint (reserved for future use)
            scope: Domain scope pattern (e.g., '*.example.com')
            depth: Crawl depth (default 1, no recursion)

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
