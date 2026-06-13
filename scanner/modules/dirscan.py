"""Directory/file scanning -- HTTP HEAD probe with 404 baseline filtering."""
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
        """Request a random non-existent path to learn 404 behavior."""
        random_path = f"nonexistent-{uuid.uuid4().hex[:8]}.html"
        url = urljoin(base_url, random_path)
        try:
            resp = request_handler.head(url)
            return resp.status_code, len(resp.text or "")
        except Exception:
            return None, None

    def _probe(self, url, request_handler, baseline_status, baseline_length):
        """Probe a single path. Returns finding dict or None if filtered."""
        try:
            resp = request_handler.head(url)
            code = resp.status_code

            # Filter 404 false positives using baseline
            if baseline_status is not None:
                if code == baseline_status and code == 404:
                    body_len = len(resp.text or "")
                    if body_len == baseline_length:
                        return None

            content_type = resp.headers.get("Content-Type", "")
            content_length = resp.headers.get("Content-Length", "")
            try:
                size = int(content_length) if content_length else 0
            except ValueError:
                size = 0

            return {"url": resp.url, "status": code, "size": size, "content_type": content_type}
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
