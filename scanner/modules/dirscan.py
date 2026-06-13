"""Directory/file scanning -- HTTP HEAD probe with 404 baseline filtering."""
import os
import re
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin

from scanner.modules.base import BaseModule

_WORDLIST = os.path.join(os.path.dirname(__file__), "..", "data", "dirs.txt")

# ── Content Fingerprinting ─────────────────────────────────────────

_SENSITIVE_PATTERNS = [
    (r"DB_PASSWORD\s*=\s*['\"]?\S{3,}['\"]?", "DB密码泄露", "high"),
    (r"(?:SECRET_KEY|API_KEY|JWT_SECRET|AUTH_KEY|APP_KEY)\s*=\s*['\"]\S{6,}['\"]", "密钥泄露", "critical"),
    (r"AWS_(?:ACCESS_KEY_ID|SECRET_ACCESS_KEY)\s*=\s*['\"]?\S{6,}['\"]?", "AWS凭证", "critical"),
    (r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----", "私钥文件", "critical"),
    (r"--\s+MySQL\s+dump\s+", "MySQL数据库转储", "high"),
    (r"CREATE\s+TABLE\s+`?\w+`?\s*\(", "数据库表结构泄露", "high"),
    (r"\$db_(?:host|name|user|pass|password)\s*=\s*['\"]\S+['\"]", "PHP数据库配置", "high"),
    (r"(?:password|passwd)\s*[:=]\s*['\"]\S{6,}['\"]", "密码明文", "high"),
    (r"define\s*\(\s*['\"]DB_PASSWORD['\"]", "WordPress DB配置", "high"),
    (r"(?:mongodb|redis|mysql)://[^:]+:[^@]+@", "数据库连接字符串", "critical"),
]


def _check_content(url, request_handler):
    """GET a file and check for sensitive content fingerprints.

    Args:
        url: Full URL to fetch.
        request_handler: RequestHandler instance.

    Returns:
        {"label": str, "severity": str, "pattern": str} or None.
    """
    try:
        resp = request_handler.get(url, timeout=5)
        for pattern, label, severity in _SENSITIVE_PATTERNS:
            if re.search(pattern, resp.text, re.IGNORECASE):
                return {"label": label, "severity": severity, "pattern": pattern}
    except Exception:
        pass
    return None


class DirscanModule(BaseModule):
    name = "dirscan"
    description = "Scan for sensitive directories and files via HTTP HEAD"
    requires_url = True

    def __init__(self, wordlist_path=None):
        self.wordlist_path = wordlist_path or _WORDLIST

    def _load_wordlist(self):
        path = os.path.normpath(self.wordlist_path)
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

        output.log_progress(f"Phase 1 done: {len(findings)} accessible paths found")

        # Phase 2: Content fingerprinting for 2xx findings
        content_targets = [f for f in findings if 200 <= f["status"] < 300]
        if content_targets:
            output.log_progress(
                f"Phase 2: Checking content of {len(content_targets)} accessible files..."
            )
            for finding in content_targets:
                match = _check_content(finding["url"], request_handler)
                if match:
                    finding["severity"] = match["severity"]
                    finding["sensitive"] = match["label"]
                    finding["evidence"] = f"Pattern '{match['pattern']}' matched — {match['label']}"
                    output.log_progress(
                        f"  [{match['severity'].upper()}] {finding['url']} — {match['label']}"
                    )

        elevated = sum(1 for f in findings if "severity" in f)
        output.log_progress(
            f"Dirscan done: {len(findings)} found, {elevated} with sensitive content"
        )
        return {"module": self.name, "findings": findings}
