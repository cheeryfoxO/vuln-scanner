"""Subdomain enumeration -- DNS resolution + HTTP liveness check."""
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

    def __init__(self, wordlist_path=None):
        self.wordlist_path = wordlist_path or _WORDLIST

    def _load_wordlist(self):
        path = os.path.normpath(self.wordlist_path)
        with open(path, encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip()]

    def _resolve(self, hostname):
        """Return list of IPv4 addresses for a hostname."""
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
            bar = output.create_progress_bar("DNS Resolving", len(prefixes))
            for future in as_completed(futures):
                ips = future.result()
                if ips:
                    prefix = futures[future]
                    resolved.append((f"{prefix}.{target}", ips[0]))
                output.update_progress(bar)
            bar.close()

        output.log_progress(f"DNS complete: {len(resolved)} subdomains resolved, checking HTTP...")

        # Phase 2: HTTP liveness (20 concurrent workers)
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
