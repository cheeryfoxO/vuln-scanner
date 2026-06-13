"""HTTP request wrapper with UA rotation, retry, timeout, proxy, and rate limiting."""
import random
import re
import time

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

USER_AGENTS = [
    # Chrome on various platforms
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    # Firefox
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (X11; Linux i686; rv:125.0) Gecko/20100101 Firefox/125.0",
    # Safari
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    # Edge
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
    # Mobile
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.53 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 13; SM-S908B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6356.14 Mobile Safari/537.36",
    # Less common
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 OPR/110.0.0.0",
    "Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    # Slightly older versions for diversity
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
]

DEFAULT_TIMEOUT = 10
MAX_BACKOFF_RETRIES = 3
BACKOFF_BASE = 2.0  # seconds


def _parse_retry_after(headers):
    """Parse Retry-After header. Returns seconds to wait, or 0."""
    val = headers.get("Retry-After", "")
    if not val:
        return 0
    # Try integer seconds
    try:
        return int(val)
    except ValueError:
        pass
    # Try HTTP-date (unlikely but spec-compliant)
    try:
        from email.utils import parsedate_to_datetime
        from datetime import timezone
        retry_dt = parsedate_to_datetime(val)
        now = datetime.now(timezone.utc)
        return max(0, (retry_dt - now).total_seconds())
    except Exception:
        pass
    return 0


class RequestHandler:
    """Wraps requests.Session with UA rotation, retry, rate limiting, proxy.

    Args:
        timeout: Request timeout in seconds.
        max_retries: Number of retries on 5xx/429 via urllib3.
        delay: Delay in ms between requests (rate limiting).
        cookies: Cookie string or dict to attach to every request.
        extra_headers: Dict of extra headers to merge into every request.
        proxy: Proxy URL (e.g. 'http://127.0.0.1:8080').
    """

    def __init__(self, timeout=DEFAULT_TIMEOUT, max_retries=1,
                 delay=0, cookies=None, extra_headers=None, proxy=None):
        self.timeout = timeout
        self.delay = delay / 1000.0 if delay else 0  # ms → seconds
        self.session = requests.Session()

        # Proxy support
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}
            # Trust Burp/MITM proxy certs
            self.session.verify = False
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        # Always-attached cookies
        if cookies:
            if isinstance(cookies, str):
                for item in cookies.split(";"):
                    item = item.strip()
                    if "=" in item:
                        k, v = item.split("=", 1)
                        self.session.cookies.set(k.strip(), v.strip())
            elif isinstance(cookies, dict):
                for k, v in cookies.items():
                    self.session.cookies.set(k, v)

        # Always-merged extra headers
        self.extra_headers = extra_headers or {}
        self._last_request_time = 0.0

        retry_strategy = Retry(
            total=max_retries,
            backoff_factor=0.5,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "HEAD", "POST"],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

    def _random_ua(self):
        return random.choice(USER_AGENTS)

    def _throttle(self):
        """Enforce minimum delay between requests."""
        if self.delay > 0:
            now = time.perf_counter()
            since_last = now - self._last_request_time
            if since_last < self.delay:
                time.sleep(self.delay - since_last)

    def _prepare(self, kwargs):
        headers = kwargs.pop("headers", {})
        headers.setdefault("User-Agent", self._random_ua())
        # Merge extra_headers (caller's explicit headers take precedence)
        for k, v in self.extra_headers.items():
            headers.setdefault(k, v)
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("allow_redirects", True)
        kwargs["headers"] = headers
        return kwargs

    def _request_with_backoff(self, method, url, **kwargs):
        """Execute request with additional backoff for 429/503 after urllib3 retries."""
        for attempt in range(MAX_BACKOFF_RETRIES + 1):
            resp = method(url, **kwargs)
            if resp.status_code in (429, 503) and attempt < MAX_BACKOFF_RETRIES:
                retry_after = _parse_retry_after(resp.headers)
                wait = retry_after if retry_after > 0 else BACKOFF_BASE * (2 ** attempt)
                wait = min(wait, 60)  # cap at 60s
                time.sleep(wait)
                continue
            return resp
        return resp  # last attempt, return as-is

    def get(self, url, **kwargs):
        """GET request with automatic UA, rate limiting, and timeout."""
        self._throttle()
        resp = self._request_with_backoff(self.session.get, url, **self._prepare(kwargs))
        self._last_request_time = time.perf_counter()
        return resp

    def head(self, url, **kwargs):
        """HEAD request with automatic UA, rate limiting, and timeout."""
        self._throttle()
        resp = self._request_with_backoff(self.session.head, url, **self._prepare(kwargs))
        self._last_request_time = time.perf_counter()
        return resp

    def post(self, url, data=None, **kwargs):
        """POST request with automatic UA, rate limiting, and timeout."""
        self._throttle()
        resp = self._request_with_backoff(self.session.post, url, data=data, **self._prepare(kwargs))
        self._last_request_time = time.perf_counter()
        return resp
