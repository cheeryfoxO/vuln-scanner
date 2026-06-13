"""HTTP request wrapper with UA rotation, retry, timeout, and rate limiting."""
import random
import time

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
    """Wraps requests.Session with UA rotation, retry, rate limiting.

    Args:
        timeout: Request timeout in seconds.
        max_retries: Number of retries on 5xx/429.
        delay: Delay in ms between requests (rate limiting).
        cookies: Cookie string or dict to attach to every request.
        extra_headers: Dict of extra headers to merge into every request.
    """

    def __init__(self, timeout=DEFAULT_TIMEOUT, max_retries=1,
                 delay=0, cookies=None, extra_headers=None):
        self.timeout = timeout
        self.delay = delay / 1000.0 if delay else 0  # ms → seconds
        self.session = requests.Session()

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
            allowed_methods=["GET", "HEAD"],
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

    def get(self, url, **kwargs):
        """GET request with automatic UA, rate limiting, and timeout."""
        self._throttle()
        resp = self.session.get(url, **self._prepare(kwargs))
        self._last_request_time = time.perf_counter()
        return resp

    def head(self, url, **kwargs):
        """HEAD request with automatic UA, rate limiting, and timeout."""
        self._throttle()
        resp = self.session.head(url, **self._prepare(kwargs))
        self._last_request_time = time.perf_counter()
        return resp

    def post(self, url, data=None, **kwargs):
        """POST request with automatic UA, rate limiting, and timeout."""
        self._throttle()
        resp = self.session.post(url, data=data, **self._prepare(kwargs))
        self._last_request_time = time.perf_counter()
        return resp
