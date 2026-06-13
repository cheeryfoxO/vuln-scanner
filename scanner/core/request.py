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
