"""Shared HTML parsing and URL utilities for scanner modules."""
import urllib.parse
from html.parser import HTMLParser


class _FormParser(HTMLParser):
    """Extract form input names and URL parameter hints from HTML."""

    def __init__(self):
        super().__init__()
        self.input_names = set()
        self.param_hints = set()
        self.post_params = set()
        self._current_form_method = "GET"

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "form":
            self._current_form_method = attrs.get("method", "GET").upper()
        elif tag == "input":
            name = attrs.get("name", "")
            if name:
                if self._current_form_method == "POST":
                    self.post_params.add(name)
                else:
                    self.input_names.add(name)
        elif tag == "a":
            href = attrs.get("href", "")
            if "?" in href:
                parsed = urllib.parse.urlparse(href)
                for k in urllib.parse.parse_qs(parsed.query):
                    self.param_hints.add(k)


def _extract_params(target_url, html):
    """Extract parameter names from URL query string and HTML forms.

    Returns list of dicts: [{"name": str, "method": "GET"|"POST"}, ...]
    POST takes precedence when a param appears in both GET and POST contexts.
    """
    result = {}

    # From URL itself → GET
    parsed = urllib.parse.urlparse(target_url)
    for k in urllib.parse.parse_qs(parsed.query):
        result.setdefault(k, "GET")

    # From HTML forms/links
    parser = _FormParser()
    try:
        parser.feed(html)
    except Exception:
        pass

    for name in parser.input_names:
        result.setdefault(name, "GET")
    for name in parser.param_hints:
        result.setdefault(name, "GET")
    for name in parser.post_params:
        result[name] = "POST"  # POST takes precedence

    return [{"name": k, "method": v} for k, v in result.items()]


def _make_test_url(base_url, param_name, payload):
    """Replace or append a GET parameter with the payload value."""
    parsed = list(urllib.parse.urlparse(base_url))
    query = dict(urllib.parse.parse_qsl(parsed[4]))
    query[param_name] = payload
    parsed[4] = urllib.parse.urlencode(query)
    return urllib.parse.urlunparse(parsed)
