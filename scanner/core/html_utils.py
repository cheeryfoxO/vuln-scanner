"""Shared HTML parsing and URL utilities for scanner modules."""
import urllib.parse
from html.parser import HTMLParser


class _FormParser(HTMLParser):
    """Extract form input names and URL parameter hints from HTML."""

    def __init__(self):
        super().__init__()
        self.input_names = set()
        self.param_hints = set()

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "input":
            name = attrs.get("name", "")
            if name:
                self.input_names.add(name)
        elif tag == "a":
            href = attrs.get("href", "")
            if "?" in href:
                parsed = urllib.parse.urlparse(href)
                for k in urllib.parse.parse_qs(parsed.query):
                    self.param_hints.add(k)


def _extract_params(target_url, html):
    """Extract parameter names from URL query string and HTML forms."""
    params = set()

    # From URL itself
    parsed = urllib.parse.urlparse(target_url)
    for k in urllib.parse.parse_qs(parsed.query):
        params.add(k)

    # From HTML forms/links
    parser = _FormParser()
    try:
        parser.feed(html)
    except Exception:
        pass
    params.update(parser.input_names)
    params.update(parser.param_hints)

    return list(params)


def _make_test_url(base_url, param_name, payload):
    """Replace or append a GET parameter with the payload value."""
    parsed = list(urllib.parse.urlparse(base_url))
    query = dict(urllib.parse.parse_qsl(parsed[4]))
    query[param_name] = payload
    parsed[4] = urllib.parse.urlencode(query)
    return urllib.parse.urlunparse(parsed)
