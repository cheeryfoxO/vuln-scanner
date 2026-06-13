"""Tests for BFS crawler."""
from scanner.core.crawler import _extract_links, _match_scope, Crawler


class TestExtractLinks:
    def test_extracts_href_links(self):
        html = '<a href="/page1">1</a><a href="/page2">2</a>'
        links = _extract_links(html, "http://test.com")
        assert "http://test.com/page1" in links
        assert "http://test.com/page2" in links

    def test_skips_anchors(self):
        html = '<a href="#">top</a><a href="#section">sec</a>'
        links = _extract_links(html, "http://test.com")
        assert len(links) == 0

    def test_skips_javascript(self):
        html = '<a href="javascript:void(0)">x</a>'
        links = _extract_links(html, "http://test.com")
        assert len(links) == 0

    def test_resolves_relative_urls(self):
        html = '<a href="about">About</a>'
        links = _extract_links(html, "http://test.com/")
        assert "http://test.com/about" in links

    def test_strips_fragments(self):
        html = '<a href="/page#section">Page</a>'
        links = _extract_links(html, "http://test.com")
        assert "http://test.com/page" in links
        assert "#" not in links[0]


class TestMatchScope:
    def test_wildcard_matches_subdomain(self):
        assert _match_scope("http://sub.example.com/page", "*.example.com") is True

    def test_wildcard_matches_root(self):
        assert _match_scope("http://example.com/", "*.example.com") is True

    def test_wildcard_rejects_unrelated(self):
        assert _match_scope("http://evil.com/", "*.example.com") is False

    def test_exact_matches_only(self):
        assert _match_scope("http://example.com/", "example.com") is True
        assert _match_scope("http://sub.example.com/", "example.com") is False

    def test_none_scope_matches_all(self):
        assert _match_scope("http://evil.com/", None) is True


class TestCrawler:
    def test_depth_one_returns_seed_only(self):
        c = Crawler()
        urls = c.crawl("http://test.com", 1, None, None, None)
        assert urls == ["http://test.com"]

    def test_max_urls_limit(self):
        c = Crawler()
        # MAX_URLS is 200, so default request is well under
        assert c.MAX_URLS == 200
