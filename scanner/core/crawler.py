"""BFS crawler for discovering same-domain URLs."""
import re
import urllib.parse


def _extract_links(html, base_url):
    """Extract all unique href links from HTML, resolved to absolute URLs."""
    links = set()
    for match in re.finditer(r'<a[^>]*?href=["\']([^"\']+)["\']', html, re.I):
        href = match.group(1)
        # Skip anchors, javascript, mailto
        if href.startswith(('#', 'javascript:', 'mailto:', 'tel:')):
            continue
        full = urllib.parse.urljoin(base_url, href)
        # Remove fragment
        full = full.split('#')[0]
        if full.startswith(('http://', 'https://')):
            links.add(full)
    return list(links)


def _match_scope(url, scope):
    """Check if url matches the scope pattern.

    scope='*.example.com' matches sub.example.com, www.example.com, but NOT evil.com
    scope='example.com' matches example.com only
    scope=None matches everything (all domains)
    """
    if scope is None:
        return True
    parsed = urllib.parse.urlparse(url)
    host = parsed.netloc.lower()

    # Exact match
    if host == scope.lstrip('*.'):
        return True

    # Wildcard: *.example.com
    if scope.startswith('*.'):
        suffix = scope[1:]  # .example.com
        if host.endswith(suffix) or host == scope[2:]:
            return True

    return False


class Crawler:
    """BFS web crawler for discovering same-site URLs."""

    MAX_URLS = 200

    def crawl(self, seed_url, depth, scope, request_handler, output):
        """Crawl from seed_url, BFS up to `depth` levels.

        Args:
            seed_url: Starting URL.
            depth: Maximum crawl depth (1 = seed only).
            scope: Domain scope pattern.
            request_handler: RequestHandler instance.
            output: Output instance.

        Returns:
            List of discovered URLs (seed_url is always first).
        """
        if depth <= 1:
            return [seed_url]

        seed_domain = urllib.parse.urlparse(seed_url).netloc
        effective_scope = scope or f"*.{seed_domain}"

        visited = set()
        discovered = [seed_url]
        queue = [(seed_url, 0)]  # (url, current_depth)

        output.log_progress(
            f"Crawling from {seed_url} (depth={depth}, scope={effective_scope})"
        )

        while queue:
            url, current_depth = queue.pop(0)

            if url in visited:
                continue
            visited.add(url)

            if current_depth >= depth:
                continue

            # Stop if we've found enough
            if len(discovered) >= self.MAX_URLS:
                output.log_progress(f"Reached {self.MAX_URLS} URL limit, stopping crawl")
                break

            # Fetch and extract links
            try:
                resp = request_handler.get(url)
                links = _extract_links(resp.text, url)
            except Exception:
                continue

            for link in links:
                if link not in visited and _match_scope(link, effective_scope):
                    discovered.append(link)
                    queue.append((link, current_depth + 1))

        output.log_progress(
            f"Crawl done: {len(discovered)} URLs discovered"
        )
        return discovered
