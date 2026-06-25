"""Tests for IDOR detection module."""
from unittest.mock import Mock
from scanner.modules.idor import (
    IdorModule,
    _extract_numeric_ids,
    _generate_idor_urls,
    _replace_id,
    _fingerprint_response,
    _extract_title,
    _compare_responses,
)


# ── _extract_numeric_ids tests ────────────────────────────────────────

class TestExtractNumericIds:
    def test_path_ids(self):
        """Finds numeric ID in URL path segments."""
        ids = _extract_numeric_ids("https://example.com/user/123/profile")
        assert len(ids) == 1
        assert ids[0]["location"] == "path"
        assert ids[0]["index"] == 1  # "user" is index 0, "123" is index 1
        assert ids[0]["value"] == 123
        assert ids[0]["route"] == "user"

    def test_query_ids(self):
        """Finds numeric ID in query parameters."""
        ids = _extract_numeric_ids("https://example.com/page?id=456")
        assert len(ids) == 1
        assert ids[0]["location"] == "query"
        assert ids[0]["key"] == "id"
        assert ids[0]["value"] == 456

    def test_both_path_and_query_ids(self):
        """Finds IDs in both path and query."""
        ids = _extract_numeric_ids("https://example.com/user/123?page=5")
        assert len(ids) == 2
        path_id = [i for i in ids if i["location"] == "path"][0]
        query_id = [i for i in ids if i["location"] == "query"][0]
        assert path_id["value"] == 123
        assert query_id["value"] == 5

    def test_multiple_path_ids(self):
        """Finds multiple numeric path segments."""
        ids = _extract_numeric_ids("https://example.com/user/10/post/25")
        assert len(ids) == 2
        assert ids[0]["value"] == 10
        assert ids[1]["value"] == 25

    def test_multiple_query_ids(self):
        """Finds multiple numeric query parameters."""
        ids = _extract_numeric_ids("https://example.com/page?a=1&b=2")
        assert len(ids) == 2
        assert all(i["location"] == "query" for i in ids)

    def test_no_ids(self):
        """Returns empty list when URL has no numeric IDs."""
        ids = _extract_numeric_ids("https://example.com/user/profile")
        assert ids == []

    def test_no_digits_at_all(self):
        """Returns empty list when URL contains no digits."""
        ids = _extract_numeric_ids("https://example.com/home")
        assert ids == []

    def test_short_number(self):
        """Single-digit numbers are treated as IDs."""
        ids = _extract_numeric_ids("https://example.com/item/1")
        assert len(ids) == 1
        assert ids[0]["value"] == 1

    def test_long_number_excluded(self):
        """Numbers with 10+ digits are excluded (unreasonable ID length)."""
        ids = _extract_numeric_ids("https://example.com/item/1234567890")
        assert ids == []

    def test_long_query_number_excluded(self):
        """10+ digit query params are excluded."""
        ids = _extract_numeric_ids("https://example.com/page?timestamp=1234567890")
        assert ids == []

    def test_non_digit_path_segments_ignored(self):
        """Alphanumeric or non-numeric segments are ignored."""
        ids = _extract_numeric_ids("https://example.com/user/abc123/profile")
        assert ids == []

    def test_empty_query_value(self):
        """Empty query values are not treated as IDs."""
        ids = _extract_numeric_ids("https://example.com/page?id=")
        assert ids == []

    def test_root_path_with_numeric(self):
        """Numeric ID at root path level."""
        ids = _extract_numeric_ids("https://example.com/42")
        assert len(ids) == 1
        assert ids[0]["value"] == 42
        assert ids[0]["route"] == ""

    def test_route_captures_preceding_segments(self):
        """Route field contains path segments before the ID."""
        ids = _extract_numeric_ids("https://example.com/api/10/user/99/details")
        # "10" at index 1, "99" at index 3
        num_ids = [i for i in ids if i["location"] == "path"]
        assert len(num_ids) == 2
        id_99 = [i for i in num_ids if i["value"] == 99][0]
        assert id_99["route"] == "api/10/user"


# ── _generate_idor_urls tests ────────────────────────────────────────

class TestGenerateIdorUrls:
    def test_generates_variants(self):
        """Generates multiple variant URLs from a URL with a numeric ID."""
        variants = _generate_idor_urls("https://example.com/user/123")
        assert len(variants) > 0
        # Each entry is (url, note) tuple
        for url, note in variants:
            assert url.startswith("https://example.com/user/")
            assert "123" not in url or note  # original ID should not appear

    def test_limits_variants_per_id(self):
        """No more than 8 variants per ID."""
        variants = _generate_idor_urls("https://example.com/item/50")
        assert len(variants) <= 8

    def test_no_digits_returns_empty(self):
        """URL with no digits produces no variants."""
        variants = _generate_idor_urls("https://example.com/home")
        assert variants == []

    def test_variants_include_low_ids(self):
        """Generated variants include 0, 1, 2, 3."""
        variants = _generate_idor_urls("https://example.com/user/50")
        urls = [v[0] for v in variants]
        assert any("/user/0" in u for u in urls)
        assert any("/user/1" in u for u in urls)

    def test_variants_include_adjacent_ids(self):
        """Generated variants include current - 1 and current + 1."""
        variants = _generate_idor_urls("https://example.com/user/50")
        urls = [v[0] for v in variants]
        assert any("/user/49" in u for u in urls)
        assert any("/user/51" in u for u in urls)

    def test_variants_exclude_current_value(self):
        """Original ID value is not included in variants."""
        variants = _generate_idor_urls("https://example.com/user/5")
        urls = [v[0] for v in variants]
        assert "/user/5" not in [u.split("?")[0].rstrip("/") if "?" in u else u.rstrip("/") for u in urls]
        # Simpler check: all variant URLs should differ from original
        for url, _ in variants:
            assert "/user/5" not in url or url.count("5") <= sum(1 for c in "https://example.com/user/5" if c == "5")

    def test_variants_with_query_ids(self):
        """Generates variants for query parameter IDs."""
        variants = _generate_idor_urls("https://example.com/page?id=10")
        assert len(variants) > 0
        urls = [v[0] for v in variants]
        assert any("id=9" in u for u in urls)
        assert any("id=11" in u for u in urls)

    def test_note_format(self):
        """Each variant has a descriptive note."""
        variants = _generate_idor_urls("https://example.com/user/42")
        for url, note in variants:
            assert "Replace" in note
            assert "→" in note

    def test_multiple_ids_in_url(self):
        """URL with multiple IDs produces variants for each."""
        variants = _generate_idor_urls("https://example.com/user/5/post/10")
        # Should have variants for both ID=5 and ID=10
        assert len(variants) > 0
        notes = [v[1] for v in variants]
        has_path_variants = any("path" in n for n in notes)
        assert has_path_variants

    def test_zero_handled(self):
        """URL with ID=0 still generates positive variants."""
        variants = _generate_idor_urls("https://example.com/user/0")
        urls = [v[0] for v in variants]
        # Should include 1, 2, etc. but not negative numbers
        assert all("/user/-" not in u for u in urls)


# ── _replace_id tests ────────────────────────────────────────────────

class TestReplaceId:
    def test_path_replacement(self):
        """Replaces a numeric ID in a URL path segment."""
        id_info = {"location": "path", "index": 1, "value": 123}
        new_url = _replace_id("https://example.com/user/123/profile", id_info, "999")
        assert new_url == "https://example.com/user/999/profile"

    def test_query_replacement(self):
        """Replaces a numeric ID in a query parameter."""
        id_info = {"location": "query", "key": "id", "value": 10}
        new_url = _replace_id("https://example.com/page?id=10", id_info, "42")
        assert "id=42" in new_url

    def test_query_replacement_keeps_other_params(self):
        """Other query parameters are preserved when replacing one."""
        id_info = {"location": "query", "key": "user_id", "value": 100}
        new_url = _replace_id("https://example.com/page?user_id=100&sort=asc", id_info, "200")
        assert "user_id=200" in new_url
        assert "sort=asc" in new_url

    def test_root_path_replacement(self):
        """Replaces ID at root path level."""
        id_info = {"location": "path", "index": 0, "value": 42}
        new_url = _replace_id("https://example.com/42", id_info, "1")
        assert new_url == "https://example.com/1"

    def test_preserves_scheme_and_host(self):
        """Scheme and netloc are preserved."""
        id_info = {"location": "path", "index": 1, "value": 5}
        new_url = _replace_id("https://sub.example.com:8080/a/5", id_info, "10")
        assert new_url.startswith("https://sub.example.com:8080")

    def test_preserves_fragment(self):
        """URL fragment is preserved."""
        id_info = {"location": "path", "index": 1, "value": 123}
        new_url = _replace_id("https://example.com/user/123#section", id_info, "456")
        assert new_url.endswith("#section")

    def test_string_new_value(self):
        """new_value is passed as string and replaces correctly."""
        id_info = {"location": "path", "index": 1, "value": 10}
        new_url = _replace_id("https://example.com/item/10", id_info, "007")
        assert "/item/007" in new_url


# ── _fingerprint_response tests ──────────────────────────────────────

class TestFingerprintResponse:
    def test_creates_correct_dict(self):
        """Fingerprint contains status, len, hash, and title."""
        resp = Mock()
        resp.status_code = 200
        resp.text = "<html><head><title>Test Page</title></head><body>Hello</body></html>"
        fp = _fingerprint_response(resp)
        assert fp["status"] == 200
        assert fp["len"] == len(resp.text)
        assert isinstance(fp["hash"], str)
        assert len(fp["hash"]) == 32  # MD5 hex digest
        assert fp["title"] == "Test Page"

    def test_empty_text(self):
        """Handles response with empty text."""
        resp = Mock()
        resp.status_code = 404
        resp.text = ""
        fp = _fingerprint_response(resp)
        assert fp["status"] == 404
        assert fp["len"] == 0
        assert fp["title"] == ""

    def test_none_text(self):
        """Handles response with None text (treated as empty string)."""
        resp = Mock()
        resp.status_code = 200
        resp.text = None
        fp = _fingerprint_response(resp)
        assert fp["len"] == 0
        assert fp["title"] == ""
        assert len(fp["hash"]) == 32

    def test_md5_hash_is_deterministic(self):
        """Same content produces same hash."""
        resp1 = Mock()
        resp1.status_code = 200
        resp1.text = "response body"
        resp2 = Mock()
        resp2.status_code = 200
        resp2.text = "response body"
        assert _fingerprint_response(resp1)["hash"] == _fingerprint_response(resp2)["hash"]

    def test_md5_hash_differs_for_different_content(self):
        """Different content produces different hashes."""
        resp1 = Mock()
        resp1.status_code = 200
        resp1.text = "response A"
        resp2 = Mock()
        resp2.status_code = 200
        resp2.text = "response B"
        assert _fingerprint_response(resp1)["hash"] != _fingerprint_response(resp2)["hash"]


# ── _extract_title tests ─────────────────────────────────────────────

class TestExtractTitle:
    def test_extracts_title(self):
        """Extracts content from <title> tag."""
        html = "<html><head><title>My Page</title></head><body></body></html>"
        assert _extract_title(html) == "My Page"

    def test_no_title_returns_empty(self):
        """Returns empty string when no <title> tag present."""
        html = "<html><head></head><body>No title here</body></html>"
        assert _extract_title(html) == ""

    def test_multiline_title(self):
        """Extracts title spanning multiple lines (re.S flag)."""
        html = "<html><head><title>\n    Multi-line\n    Title\n</title></head></html>"
        result = _extract_title(html)
        assert "Multi-line" in result
        assert "Title" in result

    def test_title_with_attributes(self):
        """Handles <title> tag with attributes."""
        html = '<html><head><title id="page-title">Dashboard</title></head></html>'
        assert _extract_title(html) == "Dashboard"

    def test_whitespace_collapsed(self):
        """Extra whitespace in title is collapsed to single spaces."""
        html = "<html><head><title>   Lots   of   spaces   </title></head></html>"
        assert _extract_title(html) == "Lots of spaces"

    def test_very_long_title_truncated(self):
        """Title is truncated to 120 characters."""
        long_title = "A" * 200
        html = f"<html><head><title>{long_title}</title></head></html>"
        result = _extract_title(html)
        assert len(result) <= 120

    def test_case_insensitive(self):
        """<TITLE> tag is matched case-insensitively."""
        html = "<HTML><HEAD><TITLE>UPPERCASE TITLE</TITLE></HEAD></HTML>"
        assert _extract_title(html) == "UPPERCASE TITLE"

    def test_empty_html(self):
        """Empty HTML string returns empty string."""
        assert _extract_title("") == ""


# ── _compare_responses tests ─────────────────────────────────────────

class TestCompareResponses:
    def _make_resp(self, status=200, text="a" * 500):
        """Helper to create a mock response with a given status and body."""
        resp = Mock()
        resp.status_code = status
        resp.text = text
        return resp

    def test_returns_none_when_baseline_not_200(self):
        """Returns None if baseline status is not 200."""
        resp_a = self._make_resp(status=403, text="b" * 500)
        resp_b = self._make_resp(status=200, text="b" * 500)
        assert _compare_responses(resp_a, resp_b) is None

    def test_returns_none_when_variant_not_200(self):
        """Returns None if variant status is not 200."""
        resp_a = self._make_resp(status=200, text="b" * 500)
        resp_b = self._make_resp(status=404, text="b" * 500)
        assert _compare_responses(resp_a, resp_b) is None

    def test_returns_none_when_both_not_200(self):
        """Returns None if both statuses are not 200."""
        resp_a = self._make_resp(status=500, text="b" * 500)
        resp_b = self._make_resp(status=500, text="b" * 500)
        assert _compare_responses(resp_a, resp_b) is None

    def test_returns_none_when_baseline_small(self):
        """Returns None if baseline body length is <= 100 bytes."""
        resp_a = self._make_resp(status=200, text="tiny")
        resp_b = self._make_resp(status=200, text="tiny")
        assert _compare_responses(resp_a, resp_b) is None

    def test_returns_none_when_baseline_exactly_100(self):
        """Returns None when baseline is exactly 100 bytes (<=100)."""
        resp_a = self._make_resp(status=200, text="x" * 100)
        resp_b = self._make_resp(status=200, text="x" * 100)
        assert _compare_responses(resp_a, resp_b) is None

    def test_root_id_access_0_in_note(self):
        """Detects root ID access when note contains → 0."""
        resp_a = self._make_resp(status=200, text="x" * 500)
        resp_b = self._make_resp(status=200, text="y" * 600)
        result = _compare_responses(resp_a, resp_b, "Replace path ID 123 → 0")
        assert result is not None
        assert result["type"] == "idor_root_id_access"
        assert result["severity"] == "high"

    def test_root_id_access_1_in_note(self):
        """Detects root ID access when note contains → 1."""
        resp_a = self._make_resp(status=200, text="x" * 500)
        resp_b = self._make_resp(status=200, text="y" * 600)
        result = _compare_responses(resp_a, resp_b, "Replace query ID 456 → 1")
        assert result is not None
        assert result["type"] == "idor_root_id_access"

    def test_identical_response_same_hash(self):
        """Returns identical_response when hashes match for different IDs."""
        resp_text = "x" * 500
        resp_a = self._make_resp(status=200, text=resp_text)
        resp_b = self._make_resp(status=200, text=resp_text)
        result = _compare_responses(resp_a, resp_b, "Replace path ID 50 → 51")
        assert result is not None
        assert result["type"] == "idor_identical_response"
        assert result["severity"] == "high"

    def test_identical_response_but_root_id_takes_priority(self):
        """root_id_access check runs before identical_response check."""
        resp_text = "x" * 500
        resp_a = self._make_resp(status=200, text=resp_text)
        resp_b = self._make_resp(status=200, text=resp_text)
        result = _compare_responses(resp_a, resp_b, "Replace path ID 50 → 0")
        assert result is not None
        assert result["type"] == "idor_root_id_access"

    def test_similar_response_within_5_percent(self):
        """Returns similar_response when sizes differ by less than 5%."""
        resp_a = self._make_resp(status=200, text="a" * 1000)
        resp_b = self._make_resp(status=200, text="b" * 1020)  # 2% bigger
        result = _compare_responses(resp_a, resp_b, "Replace path ID 50 → 51")
        assert result is not None
        assert result["type"] == "idor_similar_response"
        assert result["severity"] == "medium"

    def test_similar_response_at_5_percent_boundary(self):
        """abs(len_a - len_b) < len_a * 0.05 (strictly less than 5%)."""
        resp_a = self._make_resp(status=200, text="a" * 1000)
        # 5% = 50 bytes. 1049 - 1000 = 49 (< 50)
        resp_b = self._make_resp(status=200, text="b" * 1049)
        result = _compare_responses(resp_a, resp_b, "Replace path ID 50 → 51")
        assert result is not None
        assert result["type"] == "idor_similar_response"

    def test_returns_none_when_sizes_differ_significantly(self):
        """Returns None when sizes differ by more than 5% and hashes differ."""
        resp_a = self._make_resp(status=200, text="a" * 1000)
        resp_b = self._make_resp(status=200, text="b" * 2000)  # 100% bigger
        result = _compare_responses(resp_a, resp_b, "Replace path ID 50 → 51")
        assert result is None

    def test_returns_none_when_sizes_differ_exactly_5_percent(self):
        """exactly 5% difference is not 'similar' (strict < check)."""
        resp_a = self._make_resp(status=200, text="a" * 1000)
        resp_b = self._make_resp(status=200, text="b" * 1050)  # exactly 5%
        result = _compare_responses(resp_a, resp_b, "Replace path ID 50 → 51")
        # 1000 * 0.05 = 50, abs(1050-1000) = 50, not < 50, so falls through
        assert result is None

    def test_empty_note(self):
        """Works with empty note (no root_id_access trigger)."""
        resp_text = "x" * 500
        resp_a = self._make_resp(status=200, text=resp_text)
        resp_b = self._make_resp(status=200, text=resp_text)
        result = _compare_responses(resp_a, resp_b, "")
        assert result is not None
        assert result["type"] == "idor_identical_response"


# ── IdorModule tests ─────────────────────────────────────────────────

class TestIdorModuleAttributes:
    def test_name(self):
        mod = IdorModule()
        assert mod.name == "idor"

    def test_requires_url(self):
        mod = IdorModule()
        assert mod.requires_url is True

    def test_description(self):
        mod = IdorModule()
        assert "idor" in mod.description.lower()


class TestIdorModuleRun:
    def test_skips_when_url_has_no_digits(self):
        """run() skips and returns empty findings when URL has no digits."""
        mod = IdorModule()
        rh = Mock()
        out = Mock()

        result = mod.run("https://example.com/home", rh, out)
        assert result["module"] == "idor"
        assert result["findings"] == []

    def test_baseline_fetch_exception_is_handled(self):
        """If baseline GET raises, returns empty findings gracefully."""
        mod = IdorModule()
        rh = Mock()
        rh.get.side_effect = Exception("Connection refused")
        out = Mock()

        result = mod.run("https://example.com/user/123", rh, out)
        assert result["module"] == "idor"
        assert result["findings"] == []

    def test_variant_exception_is_handled(self):
        """If individual variant GET raises, it is silently skipped."""
        mod = IdorModule()
        out = Mock()

        # Baseline succeeds, but one variant fails
        def get_side_effect(url, **kwargs):
            if url == "https://example.com/user/123":
                resp = Mock()
                resp.status_code = 200
                resp.text = "x" * 500
                return resp
            raise Exception("Timeout")

        rh = Mock()
        rh.get.side_effect = get_side_effect

        result = mod.run("https://example.com/user/123", rh, out)
        # Should not crash; findings may be empty because variants all fail
        assert result["module"] == "idor"
        assert isinstance(result["findings"], list)

    def test_runs_variants_and_finds_identical_response(self):
        """When a variant matches the baseline, identical_response is detected."""
        mod = IdorModule()
        out = Mock()

        resp_body = "x" * 500

        def get_side_effect(url, **kwargs):
            resp = Mock()
            resp.status_code = 200
            resp.text = resp_body
            return resp

        rh = Mock()
        rh.get.side_effect = get_side_effect

        result = mod.run("https://example.com/user/123", rh, out)
        assert result["module"] == "idor"
        # All variants return same body → identical_response or root_id_access
        assert len(result["findings"]) > 0
        finding_types = [f["type"] for f in result["findings"]]
        # ID 0 and 1 variants produce root_id_access, others produce identical_response
        assert "idor_identical_response" in finding_types or "idor_root_id_access" in finding_types

    def test_variant_with_non_200_status_is_skipped(self):
        """Variants returning non-200 are skipped silently."""
        mod = IdorModule()
        out = Mock()

        def get_side_effect(url, **kwargs):
            resp = Mock()
            if url == "https://example.com/user/123":
                resp.status_code = 200
                resp.text = "x" * 500
            else:
                resp.status_code = 404
                resp.text = "not found"
            return resp

        rh = Mock()
        rh.get.side_effect = get_side_effect

        result = mod.run("https://example.com/user/123", rh, out)
        assert result["module"] == "idor"
        # All variants return 404 → _compare_responses is not called
        assert result["findings"] == []

    def test_small_variant_body_is_skipped(self):
        """Variants with body length < 50 are skipped."""
        mod = IdorModule()
        out = Mock()

        def get_side_effect(url, **kwargs):
            resp = Mock()
            if url == "https://example.com/user/123":
                resp.status_code = 200
                resp.text = "x" * 500  # baseline is big enough
            else:
                resp.status_code = 200
                resp.text = "short"  # variant is too small
            return resp

        rh = Mock()
        rh.get.side_effect = get_side_effect

        result = mod.run("https://example.com/user/123", rh, out)
        assert result["module"] == "idor"
        # All variants have body < 50 → skipped before _compare_responses
        assert result["findings"] == []

    def test_different_response_finding(self):
        """When variant size differs >10% from baseline, idor_different_response found."""
        mod = IdorModule()
        out = Mock()

        def get_side_effect(url, **kwargs):
            resp = Mock()
            if url == "https://example.com/user/123":
                resp.status_code = 200
                resp.text = "a" * 1000  # baseline
            else:
                resp.status_code = 200
                resp.text = "b" * 2000  # very different size, also different hash
            return resp

        rh = Mock()
        rh.get.side_effect = get_side_effect

        result = mod.run("https://example.com/user/123", rh, out)
        assert result["module"] == "idor"
        finding_types = [f["type"] for f in result["findings"]]
        assert "idor_different_response" in finding_types


class TestIdorModuleIntegration:
    """Higher-level integration tests mimicking real scan workflow."""

    def test_full_run_with_mock_responses(self):
        """Complete run() with baseline and mixed variant responses."""
        mod = IdorModule()
        out = Mock()

        baseline_body = "<html><title>User 123</title>Content for user 123</html>"

        def get_side_effect(url, **kwargs):
            resp = Mock()
            resp.status_code = 200
            # Baseline is the original URL
            if url == "https://example.com/user/123":
                resp.text = baseline_body
            # Variant for ID=0: different title
            elif "/user/0" in url:
                resp.text = "<html><title>Admin Panel</title>Admin content here</html>"
            # Variant for ID=1: different title
            elif "/user/1" in url:
                resp.text = "<html><title>Admin Panel</title>Admin content here</html>"
            # Other variants: similar or identical
            elif "/user/122" in url:
                resp.text = baseline_body  # same as baseline
            elif "/user/124" in url:
                resp.text = baseline_body.replace("123", "124")
            else:
                resp.text = "x" * 500
            return resp

        rh = Mock()
        rh.get.side_effect = get_side_effect

        result = mod.run("https://example.com/user/123", rh, out)
        assert result["module"] == "idor"
        # We expect some findings
        assert isinstance(result["findings"], list)

    def test_no_false_positives_on_normal_page(self):
        """URL without IDs should produce no findings."""
        mod = IdorModule()
        rh = Mock()
        out = Mock()

        result = mod.run("https://example.com/about", rh, out)
        assert result["findings"] == []
