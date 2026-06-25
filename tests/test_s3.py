"""Tests for cloud storage bucket enumeration module."""
from scanner.modules.s3 import (
    _generate_bucket_names,
    _classify_response,
    S3Module,
)


class TestGenerateBucketNames:
    """Test bucket name candidate generation from domains."""

    def test_basic_domain(self):
        names = _generate_bucket_names("example.com")
        assert "example" in names
        assert "example-com" in names
        assert "example-backup" in names
        assert "example-prod" in names
        assert len(names) > 5

    def test_includes_suffixed_patterns(self):
        names = _generate_bucket_names("example.com")
        assert "example-assets" in names
        assert "example-static" in names
        assert "example-media" in names
        assert "example-files" in names
        assert "example-data" in names
        assert "example-logs" in names

    def test_includes_domain_with_dots(self):
        names = _generate_bucket_names("example.com")
        assert "example.com" in names

    def test_subdomain_multi_part(self):
        names = _generate_bucket_names("sub.example.com")
        assert "sub" in names
        # Should also include base parts
        assert "sub-example-com" in names

    def test_capped_at_50(self):
        names = _generate_bucket_names("a.b.c.d.e.f.example.com")
        assert len(names) <= 50

    def test_no_duplicates(self):
        names = _generate_bucket_names("example.com")
        assert len(names) == len(set(names))

    def test_empty_domain_returns_empty(self):
        names = _generate_bucket_names("")
        assert names == []

    def test_no_dot_returns_empty(self):
        names = _generate_bucket_names("nodot")
        assert names == []

    def test_result_is_sorted(self):
        names = _generate_bucket_names("example.com")
        assert names == sorted(names)


class TestClassifyResponse:
    """Test response classification logic for different cloud providers."""

    # ── AWS S3 ──────────────────────────────────────────────

    def test_aws_public_listing_critical(self):
        severity, desc = _classify_response(
            200, "<ListBucketResult><Contents><Key>file.txt</Key></Contents></ListBucketResult>", "AWS"
        )
        assert severity == "critical"
        assert "public" in desc.lower()

    def test_aws_access_denied_high(self):
        severity, desc = _classify_response(
            403, "<Error><Code>AccessDenied</Code></Error>", "AWS"
        )
        assert severity == "high"
        assert "access denied" in desc.lower()

    def test_aws_access_denied_body_only(self):
        """AccessDenied in body even with non-403 status."""
        severity, desc = _classify_response(
            200, "<Error><Code>AccessDenied</Code></Error>", "AWS"
        )
        assert severity == "high"

    def test_aws_no_such_bucket_info(self):
        severity, desc = _classify_response(
            404, "<Error><Code>NoSuchBucket</Code></Error>", "AWS"
        )
        assert severity == "info"
        assert "does not exist" in desc.lower()

    def test_aws_404_no_body(self):
        severity, desc = _classify_response(404, "", "AWS")
        assert severity == "info"

    def test_aws_other_200_medium(self):
        severity, desc = _classify_response(200, "<html>Welcome</html>", "AWS")
        assert severity == "medium"

    # ── GCP ──────────────────────────────────────────────────

    def test_gcp_access_denied_high(self):
        severity, desc = _classify_response(
            403, "<Error><Code>AccessDenied</Code></Error>", "GCP"
        )
        assert severity == "high"

    def test_gcp_no_such_bucket_info(self):
        severity, desc = _classify_response(
            404, "<Error><Code>NoSuchBucket</Code></Error>", "GCP"
        )
        assert severity == "info"

    # ── Azure ────────────────────────────────────────────────

    def test_azure_not_found_info(self):
        severity, desc = _classify_response(
            404, "<Error><Code>ContainerNotFound</Code></Error>", "Azure"
        )
        assert severity == "info"

    def test_azure_access_denied_high(self):
        severity, desc = _classify_response(
            403, "<Error><Code>AuthorizationFailure</Code></Error>", "Azure"
        )
        assert severity == "high"

    # ── Edge cases ───────────────────────────────────────────

    def test_none_text(self):
        severity, desc = _classify_response(404, None, "AWS")
        assert severity == "info"

    def test_500_range_info(self):
        severity, desc = _classify_response(503, "", "AWS")
        assert severity == "info"

    def test_302_redirect_medium(self):
        severity, desc = _classify_response(302, "", "AWS")
        assert severity == "medium"


class TestS3Module:
    """Test module attributes and behavior."""

    def test_module_attributes(self):
        m = S3Module()
        assert m.name == "s3"
        assert m.requires_url is False
        assert "cloud" in m.description.lower() or "s3" in m.description.lower() or "bucket" in m.description.lower()

    def test_empty_target_returns_empty(self):
        from unittest.mock import Mock
        m = S3Module()
        output = Mock()
        request_handler = Mock()
        result = m.run("", request_handler, output)
        assert result["module"] == "s3"
        assert result["findings"] == []

    def test_no_dot_target_returns_empty(self):
        from unittest.mock import Mock
        m = S3Module()
        output = Mock()
        request_handler = Mock()
        result = m.run("nodot", request_handler, output)
        assert result["module"] == "s3"
        assert result["findings"] == []
