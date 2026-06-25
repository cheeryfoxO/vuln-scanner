"""Tests for deduplication utility."""
from scanner.core.dedup import (
    deduplicate_findings,
    _extract_url,
    _dedup_key,
    SEVERITY_ORDER,
)


class TestDeduplicateFindingsUrlType:
    """Tests for deduplicate_findings with url_type strategy."""

    def test_removes_exact_duplicate_same_url_same_type(self):
        findings = {
            "xss": [
                {"type": "reflected_xss", "url": "http://example.com/page", "severity": "medium", "evidence": "payload reflected"},
                {"type": "reflected_xss", "url": "http://example.com/page", "severity": "medium", "evidence": "payload reflected"},
            ],
        }
        deduped, stats = deduplicate_findings(findings, strategy="url_type")
        assert len(deduped["xss"]) == 1
        assert stats["xss"] == (2, 1, 1)

    def test_keeps_higher_severity_when_duplicates_found(self):
        findings = {
            "sqli": [
                {"type": "error_based", "url": "http://example.com/page?id=1", "severity": "medium", "evidence": "sql error"},
                {"type": "error_based", "url": "http://example.com/page?id=1", "severity": "high", "evidence": "sql error"},
            ],
        }
        deduped, stats = deduplicate_findings(findings, strategy="url_type")
        assert len(deduped["sqli"]) == 1
        assert deduped["sqli"][0]["severity"] == "high"

    def test_handles_empty_findings_dict(self):
        deduped, stats = deduplicate_findings({}, strategy="url_type")
        assert deduped == {}
        assert stats == {}

    def test_handles_module_with_empty_findings_list(self):
        findings = {"xss": []}
        deduped, stats = deduplicate_findings(findings, strategy="url_type")
        assert deduped["xss"] == []
        assert stats["xss"] == (0, 0, 0)

    def test_handles_findings_with_no_url_field(self):
        findings = {
            "subdomain": [
                {"type": "subdomain", "host": "admin.example.com", "severity": "info"},
                {"type": "subdomain", "host": "admin.example.com", "severity": "info"},
            ],
        }
        deduped, stats = deduplicate_findings(findings, strategy="url_type")
        assert len(deduped["subdomain"]) == 1
        assert stats["subdomain"] == (2, 1, 1)

    def test_falls_back_to_source_field(self):
        findings = {
            "params": [
                {"type": "query_param", "source": "http://example.com/page?x=1", "severity": "info"},
                {"type": "query_param", "source": "http://example.com/page?x=1", "severity": "info"},
            ],
        }
        deduped, stats = deduplicate_findings(findings, strategy="url_type")
        assert len(deduped["params"]) == 1

    def test_different_url_same_type_not_deduped(self):
        findings = {
            "xss": [
                {"type": "reflected_xss", "url": "http://example.com/page1", "severity": "medium"},
                {"type": "reflected_xss", "url": "http://example.com/page2", "severity": "medium"},
            ],
        }
        deduped, stats = deduplicate_findings(findings, strategy="url_type")
        assert len(deduped["xss"]) == 2
        assert stats["xss"] == (2, 2, 0)

    def test_same_url_different_type_not_deduped(self):
        findings = {
            "xss": [
                {"type": "reflected_xss", "url": "http://example.com/page", "severity": "medium"},
                {"type": "dom_xss", "url": "http://example.com/page", "severity": "medium"},
            ],
        }
        deduped, stats = deduplicate_findings(findings, strategy="url_type")
        assert len(deduped["xss"]) == 2
        assert stats["xss"] == (2, 2, 0)

    def test_same_severity_keeps_more_detail(self):
        findings = {
            "xss": [
                {"type": "reflected_xss", "url": "http://example.com/page", "severity": "medium", "evidence": "short"},
                {"type": "reflected_xss", "url": "http://example.com/page", "severity": "medium", "evidence": "much longer evidence string with details"},
            ],
        }
        deduped, stats = deduplicate_findings(findings, strategy="url_type")
        assert len(deduped["xss"]) == 1
        assert deduped["xss"][0]["evidence"] == "much longer evidence string with details"


class TestDeduplicateFindingsTypeEvidence:
    """Tests for deduplicate_findings with type_evidence strategy."""

    def test_removes_duplicate_when_type_and_evidence_match(self):
        findings = {
            "cmdi": [
                {"type": "time_based", "url": "http://a.com/cmd", "severity": "critical", "evidence": "sleep 5 detected"},
                {"type": "time_based", "url": "http://b.com/cmd", "severity": "critical", "evidence": "sleep 5 detected"},
            ],
        }
        deduped, stats = deduplicate_findings(findings, strategy="type_evidence")
        assert len(deduped["cmdi"]) == 1

    def test_different_evidence_not_deduped(self):
        findings = {
            "cmdi": [
                {"type": "time_based", "url": "http://a.com/cmd", "severity": "critical", "evidence": "sleep 5 detected"},
                {"type": "time_based", "url": "http://b.com/cmd", "severity": "critical", "evidence": "sleep 10 detected"},
            ],
        }
        deduped, stats = deduplicate_findings(findings, strategy="type_evidence")
        assert len(deduped["cmdi"]) == 2


class TestDeduplicateFindingsStrict:
    """Tests for deduplicate_findings with strict strategy."""

    def test_only_removes_when_all_fields_match(self):
        findings = {
            "xss": [
                {"type": "reflected_xss", "url": "http://example.com/page", "severity": "medium"},
                {"type": "reflected_xss", "url": "http://example.com/page", "severity": "medium"},
            ],
        }
        deduped, stats = deduplicate_findings(findings, strategy="strict")
        assert len(deduped["xss"]) == 1

    def test_different_severity_not_deduped_in_strict_mode(self):
        findings = {
            "xss": [
                {"type": "reflected_xss", "url": "http://example.com/page", "severity": "medium"},
                {"type": "reflected_xss", "url": "http://example.com/page", "severity": "high"},
            ],
        }
        deduped, stats = deduplicate_findings(findings, strategy="strict")
        assert len(deduped["xss"]) == 2


class TestExtractUrl:
    """Tests for _extract_url helper."""

    def test_returns_url_field_if_present(self):
        finding = {"url": "http://example.com/page", "type": "xss"}
        assert _extract_url(finding) == "http://example.com/page"

    def test_falls_back_to_host_field(self):
        finding = {"host": "admin.example.com", "type": "subdomain"}
        assert _extract_url(finding) == "admin.example.com"

    def test_falls_back_to_source_field(self):
        finding = {"source": "http://example.com/api", "type": "params"}
        assert _extract_url(finding) == "http://example.com/api"

    def test_falls_back_to_endpoint_field(self):
        finding = {"endpoint": "/graphql", "type": "graphql"}
        assert _extract_url(finding) == "/graphql"

    def test_returns_empty_string_when_nothing_found(self):
        finding = {"type": "unknown", "severity": "info"}
        assert _extract_url(finding) == ""

    def test_scans_evidence_string_for_url(self):
        finding = {
            "type": "sqli",
            "evidence": "SQL error at http://example.com/vuln.php?id=1 triggered",
        }
        assert _extract_url(finding) == "http://example.com/vuln.php?id=1"

    def test_url_takes_priority_over_host(self):
        finding = {"url": "http://example.com/page", "host": "other.example.com", "type": "xss"}
        assert _extract_url(finding) == "http://example.com/page"


class TestDedupKey:
    """Tests for _dedup_key helper."""

    def test_url_type_strategy_key(self):
        finding = {"type": "reflected_xss", "url": "http://example.com/page"}
        key = _dedup_key(finding, "url_type")
        assert key == ("http://example.com/page", "reflected_xss")

    def test_type_evidence_strategy_key(self):
        finding = {"type": "sqli", "evidence": "error detected"}
        key = _dedup_key(finding, "type_evidence")
        assert key == ("sqli", "error detected")

    def test_strict_strategy_key(self):
        finding = {"type": "xss", "url": "http://example.com", "severity": "high"}
        key = _dedup_key(finding, "strict")
        # frozenset for order-independent comparison
        assert ("type", "xss") in key
        assert ("url", "http://example.com") in key
        assert ("severity", "high") in key

    def test_url_type_uses_host_fallback(self):
        finding = {"type": "subdomain", "host": "test.example.com"}
        key = _dedup_key(finding, "url_type")
        assert key == ("test.example.com", "subdomain")


class TestMultipleModules:
    """Tests for multi-module deduplication."""

    def test_dedup_works_across_modules_independently(self):
        findings = {
            "xss": [
                {"type": "reflected_xss", "url": "http://example.com/page", "severity": "medium"},
                {"type": "reflected_xss", "url": "http://example.com/page", "severity": "high"},
            ],
            "sqli": [
                {"type": "error_based", "url": "http://example.com/page?id=1", "severity": "high"},
                {"type": "error_based", "url": "http://example.com/page?id=1", "severity": "medium"},
            ],
            "headers": [
                {"type": "missing_header", "url": "http://example.com", "severity": "info"},
            ],
        }
        deduped, stats = deduplicate_findings(findings, strategy="url_type")
        assert len(deduped["xss"]) == 1
        assert len(deduped["sqli"]) == 1
        assert len(deduped["headers"]) == 1

    def test_returns_correct_stats(self):
        findings = {
            "xss": [
                {"type": "reflected_xss", "url": "http://example.com/page", "severity": "medium"},
                {"type": "reflected_xss", "url": "http://example.com/page", "severity": "high"},
                {"type": "dom_xss", "url": "http://example.com/page", "severity": "medium"},
            ],
            "sqli": [
                {"type": "error_based", "url": "http://example.com/page?id=1", "severity": "high"},
                {"type": "error_based", "url": "http://example.com/page?id=1", "severity": "critical"},
            ],
        }
        deduped, stats = deduplicate_findings(findings, strategy="url_type")
        assert stats["xss"] == (3, 2, 1)
        assert stats["sqli"] == (2, 1, 1)
