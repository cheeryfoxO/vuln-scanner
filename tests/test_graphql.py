"""Tests for GraphQL endpoint detection module."""
from unittest.mock import Mock
from scanner.modules.graphql import (
    GraphqlModule,
    _is_endpoint_responsive,
    _has_introspection,
    _has_graphiql,
    _has_graphql_errors,
    _check_graphql_endpoint,
    GRAPHQL_PATHS,
    GRAPHQL_ERROR_PATTERNS,
    INTROSPECTION_QUERY,
)


# ── Pure function tests ──────────────────────────────────────────────

class TestIsEndpointResponsive:
    def test_200_is_responsive(self):
        resp = Mock(status_code=200, headers={})
        assert _is_endpoint_responsive(resp) is True

    def test_404_is_not_responsive(self):
        resp = Mock(status_code=404, headers={})
        assert _is_endpoint_responsive(resp) is False

    def test_410_is_not_responsive(self):
        resp = Mock(status_code=410, headers={})
        assert _is_endpoint_responsive(resp) is False

    def test_301_redirect_to_home_is_not_responsive(self):
        resp = Mock(status_code=301, headers={"Location": "/"})
        assert _is_endpoint_responsive(resp) is False

    def test_302_redirect_to_home_index_is_not_responsive(self):
        resp = Mock(status_code=302, headers={"Location": "/home"})
        assert _is_endpoint_responsive(resp) is False

    def test_301_redirect_to_non_root_is_responsive(self):
        resp = Mock(status_code=301, headers={"Location": "/login"})
        assert _is_endpoint_responsive(resp) is True

    def test_403_is_responsive(self):
        resp = Mock(status_code=403, headers={})
        assert _is_endpoint_responsive(resp) is True


class TestHasIntrospection:
    def test_detects_schema_in_body(self):
        resp = Mock(text='{"data":{"__schema":{"queryType":{"name":"Query"}}}}')
        assert _has_introspection(resp) is True

    def test_detects_schema_without_quotes(self):
        resp = Mock(text='data contains __schema keyword somewhere')
        assert _has_introspection(resp) is True

    def test_no_schema_returns_false(self):
        resp = Mock(text='{"errors":[{"message":"Introspection disabled"}]}')
        assert _has_introspection(resp) is False

    def test_empty_body_returns_false(self):
        resp = Mock(text="")
        assert _has_introspection(resp) is False

    def test_no_text_attribute_returns_false(self):
        resp = Mock(spec=[])  # no text attribute
        assert _has_introspection(resp) is False


class TestHasGraphiql:
    def test_detects_graphiql_in_html(self):
        resp = Mock(text='<html><title>GraphiQL</title></html>')
        assert _has_graphiql(resp) is True

    def test_detects_graphiql_case_insensitive(self):
        resp = Mock(text='<div id="graphiql">loading</div>')
        assert _has_graphiql(resp) is True

    def test_detects_graphql_playground(self):
        resp = Mock(text='<title>GraphQL Playground</title>')
        assert _has_graphiql(resp) is True

    def test_no_graphiql_returns_false(self):
        resp = Mock(text="<html><body>Welcome</body></html>")
        assert _has_graphiql(resp) is False

    def test_empty_body_returns_false(self):
        resp = Mock(text="")
        assert _has_graphiql(resp) is False


class TestHasGraphqlErrors:
    def test_detects_graphql_in_error_message(self):
        resp = Mock(text='{"errors":[{"message":"graphql error occurred"}]}')
        assert _has_graphql_errors(resp) is True

    def test_detects_must_provide_query_string(self):
        resp = Mock(text="Must provide query string")
        assert _has_graphql_errors(resp) is True

    def test_detects_introspection_disabled(self):
        resp = Mock(text='{"errors":[{"message":"Introspection is not allowed"}]}')
        assert _has_graphql_errors(resp) is True

    def test_detects_cannot_query_field(self):
        resp = Mock(text='{"errors":[{"message":"Cannot query field \\"test\\""}]}')
        assert _has_graphql_errors(resp) is True

    def test_detects_syntax_error(self):
        resp = Mock(text='{"errors":[{"message":"Syntax Error: unexpected token"}]}')
        assert _has_graphql_errors(resp) is True

    def test_no_graphql_content_returns_false(self):
        resp = Mock(text="<html><body>Hello World</body></html>")
        assert _has_graphql_errors(resp) is False

    def test_empty_body_returns_false(self):
        resp = Mock(text="")
        assert _has_graphql_errors(resp) is False


# ── Endpoint probing tests ───────────────────────────────────────────

class TestCheckGraphqlEndpoint:
    def test_404_endpoint_returns_no_finding(self):
        """404 response should produce no findings."""
        rh = Mock()
        rh.get.return_value = Mock(status_code=404, headers={})
        out = Mock()

        findings = _check_graphql_endpoint(
            "https://example.com", "/graphql", rh, out
        )
        assert findings == []

    def test_introspection_enabled_detected(self):
        """Response with __schema in body should detect introspection."""
        rh = Mock()
        rh.get.return_value = Mock(
            status_code=200,
            headers={},
            text="<html>Normal page</html>",
        )
        rh.post.return_value = Mock(
            status_code=200,
            headers={},
            text='{"data":{"__schema":{"queryType":{"name":"Query"}}}}',
        )
        out = Mock()

        findings = _check_graphql_endpoint(
            "https://example.com", "/graphql", rh, out
        )
        assert len(findings) >= 1
        high_findings = [f for f in findings if f["severity"] == "high"]
        assert len(high_findings) == 1
        assert high_findings[0]["type"] == "graphql_introspection_enabled"

    def test_introspection_and_graphiql_critical(self):
        """Introspection + GraphiQL should produce critical finding."""
        rh = Mock()
        rh.get.return_value = Mock(
            status_code=200,
            headers={},
            text='<html><title>GraphiQL</title><div id="graphiql"></div></html>',
        )
        rh.post.return_value = Mock(
            status_code=200,
            headers={},
            text='{"data":{"__schema":{"queryType":{"name":"Query"}}}}',
        )
        out = Mock()

        findings = _check_graphql_endpoint(
            "https://example.com", "/graphql", rh, out
        )
        critical = [f for f in findings if f["severity"] == "critical"]
        assert len(critical) == 1
        assert critical[0]["type"] == "graphql_introspection_with_graphiql"

    def test_graphiql_exposed_introspection_disabled(self):
        """GraphiQL without introspection should produce info finding."""
        rh = Mock()
        rh.get.return_value = Mock(
            status_code=200,
            headers={},
            text='<html><title>GraphiQL</title></html>',
        )
        rh.post.return_value = Mock(
            status_code=200,
            headers={},
            text='{"errors":[{"message":"Introspection disabled"}]}',
        )
        out = Mock()

        findings = _check_graphql_endpoint(
            "https://example.com", "/graphql", rh, out
        )
        info_findings = [f for f in findings if f["severity"] == "info"]
        assert len(info_findings) == 1
        assert info_findings[0]["type"] == "graphql_graphiql_exposed"

    def test_endpoint_exists_introspection_disabled(self):
        """Endpoint with GraphQL errors but no introspection → medium."""
        rh = Mock()
        rh.get.return_value = Mock(
            status_code=200,
            headers={},
            text="Must provide query string",
        )
        rh.post.return_value = Mock(
            status_code=200,
            headers={},
            text='{"errors":[{"message":"graphql: introspection is not allowed"}]}',
        )
        out = Mock()

        findings = _check_graphql_endpoint(
            "https://example.com", "/graphql", rh, out
        )
        medium = [f for f in findings if f["severity"] == "medium"]
        assert len(medium) >= 1
        assert medium[0]["type"] == "graphql_endpoint_exists"

    def test_error_info_leak_detected(self):
        """GraphQL error messages should produce low-severity finding."""
        rh = Mock()
        rh.get.return_value = Mock(
            status_code=200,
            headers={},
            text="GraphQL validation error: cannot query field",
        )
        rh.post.return_value = Mock(
            status_code=200,
            headers={},
            text='{"errors":[{"message":"Cannot query field \\"test\\" on type \\"Query\\""}]}',
        )
        out = Mock()

        findings = _check_graphql_endpoint(
            "https://example.com", "/graphql", rh, out
        )
        low = [f for f in findings if f["severity"] == "low"]
        assert len(low) >= 1
        assert low[0]["type"] == "graphql_error_info_leak"

    def test_get_based_introspection_detected(self):
        """GET-based introspection should be attempted as fallback."""
        rh = Mock()
        rh.get.return_value = Mock(
            status_code=200,
            headers={},
            text="<html>Normal page</html>",
        )
        rh.post.return_value = Mock(
            status_code=200,
            headers={},
            text='{"errors":[{"message":"POST not allowed"}]}',
        )
        # GET-based call returns introspection data
        # We need to return different values for different GET URLs
        def get_side_effect(url, **kwargs):
            if "?query=" in url:
                return Mock(
                    status_code=200,
                    headers={},
                    text='{"data":{"__schema":{"queryType":{"name":"Query"}}}}',
                )
            return Mock(
                status_code=200,
                headers={},
                text="<html>Normal page</html>",
            )
        rh.get.side_effect = get_side_effect
        out = Mock()

        findings = _check_graphql_endpoint(
            "https://example.com", "/graphql", rh, out
        )
        high = [f for f in findings if f["severity"] == "high"]
        assert len(high) == 1

    def test_connection_error_returns_no_findings(self):
        """If GET raises an exception, no findings should be produced."""
        rh = Mock()
        rh.get.side_effect = Exception("Connection refused")
        out = Mock()

        findings = _check_graphql_endpoint(
            "https://example.com", "/graphql", rh, out
        )
        assert findings == []

    def test_post_exception_still_checks_get(self):
        """If POST fails, still evaluate based on GET response."""
        rh = Mock()
        rh.get.return_value = Mock(
            status_code=200,
            headers={},
            text="<html><title>GraphiQL</title></html>",
        )
        rh.post.side_effect = Exception("Timeout")
        out = Mock()

        findings = _check_graphql_endpoint(
            "https://example.com", "/graphql", rh, out
        )
        # Should find graphiql exposed at info level
        assert len(findings) >= 1
        info_findings = [f for f in findings if f["severity"] == "info"]
        assert len(info_findings) == 1


# ── Module attribute tests ───────────────────────────────────────────

class TestModule:
    def test_module_attributes(self):
        mod = GraphqlModule()
        assert mod.name == "graphql"
        assert mod.requires_url is True
        assert "graphql" in mod.description.lower()
        assert "introspection" in mod.description.lower()

    def test_run_with_mocked_handler(self):
        """Integration-style test: run() with mocked handler over all paths."""
        mod = GraphqlModule()
        rh = Mock()

        # All endpoints return 404 — no findings
        rh.get.return_value = Mock(status_code=404, headers={})
        out = Mock()

        result = mod.run("https://example.com", rh, out)
        assert result["module"] == "graphql"
        assert result["findings"] == []

    def test_run_finds_endpoint(self):
        """Integration-style test: run() finds a GraphQL endpoint."""
        mod = GraphqlModule()
        rh = Mock()
        rh.get.return_value = Mock(
            status_code=200,
            headers={},
            text="Must provide query string",
        )
        rh.post.return_value = Mock(
            status_code=200,
            headers={},
            text='{"errors":[{"message":"graphql introspection disabled"}]}',
        )
        out = Mock()

        result = mod.run("https://example.com", rh, out)
        assert result["module"] == "graphql"
        # All 11 paths will be probed, and get/post are the same mock
        # so each responsive path produces findings
        assert len(result["findings"]) > 0


# ── Constants tests ──────────────────────────────────────────────────

class TestConstants:
    def test_introspection_query_is_nonempty(self):
        assert len(INTROSPECTION_QUERY) > 0
        assert "IntrospectionQuery" in INTROSPECTION_QUERY
        assert "__schema" in INTROSPECTION_QUERY

    def test_paths_has_expected_entries(self):
        assert "/graphql" in GRAPHQL_PATHS
        assert "/gql" in GRAPHQL_PATHS
        assert "/graphiql" in GRAPHQL_PATHS
        assert "/api/graphql" in GRAPHQL_PATHS
        assert len(GRAPHQL_PATHS) == 11

    def test_error_patterns_nonempty(self):
        assert len(GRAPHQL_ERROR_PATTERNS) > 0
        assert "graphql" in GRAPHQL_ERROR_PATTERNS
