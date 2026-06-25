"""GraphQL endpoint detection and misconfiguration checks."""
import json
from scanner.modules.base import BaseModule

# Common GraphQL endpoint paths to probe
GRAPHQL_PATHS = [
    "/graphql",
    "/gql",
    "/graphiql",
    "/api/graphql",
    "/v1/graphql",
    "/v2/graphql",
    "/query",
    "/api/gql",
    "/playground",
    "/graphql/console",
    "/__graphql",
]

# Standard GraphQL introspection query
INTROSPECTION_QUERY = (
    '{"query":"query IntrospectionQuery { __schema { queryType { name } '
    'mutationType { name } subscriptionType { name } types { name kind '
    'description fields { name args { name type { name kind } } } } '
    'directives { name description locations args { name type { name kind } } } } }"}'
)

# Patterns that indicate GraphQL-specific error messages
GRAPHQL_ERROR_PATTERNS = [
    "graphql",
    "graphql validation error",
    "must provide query string",
    "introspection is not allowed",
    "introspection disabled",
    "cannot query field",
    "unknown type",
    "field \"__schema\"",
    "syntax error",
    "parse error",
    "validation error",
    "execution error",
    "graphql error",
    "did you mean",
    "graphql schema",
    "unexpected token",
]

# HTTP status codes that indicate a non-existent endpoint
_NOT_FOUND_STATUSES = {404, 410}
# Headers that suggest a 301/302 is redirecting to home/not-found
_REDIRECT_TO_HOME_PATTERNS = ("/", "/home", "/index")


def _is_endpoint_responsive(response):
    """Return True if the response indicates the endpoint exists (not 404/etc)."""
    if response.status_code in _NOT_FOUND_STATUSES:
        return False
    # Redirect to root/home usually means the path doesn't exist
    if response.status_code in (301, 302):
        location = response.headers.get("Location", "")
        if location.rstrip("/") in _REDIRECT_TO_HOME_PATTERNS or location.rstrip("/") == "":
            return False
    return True


def _has_introspection(response):
    """Return True if the response body contains introspection schema data."""
    try:
        body = response.text
    except Exception:
        return False
    if not body:
        return False
    # Introspection responses contain __schema key
    return '"__schema"' in body or "__schema" in body


def _has_graphiql(response):
    """Return True if the response HTML contains GraphiQL markers."""
    try:
        body = response.text
    except Exception:
        return False
    if not body:
        return False
    body_lower = body.lower()
    return (
        "graphiql" in body_lower
        or "graphql playground" in body_lower
        or 'id="graphiql"' in body_lower
    )


def _has_graphql_errors(response):
    """Return True if the response body suggests GraphQL-specific error output."""
    try:
        body = response.text
    except Exception:
        return False
    if not body:
        return False
    body_lower = body.lower()
    return any(pattern in body_lower for pattern in GRAPHQL_ERROR_PATTERNS)


def _check_graphql_endpoint(url, path, request_handler, output):
    """Probe a single GraphQL endpoint path and return findings list."""
    findings = []
    endpoint_url = url + path

    # Step 1: Check if endpoint exists via GET
    try:
        get_resp = request_handler.get(endpoint_url)
    except Exception:
        return findings

    if not _is_endpoint_responsive(get_resp):
        return findings

    output.log_progress(f"GraphQL: probing {endpoint_url}")

    # Step 2: POST introspection query
    introspection_enabled = False
    try:
        post_resp = request_handler.post(
            endpoint_url,
            data=INTROSPECTION_QUERY,
            headers={"Content-Type": "application/json"},
        )
        introspection_enabled = _has_introspection(post_resp)
    except Exception:
        post_resp = None

    # Step 3: Check for GraphiQL in GET response
    graphiql_exposed = _has_graphiql(get_resp)

    # Step 4: Try GET-based introspection (some servers accept query param)
    get_introspection_enabled = False
    if not introspection_enabled:
        try:
            get_query_url = f"{endpoint_url}?query={INTROSPECTION_QUERY}"
            get_query_resp = request_handler.get(get_query_url)
            get_introspection_enabled = _has_introspection(get_query_resp)
        except Exception:
            pass

    introspection_enabled = introspection_enabled or get_introspection_enabled

    # Step 5: Check for GraphQL errors in response
    error_resp = post_resp if post_resp is not None else get_resp
    has_errors = _has_graphql_errors(error_resp)

    # Step 6: Classify and create findings
    if introspection_enabled and graphiql_exposed:
        findings.append({
            "type": "graphql_introspection_with_graphiql",
            "severity": "critical",
            "url": endpoint_url,
            "desc": (
                "GraphQL introspection is enabled and GraphiQL playground is exposed. "
                "Attackers can discover the full API schema and interactively craft queries, "
                "potentially exposing sensitive data structures, hidden fields, "
                "and internal API operations."
            ),
            "evidence": f"GraphQL endpoint at {endpoint_url} returns full schema via introspection and serves GraphiQL IDE",
        })
    elif introspection_enabled:
        findings.append({
            "type": "graphql_introspection_enabled",
            "severity": "high",
            "url": endpoint_url,
            "desc": (
                "GraphQL introspection is enabled, allowing attackers to discover "
                "the full API schema including types, fields, queries, and mutations. "
                "This exposes the entire data model and internal API surface."
            ),
            "evidence": f"Introspection query to {endpoint_url} returned full __schema data",
        })
    elif graphiql_exposed:
        findings.append({
            "type": "graphql_graphiql_exposed",
            "severity": "info",
            "url": endpoint_url,
            "desc": (
                "GraphiQL interactive IDE is exposed. While introspection may be disabled, "
                "exposing the IDE increases the attack surface and aids reconnaissance."
            ),
            "evidence": f"GET {endpoint_url} returns HTML containing GraphiQL",
        })
    elif has_errors:
        # Endpoint exists but introspection is disabled; errors may still leak info
        error_evidence = ""
        try:
            body = error_resp.text[:500] if error_resp is not None else ""
            error_evidence = f"Response from {endpoint_url}: {body}"
        except Exception:
            error_evidence = f"Response from {endpoint_url}"

        findings.append({
            "type": "graphql_endpoint_exists",
            "severity": "medium",
            "url": endpoint_url,
            "desc": (
                "GraphQL endpoint discovered but introspection appears disabled. "
                "The endpoint is still accessible and may expose information "
                "through error messages or be vulnerable to other attacks."
            ),
            "evidence": error_evidence,
        })

        # Low-severity finding if errors reveal GraphQL internals
        if has_errors:
            findings.append({
                "type": "graphql_error_info_leak",
                "severity": "low",
                "url": endpoint_url,
                "desc": (
                    "GraphQL endpoint error messages reveal GraphQL-specific "
                    "implementation details that can aid attackers in "
                    "understanding the API structure."
                ),
                "evidence": error_evidence,
            })
    else:
        # Endpoint responds but no GraphQL indicators — still note it
        findings.append({
            "type": "graphql_endpoint_exists",
            "severity": "medium",
            "url": endpoint_url,
            "desc": (
                "A GraphQL endpoint path responded but does not appear to process "
                "GraphQL queries, or introspection is disabled without error details. "
                "Manual verification recommended."
            ),
            "evidence": f"Endpoint {endpoint_url} responded with status {get_resp.status_code}",
        })

    return findings


class GraphqlModule(BaseModule):
    name = "graphql"
    description = "Detect GraphQL endpoints and check for introspection/GraphiQL misconfigurations"
    requires_url = True

    def run(self, target, request_handler, output):
        """Probe common GraphQL paths and check for misconfigurations."""
        target = target.rstrip("/")
        output.log_progress(f"GraphQL: scanning {target} for GraphQL endpoints...")

        findings = []
        for path in GRAPHQL_PATHS:
            try:
                path_findings = _check_graphql_endpoint(
                    target, path, request_handler, output
                )
                for finding in path_findings:
                    findings.append(finding)
                    output.log_finding(self.name, finding)
            except Exception as e:
                output.log_progress(f"GraphQL: error probing {target}{path}: {e}")

        output.log_progress(
            f"GraphQL: scanned {len(GRAPHQL_PATHS)} paths, "
            f"{len(findings)} finding(s)"
        )
        return {"module": self.name, "findings": findings}
