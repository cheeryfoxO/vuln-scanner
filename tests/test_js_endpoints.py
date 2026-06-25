"""Tests for JS endpoints extraction module."""
from scanner.modules.js_endpoints import (
    JsEndpointsModule,
    _extract_scripts,
    _find_api_endpoints,
    _find_secrets,
    _find_subdomains,
    _find_url_paths,
)


class TestModuleAttributes:
    def test_name(self):
        mod = JsEndpointsModule()
        assert mod.name == "js_endpoints"

    def test_requires_url(self):
        mod = JsEndpointsModule()
        assert mod.requires_url is True

    def test_description(self):
        mod = JsEndpointsModule()
        assert "JavaScript" in mod.description


class TestExtractScripts:
    def test_extracts_inline_script(self):
        html = '<html><script>var x = 1;</script></html>'
        inline, external = _extract_scripts(html, "http://test.com")
        assert len(inline) >= 1
        assert any("var x = 1" in code for _, code in inline)

    def test_extracts_external_script(self):
        html = '<script src="/app.js"></script>'
        inline, external = _extract_scripts(html, "http://test.com")
        assert "http://test.com/app.js" in external

    def test_resolves_relative_paths(self):
        html = '<script src="static/main.js"></script>'
        inline, external = _extract_scripts(html, "http://test.com/page/")
        assert "http://test.com/page/static/main.js" in external

    def test_handles_absolute_urls(self):
        html = '<script src="https://cdn.example.com/lib.js"></script>'
        inline, external = _extract_scripts(html, "http://test.com")
        assert "https://cdn.example.com/lib.js" in external

    def test_ignores_empty_inline_scripts(self):
        html = '<script src="/lib.js"></script><script>  </script>'
        inline, external = _extract_scripts(html, "http://test.com")
        assert len(inline) == 0

    def test_multiple_scripts(self):
        html = """
        <script src="/a.js"></script>
        <script>var x=1;</script>
        <script src="/b.js"></script>
        <script>var y=2;</script>
        """
        inline, external = _extract_scripts(html, "http://test.com")
        assert len(inline) == 2
        assert len(external) == 2


class TestFindApiEndpoints:
    def test_finds_fetch_endpoint(self):
        js = """fetch('/api/users').then(r => r.json())"""
        findings = _find_api_endpoints(js, "app.js")
        assert len(findings) >= 1
        assert any("/api/users" in f["evidence"] for f in findings)

    def test_finds_axios_get(self):
        js = """axios.get('/api/v1/products')"""
        findings = _find_api_endpoints(js, "app.js")
        assert any("/api/v1/products" in f["evidence"] for f in findings)

    def test_finds_axios_post(self):
        js = """axios.post('/api/v1/login', data)"""
        findings = _find_api_endpoints(js, "app.js")
        assert any("/api/v1/login" in f["evidence"] for f in findings)

    def test_finds_jquery_ajax(self):
        js = """$.ajax({url: '/api/data', method: 'GET'})"""
        findings = _find_api_endpoints(js, "app.js")
        assert any("/api/data" in f["evidence"] for f in findings)

    def test_finds_jquery_get(self):
        js = """$.get('/api/items', function(data) {})"""
        findings = _find_api_endpoints(js, "app.js")
        assert any("/api/items" in f["evidence"] for f in findings)

    def test_finds_xmlhttprequest(self):
        js = '''xhr.open("GET", "/api/v2/status", true)'''
        findings = _find_api_endpoints(js, "app.js")
        assert any("/api/v2/status" in f["evidence"] for f in findings)

    def test_finds_axios_config_object(self):
        js = """axios({url: '/api/config', method: 'GET'})"""
        findings = _find_api_endpoints(js, "app.js")
        assert any("/api/config" in f["evidence"] for f in findings)

    def test_deduplicates_endpoints(self):
        js = """
        fetch('/api/users')
        fetch('/api/users')
        """
        findings = _find_api_endpoints(js, "app.js")
        assert len(findings) == 1

    def test_empty_js_returns_empty(self):
        findings = _find_api_endpoints("", "empty.js")
        assert len(findings) == 0

    def test_plain_js_no_endpoints(self):
        js = "var x = 1; var y = 2; console.log('hello');"
        findings = _find_api_endpoints(js, "plain.js")
        assert len(findings) == 0


class TestFindSecrets:
    def test_finds_api_key(self):
        js = """const apiKey = "sk-abcdefghijklmnopqrstuvwxyz123456" """
        findings = _find_secrets(js, "config.js")
        assert len(findings) >= 1
        assert any(f["type"] == "secret" for f in findings)
        assert any(f["severity"] == "high" for f in findings)

    def test_finds_api_secret(self):
        js = """const api_secret = "supersecretvalue12345" """
        findings = _find_secrets(js, "config.js")
        assert any("API Secret" in f["desc"] for f in findings)

    def test_finds_token(self):
        js = """token = "ghp_abcdefghijklmnopqrstuvwxyz" """
        findings = _find_secrets(js, "config.js")
        assert any("Token" in f["desc"] for f in findings)

    def test_finds_bearer_token(self):
        js = """bearer = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." """
        findings = _find_secrets(js, "config.js")
        assert any("Bearer" in f["desc"] for f in findings)

    def test_finds_password(self):
        js = """password = "admin12345" """
        findings = _find_secrets(js, "config.js")
        assert any("Password" in f["desc"] for f in findings)

    def test_finds_aws_key(self):
        js = """const AWS_KEY = "AKIAIOSFODNN7EXAMPLE" """
        findings = _find_secrets(js, "config.js")
        assert any("AWS" in f["desc"] for f in findings)

    def test_finds_google_api_key(self):
        js = """const gkey = "AIzaSyD-abcdefghijklmnopqrstuvwxyz123456" """
        findings = _find_secrets(js, "config.js")
        assert any("Google" in f["desc"] for f in findings)

    def test_empty_js_returns_empty(self):
        findings = _find_secrets("", "empty.js")
        assert len(findings) == 0

    def test_plain_js_returns_no_findings(self):
        js = "function add(a, b) { return a + b; }"
        findings = _find_secrets(js, "plain.js")
        assert len(findings) == 0


class TestFindSubdomains:
    def test_finds_subdomain_in_url(self):
        js = """const api = "https://api.internal.example.com/v1" """
        findings = _find_subdomains(js, "app.js", "target.com")
        assert len(findings) >= 1
        assert any("api.internal.example.com" in f["evidence"] for f in findings)

    def test_filters_target_domain(self):
        js = """const url = "https://www.target.com/api" """
        findings = _find_subdomains(js, "app.js", "target.com")
        # www.target.com is the target domain itself
        assert not any("target.com" in f["evidence"] for f in findings)

    def test_filters_subdomains_of_target(self):
        js = """const url = "https://api.target.com/v1" """
        findings = _find_subdomains(js, "app.js", "target.com")
        # api.target.com is still part of target.com
        assert not any("target.com" in f["evidence"] for f in findings)

    def test_filters_common_cdns(self):
        js = """const lib = "https://cdnjs.cloudflare.com/lib.js" """
        findings = _find_subdomains(js, "app.js", "mysite.com")
        assert not any("cloudflare" in f["evidence"] for f in findings)

    def test_deduplicates_same_subdomain(self):
        js = """
        const a = "https://api.other.com/v1";
        const b = "https://api.other.com/v2";
        """
        findings = _find_subdomains(js, "app.js", "target.com")
        count_api_other = sum(1 for f in findings if "api.other.com" in f["evidence"])
        assert count_api_other == 1

    def test_empty_js_returns_empty(self):
        findings = _find_subdomains("", "empty.js", "target.com")
        assert len(findings) == 0


class TestFindUrlPaths:
    def test_finds_api_v1_path(self):
        js = """const url = "/api/v1/users" """
        findings = _find_url_paths(js, "app.js")
        assert any("/api/v1/users" in f["evidence"] for f in findings)

    def test_finds_v2_path(self):
        js = """const url = "/v2/products" """
        findings = _find_url_paths(js, "app.js")
        assert any("/v2/products" in f["evidence"] for f in findings)

    def test_finds_graphql(self):
        js = """const endpoint = "/graphql" """
        findings = _find_url_paths(js, "app.js")
        assert any("/graphql" in f["evidence"] for f in findings)

    def test_finds_oauth_path(self):
        js = """const url = "/oauth/authorize" """
        findings = _find_url_paths(js, "app.js")
        assert any("/oauth/authorize" in f["evidence"] for f in findings)

    def test_finds_well_known_path(self):
        js = """const url = "/.well-known/openid-configuration" """
        findings = _find_url_paths(js, "app.js")
        assert any("/.well-known/openid-configuration" in f["evidence"] for f in findings)

    def test_finds_generic_api_path(self):
        js = """const url = "/api/internal/config" """
        findings = _find_url_paths(js, "app.js")
        assert any("/api/internal/config" in f["evidence"] for f in findings)

    def test_empty_js_returns_empty(self):
        findings = _find_url_paths("", "empty.js")
        assert len(findings) == 0

    def test_plain_js_returns_no_findings(self):
        js = "var x = 1; var y = 2;"
        findings = _find_url_paths(js, "plain.js")
        assert len(findings) == 0
