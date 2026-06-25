"""Tests for params module -- form parsing, JS endpoint extraction, and run()."""
from unittest.mock import Mock

from scanner.modules.params import ParamsModule, _FormParser


# ── FormParser tests ──────────────────────────────────────────────────

class TestFormParserExtractForm:
    def test_extracts_form_with_action_method_inputs(self):
        html = (
            '<form action="/login" method="POST">'
            '<input type="text" name="username">'
            '<input type="password" name="password">'
            '<input type="submit" value="Login">'
            '</form>'
        )
        parser = _FormParser()
        parser.feed(html)
        assert len(parser.forms) == 1
        form = parser.forms[0]
        assert form["action"] == "/login"
        assert form["method"] == "POST"
        assert len(form["inputs"]) == 2
        assert form["inputs"][0] == {"name": "username", "type": "text"}
        assert form["inputs"][1] == {"name": "password", "type": "password"}

    def test_form_default_method_is_get(self):
        html = '<form action="/search"><input name="q"></form>'
        parser = _FormParser()
        parser.feed(html)
        assert parser.forms[0]["method"] == "GET"

    def test_form_default_action_is_empty(self):
        html = '<form><input name="email"></form>'
        parser = _FormParser()
        parser.feed(html)
        assert parser.forms[0]["action"] == ""

    def test_ignores_input_without_name(self):
        html = '<form action="/x" method="POST"><input type="text"><input name="valid"></form>'
        parser = _FormParser()
        parser.feed(html)
        assert len(parser.forms[0]["inputs"]) == 1
        assert parser.forms[0]["inputs"][0]["name"] == "valid"

    def test_default_input_type_is_text(self):
        html = '<form><input name="email"></form>'
        parser = _FormParser()
        parser.feed(html)
        assert parser.forms[0]["inputs"][0]["type"] == "text"


class TestFormParserExtractMultipleForms:
    def test_extracts_multiple_forms(self):
        html = (
            '<form action="/login" method="POST"><input name="user"></form>'
            '<form action="/register" method="POST"><input name="email"></form>'
        )
        parser = _FormParser()
        parser.feed(html)
        assert len(parser.forms) == 2
        assert parser.forms[0]["action"] == "/login"
        assert parser.forms[1]["action"] == "/register"
        assert parser.forms[0]["inputs"][0]["name"] == "user"
        assert parser.forms[1]["inputs"][0]["name"] == "email"

    def test_inputs_assigned_to_correct_form(self):
        html = (
            '<form action="/a"><input name="a1"><input name="a2"></form>'
            '<form action="/b"><input name="b1"></form>'
        )
        parser = _FormParser()
        parser.feed(html)
        assert len(parser.forms[0]["inputs"]) == 2
        assert len(parser.forms[1]["inputs"]) == 1
        inp_names_0 = [i["name"] for i in parser.forms[0]["inputs"]]
        inp_names_1 = [i["name"] for i in parser.forms[1]["inputs"]]
        assert inp_names_0 == ["a1", "a2"]
        assert inp_names_1 == ["b1"]

    def test_input_before_first_form_is_ignored(self):
        html = '<input name="orphan"><form action="/f"><input name="f1"></form>'
        parser = _FormParser()
        parser.feed(html)
        assert len(parser.forms) == 1
        assert len(parser.forms[0]["inputs"]) == 1
        assert parser.forms[0]["inputs"][0]["name"] == "f1"


class TestFormParserExtractLinks:
    def test_extracts_a_href_links(self):
        html = '<a href="/about">About</a><a href="/contact">Contact</a>'
        parser = _FormParser()
        parser.feed(html)
        assert parser.links == ["/about", "/contact"]

    def test_extracts_link_href(self):
        html = '<link rel="stylesheet" href="/style.css"><link rel="icon" href="/favicon.ico">'
        parser = _FormParser()
        parser.feed(html)
        assert "/style.css" in parser.links
        assert "/favicon.ico" in parser.links

    def test_ignores_anchor_links(self):
        html = '<a href="#section">Jump</a><a href="/page">Page</a>'
        parser = _FormParser()
        parser.feed(html)
        assert "#section" not in parser.links
        assert "/page" in parser.links

    def test_ignores_empty_href(self):
        html = '<a href="">Empty</a><a href="/valid">Valid</a>'
        parser = _FormParser()
        parser.feed(html)
        assert "" not in parser.links
        assert "/valid" in parser.links

    def test_link_without_href_is_ignored(self):
        html = '<a>No href</a><link rel="stylesheet">'
        parser = _FormParser()
        parser.feed(html)
        assert parser.links == []


class TestFormParserExtractScripts:
    def test_extracts_script_src(self):
        html = '<script src="/app.js"></script><script src="/vendor.js"></script>'
        parser = _FormParser()
        parser.feed(html)
        assert parser.scripts == ["/app.js", "/vendor.js"]

    def test_ignores_inline_script(self):
        html = '<script>console.log("hello")</script><script src="/main.js"></script>'
        parser = _FormParser()
        parser.feed(html)
        assert parser.scripts == ["/main.js"]

    def test_script_without_src_is_ignored(self):
        html = '<script>var x = 1;</script>'
        parser = _FormParser()
        parser.feed(html)
        assert parser.scripts == []

    def test_empty_src_is_ignored(self):
        html = '<script src=""></script><script src="/real.js"></script>'
        parser = _FormParser()
        parser.feed(html)
        assert parser.scripts == ["/real.js"]


class TestFormParserEmpty:
    def test_handles_empty_html(self):
        parser = _FormParser()
        parser.feed("")
        assert parser.forms == []
        assert parser.links == []
        assert parser.scripts == []

    def test_handles_non_html_text(self):
        parser = _FormParser()
        parser.feed("Just some plain text without any HTML tags.")
        assert parser.forms == []
        assert parser.links == []
        assert parser.scripts == []


# ── _extract_js_endpoints tests ────────────────────────────────────────

class TestExtractJsEndpointsFetch:
    def test_finds_fetch_url(self):
        mod = ParamsModule()
        result = mod._extract_js_endpoints('fetch("/api/users")')
        assert "/api/users" in result

    def test_finds_fetch_with_single_quotes(self):
        mod = ParamsModule()
        result = mod._extract_js_endpoints("fetch('/api/data')")
        assert "/api/data" in result

    def test_finds_fetch_case_insensitive(self):
        mod = ParamsModule()
        result = mod._extract_js_endpoints('FETCH("/api/items")')
        assert "/api/items" in result

    def test_finds_fetch_with_spaces(self):
        mod = ParamsModule()
        result = mod._extract_js_endpoints('fetch(  "/api/spaced"  )')
        assert "/api/spaced" in result


class TestExtractJsEndpointsAxios:
    def test_finds_axios_get(self):
        mod = ParamsModule()
        result = mod._extract_js_endpoints('axios.get("/api/users")')
        assert "/api/users" in result

    def test_finds_axios_post(self):
        mod = ParamsModule()
        result = mod._extract_js_endpoints('axios.post("/api/login")')
        assert "/api/login" in result

    def test_finds_axios_put(self):
        mod = ParamsModule()
        result = mod._extract_js_endpoints('axios.put("/api/update")')
        assert "/api/update" in result

    def test_finds_axios_delete(self):
        mod = ParamsModule()
        result = mod._extract_js_endpoints('axios.delete("/api/remove")')
        assert "/api/remove" in result

    def test_finds_axios_patch(self):
        mod = ParamsModule()
        result = mod._extract_js_endpoints('axios.patch("/api/edit")')
        assert "/api/edit" in result


class TestExtractJsEndpointsJquery:
    def test_finds_jquery_ajax(self):
        mod = ParamsModule()
        result = mod._extract_js_endpoints('$.ajax("/api/data")')
        assert "/api/data" in result

    def test_finds_jquery_get(self):
        mod = ParamsModule()
        result = mod._extract_js_endpoints('$.get("/api/items")')
        assert "/api/items" in result

    def test_finds_jquery_post(self):
        mod = ParamsModule()
        result = mod._extract_js_endpoints('$.post("/api/submit")')
        assert "/api/submit" in result


class TestExtractJsEndpointsXMLHttpRequest:
    def test_finds_xmlhttprequest_open(self):
        mod = ParamsModule()
        result = mod._extract_js_endpoints(
            'var xhr = new XMLHttpRequest(); xhr.open("GET", "/api/legacy");'
        )
        assert "/api/legacy" in result


class TestExtractJsEndpointsEdgeCases:
    def test_returns_empty_for_no_endpoints(self):
        mod = ParamsModule()
        result = mod._extract_js_endpoints("var x = 1; console.log('hello');")
        assert result == []

    def test_returns_empty_for_empty_text(self):
        mod = ParamsModule()
        result = mod._extract_js_endpoints("")
        assert result == []

    def test_deduplicates_same_endpoint(self):
        mod = ParamsModule()
        result = mod._extract_js_endpoints(
            'fetch("/api/users"); fetch("/api/users"); axios.get("/api/users")'
        )
        assert result == ["/api/users"]

    def test_ignores_anchor_urls(self):
        mod = ParamsModule()
        result = mod._extract_js_endpoints('var x = "#section"; fetch("/real")')
        assert "#section" not in result
        assert "/real" in result

    def test_ignores_data_urls(self):
        mod = ParamsModule()
        result = mod._extract_js_endpoints(
            'fetch("data:image/png;base64,..."); fetch("/api/real")'
        )
        assert "data:image/png;base64,..." not in result
        assert "/api/real" in result

    def test_returns_multiple_distinct_endpoints(self):
        mod = ParamsModule()
        result = mod._extract_js_endpoints(
            'fetch("/api/a"); axios.get("/api/b"); $.ajax("/api/c")'
        )
        assert len(result) == 3
        assert "/api/a" in result
        assert "/api/b" in result
        assert "/api/c" in result


# ── ParamsModule run() tests ───────────────────────────────────────────

class TestParamsModuleRunQueryParams:
    def test_extracts_url_query_params(self):
        mod = ParamsModule()
        rh = Mock()
        rh.get.return_value = Mock(text="<html></html>")
        out = Mock()

        mod.run("https://example.com/page?id=1&name=test", rh, out)

        calls = out.log_finding.call_args_list
        types = [c[0][1]["type"] for c in calls]
        assert "URL参数" in types

    def test_query_param_values_preserved(self):
        mod = ParamsModule()
        rh = Mock()
        rh.get.return_value = Mock(text="<html></html>")
        out = Mock()

        mod.run("https://example.com/search?q=hello&page=2", rh, out)

        calls = out.log_finding.call_args_list
        query_findings = [c[0][1] for c in calls if c[0][1]["type"] == "URL参数"]
        sources = {f["source"]: f["values"] for f in query_findings}
        assert sources["q"] == ["hello"]
        assert sources["page"] == ["2"]

    def test_url_without_query_params_no_url_findings(self):
        mod = ParamsModule()
        rh = Mock()
        rh.get.return_value = Mock(text="<html></html>")
        out = Mock()

        mod.run("https://example.com/page", rh, out)

        calls = out.log_finding.call_args_list
        types = [c[0][1]["type"] for c in calls]
        assert "URL参数" not in types


class TestParamsModuleRunFormExtraction:
    def test_extracts_form_details(self):
        mod = ParamsModule()
        rh = Mock()
        rh.get.return_value = Mock(text=(
            '<form action="/login" method="POST">'
            '<input name="username" type="text">'
            '<input name="password" type="password">'
            '</form>'
        ))
        out = Mock()

        mod.run("https://example.com", rh, out)

        calls = out.log_finding.call_args_list
        form_findings = [c[0][1] for c in calls if "表单" in c[0][1]["type"]]
        assert len(form_findings) == 1
        f = form_findings[0]
        assert f["type"] == "表单 (POST)"
        assert f["source"] == "/login"
        assert f["inputs"] == ["username", "password"]

    def test_form_without_action_uses_target_url(self):
        mod = ParamsModule()
        rh = Mock()
        rh.get.return_value = Mock(text=(
            '<form method="GET"><input name="q"></form>'
        ))
        out = Mock()

        mod.run("https://example.com/search", rh, out)

        calls = out.log_finding.call_args_list
        form_findings = [c[0][1] for c in calls if "表单" in c[0][1]["type"]]
        assert len(form_findings) == 1
        assert form_findings[0]["source"] == "https://example.com/search"

    def test_target_trailing_slash_stripped(self):
        mod = ParamsModule()
        rh = Mock()
        rh.get.return_value = Mock(text="<html></html>")
        out = Mock()

        mod.run("https://example.com/", rh, out)

        # Verify the get was called with stripped URL
        rh.get.assert_called_with("https://example.com")


class TestParamsModuleRunLinksAndScripts:
    def test_extracts_links(self):
        mod = ParamsModule()
        rh = Mock()
        rh.get.return_value = Mock(text=(
            '<a href="/about">About</a>'
            '<a href="/contact">Contact</a>'
        ))
        out = Mock()

        mod.run("https://example.com", rh, out)

        calls = out.log_finding.call_args_list
        link_findings = [c[0][1] for c in calls if c[0][1]["type"] == "链接/资源"]
        assert len(link_findings) == 2
        sources = [f["source"] for f in link_findings]
        assert "/about" in sources
        assert "/contact" in sources

    def test_extracts_script_src(self):
        mod = ParamsModule()
        rh = Mock()
        rh.get.return_value = Mock(text=(
            '<script src="/app.js"></script>'
            '<script src="/utils.js"></script>'
        ))
        out = Mock()

        mod.run("https://example.com", rh, out)

        calls = out.log_finding.call_args_list
        js_findings = [c[0][1] for c in calls if c[0][1]["type"] == "JS文件"]
        assert len(js_findings) == 2
        sources = [f["source"] for f in js_findings]
        assert "/app.js" in sources
        assert "/utils.js" in sources

    def test_links_capped_at_30(self):
        mod = ParamsModule()
        rh = Mock()
        links_html = "".join(f'<a href="/link{i}">L{i}</a>' for i in range(50))
        rh.get.return_value = Mock(text=links_html)
        out = Mock()

        mod.run("https://example.com", rh, out)

        calls = out.log_finding.call_args_list
        link_findings = [c[0][1] for c in calls if c[0][1]["type"] == "链接/资源"]
        assert len(link_findings) == 30

    def test_scripts_capped_at_10(self):
        mod = ParamsModule()
        rh = Mock()
        scripts_html = "".join(f'<script src="/s{i}.js"></script>' for i in range(20))
        rh.get.return_value = Mock(text=scripts_html)
        out = Mock()

        mod.run("https://example.com", rh, out)

        calls = out.log_finding.call_args_list
        js_findings = [c[0][1] for c in calls if c[0][1]["type"] == "JS文件"]
        assert len(js_findings) == 10


class TestParamsModuleRunJsEndpoints:
    def test_extracts_js_endpoints_from_inline_script(self):
        mod = ParamsModule()
        rh = Mock()
        rh.get.return_value = Mock(text=(
            '<script>fetch("/api/data")</script>'
        ))
        out = Mock()

        mod.run("https://example.com", rh, out)

        calls = out.log_finding.call_args_list
        ep_findings = [c[0][1] for c in calls if c[0][1]["type"] == "JS端点"]
        assert len(ep_findings) == 1
        assert ep_findings[0]["source"] == "/api/data"


class TestParamsModuleRunRequestFailure:
    def test_handles_request_failure_gracefully(self):
        mod = ParamsModule()
        rh = Mock()
        rh.get.side_effect = Exception("Connection refused")
        out = Mock()

        result = mod.run("https://example.com", rh, out)

        assert result == {"module": "params", "findings": []}
        out.log_finding.assert_not_called()

    def test_returns_empty_findings_on_failure(self):
        mod = ParamsModule()
        rh = Mock()
        rh.get.side_effect = Exception("Timeout")
        out = Mock()

        result = mod.run("https://example.com", rh, out)

        assert result["module"] == "params"
        assert result["findings"] == []


class TestParamsModuleRunCallsOutput:
    def test_logs_finding_for_each_finding(self):
        mod = ParamsModule()
        rh = Mock()
        rh.get.return_value = Mock(text=(
            '<form action="/login" method="POST"><input name="user"></form>'
            '<a href="/page">Page</a>'
        ))
        out = Mock()

        mod.run("https://example.com", rh, out)

        # Expect findings: form + link
        assert out.log_finding.call_count == 2

    def test_logs_finding_with_module_name(self):
        mod = ParamsModule()
        rh = Mock()
        rh.get.return_value = Mock(text='<a href="/link">L</a>')
        out = Mock()

        mod.run("https://example.com", rh, out)

        for call in out.log_finding.call_args_list:
            assert call[0][0] == "params"

    def test_logs_progress_messages(self):
        mod = ParamsModule()
        rh = Mock()
        rh.get.return_value = Mock(text="<html></html>")
        out = Mock()

        mod.run("https://example.com", rh, out)

        progress_calls = out.log_progress.call_args_list
        assert len(progress_calls) >= 1
        # First call should mention fetching
        assert "Fetching" in progress_calls[0][0][0]
        # Last call should mention done
        assert "done" in progress_calls[-1][0][0]


# ── Module attribute tests ─────────────────────────────────────────────

class TestParamsModuleAttributes:
    def test_module_name(self):
        mod = ParamsModule()
        assert mod.name == "params"

    def test_module_requires_url(self):
        mod = ParamsModule()
        assert mod.requires_url is True

    def test_module_has_description(self):
        mod = ParamsModule()
        assert isinstance(mod.description, str)
        assert len(mod.description) > 0

    def test_js_api_patterns_defined(self):
        mod = ParamsModule()
        assert isinstance(mod.JS_API_PATTERNS, list)
        assert len(mod.JS_API_PATTERNS) > 0
