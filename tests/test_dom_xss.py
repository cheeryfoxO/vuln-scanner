"""Tests for DOM XSS sink analysis module."""
from scanner.modules.dom_xss import (
    _find_dom_xss,
    _extract_scripts,
    SINK_PATTERNS,
    SOURCE_PATTERNS,
    DomXssModule,
)


class TestFindDomXss:
    def test_finds_innerhtml_with_location_hash(self):
        js_code = """
        function update() {
            var hash = location.hash;
            document.getElementById('main').innerHTML = hash;
        }
        """
        results = _find_dom_xss(js_code, "app.js")
        assert len(results) >= 1
        assert any(r["sink"] == ".innerHTML" for r in results)
        assert any(r["source"] == "location.hash" for r in results)

    def test_reports_correct_line_number(self):
        js_code = """
        var x = 1;
        var y = 2;
        document.write(location.search);
        """
        results = _find_dom_xss(js_code, "inline")
        assert len(results) >= 1
        assert results[0]["line"] == 4

    def test_eval_with_document_url(self):
        js_code = 'eval(document.URL.split("#")[1]);'
        results = _find_dom_xss(js_code, "app.js")
        assert len(results) >= 1

    def test_sink_without_source_not_reported(self):
        js_code = 'document.getElementById("x").innerHTML = "safe";'
        results = _find_dom_xss(js_code, "app.js")
        assert len(results) == 0

    def test_source_outside_window_not_reported(self):
        js_code = """
        var url = location.hash;
        // some comment
        // more comments
        // padding
        // padding line 2
        document.getElementById('x').innerHTML = url;
        """
        results = _find_dom_xss(js_code, "app.js")
        assert len(results) == 0  # source more than 3 lines away


class TestExtractScripts:
    def test_extracts_inline_script(self):
        html = '<html><script>var x = 1;</script></html>'
        inline, external = _extract_scripts(html, "http://test.com")
        assert len(inline) >= 1
        assert "var x = 1" in inline[0][1]

    def test_extracts_external_script(self):
        html = '<script src="/app.js"></script>'
        inline, external = _extract_scripts(html, "http://test.com")
        assert "http://test.com/app.js" in external

    def test_ignores_empty_inline_scripts(self):
        html = '<script src="/lib.js"></script><script>  </script>'
        inline, external = _extract_scripts(html, "http://test.com")
        assert len(inline) == 0

    def test_handles_absolute_external_urls(self):
        html = '<script src="https://cdn.example.com/lib.js"></script>'
        inline, external = _extract_scripts(html, "http://test.com")
        assert "https://cdn.example.com/lib.js" in external


class TestPatterns:
    def test_sinks_non_empty(self):
        assert len(SINK_PATTERNS) >= 8

    def test_sources_non_empty(self):
        assert len(SOURCE_PATTERNS) >= 6


class TestModule:
    def test_module_attributes(self):
        mod = DomXssModule()
        assert mod.name == "dom_xss"
        assert mod.requires_url is True
        assert "DOM" in mod.description
