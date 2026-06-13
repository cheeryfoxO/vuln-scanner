"""Tests for output formatter."""
import json
import os
import tempfile
from scanner.core.output import Output


def test_log_finding_stores_result():
    out = Output(verbose=False, use_color=False)
    finding = {"host": "admin.example.com", "ip": "1.2.3.4", "status": 200, "title": "Admin"}
    out.log_finding("subdomain", finding)
    assert "subdomain" in out.results
    assert out.results["subdomain"] == [finding]


def test_json_report_structure():
    out = Output(verbose=False, use_color=False)
    out.log_finding("dirscan", {"url": "http://x.com/.git/HEAD", "status": 200, "size": 41, "content_type": "text/plain"})

    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as f:
        path = f.name

    try:
        out.json_path = path
        report = out.write_report("example.com", ["dirscan"])
        assert report["target"] == "example.com"
        assert report["modules"] == ["dirscan"]
        assert "scan_time" in report
        assert "dirscan" in report["findings"]
        assert len(report["findings"]["dirscan"]) == 1

        with open(path) as f:
            saved = json.load(f)
        assert saved == report
    finally:
        os.unlink(path)


def test_multiple_modules_isolated():
    out = Output(verbose=False, use_color=False)
    out.log_finding("subdomain", {"host": "a.example.com", "status": 200, "title": "A"})
    out.log_finding("dirscan", {"url": "http://x.com/admin/", "status": 403, "size": 0, "content_type": "text/html"})
    assert len(out.results["subdomain"]) == 1
    assert len(out.results["dirscan"]) == 1
