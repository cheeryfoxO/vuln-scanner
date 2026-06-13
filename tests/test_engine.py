"""Tests for the scan engine."""
from scanner.core.engine import Engine
from scanner.modules.base import BaseModule


class FakeOutput:
    """Minimal Output stub for testing."""
    def __init__(self):
        self.results = {}
        self.progress = []

    def log_finding(self, module_name, finding):
        self.results.setdefault(module_name, []).append(finding)

    def log_progress(self, message):
        self.progress.append(message)

    def write_report(self, target, modules):
        pass


class FakeRequestHandler:
    """Stub request handler."""
    pass


class FakeModule(BaseModule):
    name = "fake"
    description = "A test module"
    requires_url = False

    def run(self, target, request_handler, output):
        output.log_finding(self.name, {"key": "value"})
        return {"module": self.name, "findings": [{"key": "value"}]}


def test_engine_registers_module():
    engine = Engine()
    mod = FakeModule()
    engine.register(mod)
    assert mod.name in engine.modules


def test_engine_runs_single_module():
    engine = Engine()
    engine.register(FakeModule())
    output = FakeOutput()
    req = FakeRequestHandler()
    results = engine.run("example.com", ["fake"], req, output, threads=10)
    assert results["target"] == "example.com"
    assert results["findings"]["fake"] == [{"key": "value"}]


def test_engine_skips_unknown_module():
    engine = Engine()
    engine.register(FakeModule())
    output = FakeOutput()
    results = engine.run("example.com", ["nonexistent"], FakeRequestHandler(), output, threads=10)
    assert results["findings"] == {}


def test_engine_lists_registered_modules():
    engine = Engine()
    engine.register(FakeModule())
    info = engine.list_modules()
    assert info["fake"] == "A test module"
