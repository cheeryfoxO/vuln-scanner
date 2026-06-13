"""Tests for base module interface."""
from scanner.modules.base import BaseModule


def test_cannot_instantiate_abstract():
    """Instantiating BaseModule directly should raise TypeError."""
    try:
        BaseModule()
        assert False, "Should have raised TypeError"
    except TypeError:
        pass


def test_concrete_subclass_works():
    """A subclass that implements run() should work."""
    class TestMod(BaseModule):
        name = "test"
        description = "Test module"
        requires_url = False

        def run(self, target, request_handler, output):
            return {"module": self.name, "findings": []}

    mod = TestMod()
    assert mod.name == "test"
    assert mod.requires_url is False
    result = mod.run("example.com", None, None)
    assert result == {"module": "test", "findings": []}
