"""Tests for scan presets."""
from scanner.core.presets import (
    BUILTIN_PRESETS, load_presets, save_user_preset,
)

import tempfile, os
from unittest.mock import patch


class TestBuiltins:
    def test_quick_exists(self):
        assert "quick" in BUILTIN_PRESETS
        assert BUILTIN_PRESETS["quick"]["modules"] == "fingerprint,headers,cors,dirscan"

    def test_full_uses_all(self):
        assert BUILTIN_PRESETS["full"]["modules"] == "all"

    def test_six_builtins(self):
        assert len(BUILTIN_PRESETS) == 6


class TestLoadPresets:
    def test_loads_builtins(self):
        presets = load_presets()
        assert "quick" in presets
        assert "full" in presets


class TestSaveUserPreset:
    def test_saves_and_loads(self):
        import scanner.core.presets as pmod
        old_path = pmod.PRESETS_FILE
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            pmod.PRESETS_FILE = f.name
        try:
            save_user_preset("my-test", "sqli,headers", threads=5, delay=50)
            presets = load_presets()
            assert "my-test" in presets
            assert presets["my-test"]["modules"] == "sqli,headers"
            assert presets["my-test"]["threads"] == 5
        finally:
            os.unlink(pmod.PRESETS_FILE)
            pmod.PRESETS_FILE = old_path
