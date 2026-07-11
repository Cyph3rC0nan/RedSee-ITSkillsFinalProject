"""
Tests for engine/env.py — the process-entry-point .env loader.

Fully offline: writes a temp .env file and monkeypatches engine.env._ENV_PATH
to point at it, so no real .env or network is touched. Also verifies the
ImportError-safe no-op path by simulating python-dotenv being unavailable.

Run: PYTHONPATH=. python -m pytest tests/test_env.py -v
"""
import importlib
import os
import sys

import pytest

import engine.env as env_module
from engine.env import load_env


_MARKER_KEY = "REDSEE_TEST_ENV_MARKER"
_PRESET_KEY = "REDSEE_TEST_ENV_PRESET"


@pytest.fixture(autouse=True)
def _clean_marker_vars():
    """Never let these test-only keys leak between tests or into the real env."""
    for k in (_MARKER_KEY, _PRESET_KEY):
        os.environ.pop(k, None)
    yield
    for k in (_MARKER_KEY, _PRESET_KEY):
        os.environ.pop(k, None)


def _write_env_file(tmp_path, contents: str):
    p = tmp_path / ".env"
    p.write_text(contents, encoding="utf-8")
    return p


def test_load_env_populates_unset_var_from_dotenv_file(tmp_path, monkeypatch):
    pytest.importorskip("dotenv")
    env_path = _write_env_file(tmp_path, f"{_MARKER_KEY}=from_dotenv_file\n")
    monkeypatch.setattr(env_module, "_ENV_PATH", env_path)

    assert _MARKER_KEY not in os.environ
    load_env()
    assert os.environ[_MARKER_KEY] == "from_dotenv_file"


def test_load_env_never_overrides_an_already_exported_var(tmp_path, monkeypatch):
    pytest.importorskip("dotenv")
    env_path = _write_env_file(tmp_path, f"{_PRESET_KEY}=from_dotenv_file\n")
    monkeypatch.setattr(env_module, "_ENV_PATH", env_path)

    os.environ[_PRESET_KEY] = "explicitly_exported"
    load_env()
    # The real, operator-exported value must win over the .env file.
    assert os.environ[_PRESET_KEY] == "explicitly_exported"


def test_load_env_is_idempotent(tmp_path, monkeypatch):
    pytest.importorskip("dotenv")
    env_path = _write_env_file(tmp_path, f"{_MARKER_KEY}=first_load\n")
    monkeypatch.setattr(env_module, "_ENV_PATH", env_path)

    load_env()
    load_env()
    load_env()
    assert os.environ[_MARKER_KEY] == "first_load"


def test_load_env_missing_file_is_a_safe_noop(tmp_path, monkeypatch):
    monkeypatch.setattr(env_module, "_ENV_PATH", tmp_path / "does_not_exist.env")
    load_env()  # must not raise
    assert _MARKER_KEY not in os.environ


def test_load_env_degrades_gracefully_without_python_dotenv(tmp_path, monkeypatch):
    # Simulate python-dotenv being uninstalled: make `from dotenv import
    # load_dotenv` raise ImportError inside load_env(), regardless of whether
    # dotenv is actually installed in this environment.
    env_path = _write_env_file(tmp_path, f"{_MARKER_KEY}=should_not_appear\n")
    monkeypatch.setattr(env_module, "_ENV_PATH", env_path)

    real_import = __import__

    def _fake_import(name, *args, **kwargs):
        if name == "dotenv":
            raise ImportError("simulated: python-dotenv not installed")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr("builtins.__import__", _fake_import)

    load_env()  # must not raise
    assert _MARKER_KEY not in os.environ  # no-op: nothing was loaded


if __name__ == "__main__":
    import tempfile
    from pathlib import Path

    class _MP:
        def __init__(self):
            self._undo = []

        def setattr(self, obj, name, value=None):
            # Support both monkeypatch.setattr(obj, name, value) and the
            # dotted-string form monkeypatch.setattr("builtins.__import__", fn).
            if value is None and isinstance(obj, str):
                mod_name, _, attr = obj.rpartition(".")
                obj, name, value = sys.modules[mod_name], attr, name
            self._undo.append((obj, name, getattr(obj, name)))
            setattr(obj, name, value)

        def undo(self):
            for obj, name, old in reversed(self._undo):
                setattr(obj, name, old)

    def _run(fn):
        needs_tmp = "tmp_path" in fn.__code__.co_varnames[:fn.__code__.co_argcount]
        needs_mp = "monkeypatch" in fn.__code__.co_varnames[:fn.__code__.co_argcount]
        for k in (_MARKER_KEY, _PRESET_KEY):
            os.environ.pop(k, None)
        mp = _MP() if needs_mp else None
        try:
            with tempfile.TemporaryDirectory() as d:
                args = []
                if needs_tmp:
                    args.append(Path(d))
                if needs_mp:
                    args.append(mp)
                try:
                    fn(*args)
                    print(f"  ok  {fn.__name__}")
                except BaseException as exc:
                    if type(exc).__name__ == "Skipped":
                        print(f"  skip {fn.__name__} ({exc})")
                    else:
                        raise
        finally:
            if mp is not None:
                mp.undo()
            for k in (_MARKER_KEY, _PRESET_KEY):
                os.environ.pop(k, None)

    for _fn in (
        test_load_env_populates_unset_var_from_dotenv_file,
        test_load_env_never_overrides_an_already_exported_var,
        test_load_env_is_idempotent,
        test_load_env_missing_file_is_a_safe_noop,
        test_load_env_degrades_gracefully_without_python_dotenv,
    ):
        _run(_fn)
    print("All env-loader unit tests passed!")
