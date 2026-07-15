"""
Tests for scan modes (fast / standard / deep) in modules/scan.py.

Fully offline: crawl + the injection agents (run_sqli_agent/run_xss_agent) + the
recon runners (run_nuclei_agent/run_httpx/run_tlsx/run_ffuf) are monkeypatched at
the modules.scan boundary and RECORD how they were called, so no sandbox/LLM/
network is touched. A guard on engine.recon_tools.run_in_sandbox fails loudly if
anything slips through.

Covers: fast/standard/deep differ as specified (breadth cap, injection depth,
recon selection); injection runs ONLY on param-bearing targets; nuclei uses the
scoped tag set + wall-clock bound; the mode is persisted in the record; deep is
unchanged (all param-bearing endpoints, default depth, every recon tool); and the
concurrent path records a per-tool failure as an error entry without aborting.

Run: PYTHONPATH=. python -m pytest tests/test_scan_modes.py -v
"""
import pytest

import modules.scan as scan
from modules.scan import run_scan
from schemas import Endpoint, Finding, Sitemap
from engine.params import InjectionTarget
from engine.scope import ScopeConfig
from engine.llm import Usage
from engine.agent import SqliAgentResult
from engine.xss_agent import XssAgentResult
from engine.nuclei_agent import NucleiAgentResult
from engine.recon_tools import ReconObservation


IN_SCOPE = "http://localhost:8080/"


def _scope():
    return ScopeConfig(target_url=IN_SCOPE, allowed_hosts=["localhost"], authorized=True)


def _link(i):
    """A param-bearing link endpoint (injectable)."""
    return Endpoint(url=f"http://localhost:8080/p{i:02d}?q=1", method="GET",
                    form_action=None, inputs=["q"], cookies_needed=[],
                    endpoint_type="link")


def _pageless(i):
    """A param-less page endpoint (NOT injectable — must be excluded)."""
    return Endpoint(url=f"http://localhost:8080/about{i}", method="GET",
                    form_action=None, inputs=[], cookies_needed=[],
                    endpoint_type="page")


def _sitemap(target, eps):
    return Sitemap(target_url=target, crawl_timestamp="2026-01-01T00:00:00Z",
                   endpoints=eps, total_pages=0, total_forms=0,
                   total_api_endpoints=0)


def _empty_sqli():
    return SqliAgentResult(candidates=[], usage=Usage(0, 0, 0.0, 0),
                           iterations=0, transcript=[], stopped_reason="done")


def _empty_xss():
    return XssAgentResult(candidates=[], usage=Usage(0, 0, 0.0, 0),
                          iterations=0, transcript=[], stopped_reason="done")


def _empty_nuclei():
    return NucleiAgentResult(candidates=[], usage=Usage(0, 0, 0.0, 0),
                             iterations=0, transcript=[], stopped_reason="done")


def _setup(monkeypatch, *, endpoints):
    """Install recording doubles; return a dict capturing how each was called."""
    rec = {"sqli": None, "xss": None, "nuclei": None,
           "httpx": 0, "tlsx": 0, "ffuf": 0}

    monkeypatch.setattr(scan, "crawl", lambda t: _sitemap(t, endpoints))

    def fake_sqli(targets, **kw):
        rec["sqli"] = {"targets": list(targets), "kw": kw}
        return _empty_sqli()

    def fake_xss(targets, **kw):
        rec["xss"] = {"targets": list(targets), "kw": kw}
        return _empty_xss()

    def fake_nuclei(t, **kw):
        rec["nuclei"] = {"targets": list(t), "kw": kw}
        return _empty_nuclei()

    monkeypatch.setattr(scan, "run_sqli_agent", fake_sqli)
    monkeypatch.setattr(scan, "run_xss_agent", fake_xss)
    monkeypatch.setattr(scan, "run_nuclei_agent", fake_nuclei)
    monkeypatch.setattr(scan, "run_httpx",
                        lambda t, **k: (rec.__setitem__("httpx", rec["httpx"] + 1), [])[1])
    monkeypatch.setattr(scan, "run_tlsx",
                        lambda t, **k: (rec.__setitem__("tlsx", rec["tlsx"] + 1), [])[1])
    monkeypatch.setattr(scan, "run_ffuf",
                        lambda t, **k: (rec.__setitem__("ffuf", rec["ffuf"] + 1), [])[1])

    def _boom(*a, **k):
        raise AssertionError("run_in_sandbox must not be reached — agents are mocked")
    monkeypatch.setattr("engine.recon_tools.run_in_sandbox", _boom)
    return rec


# ── breadth: injection only on param-bearing, capped per mode ────────────────

@pytest.mark.parametrize("mode,expected", [("fast", 5), ("standard", 10), ("deep", 12)])
def test_injection_targets_capped_per_mode_and_param_bearing_only(monkeypatch, tmp_path,
                                                                  mode, expected):
    eps = [_link(i) for i in range(12)] + [_pageless(i) for i in range(3)]
    rec = _setup(monkeypatch, endpoints=eps)

    run_scan(IN_SCOPE, scope_config=_scope(), out_dir=str(tmp_path), mode=mode)

    targets = rec["sqli"]["targets"]
    assert len(targets) == expected
    # every injected target is a real param-bearing InjectionTarget ...
    assert all(isinstance(t, InjectionTarget) and t.param_names for t in targets)
    # ... and NOT one of the param-less pages
    assert all("/about" not in t.url for t in targets)
    # xss gets the same target set
    assert len(rec["xss"]["targets"]) == expected


# ── depth: level/risk/iterations/timeout differ per mode ─────────────────────

def test_fast_mode_shallow_injection_depth(monkeypatch, tmp_path):
    rec = _setup(monkeypatch, endpoints=[_link(0)])
    run_scan(IN_SCOPE, scope_config=_scope(), out_dir=str(tmp_path), mode="fast")
    kw = rec["sqli"]["kw"]
    assert kw["max_level"] == 1 and kw["max_risk"] == 1
    assert kw["max_iterations"] == 2
    assert kw["timeout_sec"] == 60
    assert rec["xss"]["kw"]["max_iterations"] == 2


def test_standard_mode_medium_injection_depth(monkeypatch, tmp_path):
    rec = _setup(monkeypatch, endpoints=[_link(0)])
    run_scan(IN_SCOPE, scope_config=_scope(), out_dir=str(tmp_path), mode="standard")
    kw = rec["sqli"]["kw"]
    assert kw["max_level"] == 3 and kw["max_risk"] == 2
    assert kw["max_iterations"] == 4
    assert kw["timeout_sec"] == 120


def test_deep_mode_uses_agent_default_depth(monkeypatch, tmp_path):
    rec = _setup(monkeypatch, endpoints=[_link(0)])
    run_scan(IN_SCOPE, scope_config=_scope(), out_dir=str(tmp_path), mode="deep")
    kw = rec["sqli"]["kw"]
    assert kw["max_level"] == 3 and kw["max_risk"] == 2
    assert kw["max_iterations"] == 6       # the agents' own default
    assert kw["timeout_sec"] is None       # -> agent default sandbox timeout


# ── recon selection per mode ─────────────────────────────────────────────────

def test_fast_mode_skips_nuclei_and_ffuf(monkeypatch, tmp_path):
    rec = _setup(monkeypatch, endpoints=[_link(0)])
    record = run_scan(IN_SCOPE, scope_config=_scope(), out_dir=str(tmp_path), mode="fast")

    assert rec["nuclei"] is None           # nuclei never invoked
    assert rec["ffuf"] == 0                 # ffuf never invoked
    assert rec["httpx"] == 1 and rec["tlsx"] == 1

    by_name = {t["name"]: t for t in record["tools_run"]}
    assert by_name["nuclei"]["status"] == "skipped"
    assert by_name["ffuf"]["status"] == "skipped"
    assert by_name["httpx"]["status"] == "ran"


def test_standard_mode_runs_scoped_nuclei_and_ffuf(monkeypatch, tmp_path):
    rec = _setup(monkeypatch, endpoints=[_link(0)])
    run_scan(IN_SCOPE, scope_config=_scope(), out_dir=str(tmp_path), mode="standard")

    assert rec["ffuf"] == 1
    assert rec["nuclei"] is not None
    # SCOPED template tags + a wall-clock bound handed to the nuclei agent (the
    # template DIRS are memory-bounded inside the agent; these tags scope within them)
    assert rec["nuclei"]["kw"]["default_tags"] == ["exposure", "misconfig"]
    assert rec["nuclei"]["kw"]["timeout_sec"] == 300


def test_deep_mode_runs_all_recon_with_default_nuclei(monkeypatch, tmp_path):
    rec = _setup(monkeypatch, endpoints=[_link(0)])
    run_scan(IN_SCOPE, scope_config=_scope(), out_dir=str(tmp_path), mode="deep")

    assert rec["httpx"] == 1 and rec["tlsx"] == 1 and rec["ffuf"] == 1
    assert rec["nuclei"] is not None
    assert rec["nuclei"]["kw"]["default_tags"] is None    # nuclei's own default profile
    assert rec["nuclei"]["kw"]["timeout_sec"] is None


# ── mode persisted in the record ─────────────────────────────────────────────

def test_mode_persisted_in_record(monkeypatch, tmp_path):
    _setup(monkeypatch, endpoints=[_link(0), _link(1)])
    record = run_scan(IN_SCOPE, scope_config=_scope(), out_dir=str(tmp_path), mode="fast")
    assert record["mode"] == "fast"
    assert record["summary"]["mode"] == "fast"
    assert record["caps"]["mode"] == "fast"
    assert record["caps"]["max_injection_targets"] == 5
    assert record["summary"]["injection_targets"] == 2      # only 2 crawled targets


def test_unknown_mode_degrades_to_standard(monkeypatch, tmp_path):
    rec = _setup(monkeypatch, endpoints=[_link(0)])
    record = run_scan(IN_SCOPE, scope_config=_scope(), out_dir=str(tmp_path),
                      mode="turbo-nonsense")
    assert record["mode"] == "standard"
    assert rec["nuclei"] is not None                        # standard runs nuclei


# ── deep unchanged: every param-bearing endpoint, all recon ──────────────────

def test_deep_injects_every_param_bearing_endpoint(monkeypatch, tmp_path):
    # Kept comfortably under the global _MAX_TOTAL_INJECTION_TARGETS safety ceiling
    # (see test_global_injection_ceiling_bounds_a_pathological_target below) so this
    # test isolates "deep has no MODE-level cap" from the separate hard ceiling.
    eps = [_link(i) for i in range(12)] + [_pageless(0)]
    rec = _setup(monkeypatch, endpoints=eps)
    record = run_scan(IN_SCOPE, scope_config=_scope(), out_dir=str(tmp_path), mode="deep")
    # all 12 param-bearing endpoints injected (the one param-less page excluded)
    assert len(rec["sqli"]["targets"]) == 12
    assert record["caps"]["injection_targets_selected"] == 12
    assert record["caps"]["max_injection_targets"] is None


def test_global_injection_ceiling_bounds_a_pathological_target(monkeypatch, tmp_path):
    """Even deep mode (max_injection_targets=None -> no MODE cap) must never exceed
    the HARD _MAX_TOTAL_INJECTION_TARGETS ceiling — the last line of defense against
    a param-rich target spawning dozens of sandboxed injection runs in one scan."""
    eps = [_link(i) for i in range(40)]
    rec = _setup(monkeypatch, endpoints=eps)
    record = run_scan(IN_SCOPE, scope_config=_scope(), out_dir=str(tmp_path), mode="deep")
    ceiling = record["caps"]["max_total_injection_targets"]
    assert len(rec["sqli"]["targets"]) == ceiling
    assert record["summary"]["injection_targets"] <= ceiling


# ── concurrent path: a per-tool failure is an error entry, scan completes ─────

def test_concurrent_tool_failure_recorded_not_aborted(monkeypatch, tmp_path):
    rec = _setup(monkeypatch, endpoints=[_link(0)])

    def boom_tlsx(t, **k):
        raise RuntimeError("tlsx sandbox exploded")
    monkeypatch.setattr(scan, "run_tlsx", boom_tlsx)

    record = run_scan(IN_SCOPE, scope_config=_scope(), out_dir=str(tmp_path), mode="standard")
    by_name = {t["name"]: t for t in record["tools_run"]}

    assert by_name["tlsx"]["status"] == "error"
    assert "RuntimeError" in by_name["tlsx"]["detail"]
    # the failure did not abort the rest of the concurrent stages
    assert by_name["httpx"]["status"] == "ran"
    assert by_name["nuclei"]["status"] in ("ran", "skipped", "error")
    assert record["summary"]["tools_error"] >= 1


# ── standalone runner (repo convention) ──────────────────────────────────────

if __name__ == "__main__":
    class _MP:
        def __init__(self):
            self._undo = []

        def setattr(self, obj, name, value=None):
            if isinstance(obj, str):
                import importlib
                mod, _, attr = obj.rpartition(".")
                obj, name = importlib.import_module(mod), attr
            self._undo.append((obj, name, getattr(obj, name)))
            setattr(obj, name, value)

        def undo(self):
            for obj, name, old in reversed(self._undo):
                setattr(obj, name, old)

    import inspect
    import tempfile
    from pathlib import Path

    def _run(fn, **extra):
        needs_mp = "monkeypatch" in inspect.signature(fn).parameters
        needs_tmp = "tmp_path" in inspect.signature(fn).parameters
        mp = _MP() if needs_mp else None
        try:
            with tempfile.TemporaryDirectory() as d:
                kwargs = dict(extra)
                if needs_mp:
                    kwargs["monkeypatch"] = mp
                if needs_tmp:
                    kwargs["tmp_path"] = Path(d)
                fn(**kwargs)
            print(f"  ok  {fn.__name__}{extra or ''}")
        finally:
            if mp:
                mp.undo()

    print("Running scan-mode tests...")
    _run(test_injection_targets_capped_per_mode_and_param_bearing_only, mode="fast", expected=5)
    _run(test_injection_targets_capped_per_mode_and_param_bearing_only, mode="standard", expected=10)
    _run(test_injection_targets_capped_per_mode_and_param_bearing_only, mode="deep", expected=12)
    for _fn in [v for k, v in sorted(globals().items())
                if k.startswith("test_") and callable(v)
                and k != "test_injection_targets_capped_per_mode_and_param_bearing_only"]:
        _run(_fn)
    print("All scan-mode tests passed!")
