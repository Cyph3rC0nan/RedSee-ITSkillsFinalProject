"""
Tests for engine/recon_tools.py's run_ffuf (content discovery / directory
brute-force), modules/recon.py's httpx->ffuf chaining, and ffuf's surfacing
into engine/report_io.py's SARIF/recon_<id>.json/run.json channel.

Fully offline: run_in_sandbox is monkeypatched with REAL captured ffuf JSON
output (tests/fixtures/ffuf_localhost_real.jsonl — captured from a throwaway
local HTTP test site seeded with a .git/config file and a robots.txt, scanned
with the exact built-image ffuf argv this module produces). No Docker, no
network, no LLM (recon_tools has no LLM/agent loop at all).

Run: PYTHONPATH=. python -m pytest tests/test_ffuf_recon.py -v
"""
import json
from pathlib import Path

import pytest

import engine.recon_tools as recon
from engine.recon_tools import (
    run_ffuf, ReconObservation,
    _build_ffuf_argv, _build_ffuf_target_url, _ffuf_rate,
    _assert_no_forbidden_flags, _FFUF_FORBIDDEN, _FFUF_RATE_CEILING,
    _is_sensitive_path, _parse_json_lines,
)
from engine.scope import ScopeConfig
from engine.agent import SqliCandidate, SqliAgentResult
from engine.llm import Usage
from engine.report_io import write_outputs

import modules.recon as recon_module
from modules.recon import _live_urls_from_httpx


# ── Real captured fixture ────────────────────────────────────────────────────

_FIXTURES = Path(__file__).resolve().parent / "fixtures"
_FFUF_REAL_LINES = _FIXTURES.joinpath("ffuf_localhost_real.jsonl").read_text(encoding="utf-8").strip()
_FFUF_SENSITIVE_LINE, _FFUF_NORMAL_LINE = _FFUF_REAL_LINES.splitlines()

IN_SCOPE_URL = "http://localhost:8080/"
OUT_SCOPE_URL = "http://evil.com/"


def _scope(rate_limit=60):
    return ScopeConfig(
        target_url="http://localhost:8080/",
        allowed_hosts=["localhost"],
        authorized=True,
        max_requests_per_min=rate_limit,
    )


def _fake_sandbox(calls, stdout, *, exit_code=0, timed_out=False):
    from engine.sandbox import SandboxResult

    def fake(argv, *, target_url, config, timeout_sec=120, **kwargs):
        calls.append({"argv": list(argv), "target_url": target_url})
        return SandboxResult(exit_code=exit_code, stdout=stdout, stderr="",
                             timed_out=timed_out, target_ip="10.0.0.9")

    return fake


def _raising_sandbox(calls, message="isolation self-test FAILED — target_unreachable=7"):
    from engine.sandbox import SandboxError

    def fake(argv, *, target_url, config, timeout_sec=120, **kwargs):
        calls.append({"argv": list(argv), "target_url": target_url})
        raise SandboxError(message)

    return fake


# ── argv builders / forbidden-flag guards (unit) ────────────────────────────

def test_ffuf_argv_has_detection_flags_and_no_forbidden():
    argv = _build_ffuf_argv(IN_SCOPE_URL, scope_config=_scope(), timeout_sec=150)
    assert argv[:3] == ["ffuf", "-u", "http://localhost:8080/FUZZ"]
    assert "-w" in argv and "/opt/wordlists/common.txt" in argv
    for flag in ("-json", "-s", "-noninteractive", "-mc", "-ac", "-t", "-rate", "-timeout", "-maxtime"):
        assert flag in argv
    for bad in _FFUF_FORBIDDEN:
        assert bad not in argv


def test_ffuf_target_url_adds_fuzz_keyword_exactly_once():
    assert _build_ffuf_target_url("http://h/market") == "http://h/market/FUZZ"
    assert _build_ffuf_target_url("http://h/market/") == "http://h/market/FUZZ"


def test_ffuf_argv_never_contains_write_recursion_or_method_flags():
    argv = _build_ffuf_argv(IN_SCOPE_URL, scope_config=_scope(), timeout_sec=150)
    for bad in ("-o", "-od", "-recursion", "-X", "-d", "-x", "-input-cmd", "-config"):
        assert bad not in argv


def test_ffuf_rate_honors_configured_value_and_is_ceiling_bounded():
    assert _ffuf_rate(_scope(rate_limit=10)) == "10"
    # A configured value above the ceiling is clamped, never passed through raw.
    assert _ffuf_rate(_scope(rate_limit=10_000)) == str(_FFUF_RATE_CEILING)
    assert int(_ffuf_rate(_scope(rate_limit=10_000))) < 10_000


def test_ffuf_maxtime_stays_below_the_sandbox_timeout():
    argv = _build_ffuf_argv(IN_SCOPE_URL, scope_config=_scope(), timeout_sec=150)
    maxtime = int(argv[argv.index("-maxtime") + 1])
    assert 0 < maxtime < 150


def test_forbidden_flag_assertion_trips():
    with pytest.raises(AssertionError):
        _assert_no_forbidden_flags(["ffuf", "-u", "x", "-recursion"], _FFUF_FORBIDDEN, tool="ffuf")


def test_is_sensitive_path():
    assert _is_sensitive_path("/.git/config")
    assert _is_sensitive_path("/admin")
    assert _is_sensitive_path("/backup.zip")
    assert _is_sensitive_path("/.env")
    assert not _is_sensitive_path("/robots.txt")
    assert not _is_sensitive_path("/index.html")


# ── Output parsing (source of truth) ────────────────────────────────────────

def test_parse_real_ffuf_json_lines():
    objs = _parse_json_lines(_FFUF_REAL_LINES)
    assert len(objs) == 2
    assert objs[0]["status"] == 200
    assert objs[0]["url"].endswith("/.git/config")


# ── run_ffuf: real hits -> ReconObservation(status="observed") ─────────────

def test_real_ffuf_hits_yield_observed_observations_with_path_status_length(monkeypatch):
    calls = []
    monkeypatch.setattr(recon, "run_in_sandbox", _fake_sandbox(calls, _FFUF_REAL_LINES))

    obs = run_ffuf([IN_SCOPE_URL], scope_config=_scope())

    assert len(calls) == 1
    assert len(obs) == 2
    for o in obs:
        assert isinstance(o, ReconObservation)
        assert o.tool == "ffuf"
        assert o.status == "observed"
        assert o.category == "content-discovery"
        assert o.error is None
        assert "path=" in o.evidence and "status=" in o.evidence and "length=" in o.evidence


def test_sensitive_path_hit_is_medium_severity(monkeypatch):
    calls = []
    monkeypatch.setattr(recon, "run_in_sandbox", _fake_sandbox(calls, _FFUF_REAL_LINES))

    obs = run_ffuf([IN_SCOPE_URL], scope_config=_scope())
    by_path = {o.evidence: o for o in obs}

    git_hit = next(o for o in obs if ".git/config" in o.evidence)
    assert git_hit.severity == "Medium"
    assert "path=/.git/config" in git_hit.evidence
    assert "status=200" in git_hit.evidence
    assert "length=16" in git_hit.evidence

    robots_hit = next(o for o in obs if "robots.txt" in o.evidence)
    assert robots_hit.severity == "Low"


# ── out-of-scope -> run_in_sandbox NOT called ───────────────────────────────

def test_ffuf_out_of_scope_target_not_scanned(monkeypatch):
    calls = []
    monkeypatch.setattr(recon, "run_in_sandbox", _fake_sandbox(calls, _FFUF_REAL_LINES))

    obs = run_ffuf([OUT_SCOPE_URL], scope_config=_scope())

    assert calls == [], "run_in_sandbox must NOT be called for an out-of-scope target"
    assert len(obs) == 1
    assert obs[0].status == "out_of_scope"
    assert obs[0].severity is None
    assert "evil.com" in obs[0].error


# ── sandbox error/timeout -> status="error", no fabricated hit ─────────────

def test_ffuf_sandbox_error_yields_error_status_not_fabricated(monkeypatch):
    calls = []
    monkeypatch.setattr(recon, "run_in_sandbox", _raising_sandbox(calls))

    obs = run_ffuf([IN_SCOPE_URL], scope_config=_scope())

    assert len(obs) == 1
    o = obs[0]
    assert o.status == "error"
    assert o.severity is None
    assert o.evidence == ""
    assert "self-test" in o.error.lower()


def test_ffuf_timeout_yields_error_status_not_fabricated(monkeypatch):
    calls = []
    monkeypatch.setattr(recon, "run_in_sandbox",
                        _fake_sandbox(calls, "", timed_out=True))

    obs = run_ffuf([IN_SCOPE_URL], scope_config=_scope())

    assert len(obs) == 1
    assert obs[0].status == "error"
    assert obs[0].severity is None
    assert "timed out" in obs[0].error


def test_ffuf_nonzero_exit_yields_error_not_fabricated(monkeypatch):
    calls = []
    monkeypatch.setattr(recon, "run_in_sandbox",
                        _fake_sandbox(calls, _FFUF_REAL_LINES, exit_code=1))

    obs = run_ffuf([IN_SCOPE_URL], scope_config=_scope())

    assert len(obs) == 1
    assert obs[0].status == "error"
    assert "non-zero" in obs[0].error
    assert obs[0].evidence == ""


def test_clean_empty_result_yields_no_observation_not_an_error(monkeypatch):
    calls = []
    monkeypatch.setattr(recon, "run_in_sandbox", _fake_sandbox(calls, ""))

    obs = run_ffuf([IN_SCOPE_URL], scope_config=_scope())
    assert obs == []


# ── httpx -> ffuf chaining (modules/recon.py) ───────────────────────────────

def _observed(tool, target):
    return ReconObservation(tool=tool, target=target, category="http-fingerprint",
                            title="x", severity="Low", evidence="e",
                            status="observed", error=None, argv=[])


def _errored(tool, target):
    return ReconObservation(tool=tool, target=target, category="error",
                            title="x", severity=None, evidence="",
                            status="error", error="e", argv=[])


def test_ffuf_targets_come_from_live_httpx_urls_when_present():
    httpx_obs = [
        _observed("httpx", "http://h1/"),
        _observed("httpx", "http://h2/"),
        _errored("httpx", "http://h3/"),          # not live -> excluded
    ]
    seed = ["http://h1/", "http://h2/", "http://h3/"]
    assert _live_urls_from_httpx(httpx_obs, seed) == ["http://h1/", "http://h2/"]


def test_ffuf_targets_fall_back_to_seed_when_no_live_httpx_urls():
    httpx_obs = [_errored("httpx", "http://h1/")]
    seed = ["http://h1/"]
    assert _live_urls_from_httpx(httpx_obs, seed) == ["http://h1/"]


def test_ffuf_targets_fall_back_to_seed_when_httpx_observations_empty():
    assert _live_urls_from_httpx([], ["http://h1/"]) == ["http://h1/"]


def test_run_recon_scan_chains_httpx_into_ffuf(monkeypatch, tmp_path):
    """End-to-end (still fully mocked): run_recon_scan calls run_httpx first,
    then passes ITS live URL(s) into run_ffuf — not the raw seed target."""
    from engine.nuclei_agent import NucleiAgentResult

    def fake_nuclei_agent(targets, **kwargs):
        return NucleiAgentResult(
            candidates=[],
            usage=Usage(input_tokens=0, output_tokens=0, cost_usd=0.0, calls=0),
            iterations=0, transcript=[], stopped_reason="done")

    ffuf_calls = []

    def fake_httpx(targets, *, scope_config):
        return [_observed("httpx", "http://live-host/discovered/")]

    def fake_tlsx(targets, *, scope_config):
        return []

    def fake_ffuf(targets, *, scope_config):
        ffuf_calls.append(list(targets))
        return [ReconObservation(tool="ffuf", target=targets[0],
                                 category="content-discovery", title="200 /admin",
                                 severity="Medium", evidence="path=/admin status=200 length=0",
                                 status="observed", error=None, argv=[])]

    monkeypatch.setattr(recon_module, "run_nuclei_agent", fake_nuclei_agent)
    monkeypatch.setattr(recon_module, "run_httpx", fake_httpx)
    monkeypatch.setattr(recon_module, "run_tlsx", fake_tlsx)
    monkeypatch.setattr(recon_module, "run_ffuf", fake_ffuf)

    scope_config = _scope()
    out = recon_module.run_recon_scan(
        ["http://seed-target/"], scope_config=scope_config, out_dir=str(tmp_path))

    # ffuf was called with httpx's LIVE url, not the raw seed target.
    assert ffuf_calls == [["http://live-host/discovered/"]]

    tools = {o.tool for o in out["recon_observations"]}
    assert tools == {"httpx", "ffuf"}


# ── report_io surfacing: SARIF + recon_<id>.json + run.json ────────────────

def _sqli_result():
    cand = SqliCandidate(
        endpoint_url="http://h/a?q=1", parameter="q", injectable=True,
        technique="boolean-based blind", dbms="SQLite", evidence="e",
        sqlmap_argv=["sqlmap"], depth=1, status="injectable", error=None)
    return SqliAgentResult(
        candidates=[cand],
        usage=Usage(input_tokens=1, output_tokens=1, cost_usd=0.0, calls=1),
        iterations=1, transcript=[{"role": "system", "action": "prompt", "summary": "x"}],
        stopped_reason="done")


def _real_ffuf_observations():
    """Real ffuf observations, built the same way run_ffuf does."""
    from engine.recon_tools import _ffuf_observation_for
    objs = _parse_json_lines(_FFUF_REAL_LINES)
    return [_ffuf_observation_for(IN_SCOPE_URL, obj, ["ffuf"]) for obj in objs]


def test_ffuf_observations_land_in_sarif_with_content_discovery_ruleid(tmp_path):
    observations = _real_ffuf_observations()
    paths = write_outputs(_sqli_result(), [], scan_id="f1", target_url="http://h/",
                          out_dir=str(tmp_path), recon_observations=observations)

    sarif = json.loads(Path(paths["sarif"]).read_text())
    results = sarif["runs"][0]["results"]
    rule_ids = {r["ruleId"] for r in results}
    assert "content-discovery" in rule_ids
    declared = {rule["id"] for rule in sarif["runs"][0]["tool"]["driver"]["rules"]}
    assert rule_ids <= declared

    by_evidence = {r["message"]["text"]: r["level"] for r in results}
    levels = [r["level"] for r in results if r["ruleId"] == "content-discovery"]
    assert "warning" in levels          # Medium (.git/config) -> warning
    assert "note" in levels             # Low (robots.txt) -> note


def test_ffuf_observations_written_to_dedicated_recon_json(tmp_path):
    observations = _real_ffuf_observations()
    paths = write_outputs(_sqli_result(), [], scan_id="f2", target_url="http://h/",
                          out_dir=str(tmp_path), recon_observations=observations)

    assert "recon" in paths
    data = json.loads(Path(paths["recon"]).read_text())
    assert len(data) == len(observations)
    assert all(r["tool"] == "ffuf" for r in data)
    assert any(r["severity"] == "Medium" for r in data)
    assert any(r["severity"] == "Low" for r in data)


def test_ffuf_run_json_gets_recon_summary(tmp_path):
    observations = _real_ffuf_observations()
    paths = write_outputs(_sqli_result(), [], scan_id="f3", target_url="http://h/",
                          out_dir=str(tmp_path), recon_observations=observations)

    run_data = json.loads(Path(paths["run"]).read_text())
    summ = run_data["recon"]
    assert summ["count_by_tool"]["ffuf"] == 2
    assert summ["count_by_severity"]["Medium"] == 1
    assert summ["count_by_severity"]["Low"] == 1


def test_findings_json_contains_no_ffuf_entries(tmp_path):
    observations = _real_ffuf_observations()
    from engine.finding_map import candidate_to_finding
    sqli_result = _sqli_result()
    finding = candidate_to_finding(sqli_result.candidates[0],
                                   target_url=sqli_result.candidates[0].endpoint_url,
                                   scan_id="mix")
    paths = write_outputs(sqli_result, [finding], scan_id="mix", target_url="http://h/",
                          out_dir=str(tmp_path), recon_observations=observations)

    findings_data = json.loads(Path(paths["findings"]).read_text())
    assert len(findings_data) == 1
    assert findings_data[0]["type"] == "SQLi"
    raw = Path(paths["findings"]).read_text().lower()
    assert "ffuf" not in raw
    assert "content-discovery" not in raw


# ── Standalone runner (repo convention) ─────────────────────────────────────

if __name__ == "__main__":
    class _MP:
        def __init__(self):
            self._undo = []

        def setattr(self, obj, name, value):
            self._undo.append((obj, name, getattr(obj, name)))
            setattr(obj, name, value)

        def undo(self):
            for obj, name, old in reversed(self._undo):
                setattr(obj, name, old)

    import inspect
    import tempfile

    def _run(fn):
        needs_mp = "monkeypatch" in inspect.signature(fn).parameters
        needs_tmp = "tmp_path" in inspect.signature(fn).parameters
        mp = _MP() if needs_mp else None
        try:
            if needs_tmp:
                with tempfile.TemporaryDirectory() as d:
                    kwargs = {}
                    if needs_mp:
                        kwargs["monkeypatch"] = mp
                    kwargs["tmp_path"] = Path(d)
                    fn(**kwargs)
            elif needs_mp:
                fn(mp)
            else:
                fn()
            print(f"  ok  {fn.__name__}")
        finally:
            if mp:
                mp.undo()

    _tests = [v for k, v in sorted(globals().items())
              if k.startswith("test_") and callable(v)]
    print(f"Running {len(_tests)} ffuf recon tests...")
    for _fn in _tests:
        _run(_fn)
    print("All ffuf recon tests passed!")
