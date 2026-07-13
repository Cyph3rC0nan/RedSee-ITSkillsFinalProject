"""
Tests for modules/scan.py — the unified scan orchestrator (aggregation spine).

Fully offline: crawl + every tool call (scan_sqli/scan_xss/run_nuclei_agent/
run_httpx/run_tlsx/run_ffuf) is monkeypatched at the modules.scan boundary, so
run_in_sandbox is never reached and no network/Docker/LLM is touched. A guard
monkeypatch on engine.recon_tools.run_in_sandbox asserts that (the tools are
fully mocked above it).

Run: PYTHONPATH=. python -m pytest tests/test_orchestrator.py -v
"""
import json
from pathlib import Path

import pytest

import modules.scan as scan
from modules.scan import run_scan
from schemas import Endpoint, Finding, Sitemap
from engine.scope import ScopeConfig, ScopeError
from engine.llm import Usage
from engine.nuclei_agent import NucleiCandidate, NucleiAgentResult
from engine.recon_tools import ReconObservation
from engine.report_io import write_outputs


IN_SCOPE = "http://localhost:8080/"
OUT_SCOPE = "http://evil.com/"


def _scope(authorized=True, hosts=("localhost",)):
    return ScopeConfig(target_url=IN_SCOPE, allowed_hosts=list(hosts), authorized=authorized)


# ── test doubles ─────────────────────────────────────────────────────────────

def _endpoint(url=IN_SCOPE):
    return Endpoint(url=url, method="GET", form_action=None, inputs=["q"],
                    cookies_needed=[], endpoint_type="api")


def _sitemap(target, endpoints):
    return Sitemap(target_url=target, crawl_timestamp="2026-01-01T00:00:00Z",
                   endpoints=endpoints, total_pages=1, total_forms=0,
                   total_api_endpoints=len(endpoints))


def _finding(severity, typ="SQLi", url="http://localhost:8080/a"):
    return Finding(type=typ, url=url, parameter="q", payload="p", evidence="e",
                   severity=severity, timestamp="2026-01-01T00:00:00Z")


def _nuclei_result(candidates):
    return NucleiAgentResult(
        candidates=candidates,
        usage=Usage(input_tokens=1, output_tokens=1, cost_usd=0.0, calls=1),
        iterations=1, transcript=[{"role": "system", "action": "x", "summary": "y"}],
        stopped_reason="done")


def _found_candidate(target=IN_SCOPE):
    return NucleiCandidate(target=target, template_id="tech-detect", name="Tech Detect",
                           severity="info", matched_at=target, evidence="Apache",
                           status="found", error=None)


def _obs(tool, *, status="observed", severity="Low", category="http-fingerprint",
         target=IN_SCOPE):
    return ReconObservation(tool=tool, target=target, category=category, title="x",
                            severity=severity, evidence="e", status=status,
                            error=None, argv=[])


def _guard_sandbox(monkeypatch):
    """Prove the tools are fully mocked above run_in_sandbox: if anything reaches
    it, fail loudly."""
    def _boom(*a, **k):
        raise AssertionError("run_in_sandbox must not be reached — tools are mocked")
    monkeypatch.setattr("engine.recon_tools.run_in_sandbox", _boom)


def _mock_all(monkeypatch, *, endpoints=None, sqli=None, xss=None,
              nuclei=None, httpx=None, tlsx=None, ffuf=None):
    """Install a full set of passing tool doubles; any can be overridden."""
    eps = [_endpoint()] if endpoints is None else endpoints
    monkeypatch.setattr(scan, "crawl", lambda t: _sitemap(t, eps))
    monkeypatch.setattr(scan, "scan_sqli", lambda e: list(sqli or []))
    monkeypatch.setattr(scan, "scan_xss", lambda e: list(xss or []))
    monkeypatch.setattr(scan, "run_nuclei_agent",
                        lambda t, **k: _nuclei_result(list(nuclei or [])))
    monkeypatch.setattr(scan, "run_httpx", lambda t, **k: list(httpx or []))
    monkeypatch.setattr(scan, "run_tlsx", lambda t, **k: list(tlsx or []))
    monkeypatch.setattr(scan, "run_ffuf", lambda t, **k: list(ffuf or []))
    _guard_sandbox(monkeypatch)


# ── happy path ───────────────────────────────────────────────────────────────

def test_happy_path_unifies_all_sections_with_shared_scan_id(monkeypatch, tmp_path):
    _mock_all(
        monkeypatch,
        sqli=[_finding("Critical")],
        xss=[_finding("Medium", typ="XSS")],
        nuclei=[_found_candidate()],
        httpx=[_obs("httpx")],
        tlsx=[],
        ffuf=[_obs("ffuf", severity="Medium", category="content-discovery")],
    )

    rec = run_scan(IN_SCOPE, scope_config=_scope(), out_dir=str(tmp_path))

    # all top-level sections present
    assert set(rec) >= {"scan_id", "target", "started_at", "finished_at",
                        "redsee_version", "tools_run", "findings", "recon", "summary"}
    assert rec["target"] == IN_SCOPE

    # tools_run reflects every stage
    by_name = {t["name"]: t for t in rec["tools_run"]}
    assert set(by_name) == {"crawl", "sqli", "xss", "nuclei", "httpx", "tlsx", "ffuf"}
    assert by_name["sqli"]["status"] == "ran" and by_name["sqli"]["count"] == 1
    assert by_name["nuclei"]["count"] == 1          # one "found" candidate
    assert by_name["ffuf"]["count"] == 1

    # findings + severity rollup
    assert len(rec["findings"]) == 2
    assert rec["summary"]["findings_by_severity"]["Critical"] == 1
    assert rec["summary"]["findings_by_severity"]["Medium"] == 1
    assert rec["summary"]["findings_by_severity"]["High"] == 0
    assert rec["summary"]["findings_total"] == 2

    # recon sections use the report_io serializer shapes
    assert len(rec["recon"]["nuclei"]) == 1
    assert rec["recon"]["nuclei"][0]["template_id"] == "tech-detect"
    assert len(rec["recon"]["observations"]) == 2   # httpx + ffuf
    assert rec["summary"]["recon_observations"] == 2
    assert rec["summary"]["tools_ok"] == 7 and rec["summary"]["tools_error"] == 0

    # shared scan_id across ALL artifacts
    sid = rec["scan_id"]
    for name in (f"scan_{sid}.json", f"findings_{sid}.json", f"findings_{sid}.sarif",
                 f"run_{sid}.json", f"nuclei_{sid}.json", f"recon_{sid}.json"):
        assert (tmp_path / name).exists(), f"missing {name}"

    # unified file on disk matches the returned record
    on_disk = json.loads((tmp_path / f"scan_{sid}.json").read_text())
    assert on_disk["scan_id"] == sid
    assert len(on_disk["findings"]) == 2


def test_findings_file_shares_scan_id_and_content(monkeypatch, tmp_path):
    _mock_all(monkeypatch, sqli=[_finding("High")], nuclei=[], httpx=[])
    rec = run_scan(IN_SCOPE, scope_config=_scope(), out_dir=str(tmp_path))
    sid = rec["scan_id"]

    findings_json = json.loads((tmp_path / f"findings_{sid}.json").read_text())
    assert len(findings_json) == 1
    assert findings_json[0]["type"] == "SQLi"
    assert findings_json[0]["severity"] == "High"


# ── one tool raises -> error entry, scan still completes ─────────────────────

def test_one_tool_error_is_isolated_scan_completes_no_fabrication(monkeypatch, tmp_path):
    _mock_all(monkeypatch, sqli=[_finding("Critical")], httpx=[_obs("httpx")])

    # nuclei blows up; everything else is fine.
    def _boom(t, **k):
        raise RuntimeError("nuclei sandbox exploded")
    monkeypatch.setattr(scan, "run_nuclei_agent", _boom)

    rec = run_scan(IN_SCOPE, scope_config=_scope(), out_dir=str(tmp_path))

    by_name = {t["name"]: t for t in rec["tools_run"]}
    assert by_name["nuclei"]["status"] == "error"
    assert "RuntimeError" in by_name["nuclei"]["detail"]
    assert by_name["nuclei"]["count"] == 0

    # the scan still completed: other tools present, findings intact
    assert by_name["sqli"]["status"] == "ran"
    assert by_name["httpx"]["status"] == "ran"
    assert len(rec["findings"]) == 1

    # NOTHING fabricated for the failed tool
    assert rec["recon"]["nuclei"] == []

    # per-tool artifacts still produced under the shared id (nuclei_<id>.json empty)
    sid = rec["scan_id"]
    assert (tmp_path / f"scan_{sid}.json").exists()
    assert json.loads((tmp_path / f"nuclei_{sid}.json").read_text()) == []


def test_crawl_failure_skips_vuln_agents_but_recon_still_runs(monkeypatch, tmp_path):
    _mock_all(monkeypatch, httpx=[_obs("httpx")])

    def _boom(t):
        raise ConnectionError("crawl could not connect")
    monkeypatch.setattr(scan, "crawl", _boom)

    rec = run_scan(IN_SCOPE, scope_config=_scope(), out_dir=str(tmp_path))
    by_name = {t["name"]: t for t in rec["tools_run"]}

    assert by_name["crawl"]["status"] == "error"
    # no endpoints -> vuln agents skipped (not errored, not fabricated)
    assert by_name["sqli"]["status"] == "skipped"
    assert by_name["xss"]["status"] == "skipped"
    assert rec["findings"] == []
    # recon (target-based) still ran
    assert by_name["httpx"]["status"] == "ran"


def test_all_errored_recon_tool_surfaces_as_error_entry(monkeypatch, tmp_path):
    """recon tools swallow a sandbox/isolation failure into a status="error"
    observation (they don't raise), so a tool that errored on every target must
    show as an "error" tools_run entry — not a misleading "ran count=0". This is
    exactly what a real host-local-sandbox-unreachable run produces."""
    sandbox_err = ("sandbox execution failed: isolation self-test FAILED — "
                   "target_unreachable=7")
    err_obs = _obs("httpx", status="error", severity=None, category="error")
    err_obs.error = sandbox_err
    err_cand = NucleiCandidate(target=IN_SCOPE, template_id=None, name=None,
                               severity=None, matched_at=IN_SCOPE, evidence="",
                               status="error", error=sandbox_err)

    _mock_all(monkeypatch, sqli=[_finding("Low")])
    monkeypatch.setattr(scan, "run_httpx", lambda t, **k: [err_obs])
    monkeypatch.setattr(scan, "run_tlsx", lambda t, **k: [err_obs])
    monkeypatch.setattr(scan, "run_ffuf", lambda t, **k: [err_obs])
    monkeypatch.setattr(scan, "run_nuclei_agent", lambda t, **k: _nuclei_result([err_cand]))

    rec = run_scan(IN_SCOPE, scope_config=_scope(), out_dir=str(tmp_path))
    by_name = {t["name"]: t for t in rec["tools_run"]}

    for tool in ("httpx", "tlsx", "ffuf", "nuclei"):
        assert by_name[tool]["status"] == "error", f"{tool} should be error"
        assert "target_unreachable" in by_name[tool]["detail"]
    # crawl + the two vuln agents (legacy-fallback) still ran -> honest 3 ok / 4 err
    assert rec["summary"]["tools_ok"] == 3
    assert rec["summary"]["tools_error"] == 4
    # error observations are preserved (not fabricated away), but count 0 observed
    assert rec["summary"]["recon_observations"] == 0
    assert len(rec["recon"]["observations"]) == 3     # the 3 error rows kept for audit


# ── gating: unauthorized / out-of-scope -> refuse, no outputs ────────────────

def test_unauthorized_refused_no_outputs(monkeypatch, tmp_path):
    _mock_all(monkeypatch)   # doubles installed, but gating happens first
    with pytest.raises(ScopeError):
        run_scan(IN_SCOPE, scope_config=_scope(authorized=False), out_dir=str(tmp_path))
    assert list(tmp_path.glob("*.json")) == []


def test_out_of_scope_refused_no_outputs(monkeypatch, tmp_path):
    _mock_all(monkeypatch)
    with pytest.raises(ScopeError):
        run_scan(OUT_SCOPE, scope_config=_scope(), out_dir=str(tmp_path))
    assert list(tmp_path.glob("*.json")) == []


# ── existing per-tool outputs byte-for-byte unchanged by the spine ───────────

def test_per_tool_outputs_byte_for_byte_match_direct_write_outputs(monkeypatch, tmp_path):
    """The spine must not ALTER write_outputs' output. Compare the deterministic
    per-tool files (no timestamps) produced by run_scan against a direct
    write_outputs call with the same inputs — they must be byte-identical.
    (run_<id>.json is excluded: it embeds a wall-clock timestamp.)"""
    findings = [_finding("Critical")]
    nuclei = [_found_candidate()]
    obs = [_obs("httpx"), _obs("ffuf", severity="Medium", category="content-discovery")]

    _mock_all(monkeypatch, sqli=findings, nuclei=nuclei, httpx=[obs[0]], ffuf=[obs[1]])
    rec = run_scan(IN_SCOPE, scope_config=_scope(), out_dir=str(tmp_path / "spine"))
    sid = rec["scan_id"]

    # Reproduce the SAME write_outputs call the spine makes, into a separate dir.
    ref = tmp_path / "ref"
    write_outputs(_nuclei_result(nuclei), findings, scan_id=sid,
                  target_url=IN_SCOPE, out_dir=str(ref),
                  nuclei_candidates=nuclei, recon_observations=obs)

    for name in (f"findings_{sid}.json", f"findings_{sid}.sarif",
                 f"nuclei_{sid}.json", f"recon_{sid}.json"):
        spine_bytes = (tmp_path / "spine" / name).read_bytes()
        ref_bytes = (ref / name).read_bytes()
        assert spine_bytes == ref_bytes, f"{name} differs from a direct write_outputs"


# ── secret scrub applied to scan_<id>.json ───────────────────────────────────

def test_secret_scrub_applied_to_scan_json(monkeypatch, tmp_path):
    _mock_all(monkeypatch, sqli=[_finding("Low")])
    # Inject an llm meta dict carrying secret-named fields.
    monkeypatch.setattr(scan, "_build_llm_meta", lambda: {
        "provider": "http://llm/", "model": "m", "max_usd": 1.0,
        "api_key": "SUPERSECRET", "auth_token": "TOPSECRET"})

    rec = run_scan(IN_SCOPE, scope_config=_scope(), out_dir=str(tmp_path))
    sid = rec["scan_id"]

    # returned record: safe fields kept, secret-named fields dropped
    assert rec["llm"]["provider"] == "http://llm/"
    assert rec["llm"]["model"] == "m"
    assert "api_key" not in rec["llm"]
    assert "auth_token" not in rec["llm"]

    # nothing secret written to disk (scan_<id>.json AND run_<id>.json)
    scan_text = (tmp_path / f"scan_{sid}.json").read_text()
    run_text = (tmp_path / f"run_{sid}.json").read_text()
    for blob in (scan_text, run_text):
        assert "SUPERSECRET" not in blob
        assert "TOPSECRET" not in blob
        assert "api_key" not in blob
        assert "auth_token" not in blob


# ── standalone runner (repo convention) ──────────────────────────────────────

if __name__ == "__main__":
    class _MP:
        def __init__(self):
            self._undo = []

        def setattr(self, obj, name, value):
            if isinstance(obj, str):
                mod, _, attr = obj.rpartition(".")
                import importlib
                obj = importlib.import_module(mod)
                name = attr
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
            with tempfile.TemporaryDirectory() as d:
                kwargs = {}
                if needs_mp:
                    kwargs["monkeypatch"] = mp
                if needs_tmp:
                    kwargs["tmp_path"] = Path(d)
                fn(**kwargs)
            print(f"  ok  {fn.__name__}")
        finally:
            if mp:
                mp.undo()

    _tests = [v for k, v in sorted(globals().items())
              if k.startswith("test_") and callable(v)]
    print(f"Running {len(_tests)} orchestrator tests...")
    for _fn in _tests:
        _run(_fn)
    print("All orchestrator tests passed!")
