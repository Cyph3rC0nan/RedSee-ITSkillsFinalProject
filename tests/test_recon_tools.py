"""
Tests for engine/recon_tools.py — deterministic sandboxed httpx/tlsx recon, and
its surfacing into engine/report_io.py's SARIF/recon_<id>.json/run.json channel.

Fully offline: run_in_sandbox is monkeypatched with REAL captured httpx and tlsx
JSON output (tests/fixtures/httpx_dvwa_real.jsonl — real DVWA :8080 probe;
tests/fixtures/tlsx_selfsigned_real.jsonl — a real self-signed cert captured from
a throwaway local TLS listener). No Docker, no network, no LLM (recon_tools has
no LLM/agent loop at all).

Run: PYTHONPATH=. python -m pytest tests/test_recon_tools.py -v
"""
import json
from pathlib import Path

import pytest

import engine.recon_tools as recon
from engine.recon_tools import (
    run_httpx, run_tlsx, ReconObservation,
    _build_httpx_argv, _build_tlsx_argv, _host_port_from_target,
    _assert_no_forbidden_flags, _HTTPX_FORBIDDEN, _TLSX_FORBIDDEN,
    _parse_json_lines,
)
from engine.scope import ScopeConfig
from engine.agent import SqliCandidate, SqliAgentResult
from engine.llm import Usage
from engine.report_io import write_outputs


# ── Real captured fixtures ───────────────────────────────────────────────────

_FIXTURES = Path(__file__).resolve().parent / "fixtures"
_HTTPX_REAL_LINE = _FIXTURES.joinpath("httpx_dvwa_real.jsonl").read_text(encoding="utf-8").strip()
_TLSX_REAL_LINE = _FIXTURES.joinpath("tlsx_selfsigned_real.jsonl").read_text(encoding="utf-8").strip()

IN_SCOPE_URL = "http://localhost:8080/"
IN_SCOPE_TLS_URL = "https://localhost:8443/"
OUT_SCOPE_URL = "http://evil.com/"


def _scope():
    return ScopeConfig(
        target_url="http://localhost:8080/",
        allowed_hosts=["localhost"],
        authorized=True,
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

def test_httpx_argv_has_detection_flags_and_no_forbidden():
    argv = _build_httpx_argv(IN_SCOPE_URL)
    assert argv[:3] == ["httpx", "-target", IN_SCOPE_URL]
    for flag in ("-json", "-silent", "-no-color", "-disable-update-check",
                "-status-code", "-title", "-tech-detect"):
        assert flag in argv
    for bad in _HTTPX_FORBIDDEN:
        assert bad not in argv


def test_httpx_never_contains_fuzz_or_write_flags():
    argv = _build_httpx_argv(IN_SCOPE_URL)
    for bad in ("-x", "-path", "-o", "-output", "-sr", "-pd", "-pdu"):
        assert bad not in argv


def test_tlsx_argv_derives_port_from_target_and_no_forbidden():
    argv = _build_tlsx_argv(IN_SCOPE_TLS_URL)
    assert argv[:5] == ["tlsx", "-host", "localhost", "-port", "8443"]
    for flag in ("-json", "-silent", "-disable-update-check", "-self-signed", "-expired"):
        assert flag in argv
    for bad in _TLSX_FORBIDDEN:
        assert bad not in argv


def test_host_port_from_target_matches_sandbox_formula():
    # Explicit port wins.
    assert _host_port_from_target("https://host:8443/") == ("host", 8443)
    # https with no port -> 443 (same formula engine.sandbox.run_in_sandbox uses).
    assert _host_port_from_target("https://host/") == ("host", 443)
    # http with no port -> 80.
    assert _host_port_from_target("http://host/") == ("host", 80)


def test_forbidden_flag_assertion_trips():
    with pytest.raises(AssertionError):
        _assert_no_forbidden_flags(["httpx", "-target", "x", "-up"], _HTTPX_FORBIDDEN, tool="httpx")
    with pytest.raises(AssertionError):
        _assert_no_forbidden_flags(["tlsx", "-host", "x", "-dashboard"], _TLSX_FORBIDDEN, tool="tlsx")


# ── Output parsing (source of truth) ────────────────────────────────────────

def test_parse_real_httpx_json_line():
    objs = _parse_json_lines(_HTTPX_REAL_LINE)
    assert len(objs) == 1
    assert objs[0]["status_code"] == 302
    assert objs[0]["webserver"] == "Apache/2.4.25 (Debian)"


def test_parse_real_tlsx_json_line():
    objs = _parse_json_lines(_TLSX_REAL_LINE)
    assert len(objs) == 1
    assert objs[0]["self_signed"] is True
    assert objs[0]["tls_version"] == "tls13"


def test_parse_ignores_log_lines():
    noisy = "[INF] some banner line\n" + _HTTPX_REAL_LINE + "\n[INF] done\n"
    objs = _parse_json_lines(noisy)
    assert len(objs) == 1


# ── run_httpx: real result -> ReconObservation(status="observed") ──────────

def test_real_httpx_result_yields_observed_observation(monkeypatch):
    calls = []
    monkeypatch.setattr(recon, "run_in_sandbox", _fake_sandbox(calls, _HTTPX_REAL_LINE))

    obs = run_httpx([IN_SCOPE_URL], scope_config=_scope())

    assert len(calls) == 1
    assert len(obs) == 1
    o = obs[0]
    assert isinstance(o, ReconObservation)
    assert o.tool == "httpx"
    assert o.status == "observed"
    assert o.category == "http-fingerprint"
    assert o.severity == "Low"
    assert "302" in o.title
    assert "status=302" in o.evidence
    assert "server=Apache" in o.evidence
    assert "tech=" in o.evidence and "PHP" in o.evidence
    assert o.error is None


# ── run_tlsx: real self-signed result -> observation with correct severity ──

def test_real_tlsx_selfsigned_result_yields_medium_severity_observation(monkeypatch):
    calls = []
    monkeypatch.setattr(recon, "run_in_sandbox", _fake_sandbox(calls, _TLSX_REAL_LINE))

    obs = run_tlsx([IN_SCOPE_TLS_URL], scope_config=_scope())

    assert len(calls) == 1
    # baseline tls-info (Low) + self-signed (Medium) + mismatched (Medium) —
    # the real captured cert triggers both real conditions.
    by_cat = {o.category: o for o in obs}
    assert "tls-info" in by_cat
    assert by_cat["tls-info"].severity == "Low"
    assert by_cat["tls-info"].tool == "tlsx"
    assert "tls_version=tls13" in by_cat["tls-info"].evidence

    assert "tls-self-signed" in by_cat
    assert by_cat["tls-self-signed"].severity == "Medium"
    assert by_cat["tls-self-signed"].status == "observed"

    assert "tls-hostname-mismatch" in by_cat
    assert by_cat["tls-hostname-mismatch"].severity == "Medium"

    # no weak ciphers in the real capture (cipher_enum entries are empty) -> no
    # tls-weak-cipher observation fabricated.
    assert "tls-weak-cipher" not in by_cat

    assert all(o.status == "observed" for o in obs)


def test_tlsx_weak_cipher_detected_when_present(monkeypatch):
    # Synthetic variant of the real capture with a non-empty weak-cipher entry —
    # proves the weak-cipher severity hint fires from real field SHAPE without
    # needing to find/generate an actually-weak-cipher-enabled server.
    weak_line = _TLSX_REAL_LINE.replace(
        '"cipher_enum":[{"version":"tls13","ciphers":{}},{"version":"tls12","ciphers":{}}]',
        '"cipher_enum":[{"version":"tls12","ciphers":{"TLS_RSA_WITH_RC4_128_SHA":true}}]',
    )
    calls = []
    monkeypatch.setattr(recon, "run_in_sandbox", _fake_sandbox(calls, weak_line))

    obs = run_tlsx([IN_SCOPE_TLS_URL], scope_config=_scope())
    by_cat = {o.category: o for o in obs}
    assert "tls-weak-cipher" in by_cat
    assert by_cat["tls-weak-cipher"].severity == "Medium"
    assert "TLS_RSA_WITH_RC4_128_SHA" in by_cat["tls-weak-cipher"].evidence


# ── out-of-scope -> run_in_sandbox NOT called ───────────────────────────────

def test_httpx_out_of_scope_target_not_scanned(monkeypatch):
    calls = []
    monkeypatch.setattr(recon, "run_in_sandbox", _fake_sandbox(calls, _HTTPX_REAL_LINE))

    obs = run_httpx([OUT_SCOPE_URL], scope_config=_scope())

    assert calls == [], "run_in_sandbox must NOT be called for an out-of-scope target"
    assert len(obs) == 1
    assert obs[0].status == "out_of_scope"
    assert obs[0].severity is None
    assert "evil.com" in obs[0].error


def test_tlsx_out_of_scope_target_not_scanned(monkeypatch):
    calls = []
    monkeypatch.setattr(recon, "run_in_sandbox", _fake_sandbox(calls, _TLSX_REAL_LINE))

    obs = run_tlsx(["https://evil.com/"], scope_config=_scope())

    assert calls == []
    assert len(obs) == 1
    assert obs[0].status == "out_of_scope"


# ── sandbox error/timeout -> status="error", no fabricated observation ──────

def test_httpx_sandbox_error_yields_error_status_not_fabricated(monkeypatch):
    calls = []
    monkeypatch.setattr(recon, "run_in_sandbox", _raising_sandbox(calls))

    obs = run_httpx([IN_SCOPE_URL], scope_config=_scope())

    assert len(obs) == 1
    o = obs[0]
    assert o.status == "error"
    assert o.severity is None
    assert o.evidence == ""                     # nothing fabricated
    assert "self-test" in o.error.lower()


def test_tlsx_timeout_yields_error_status_not_fabricated(monkeypatch):
    calls = []
    monkeypatch.setattr(recon, "run_in_sandbox",
                        _fake_sandbox(calls, "", timed_out=True))

    obs = run_tlsx([IN_SCOPE_TLS_URL], scope_config=_scope())

    assert len(obs) == 1
    assert obs[0].status == "error"
    assert obs[0].severity is None
    assert "timed out" in obs[0].error


def test_httpx_nonzero_exit_yields_error_not_fabricated(monkeypatch):
    calls = []
    monkeypatch.setattr(recon, "run_in_sandbox",
                        _fake_sandbox(calls, _HTTPX_REAL_LINE, exit_code=1))

    obs = run_httpx([IN_SCOPE_URL], scope_config=_scope())

    assert len(obs) == 1
    assert obs[0].status == "error"
    assert "non-zero" in obs[0].error
    # even though real-looking JSON was on stdout, a non-zero exit means the
    # scan did not reliably complete -> no observation is fabricated from it.
    assert obs[0].evidence == ""


def test_clean_empty_result_yields_no_observation_not_an_error(monkeypatch):
    # exit 0, no parseable JSON result -> nothing to report, but NOT an error.
    calls = []
    monkeypatch.setattr(recon, "run_in_sandbox", _fake_sandbox(calls, ""))

    obs = run_httpx([IN_SCOPE_URL], scope_config=_scope())
    assert obs == []


# ── Forbidden flag assertion in context ─────────────────────────────────────

def test_forbidden_flag_asserted_into_argv_raises():
    with pytest.raises(AssertionError):
        _assert_no_forbidden_flags(
            ["httpx", "-target", IN_SCOPE_URL, "-store-response"], _HTTPX_FORBIDDEN, tool="httpx")
    with pytest.raises(AssertionError):
        _assert_no_forbidden_flags(
            ["tlsx", "-host", "x", "-port", "443", "-update"], _TLSX_FORBIDDEN, tool="tlsx")


# ── report_io surfacing: SARIF + recon_<id>.json + run.json summary ─────────

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


def _real_recon_observations():
    """Real httpx + tlsx observations, built the same way run_httpx/run_tlsx do."""
    from engine.recon_tools import _httpx_observation_for, _tlsx_observations_for
    httpx_obj = _parse_json_lines(_HTTPX_REAL_LINE)[0]
    tlsx_obj = _parse_json_lines(_TLSX_REAL_LINE)[0]
    obs = [_httpx_observation_for(IN_SCOPE_URL, httpx_obj, ["httpx"])]
    obs += _tlsx_observations_for(IN_SCOPE_TLS_URL, tlsx_obj, ["tlsx"])
    return obs


def test_observed_recon_lands_in_sarif_with_category_ruleid(tmp_path):
    observations = _real_recon_observations()
    paths = write_outputs(_sqli_result(), [], scan_id="r1", target_url="http://h/",
                          out_dir=str(tmp_path), recon_observations=observations)

    sarif = json.loads(Path(paths["sarif"]).read_text())
    results = sarif["runs"][0]["results"]
    rule_ids = {r["ruleId"] for r in results}
    assert "http-fingerprint" in rule_ids
    assert "tls-self-signed" in rule_ids
    declared = {rule["id"] for rule in sarif["runs"][0]["tool"]["driver"]["rules"]}
    assert rule_ids <= declared

    by_rule = {r["ruleId"]: r["level"] for r in results}
    assert by_rule["http-fingerprint"] == "note"          # Low -> note
    assert by_rule["tls-self-signed"] == "warning"         # Medium -> warning


def test_observed_recon_written_to_dedicated_json(tmp_path):
    observations = _real_recon_observations()
    paths = write_outputs(_sqli_result(), [], scan_id="r2", target_url="http://h/",
                          out_dir=str(tmp_path), recon_observations=observations)

    assert "recon" in paths
    data = json.loads(Path(paths["recon"]).read_text())
    assert len(data) == len(observations)
    row = data[0]
    assert set(row.keys()) == {
        "tool", "target", "category", "title", "severity", "evidence", "status", "error"}
    assert any(r["tool"] == "httpx" for r in data)
    assert any(r["tool"] == "tlsx" for r in data)


def test_run_json_gets_recon_summary(tmp_path):
    observations = _real_recon_observations()
    paths = write_outputs(_sqli_result(), [], scan_id="r3", target_url="http://h/",
                          out_dir=str(tmp_path), recon_observations=observations)

    run_data = json.loads(Path(paths["run"]).read_text())
    assert "recon" in run_data
    summ = run_data["recon"]
    assert summ["observed"] == len(observations)
    assert summ["error"] == 0
    assert summ["count_by_tool"]["httpx"] == 1
    assert summ["count_by_tool"]["tlsx"] == 3            # info + self-signed + mismatched
    assert summ["count_by_severity"]["Low"] == 2         # httpx fingerprint + tls-info
    assert summ["count_by_severity"]["Medium"] == 2       # self-signed + mismatched


def test_findings_json_contains_no_recon_entries(tmp_path):
    observations = _real_recon_observations()
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
    assert "httpx" not in raw
    assert "tlsx" not in raw
    assert "self-signed" not in raw
    assert "http-fingerprint" not in raw


def test_omitting_recon_leaves_output_unchanged(tmp_path):
    a = write_outputs(_sqli_result(), [], scan_id="same", target_url="http://h/",
                      out_dir=str(tmp_path / "a"))
    b = write_outputs(_sqli_result(), [], scan_id="same", target_url="http://h/",
                      out_dir=str(tmp_path / "b"),
                      recon_observations=_real_recon_observations())

    assert "recon" not in a
    assert not (tmp_path / "a" / "recon_same.json").exists()
    run_a = json.loads(Path(a["run"]).read_text())
    assert "recon" not in run_a

    sarif_a = json.loads(Path(a["sarif"]).read_text())
    sarif_b = json.loads(Path(b["sarif"]).read_text())
    # A's results are a strict prefix of B's (recon appended after).
    assert sarif_b["runs"][0]["results"][:len(sarif_a["runs"][0]["results"])] \
        == sarif_a["runs"][0]["results"]
    assert len(sarif_b["runs"][0]["results"]) > len(sarif_a["runs"][0]["results"])


def test_error_and_out_of_scope_recon_rows_excluded_from_sarif(tmp_path):
    observations = _real_recon_observations() + [
        ReconObservation(tool="httpx", target="http://dead/", category="error",
                         title="x", severity=None, evidence="", status="error",
                         error="sandbox execution failed: x", argv=[]),
        ReconObservation(tool="tlsx", target="http://evil.com/", category="out_of_scope",
                         title="x", severity=None, evidence="", status="out_of_scope",
                         error="out of scope", argv=[]),
    ]
    paths = write_outputs(_sqli_result(), [], scan_id="r4", target_url="http://h/",
                          out_dir=str(tmp_path), recon_observations=observations)
    sarif = json.loads(Path(paths["sarif"]).read_text())
    rule_ids = {r["ruleId"] for r in sarif["runs"][0]["results"]}
    assert "error" not in rule_ids
    assert "out_of_scope" not in rule_ids
    # but they're still recorded in the raw recon json (audit trail).
    data = json.loads(Path(paths["recon"]).read_text())
    assert any(r["status"] == "error" for r in data)
    assert any(r["status"] == "out_of_scope" for r in data)


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
    print(f"Running {len(_tests)} recon_tools tests...")
    for _fn in _tests:
        _run(_fn)
    print("All recon_tools tests passed!")
