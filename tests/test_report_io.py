"""
Tests for engine/report_io.py's nuclei-surfacing extension.

nuclei candidates are BROADER than the frozen schemas.py Finding enum
(SQLi/XSS/IDOR/BrokenAuth), so they are surfaced into SARIF + a dedicated
nuclei_<id>.json + the run.json summary ONLY — never as typed Findings, never in
findings_<id>.json. With nuclei_candidates omitted, every existing output is
byte-for-byte unchanged.

Fully offline: synthetic agent results + NucleiCandidate objects built from REAL
captured nuclei JSONL (tests/fixtures/nuclei_dvwa_real.jsonl). No Docker/LLM/network.

Run: PYTHONPATH=. python -m pytest tests/test_report_io.py -v
"""
import json
from pathlib import Path

import pytest

from schemas import Finding
from engine.agent import SqliCandidate, SqliAgentResult
from engine.xss_agent import XssAgentResult
from engine.llm import Usage
from engine.nuclei_agent import (
    NucleiCandidate, NucleiAgentResult, _parse_nuclei_output,
)
from engine.report_io import write_outputs


# ── Real captured nuclei JSONL -> NucleiCandidate fixtures ──────────────────

_FIXTURE = Path(__file__).resolve().parent / "fixtures" / "nuclei_dvwa_real.jsonl"
_REAL_STDOUT = _FIXTURE.read_text(encoding="utf-8")


def _real_found_candidates(target="http://localhost:8080/"):
    """Build status='found' NucleiCandidates from the REAL captured JSONL, the
    same way engine.nuclei_agent._run_one_scan does."""
    cands = []
    for r in _parse_nuclei_output(_REAL_STDOUT):
        cands.append(NucleiCandidate(
            target=target, template_id=r["template_id"], name=r["name"],
            severity=r["severity"], matched_at=r["matched_at"],
            evidence=f"[{r['severity']}] {r['template_id']} matched-at {r['matched_at']}",
            status="found", error=None, nuclei_argv=["nuclei"]))
    return cands


def _clean_nuclei_candidate(target="http://localhost:8080/"):
    return NucleiCandidate(target=target, template_id=None, name=None, severity=None,
                           matched_at=None, evidence="", status="clean", error=None,
                           nuclei_argv=["nuclei"])


def _error_nuclei_candidate(target="http://localhost:8080/"):
    return NucleiCandidate(target=target, template_id=None, name=None, severity=None,
                           matched_at=None, evidence="", status="error",
                           error="sandbox execution failed", nuclei_argv=["nuclei"])


def _nuclei_result(candidates, stopped_reason="done"):
    return NucleiAgentResult(
        candidates=candidates,
        usage=Usage(input_tokens=10, output_tokens=5, cost_usd=0.002, calls=1),
        iterations=1, transcript=[{"role": "system", "action": "prompt", "summary": "x"}],
        stopped_reason=stopped_reason)


# ── Synthetic typed-Finding + SQLi agent-result fixtures ────────────────────

def _sqli_finding():
    return Finding(type="SQLi", url="http://h/a?q=1", parameter="q",
                   payload="q=1 AND 1=1", evidence="Parameter: q (GET)",
                   severity="High", timestamp="2026-01-01T00:00:00Z")


def _xss_finding():
    return Finding(type="XSS", url="http://h/x?name=t", parameter="name",
                   payload="<svg/onload=alert(1)>", evidence="[POC][V][GET] reflected",
                   severity="Medium", timestamp="2026-01-01T00:00:00Z")


def _sqli_result():
    cand = SqliCandidate(
        endpoint_url="http://h/a?q=1", parameter="q", injectable=True,
        technique="boolean-based blind", dbms="SQLite", evidence="e",
        sqlmap_argv=["sqlmap"], depth=1, status="injectable", error=None)
    return SqliAgentResult(
        candidates=[cand],
        usage=Usage(input_tokens=120, output_tokens=40, cost_usd=0.0123, calls=2),
        iterations=2, transcript=[{"role": "system", "action": "prompt", "summary": "x"}],
        stopped_reason="done")


# ── found nuclei -> SARIF + nuclei_<id>.json + run.json summary ──────────────

def test_found_nuclei_lands_in_sarif_with_template_id_ruleid(tmp_path):
    cands = _real_found_candidates()
    result = _nuclei_result(cands)
    paths = write_outputs(result, [], scan_id="n1", target_url="http://localhost:8080/",
                          out_dir=str(tmp_path), nuclei_candidates=cands)

    sarif = json.loads(Path(paths["sarif"]).read_text())
    results = sarif["runs"][0]["results"]
    # every found candidate is a SARIF result, ruleId == its template_id
    assert len(results) == len(cands)
    rule_ids = {r["ruleId"] for r in results}
    assert "configuration-listing" in rule_ids     # real medium template from the fixture
    # rules[] declares the distinct template_ids
    declared = {rule["id"] for rule in sarif["runs"][0]["tool"]["driver"]["rules"]}
    assert rule_ids <= declared
    # medium -> warning; info -> note (real severities present in the fixture)
    by_rule = {r["ruleId"]: r["level"] for r in results}
    assert by_rule["configuration-listing"] == "warning"   # medium
    assert by_rule["tech-detect"] == "note"                # info


def test_found_nuclei_written_to_dedicated_json(tmp_path):
    cands = _real_found_candidates()
    result = _nuclei_result(cands)
    paths = write_outputs(result, [], scan_id="n2", target_url="http://localhost:8080/",
                          out_dir=str(tmp_path), nuclei_candidates=cands)

    assert "nuclei" in paths
    data = json.loads(Path(paths["nuclei"]).read_text())
    assert len(data) == len(cands)
    row = data[0]
    assert set(row.keys()) == {
        "target", "template_id", "name", "severity", "matched_at", "evidence", "status"}
    assert row["status"] == "found"
    assert any(r["template_id"] == "configuration-listing" for r in data)


def test_run_json_gets_nuclei_summary(tmp_path):
    cands = _real_found_candidates() + [_clean_nuclei_candidate(), _error_nuclei_candidate()]
    result = _nuclei_result(cands)
    paths = write_outputs(result, [], scan_id="n3", target_url="http://localhost:8080/",
                          out_dir=str(tmp_path), nuclei_candidates=cands)

    run_data = json.loads(Path(paths["run"]).read_text())
    assert "nuclei" in run_data
    summ = run_data["nuclei"]
    assert summ["found"] == len(_real_found_candidates())
    assert summ["clean"] == 1
    assert summ["error"] == 1
    assert summ["total"] == len(cands)
    # count_by_severity covers found candidates only (real fixture: 1 medium + 2 info)
    assert summ["count_by_severity"].get("medium") == 1
    assert summ["count_by_severity"].get("info") == 2


def test_clean_and_error_nuclei_excluded_from_sarif_but_kept_in_json(tmp_path):
    cands = _real_found_candidates() + [_clean_nuclei_candidate(), _error_nuclei_candidate()]
    result = _nuclei_result(cands)
    paths = write_outputs(result, [], scan_id="n4", target_url="http://localhost:8080/",
                          out_dir=str(tmp_path), nuclei_candidates=cands)

    sarif = json.loads(Path(paths["sarif"]).read_text())
    # only the found ones become SARIF results
    assert len(sarif["runs"][0]["results"]) == len(_real_found_candidates())
    # but the raw nuclei json keeps clean+error for the audit trail
    data = json.loads(Path(paths["nuclei"]).read_text())
    assert {row["status"] for row in data} == {"found", "clean", "error"}


# ── nuclei NEVER enters findings_<id>.json ──────────────────────────────────

def test_findings_json_contains_no_nuclei_entries(tmp_path):
    cands = _real_found_candidates()
    # A real mixed run: a typed SQLi Finding PLUS found nuclei candidates.
    result = _sqli_result()
    paths = write_outputs(result, [_sqli_finding()], scan_id="mix",
                          target_url="http://h/", out_dir=str(tmp_path),
                          nuclei_candidates=cands)

    findings_data = json.loads(Path(paths["findings"]).read_text())
    # exactly the one typed Finding; every entry is a valid Finding dict
    assert len(findings_data) == 1
    assert findings_data[0]["type"] == "SQLi"
    for row in findings_data:
        assert set(row.keys()) == {
            "type", "url", "parameter", "payload", "evidence", "severity", "timestamp"}
    # no nuclei template id leaked into findings_<id>.json anywhere
    raw = Path(paths["findings"]).read_text().lower()
    assert "nuclei" not in raw
    assert "configuration-listing" not in raw


# ── nuclei omitted -> existing outputs byte-for-byte unchanged ──────────────

def test_omitting_nuclei_leaves_outputs_unchanged(tmp_path):
    findings = [_sqli_finding(), _xss_finding()]
    result = _sqli_result()

    # Run A: no nuclei arg at all.  Run B: same, with found nuclei candidates.
    a = write_outputs(result, findings, scan_id="same", target_url="http://h/",
                      out_dir=str(tmp_path / "a"))
    b = write_outputs(result, findings, scan_id="same", target_url="http://h/",
                      out_dir=str(tmp_path / "b"),
                      nuclei_candidates=_real_found_candidates())

    # findings_<id>.json is IDENTICAL — nuclei never touches it.
    assert Path(a["findings"]).read_text() == Path(b["findings"]).read_text()

    # Run A adds no nuclei artifacts / keys at all.
    assert "nuclei" not in a
    assert not (tmp_path / "a" / "nuclei_same.json").exists()
    run_a = json.loads(Path(a["run"]).read_text())
    assert "nuclei" not in run_a
    sarif_a = json.loads(Path(a["sarif"]).read_text())
    assert len(sarif_a["runs"][0]["results"]) == len(findings)   # only the typed findings
    assert {r["ruleId"] for r in sarif_a["runs"][0]["results"]} == {"SQLi", "XSS"}

    # Run B is a strict SUPERSET: the two typed-finding SARIF results come FIRST
    # and are identical to run A's (nuclei results are appended after).
    sarif_b = json.loads(Path(b["sarif"]).read_text())
    assert sarif_b["runs"][0]["results"][:len(findings)] == sarif_a["runs"][0]["results"]
    assert len(sarif_b["runs"][0]["results"]) > len(findings)


def test_omitting_nuclei_matches_committed_report_io_behavior(tmp_path):
    # Guard against silent drift: the SARIF for a SQLi+XSS run with nuclei omitted
    # is exactly the pre-nuclei shape (ruleId from Finding.type, level from severity).
    findings = [_sqli_finding(), _xss_finding()]
    paths = write_outputs(_sqli_result(), findings, scan_id="golden",
                          target_url="http://h/", out_dir=str(tmp_path))
    sarif = json.loads(Path(paths["sarif"]).read_text())
    results = sarif["runs"][0]["results"]
    assert [r["ruleId"] for r in results] == ["SQLi", "XSS"]
    assert [r["level"] for r in results] == ["error", "warning"]   # High, Medium
    rules = sarif["runs"][0]["tool"]["driver"]["rules"]
    assert rules == [{"id": "SQLi", "name": "SQLInjection"},
                     {"id": "XSS", "name": "CrossSiteScripting"}]


# ── secret scrub still intact when nuclei is passed ─────────────────────────

def test_secret_scrub_intact_with_nuclei(tmp_path):
    cands = _real_found_candidates()
    result = _nuclei_result(cands)
    llm_meta = {"provider": "ollama", "model": "llama3.2",
                "api_key": "sk-should-not-appear", "authorization": "Bearer secret-token"}
    paths = write_outputs(result, [], scan_id="sec", target_url="http://localhost:8080/",
                          out_dir=str(tmp_path), llm_meta=llm_meta,
                          nuclei_candidates=cands)
    dumped = Path(paths["run"]).read_text()
    assert "sk-should-not-appear" not in dumped
    assert "secret-token" not in dumped
    assert '"api_key"' not in dumped
    assert "llama3.2" in dumped                # non-secret preserved
    assert "nuclei" in json.loads(dumped)      # nuclei summary still added


def test_empty_nuclei_list_writes_files_but_no_sarif_results(tmp_path):
    # Explicit empty list (ran nuclei, found nothing) is distinct from omitted:
    # it still writes nuclei_<id>.json (empty) + a zeroed run.json summary, but
    # adds no SARIF results.
    result = _nuclei_result([])
    paths = write_outputs(result, [_sqli_finding()], scan_id="empty",
                          target_url="http://h/", out_dir=str(tmp_path),
                          nuclei_candidates=[])
    assert "nuclei" in paths
    assert json.loads(Path(paths["nuclei"]).read_text()) == []
    run_data = json.loads(Path(paths["run"]).read_text())
    assert run_data["nuclei"]["found"] == 0 and run_data["nuclei"]["total"] == 0
    sarif = json.loads(Path(paths["sarif"]).read_text())
    # only the typed SQLi finding, no nuclei results
    assert {r["ruleId"] for r in sarif["runs"][0]["results"]} == {"SQLi"}


# ── Standalone runner (repo convention) ─────────────────────────────────────

if __name__ == "__main__":
    import inspect
    import tempfile

    def _run(fn):
        if "tmp_path" in inspect.signature(fn).parameters:
            with tempfile.TemporaryDirectory() as d:
                fn(Path(d))
        else:
            fn()
        print(f"  ok  {fn.__name__}")

    _tests = [v for k, v in sorted(globals().items())
              if k.startswith("test_") and callable(v)]
    print(f"Running {len(_tests)} report_io nuclei tests...")
    for _fn in _tests:
        _run(_fn)
    print("All report_io nuclei tests passed!")
