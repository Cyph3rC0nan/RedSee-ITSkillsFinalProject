"""
Tests for engine/finding_map.py and engine/report_io.py — mapping agent-produced
SqliCandidate objects into schema-valid Finding objects, and writing the
findings/SARIF/run.json audit trail for one SQLi agent run.

Fully offline: synthetic SqliCandidate / SqliAgentResult objects only — no
Docker, no sandbox, no LLM.

Run: PYTHONPATH=. python -m pytest tests/test_finding_map.py -v
"""
import json
import re
from pathlib import Path

import pytest

from schemas import Finding
from engine.agent import SqliCandidate, SqliAgentResult
from engine.llm import Usage
from engine.finding_map import candidate_to_finding
from engine.report_io import write_outputs

_TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_VALID_SEVERITIES = {"Critical", "High", "Medium", "Low"}


# ── Synthetic SqliCandidate fixtures ─────────────────────────────────────────

def _injectable_candidate(**overrides):
    base = dict(
        endpoint_url="http://redsees.com:3000/rest/products/search?q=apple",
        parameter="q",
        injectable=True,
        technique="boolean-based blind, time-based blind",
        dbms="SQLite",
        evidence=(
            "Parameter: q (GET)\n"
            "    Type: boolean-based blind\n"
            "    Title: AND boolean-based blind - WHERE or HAVING clause\n"
            "    Payload: q=apple%' AND 7278=7278 AND 'dmyG%'='dmyG\n"
        ),
        sqlmap_argv=["sqlmap", "-u", "http://redsees.com:3000/...", "--level=3", "--risk=2"],
        depth=1,
        status="injectable",
        error=None,
    )
    base.update(overrides)
    return SqliCandidate(**base)


def _clean_candidate(**overrides):
    base = dict(
        endpoint_url="http://redsees.com:3000/rest/products/search?q=apple",
        parameter=None, injectable=False, technique=None, dbms=None,
        evidence="", sqlmap_argv=["sqlmap", "-u", "..."], depth=0,
        status="clean", error=None,
    )
    base.update(overrides)
    return SqliCandidate(**base)


def _error_candidate(**overrides):
    base = dict(
        endpoint_url="http://redsees.com:3000/rest/products/search?q=apple",
        parameter=None, injectable=False, technique=None, dbms=None,
        evidence="", sqlmap_argv=["sqlmap", "-u", "..."], depth=0,
        status="error",
        error="sandbox execution failed: isolation self-test FAILED — target_unreachable=7",
    )
    base.update(overrides)
    return SqliCandidate(**base)


def _oos_candidate(**overrides):
    base = dict(
        endpoint_url="http://evil.com/x?q=1",
        parameter=None, injectable=False, technique=None, dbms=None,
        evidence="", sqlmap_argv=[], depth=0,
        status="out_of_scope", error="URL is out of scope, refusing to test",
    )
    base.update(overrides)
    return SqliCandidate(**base)


def _agent_result(candidates, stopped_reason="done"):
    return SqliAgentResult(
        candidates=candidates,
        usage=Usage(input_tokens=120, output_tokens=40, cost_usd=0.0123, calls=2),
        iterations=2,
        transcript=[{"role": "system", "action": "prompt", "summary": "loaded prompt"}],
        stopped_reason=stopped_reason,
    )


# ── candidate_to_finding: injectable -> valid Finding ───────────────────────

def test_injectable_candidate_maps_to_schema_valid_finding():
    cand = _injectable_candidate()
    f = candidate_to_finding(cand, target_url=cand.endpoint_url, scan_id="s1")

    assert isinstance(f, Finding)
    assert f.type == "SQLi"
    assert f.severity in _VALID_SEVERITIES
    assert _TS_RE.match(f.timestamp), f"bad timestamp: {f.timestamp!r}"
    assert f.parameter == "q"
    assert f.url == cand.endpoint_url
    # evidence must carry REAL, traceable proof: parameter/technique/dbms/payload.
    assert "q" in f.evidence
    assert "boolean-based blind" in f.evidence
    assert "SQLite" in f.evidence
    assert "AND 7278=7278" in f.payload


def test_severity_rule_high_by_default_critical_for_union_or_error():
    blind = _injectable_candidate(technique="boolean-based blind")
    assert candidate_to_finding(blind, target_url=blind.endpoint_url, scan_id="s").severity == "High"

    union = _injectable_candidate(technique="UNION query (NULL) - 3 columns")
    assert candidate_to_finding(union, target_url=union.endpoint_url, scan_id="s").severity == "Critical"

    error_based = _injectable_candidate(technique="error-based")
    assert candidate_to_finding(error_based, target_url=error_based.endpoint_url,
                                scan_id="s").severity == "Critical"


def test_missing_parameter_falls_back_to_a_nonempty_value():
    cand = _injectable_candidate(parameter=None)
    f = candidate_to_finding(cand, target_url=cand.endpoint_url, scan_id="s")
    assert f.parameter  # never None/empty — schemas.Finding.parameter is a plain str


def test_missing_payload_line_falls_back_to_argv_not_empty():
    cand = _injectable_candidate(evidence="Parameter: q (GET)\n    Type: boolean-based blind\n")
    f = candidate_to_finding(cand, target_url=cand.endpoint_url, scan_id="s")
    assert f.payload  # non-empty fallback even with no "Payload:" line


# ── clean / error / out_of_scope NEVER produce a Finding ────────────────────

def test_clean_error_out_of_scope_never_produce_a_finding():
    for cand in (_clean_candidate(), _error_candidate(), _oos_candidate()):
        with pytest.raises(ValueError):
            candidate_to_finding(cand, target_url=cand.endpoint_url, scan_id="s")


def test_filtering_a_mixed_candidate_list_yields_only_injectable_findings():
    candidates = [_clean_candidate(), _error_candidate(), _oos_candidate(),
                  _injectable_candidate()]
    findings = [
        candidate_to_finding(c, target_url=c.endpoint_url, scan_id="s")
        for c in candidates if c.status == "injectable"
    ]
    assert len(findings) == 1
    assert findings[0].type == "SQLi"


# ── write_outputs: findings JSON / SARIF / run.json ─────────────────────────

def test_write_outputs_produces_three_valid_files(tmp_path):
    cand = _injectable_candidate()
    finding = candidate_to_finding(cand, target_url=cand.endpoint_url, scan_id="s1")
    result = _agent_result([cand], stopped_reason="completed_by_ladder")

    paths = write_outputs(result, [finding], scan_id="s1",
                          target_url=cand.endpoint_url, out_dir=str(tmp_path))

    findings_path = Path(paths["findings"])
    sarif_path = Path(paths["sarif"])
    run_path = Path(paths["run"])
    assert findings_path.exists() and sarif_path.exists() and run_path.exists()

    # findings_<id>.json — SAME shape integration.py writes / red_report.py
    # reads: a plain JSON list of Finding.to_dict() dicts.
    findings_data = json.loads(findings_path.read_text())
    assert findings_data == [finding.to_dict()]
    assert set(findings_data[0].keys()) == {
        "type", "url", "parameter", "payload", "evidence", "severity", "timestamp"}

    # findings.sarif — minimal valid SARIF 2.1.0.
    sarif = json.loads(sarif_path.read_text())
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "RedSee"
    result0 = sarif["runs"][0]["results"][0]
    assert result0["ruleId"] == "SQLi"
    assert result0["level"] == "error"  # High -> error
    assert "boolean-based blind" in result0["message"]["text"]
    assert result0["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == finding.url

    # run.json — usage/cost/stopped_reason/status-summary, no secrets.
    run_data = json.loads(run_path.read_text())
    assert run_data["stopped_reason"] == "completed_by_ladder"
    assert run_data["usage"]["calls"] == 2
    assert run_data["usage"]["cost_usd"] == 0.0123
    assert "endpoint_status_summary" in run_data
    assert cand.endpoint_url in run_data["endpoint_status_summary"]


def test_sarif_level_mapping_from_severity(tmp_path):
    findings = [
        Finding(type="SQLi", url="http://h/a", parameter="p", payload="x",
               evidence="e", severity=sev, timestamp="2026-01-01T00:00:00Z")
        for sev in ("Critical", "High", "Medium", "Low")
    ]
    result = _agent_result([])
    paths = write_outputs(result, findings, scan_id="sev", target_url="http://h/",
                          out_dir=str(tmp_path))
    sarif = json.loads(Path(paths["sarif"]).read_text())
    levels = [r["level"] for r in sarif["runs"][0]["results"]]
    assert levels == ["error", "error", "warning", "note"]


def test_no_findings_still_writes_empty_but_valid_outputs(tmp_path):
    result = _agent_result([_clean_candidate(), _error_candidate()], stopped_reason="done")
    paths = write_outputs(result, [], scan_id="clean1", target_url="http://h/",
                          out_dir=str(tmp_path))
    assert json.loads(Path(paths["findings"]).read_text()) == []
    sarif = json.loads(Path(paths["sarif"]).read_text())
    assert sarif["runs"][0]["results"] == []
    run_data = json.loads(Path(paths["run"]).read_text())
    assert run_data["stopped_reason"] == "done"


def test_run_json_never_contains_llm_secrets(tmp_path):
    result = _agent_result([])
    llm_meta = {
        "provider": "http://localhost:11434/v1", "model": "llama3.2", "max_usd": 5.0,
        "api_key": "sk-should-not-appear", "authorization": "Bearer secret-token",
    }
    paths = write_outputs(result, [], scan_id="s", target_url="http://h/",
                          out_dir=str(tmp_path), llm_meta=llm_meta)

    dumped = Path(paths["run"]).read_text()
    assert "sk-should-not-appear" not in dumped
    assert "secret-token" not in dumped
    assert '"api_key"' not in dumped
    assert '"authorization"' not in dumped.lower()
    # non-secret metadata IS preserved.
    assert "llama3.2" in dumped and "provider" in dumped


def test_run_json_omits_llm_key_when_no_meta_given(tmp_path):
    result = _agent_result([])
    paths = write_outputs(result, [], scan_id="s2", target_url="http://h/",
                          out_dir=str(tmp_path))
    run_data = json.loads(Path(paths["run"]).read_text())
    assert "llm" not in run_data


# ── Smoke: a Finding produced here is consumable by red_report.py's input path

def test_finding_dict_consumable_by_red_report_summarizer():
    pytest.importorskip("weasyprint")
    pytest.importorskip("markdown")
    from red_report import _summarize_findings

    cand = _injectable_candidate()
    finding = candidate_to_finding(cand, target_url=cand.endpoint_url, scan_id="s1")
    summary = _summarize_findings([finding.to_dict()])
    assert "SQLi" in summary
    assert finding.severity in summary


if __name__ == "__main__":
    import inspect
    import tempfile

    def _run(fn):
        try:
            if "tmp_path" in inspect.signature(fn).parameters:
                with tempfile.TemporaryDirectory() as d:
                    fn(Path(d))
            else:
                fn()
            print(f"  ok  {fn.__name__}")
        except BaseException as exc:
            if type(exc).__name__ == "Skipped":
                print(f"  skip {fn.__name__} ({exc})")
            else:
                raise

    for _fn in (
        test_injectable_candidate_maps_to_schema_valid_finding,
        test_severity_rule_high_by_default_critical_for_union_or_error,
        test_missing_parameter_falls_back_to_a_nonempty_value,
        test_missing_payload_line_falls_back_to_argv_not_empty,
        test_clean_error_out_of_scope_never_produce_a_finding,
        test_filtering_a_mixed_candidate_list_yields_only_injectable_findings,
        test_write_outputs_produces_three_valid_files,
        test_sarif_level_mapping_from_severity,
        test_no_findings_still_writes_empty_but_valid_outputs,
        test_run_json_never_contains_llm_secrets,
        test_run_json_omits_llm_key_when_no_meta_given,
        test_finding_dict_consumable_by_red_report_summarizer,
    ):
        _run(_fn)

    print("All finding_map/report_io unit tests passed!")
