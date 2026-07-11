"""
Tests for engine/finding_map.py's xss_candidate_to_finding and engine/report_io.py's
write_outputs — mapping agent-produced XssCandidate objects into schema-valid
Finding objects, and writing the findings/SARIF/run.json audit trail for one XSS
agent run.

Fully offline: synthetic XssCandidate / XssAgentResult objects only — no Docker,
no sandbox, no LLM.

Run: PYTHONPATH=. python -m pytest tests/test_xss_finding_map.py -v
"""
import json
import re
from pathlib import Path

import pytest

from schemas import Finding
from engine.xss_agent import XssCandidate, XssAgentResult
from engine.llm import Usage
from engine.finding_map import xss_candidate_to_finding
from engine.report_io import write_outputs

_TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_VALID_SEVERITIES = {"Critical", "High", "Medium", "Low"}


# ── Synthetic XssCandidate fixtures ──────────────────────────────────────────

def _injectable_candidate(**overrides):
    base = dict(
        endpoint_url="http://redsees.com:8080/vulnerabilities/xss_r/?name=test",
        parameter="name",
        injectable=True,
        context="inHTML-none(1)",
        payload="<svg/onload=alert(1)>",
        evidence=(
            "[V] Triggered XSS Payload (found DOM Object): <svg/onload=alert(1)>\n"
            "    47 line: \t\t\t<pre>Hello <svg/onload=alert(1)></pre>\n"
            "[POC][V][GET][inHTML-none(1)] http://redsees.com:8080/vulnerabilities/"
            "xss_r/?name=<svg/onload=alert(1)>\n"
        ),
        status="injectable",
        error=None,
        dalfox_argv=["dalfox", "url", "http://redsees.com:8080/...", "--no-color",
                     "--format", "plain"],
    )
    base.update(overrides)
    return XssCandidate(**base)


def _clean_candidate(**overrides):
    base = dict(
        endpoint_url="http://redsees.com:8080/vulnerabilities/xss_r/?name=test",
        parameter=None, injectable=False, context=None, payload=None,
        evidence="", status="clean", error=None,
        dalfox_argv=["dalfox", "url", "..."],
    )
    base.update(overrides)
    return XssCandidate(**base)


def _error_candidate(**overrides):
    base = dict(
        endpoint_url="http://redsees.com:8080/vulnerabilities/xss_r/?name=test",
        parameter=None, injectable=False, context=None, payload=None,
        evidence="", status="error",
        error="sandbox execution failed: isolation self-test FAILED — target_unreachable=28",
        dalfox_argv=["dalfox", "url", "..."],
    )
    base.update(overrides)
    return XssCandidate(**base)


def _oos_candidate(**overrides):
    base = dict(
        endpoint_url="http://evil.com/xss_r/?name=test",
        parameter=None, injectable=False, context=None, payload=None,
        evidence="", status="out_of_scope", error="URL is out of scope, refusing to test",
        dalfox_argv=[],
    )
    base.update(overrides)
    return XssCandidate(**base)


def _agent_result(candidates, stopped_reason="done"):
    return XssAgentResult(
        candidates=candidates,
        usage=Usage(input_tokens=80, output_tokens=30, cost_usd=0.0, calls=2),
        iterations=2,
        transcript=[{"role": "system", "action": "prompt", "summary": "loaded prompt"}],
        stopped_reason=stopped_reason,
    )


# ── xss_candidate_to_finding: injectable -> valid Finding ───────────────────

def test_injectable_candidate_maps_to_schema_valid_finding():
    cand = _injectable_candidate()
    f = xss_candidate_to_finding(cand, target_url=cand.endpoint_url, scan_id="s1")

    assert isinstance(f, Finding)
    assert f.type == "XSS"
    assert f.severity in _VALID_SEVERITIES
    assert _TS_RE.match(f.timestamp), f"bad timestamp: {f.timestamp!r}"
    assert f.parameter == "name"
    assert f.url == cand.endpoint_url
    # evidence must carry REAL, traceable proof: parameter/context/payload.
    assert "name" in f.evidence
    assert "inHTML-none(1)" in f.evidence
    assert "svg/onload" in f.evidence
    assert "svg/onload" in f.payload


def test_severity_is_high_for_confirmed_reflected_xss():
    cand = _injectable_candidate(context="inJS")
    f = xss_candidate_to_finding(cand, target_url=cand.endpoint_url, scan_id="s")
    assert f.severity == "High"

    cand2 = _injectable_candidate(context="inATTR")
    f2 = xss_candidate_to_finding(cand2, target_url=cand2.endpoint_url, scan_id="s")
    assert f2.severity == "High"


def test_missing_parameter_falls_back_to_a_nonempty_value():
    cand = _injectable_candidate(parameter=None)
    f = xss_candidate_to_finding(cand, target_url=cand.endpoint_url, scan_id="s")
    assert f.parameter  # never None/empty — schemas.Finding.parameter is a plain str


def test_missing_payload_falls_back_to_nonempty_value():
    cand = _injectable_candidate(payload=None)
    f = xss_candidate_to_finding(cand, target_url=cand.endpoint_url, scan_id="s")
    assert f.payload  # non-empty fallback even with no captured payload


# ── clean / error / out_of_scope NEVER produce a Finding ────────────────────

def test_clean_error_out_of_scope_never_produce_a_finding():
    for cand in (_clean_candidate(), _error_candidate(), _oos_candidate()):
        with pytest.raises(ValueError):
            xss_candidate_to_finding(cand, target_url=cand.endpoint_url, scan_id="s")


def test_filtering_a_mixed_candidate_list_yields_only_injectable_findings():
    candidates = [_clean_candidate(), _error_candidate(), _oos_candidate(),
                  _injectable_candidate()]
    findings = [
        xss_candidate_to_finding(c, target_url=c.endpoint_url, scan_id="s")
        for c in candidates if c.status == "injectable"
    ]
    assert len(findings) == 1
    assert findings[0].type == "XSS"


# ── write_outputs: findings JSON / SARIF / run.json (agent-type-agnostic) ───

def test_write_outputs_produces_three_valid_files(tmp_path):
    cand = _injectable_candidate()
    finding = xss_candidate_to_finding(cand, target_url=cand.endpoint_url, scan_id="s1")
    result = _agent_result([cand], stopped_reason="completed_by_ladder")

    paths = write_outputs(result, [finding], scan_id="s1",
                          target_url=cand.endpoint_url, out_dir=str(tmp_path))

    findings_path = Path(paths["findings"])
    sarif_path = Path(paths["sarif"])
    run_path = Path(paths["run"])
    assert findings_path.exists() and sarif_path.exists() and run_path.exists()

    findings_data = json.loads(findings_path.read_text())
    assert findings_data == [finding.to_dict()]
    assert set(findings_data[0].keys()) == {
        "type", "url", "parameter", "payload", "evidence", "severity", "timestamp"}

    # findings.sarif — ruleId must be "XSS" (not hardcoded "SQLi").
    sarif = json.loads(sarif_path.read_text())
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "RedSee"
    result0 = sarif["runs"][0]["results"][0]
    assert result0["ruleId"] == "XSS"
    assert result0["level"] == "error"  # High -> error
    assert "svg/onload" in result0["message"]["text"]
    assert result0["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == finding.url
    rule_ids = {r["id"] for r in sarif["runs"][0]["tool"]["driver"]["rules"]}
    assert rule_ids == {"XSS"}

    # run.json — must not crash on XssCandidate having no `depth` field.
    run_data = json.loads(run_path.read_text())
    assert run_data["stopped_reason"] == "completed_by_ladder"
    assert run_data["usage"]["calls"] == 2
    assert "endpoint_status_summary" in run_data
    assert cand.endpoint_url in run_data["endpoint_status_summary"]
    # no fabricated max_depth for a candidate type with no depth concept.
    assert "max_depth" not in run_data["endpoint_status_summary"][cand.endpoint_url]


def test_no_findings_still_writes_empty_but_valid_outputs(tmp_path):
    result = _agent_result([_clean_candidate(), _error_candidate()], stopped_reason="done")
    paths = write_outputs(result, [], scan_id="clean1", target_url="http://h/",
                          out_dir=str(tmp_path))
    assert json.loads(Path(paths["findings"]).read_text()) == []
    sarif = json.loads(Path(paths["sarif"]).read_text())
    assert sarif["runs"][0]["results"] == []
    assert sarif["runs"][0]["tool"]["driver"]["rules"] == []
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
    assert "llama3.2" in dumped and "provider" in dumped


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
        test_severity_is_high_for_confirmed_reflected_xss,
        test_missing_parameter_falls_back_to_a_nonempty_value,
        test_missing_payload_falls_back_to_nonempty_value,
        test_clean_error_out_of_scope_never_produce_a_finding,
        test_filtering_a_mixed_candidate_list_yields_only_injectable_findings,
        test_write_outputs_produces_three_valid_files,
        test_no_findings_still_writes_empty_but_valid_outputs,
        test_run_json_never_contains_llm_secrets,
    ):
        _run(_fn)

    print("All XSS finding_map/report_io unit tests passed!")
