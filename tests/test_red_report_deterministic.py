# tests/test_red_report_deterministic.py
"""
Tests for red_report.py's DETERMINISTIC (no-LLM) report path — the generator
app.py's /scan/<id>/report route actually calls.

Unlike test_red_report.py's coverage of the LLM+weasyprint path (which
legitimately needs `openai` + weasyprint), this path needs no LLM call — but it
IS PDF-only: weasyprint is a hard requirement, and there is no HTML fallback.
The PDF branch is exercised by monkeypatching a stub weasyprint module (so this
suite doesn't depend on the real package being importable on every host); a
separate test asserts the fail-loudly behavior when weasyprint is unavailable.

Run: PYTHONPATH=. pytest tests/test_red_report_deterministic.py -v
     (needs the `markdown` package — present in .venv; use .venv/bin/python -m pytest)
"""
import json
from pathlib import Path

import pytest

import red_report
from red_report import (
    _build_deterministic_markdown, _tools_table, generate_deterministic_report,
    _owasp_ref, _owasp_summary_table,
)


def _mock_findings():
    with open(Path(__file__).parent.parent / "sample_data" / "mock_findings.json") as f:
        return json.load(f)


def _record(findings=None, **overrides):
    base = {
        "scan_id": "test0001",
        "target": "http://redsees.com:3000/market/",
        "mode": "standard",
        "started_at": "2026-01-01T00:00:00Z",
        "finished_at": "2026-01-01T00:05:00Z",
        "findings": findings if findings is not None else [],
        "tools_run": [
            {"name": "crawl", "status": "ran", "count": 7, "detail": "7 endpoints"},
            {"name": "sqli", "status": "ran", "count": 0, "detail": "0 finding(s)"},
            {"name": "xss", "status": "ran", "count": 3, "detail": "3 finding(s)"},
        ],
        "recon": {"nuclei": [], "observations": []},
    }
    base.update(overrides)
    return base


# ── _build_deterministic_markdown: pure string content, env-independent ──────

def test_markdown_includes_target_mode_and_scan_window():
    md = _build_deterministic_markdown(_record(), "abc12345")
    assert "http://redsees.com:3000/market/" in md
    assert "standard" in md
    assert "abc12345" in md


def test_markdown_with_findings_lists_each_one():
    findings = _mock_findings()
    md = _build_deterministic_markdown(_record(findings=findings), "abc12345")
    assert f"**Total Findings:** {len(findings)}" in md
    for f in findings:
        assert f["url"] in md
        assert f["parameter"] in md
        assert f["evidence"] in md


def test_markdown_with_zero_findings_says_so_not_an_error():
    md = _build_deterministic_markdown(_record(findings=[]), "abc12345")
    assert "confirmed **no vulnerabilities**" in md
    assert "No confirmed vulnerabilities" in md


def test_markdown_surfaces_skip_reason_from_tools_run():
    """The D-024 skip-legibility fix (modules/scan.py) writes a human-readable
    `detail` string for a skipped sqli/xss entry — this must flow into the
    report's Methodology table, not just the dashboard UI."""
    reason = ("target appears unreachable — crawl and httpx both got no live "
              "response (0 pages crawled, 0 recon observations) — nothing to inject")
    record = _record(findings=[], tools_run=[
        {"name": "crawl", "status": "ran", "count": 0, "detail": "0 endpoints"},
        {"name": "sqli", "status": "skipped", "count": 0, "detail": reason},
        {"name": "xss", "status": "skipped", "count": 0, "detail": reason},
    ])
    md = _build_deterministic_markdown(record, "abc12345")
    assert reason in md


def test_tools_table_handles_empty_list():
    assert "No tool-execution data" in _tools_table([])


def test_tools_table_escapes_pipe_in_detail():
    rows = _tools_table([{"name": "x", "status": "error", "count": 0,
                          "detail": "a | b"}])
    assert "a \\| b" in rows


# ── OWASP Top 10 (2021) / CWE framework mapping ───────────────────────────────

@pytest.mark.parametrize("finding_type,owasp_substr,cwe_substr", [
    ("SQLi", "A03:2021", "CWE-89"),
    ("XSS", "A03:2021", "CWE-79"),
    ("IDOR", "A01:2021", "CWE-639"),
    ("BrokenAuth", "A07:2021", "CWE-287"),
])
def test_owasp_ref_maps_each_frozen_finding_type(finding_type, owasp_substr, cwe_substr):
    ref = _owasp_ref(finding_type)
    assert owasp_substr in ref["owasp"]
    assert cwe_substr in ref["cwe"]


def test_owasp_ref_unknown_type_is_uncategorized_not_fabricated():
    ref = _owasp_ref("SomethingNotInTheSchema")
    assert ref["owasp"] == "Uncategorized"


def test_owasp_summary_table_counts_by_category():
    findings = [{"type": "SQLi"}, {"type": "SQLi"}, {"type": "XSS"}]
    table = _owasp_summary_table(findings)
    assert "A03:2021" in table
    assert "| A03:2021 – Injection | CWE-89: SQL Injection | 2 |" in table


def test_markdown_findings_carry_owasp_and_cwe():
    md = _build_deterministic_markdown(_record(findings=_mock_findings()), "abc12345")
    assert "OWASP Top 10 (2021)" in md
    assert "CWE" in md
    assert "Framework Alignment" in md


# ── generate_deterministic_report: real file, PDF-only ───────────────────────

def _stub_weasyprint(monkeypatch):
    """Install a fake weasyprint.HTML that writes real PDF-magic bytes, so the
    PDF-render branch is exercised hermetically (no dependency on the real
    package being importable on whatever host runs this suite). Returns the
    list of output paths write_pdf was called with."""
    calls = []

    class _FakeHTML:
        def __init__(self, string):
            self.string = string

        def write_pdf(self, output_path):
            calls.append(output_path)
            Path(output_path).write_bytes(b"%PDF-1.4 fake pdf content for test\n" * 50)

    class _FakeWeasyprint:
        HTML = _FakeHTML

    monkeypatch.setattr(red_report, "_HAS_WEASYPRINT", True)
    monkeypatch.setattr(red_report, "weasyprint", _FakeWeasyprint)
    return calls


def test_always_produces_a_real_pdf_with_findings(tmp_path, monkeypatch):
    monkeypatch.setattr(red_report, "OUTPUTS_DIR", tmp_path)
    _stub_weasyprint(monkeypatch)
    path, fmt = generate_deterministic_report(_record(findings=_mock_findings()),
                                              scan_id="withfindings")
    assert Path(path).exists()
    assert Path(path).stat().st_size > 500
    assert fmt == "pdf"
    assert Path(path).suffix == ".pdf"


def test_always_produces_a_real_file_with_zero_findings(tmp_path, monkeypatch):
    """The old route dead-ended with a 400 on 0 findings — the new generator
    must NEVER refuse to produce a report just because nothing was found."""
    monkeypatch.setattr(red_report, "OUTPUTS_DIR", tmp_path)
    _stub_weasyprint(monkeypatch)
    path, fmt = generate_deterministic_report(_record(findings=[]), scan_id="clean0001")
    assert Path(path).exists()
    assert Path(path).stat().st_size > 500
    assert fmt == "pdf"


def test_raises_when_weasyprint_unavailable(tmp_path, monkeypatch):
    """Reports are PDF-only now — there is no HTML fallback. If weasyprint isn't
    importable, generation must fail loudly with a clear, actionable message,
    not silently produce a lesser format."""
    monkeypatch.setattr(red_report, "OUTPUTS_DIR", tmp_path)
    monkeypatch.setattr(red_report, "_HAS_WEASYPRINT", False)
    with pytest.raises(RuntimeError, match="weasyprint"):
        generate_deterministic_report(_record(findings=_mock_findings()), scan_id="nopdf")
    assert list(tmp_path.glob("*.html")) == []   # never a lesser fallback file


def test_renders_pdf_when_weasyprint_available(tmp_path, monkeypatch):
    """Stub weasyprint so this branch is exercised even when the real package
    isn't installed on this host — proves the PDF path still wires up correctly
    if/when weasyprint IS present in a future environment."""
    monkeypatch.setattr(red_report, "OUTPUTS_DIR", tmp_path)
    calls = _stub_weasyprint(monkeypatch)

    path, fmt = generate_deterministic_report(_record(findings=_mock_findings()),
                                              scan_id="pdfpath")
    assert fmt == "pdf"
    assert path.endswith(".pdf")
    assert Path(path).exists()
    assert calls == [path]


@pytest.mark.skipif(not red_report._HAS_WEASYPRINT,
                     reason="real weasyprint not importable in this environment")
def test_renders_a_real_pdf_with_the_actually_installed_weasyprint(tmp_path, monkeypatch):
    """Belt-and-suspenders: when the real weasyprint package IS installed (as it
    is expected to be per requirements.txt), prove it produces an actual,
    valid-looking PDF from our real pdf_templates/red.css — not just a stub."""
    monkeypatch.setattr(red_report, "OUTPUTS_DIR", tmp_path)
    path, fmt = generate_deterministic_report(_record(findings=_mock_findings()),
                                              scan_id="reallib")
    assert fmt == "pdf"
    data = Path(path).read_bytes()
    assert data[:5] == b"%PDF-"
    assert len(data) > 1000


def test_scan_id_defaults_when_absent_from_record(tmp_path, monkeypatch):
    monkeypatch.setattr(red_report, "OUTPUTS_DIR", tmp_path)
    _stub_weasyprint(monkeypatch)
    path, _ = generate_deterministic_report({"findings": []}, scan_id=None)
    assert Path(path).exists()


# ── standalone runner (repo convention) ──────────────────────────────────────

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
    print(f"Running {len(_tests)} deterministic red-report tests...")
    for _fn in _tests:
        _run(_fn)
    print("All deterministic red-report tests passed!")
