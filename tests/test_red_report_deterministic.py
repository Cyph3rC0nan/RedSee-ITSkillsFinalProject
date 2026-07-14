# tests/test_red_report_deterministic.py
"""
Tests for red_report.py's DETERMINISTIC (no-LLM) report path — the generator
app.py's /scan/<id>/report route actually calls.

Unlike test_red_report.py's coverage of the LLM+weasyprint path (which
legitimately needs `openai` + weasyprint and is skipped in this dev sandbox),
this path needs only stdlib + the already-installed `markdown` package, so it
must ALWAYS produce a real file — regardless of whether weasyprint happens to be
importable on this host. Both render branches (pdf/html) are exercised by
monkeypatching red_report._HAS_WEASYPRINT + a stub weasyprint module, so this
suite passes identically whether or not weasyprint is actually installed.

Run: PYTHONPATH=. pytest tests/test_red_report_deterministic.py -v
     (needs the `markdown` package — present in .venv; use .venv/bin/python -m pytest)
"""
import json
from pathlib import Path

import pytest

import red_report
from red_report import (
    _build_deterministic_markdown, _tools_table, generate_deterministic_report,
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


# ── generate_deterministic_report: real file, both render branches ───────────

def test_always_produces_a_real_file_with_findings(tmp_path, monkeypatch):
    monkeypatch.setattr(red_report, "OUTPUTS_DIR", tmp_path)
    path, fmt = generate_deterministic_report(_record(findings=_mock_findings()),
                                              scan_id="withfindings")
    assert Path(path).exists()
    assert Path(path).stat().st_size > 500
    assert fmt in ("pdf", "html")
    assert Path(path).suffix == f".{fmt}"


def test_always_produces_a_real_file_with_zero_findings(tmp_path, monkeypatch):
    """The old route dead-ended with a 400 on 0 findings — the new generator
    must NEVER refuse to produce a report just because nothing was found."""
    monkeypatch.setattr(red_report, "OUTPUTS_DIR", tmp_path)
    path, fmt = generate_deterministic_report(_record(findings=[]), scan_id="clean0001")
    assert Path(path).exists()
    assert Path(path).stat().st_size > 500


def test_renders_html_when_weasyprint_unavailable(tmp_path, monkeypatch):
    monkeypatch.setattr(red_report, "OUTPUTS_DIR", tmp_path)
    monkeypatch.setattr(red_report, "_HAS_WEASYPRINT", False)
    path, fmt = generate_deterministic_report(_record(findings=_mock_findings()),
                                              scan_id="htmlpath")
    assert fmt == "html"
    assert path.endswith(".html")
    text = Path(path).read_text(encoding="utf-8")
    assert "<html>" in text.lower()
    assert _mock_findings()[0]["url"] in text


def test_renders_pdf_when_weasyprint_available(tmp_path, monkeypatch):
    """Stub weasyprint so this branch is exercised even when the real package
    isn't installed on this host — proves the PDF path still wires up correctly
    if/when weasyprint IS present in a future environment."""
    calls = []

    class _FakeHTML:
        def __init__(self, string):
            self.string = string

        def write_pdf(self, output_path):
            calls.append(output_path)
            Path(output_path).write_bytes(b"%PDF-1.4 fake pdf content for test\n" * 50)

    class _FakeWeasyprint:
        HTML = _FakeHTML

    monkeypatch.setattr(red_report, "OUTPUTS_DIR", tmp_path)
    monkeypatch.setattr(red_report, "_HAS_WEASYPRINT", True)
    monkeypatch.setattr(red_report, "weasyprint", _FakeWeasyprint)

    path, fmt = generate_deterministic_report(_record(findings=_mock_findings()),
                                              scan_id="pdfpath")
    assert fmt == "pdf"
    assert path.endswith(".pdf")
    assert Path(path).exists()
    assert calls == [path]


def test_scan_id_defaults_when_absent_from_record(tmp_path, monkeypatch):
    monkeypatch.setattr(red_report, "OUTPUTS_DIR", tmp_path)
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
