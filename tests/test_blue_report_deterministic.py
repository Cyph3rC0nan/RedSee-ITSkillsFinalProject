# tests/test_blue_report_deterministic.py
"""
Tests for blue_report.py's DETERMINISTIC (no-LLM) report path — the generator
app.py's /generate-blue-report route actually calls.

Mirrors tests/test_red_report_deterministic.py: this path is PDF-only (no HTML
fallback) via red_report._render_report, so weasyprint is a hard requirement.
The PDF branch is exercised hermetically via a stubbed weasyprint; a separate
test proves the fail-loudly behavior when it's unavailable, and one more
confirms the real, actually-installed weasyprint produces a valid PDF.

Run: PYTHONPATH=. pytest tests/test_blue_report_deterministic.py -v
"""
from pathlib import Path

import pytest

import red_report
import blue_report
from blue_report import (
    _mitre_from_event, _mitre_section, _build_deterministic_blue_markdown,
    _events_table, generate_deterministic_blue_report,
)


def _event(rule_id="31106", severity_level=6, raw_payload="", **overrides):
    base = {
        "source": "Wazuh", "timestamp": "2026-07-15T10:11:40Z",
        "rule_id": rule_id, "description": "A web attack returned code 200 (success).",
        "severity_level": severity_level, "src_ip": "203.0.113.10",
        "target_url": "/rest/products/search?q=<script>alert(1)</script>",
        "raw_payload": raw_payload,
    }
    base.update(overrides)
    return base


# ── MITRE parsing: id + tactic + technique from the ingestor's marker ───────

def test_mitre_from_event_parses_id_tactic_and_technique():
    e = _event(raw_payload="q=x [MITRE: T1190 (Initial Access: Exploit Public-Facing Application)]")
    triples = _mitre_from_event(e)
    assert triples == [("T1190", "Initial Access", "Exploit Public-Facing Application")]


def test_mitre_from_event_parses_multiple_techniques():
    e = _event(raw_payload=(
        "sshd log [MITRE: T1110.001 (Credential Access: Password Guessing), "
        "T1021.004 (Lateral Movement: SSH)]"
    ))
    triples = _mitre_from_event(e)
    assert triples == [
        ("T1110.001", "Credential Access", "Password Guessing"),
        ("T1021.004", "Lateral Movement", "SSH"),
    ]


def test_mitre_from_event_handles_bare_id_with_no_tactic():
    e = _event(raw_payload="q=x [MITRE: T1190]")
    assert _mitre_from_event(e) == [("T1190", "", "")]


def test_mitre_from_event_no_marker_returns_empty():
    assert _mitre_from_event(_event(raw_payload="q=x, no marker here")) == []


def test_mitre_section_aggregates_across_events_and_shows_names():
    events = [
        _event(raw_payload="q=x [MITRE: T1190 (Initial Access: Exploit Public-Facing Application)]"),
        _event(raw_payload="q=y [MITRE: T1190 (Initial Access: Exploit Public-Facing Application)]"),
    ]
    table = _mitre_section(events)
    assert "T1190" in table
    assert "Initial Access" in table
    assert "Exploit Public-Facing Application" in table
    assert "| T1190 | Initial Access | Exploit Public-Facing Application | 2 |" in table


def test_mitre_section_empty_when_no_techniques():
    assert "No MITRE ATT&CK techniques" in _mitre_section([_event(raw_payload="no marker")])


# ── _events_table: raw HTML (not markdown) so blue.css can size its columns ──

def test_events_table_is_raw_html_with_events_table_class():
    table = _events_table([_event()])
    assert '<table class="events-table">' in table
    assert "<thead>" in table and "<tbody>" in table


def test_events_table_escapes_html_special_characters():
    """Real Wazuh events legitimately carry literal `<script>` XSS payloads
    (the attacks RedSee's own scans generate) — these must render as inert
    escaped text in the report, never as unescaped markup that could corrupt
    the table or (in a browser context) execute."""
    e = _event(target_url="/rest/products/search?q=<script>alert(1)</script>",
                description="Attack <b>bold</b> & 'quoted'")
    table = _events_table([e])
    assert "<script>alert(1)</script>" not in table
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in table
    assert "&lt;b&gt;bold&lt;/b&gt;" in table
    assert "&amp;" in table


def test_events_table_flags_web_attacks():
    web = _event(rule_id="31106")
    other = _event(rule_id="5710")
    table = _events_table([web, other])
    assert table.count('class="web-flag"') == 1


def test_events_table_long_description_not_truncated():
    """The complaint this fixes: full log detail must survive into the table,
    not be cut short. There is no truncation logic in _events_table itself —
    this locks in that a long, realistic description round-trips whole."""
    long_desc = "A" * 300 + " very long description with full detail " + "B" * 300
    table = _events_table([_event(description=long_desc)])
    assert long_desc in table


def test_events_table_empty_when_no_events():
    assert "No events ingested" in _events_table([])


def test_events_table_respects_limit_and_notes_it():
    events = [_event(rule_id=str(i)) for i in range(5)]
    table = _events_table(events, limit=3)
    assert "Showing 3 of 5 events" in table


# ── Framework alignment appears in the built markdown ───────────────────────

def test_markdown_includes_mitre_framework_alignment():
    events = [_event(raw_payload="q=x [MITRE: T1190 (Initial Access: Exploit Public-Facing Application)]")]
    md = _build_deterministic_blue_markdown(events, "incident001")
    assert "MITRE ATT&CK" in md
    assert "Framework Alignment" in md
    assert "T1190" in md


def test_markdown_zero_events_says_so_not_an_error():
    md = _build_deterministic_blue_markdown([], "incident002")
    assert "nothing to report" in md.lower()


# ── generate_deterministic_blue_report: real file, PDF-only ────────────────

def _stub_weasyprint(monkeypatch):
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


def test_always_produces_a_real_pdf(tmp_path, monkeypatch):
    monkeypatch.setattr(blue_report, "OUTPUTS_DIR", tmp_path)
    _stub_weasyprint(monkeypatch)
    events = [_event(raw_payload="q=x [MITRE: T1190 (Initial Access: Exploit Public-Facing Application)]")]
    path, fmt = generate_deterministic_blue_report(events, report_id="withevents")
    assert Path(path).exists()
    assert Path(path).stat().st_size > 500
    assert fmt == "pdf"
    assert Path(path).suffix == ".pdf"


def test_zero_events_still_produces_a_real_pdf(tmp_path, monkeypatch):
    monkeypatch.setattr(blue_report, "OUTPUTS_DIR", tmp_path)
    _stub_weasyprint(monkeypatch)
    path, fmt = generate_deterministic_blue_report([], report_id="empty001")
    assert Path(path).exists()
    assert fmt == "pdf"


def test_raises_when_weasyprint_unavailable(tmp_path, monkeypatch):
    """PDF-only — no HTML fallback. Fails loudly, not silently."""
    monkeypatch.setattr(blue_report, "OUTPUTS_DIR", tmp_path)
    monkeypatch.setattr(red_report, "_HAS_WEASYPRINT", False)
    with pytest.raises(RuntimeError, match="weasyprint"):
        generate_deterministic_blue_report([_event()], report_id="nopdf")
    assert list(tmp_path.glob("*.html")) == []


@pytest.mark.skipif(not red_report._HAS_WEASYPRINT,
                     reason="real weasyprint not importable in this environment")
def test_renders_a_real_pdf_with_the_actually_installed_weasyprint(tmp_path, monkeypatch):
    monkeypatch.setattr(blue_report, "OUTPUTS_DIR", tmp_path)
    events = [_event(raw_payload="q=x [MITRE: T1190 (Initial Access: Exploit Public-Facing Application)]")]
    path, fmt = generate_deterministic_blue_report(events, report_id="reallib")
    assert fmt == "pdf"
    data = Path(path).read_bytes()
    assert data[:5] == b"%PDF-"
    assert len(data) > 1000


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
