# blue_report.py
"""
Blue Team Report Engine
Takes SIEM events → calls LLM → generates defensive security PDF report.

Usage (standalone test):
    python blue_report.py

Usage (import):
    from blue_report import generate_blue_report
    pdf_path = generate_blue_report(events, report_id="incident001")
"""

import re
import html
import json
from collections import Counter
from datetime import datetime
from pathlib import Path
from dotenv import load_dotenv

# Reuse all LLM and PDF utilities from red_report — do NOT duplicate them.
# _render_report is the deterministic, PDF-only renderer shared with the red
# report; reusing it keeps blue_report free of any direct weasyprint import.
from red_report import call_llm, load_prompt, markdown_to_pdf, _render_report

load_dotenv()

BASE_DIR = Path(__file__).parent
OUTPUTS_DIR = BASE_DIR / "outputs"
OUTPUTS_DIR.mkdir(exist_ok=True)

_MITRE_MARKER_RE = re.compile(r"\[MITRE:\s*([^\]]+)\]")
# Each entry inside the marker is `T1190` or `T1190 (Tactic: Technique)` or
# `T1190 (Tactic)` (log_ingestor._compose_detail); entries are ", "-joined.
_MITRE_ENTRY_RE = re.compile(r"^(T\d{4}(?:\.\d{3})?)(?:\s*\(([^:)]+)(?::\s*(.+))?\))?$")


def _compute_severity_distribution(events: list[dict]) -> str:
    """Compute severity bucket distribution for the user message context."""
    dist = {}
    for e in events:
        level = e.get("severity_level", 0)
        if level >= 10:
            bucket = "Critical (10+)"
        elif level >= 7:
            bucket = "High (7-9)"
        elif level >= 4:
            bucket = "Medium (4-6)"
        else:
            bucket = "Low (1-3)"
        dist[bucket] = dist.get(bucket, 0) + 1
    return "\n".join(f"  - {k}: {v} event(s)" for k, v in sorted(dist.items()))


def generate_blue_report(events: list[dict], report_id: str = None, use_detailed: bool = False) -> str:
    """
    Generate a complete blue team defensive report PDF.

    Args:
        events: List of Event dicts (use Event.to_dict() or load from JSON)
        report_id: Optional identifier for filename uniqueness

    Returns:
        Path to the generated PDF file (str)
    """
    if not report_id:
        report_id = datetime.now().strftime("%Y%m%d_%H%M%S")

    system_prompt = load_prompt("blue_prompt.txt")

    sources = sorted(set(e.get("source", "Unknown") for e in events))
    severity_summary = _compute_severity_distribution(events)
    time_start = events[0].get("timestamp", "N/A") if events else "N/A"
    time_end = events[-1].get("timestamp", "N/A") if events else "N/A"
    events_json = json.dumps(events, indent=2)

    user_message = f"""Analyze the following SIEM events from a security incident and generate a comprehensive defensive security report.

Event Summary:
- Total events: {len(events)}
- Sources: {', '.join(sources)}
- Severity distribution:
{severity_summary}
- Time range: {time_start} to {time_end}

Complete SIEM event data:
{events_json}

Generate the full blue team report now. Include specific Wazuh XML and Splunk SPL rule recommendations."""

    print(f"[BlueReport] Calling LLM for report_id={report_id} with {len(events)} events...")
    md_report = call_llm(system_prompt, user_message, use_detailed=use_detailed)
    print(f"[BlueReport] LLM response received ({len(md_report)} chars)")

    cover = f"""# RedSee — Blue Team Defensive Report

**Report ID:** {report_id}
**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Tool:** RedSee SIEM Analyzer
**Total Events Analyzed:** {len(events)}
**SIEM Sources:** {', '.join(sources)}
**Time Range:** {time_start} → {time_end}

---

"""
    full_md = cover + md_report
    output_path = str(OUTPUTS_DIR / f"blue_report_{report_id}.pdf")
    markdown_to_pdf(full_md, "blue.css", output_path)
    print(f"[BlueReport] PDF saved: {output_path}")
    return output_path


# ── Deterministic blue report (no LLM, PDF-only) ─────────────────────────────
# generate_blue_report() above ALWAYS needs a working LLM call + weasyprint — a
# two-part dependency that fails closed the moment either is unavailable. The
# generator below builds the SAME kind of incident report directly from the
# ingested Events (deterministic string templates, not an LLM), rendered via
# red_report._render_report — PDF-only, raises if weasyprint is unavailable
# (see that function's docstring). This is the path app.py's
# /generate-blue-report route calls: the "Generate Blue Report" button always
# produces a real PDF, never a dead click and never a lesser HTML substitute.

def _sev_bucket(level) -> str:
    """Wazuh numeric level -> exact schema severity string (mirror of
    log_ingestor.severity_bucket, kept local so this module has no import cycle)."""
    try:
        level = int(level)
    except (TypeError, ValueError):
        level = 0
    if level >= 12:
        return "Critical"
    if level >= 7:
        return "High"
    if level >= 4:
        return "Medium"
    return "Low"


def _is_web_attack(e: dict) -> bool:
    return str(e.get("rule_id", "")).startswith("31")


def _fmt_ts(iso) -> str:
    if not iso:
        return "—"
    m = re.search(r"(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})", str(iso))
    return f"{m.group(1)} {m.group(2)}" if m else str(iso)


def _mitre_from_event(e: dict) -> list:
    """Recover MITRE ATT&CK (id, tactic, technique) triples the ingestor packed
    into raw_payload's `[MITRE: ...]` marker (the frozen Event schema has no
    dedicated field). tactic/technique are "" when the SIEM's rule metadata
    didn't supply them for that id — never guessed or backfilled."""
    marker = _MITRE_MARKER_RE.search(e.get("raw_payload", "") or "")
    if not marker:
        return []
    out = []
    for entry in marker.group(1).split(", "):
        m = _MITRE_ENTRY_RE.match(entry.strip())
        if m:
            out.append((m.group(1), m.group(2) or "", m.group(3) or ""))
    return out


def _severity_table(events: list) -> str:
    counts = Counter(_sev_bucket(e.get("severity_level", 0)) for e in events)
    rows = ["| Severity | Events |", "|---|---|"]
    for sev in ("Critical", "High", "Medium", "Low"):
        rows.append(f"| {sev} | {counts.get(sev, 0)} |")
    return "\n".join(rows) + "\n"


def _mitre_section(events: list) -> str:
    """MITRE ATT&CK® Enterprise technique table — id, tactic, technique name,
    and event count. tactic/technique come solely from the SIEM's own rule
    metadata (Wazuh's rule.mitre block); an id the SIEM tagged with no name is
    shown with the id alone, never a fabricated label."""
    seen: dict[str, dict] = {}
    for e in events:
        for tid, tactic, technique in _mitre_from_event(e):
            row = seen.setdefault(tid, {"tactic": "", "technique": "", "count": 0})
            row["tactic"] = row["tactic"] or tactic
            row["technique"] = row["technique"] or technique
            row["count"] += 1
    if not seen:
        return "_No MITRE ATT&CK techniques recorded on these events._\n"
    rows = ["| Technique ID | Tactic | Technique | Events |", "|---|---|---|---|"]
    for tid, info in sorted(seen.items(), key=lambda kv: -kv[1]["count"]):
        rows.append(f"| {tid} | {info['tactic'] or '—'} | {info['technique'] or '—'} | {info['count']} |")
    return "\n".join(rows) + "\n"


def _top_source_ips(events: list, limit: int = 10) -> str:
    counts = Counter(e.get("src_ip", "") for e in events if e.get("src_ip"))
    if not counts:
        return "_No source IPs recorded on these events._\n"
    rows = ["| Source IP | Events |", "|---|---|"]
    for ip, n in counts.most_common(limit):
        rows.append(f"| {ip} | {n} |")
    return "\n".join(rows) + "\n"


def _events_table(events: list, limit: int = 100) -> str:
    """Render the normalized-events list as a raw HTML `<table class="events-
    table">` (not a markdown pipe-table) so pdf_templates/blue.css can size its
    7 columns explicitly — the markdown-table version had no way to give the
    free-text Description/Target columns more width than the numeric ones,
    which squeezed them illegibly. Every field is html.escape()'d: real Wazuh
    events legitimately contain literal `<script>...</script>` XSS payloads
    (the attacks RedSee's own scans generate), which must render as inert text
    in the report, never as unescaped markup.
    """
    if not events:
        return "_No events ingested._\n"
    body_rows = []
    for e in events[:limit]:
        lvl = e.get("severity_level", 0)
        sev = _sev_bucket(lvl)
        flag = ' <span class="web-flag">⚠</span>' if _is_web_attack(e) else ""
        rule_id = html.escape(str(e.get("rule_id", "?")))
        desc = html.escape(str(e.get("description", "")))
        src_ip = html.escape(str(e.get("src_ip", "")))
        url = html.escape(str(e.get("target_url", "")))
        body_rows.append(
            f"<tr><td>{lvl}</td><td>{sev}</td><td>{_fmt_ts(e.get('timestamp'))}</td>"
            f"<td>{rule_id}{flag}</td><td>{desc}</td><td>{src_ip}</td><td>{url}</td></tr>"
        )
    table = (
        '<table class="events-table">\n'
        "<thead><tr><th>Lvl</th><th>Sev</th><th>Time</th><th>Rule</th>"
        "<th>Description</th><th>Source IP</th><th>Target</th></tr></thead>\n"
        "<tbody>\n" + "\n".join(body_rows) + "\n</tbody>\n</table>\n"
    )
    extra = f"\n_Showing {min(limit, len(events))} of {len(events)} events._\n" if len(events) > limit else ""
    return table + extra


def _build_deterministic_blue_markdown(events: list, report_id: str) -> str:
    total = len(events)
    sources = sorted(set(e.get("source", "Unknown") for e in events)) or ["—"]
    counts = Counter(_sev_bucket(e.get("severity_level", 0)) for e in events)
    web_attacks = [e for e in events if _is_web_attack(e)]
    times = sorted(e.get("timestamp", "") for e in events if e.get("timestamp"))
    t_start = _fmt_ts(times[0]) if times else "—"
    t_end = _fmt_ts(times[-1]) if times else "—"

    cover = f"""# RedSee — Blue Team Incident Report

**Report ID:** {report_id}
**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Tool:** RedSee SIEM Analyzer (deterministic report — no LLM narrative)
**Framework Alignment:** MITRE ATT&CK® Enterprise
**Total Events Analyzed:** {total}
**SIEM Sources:** {', '.join(sources)}
**Time Range:** {t_start} → {t_end}
**Critical:** {counts.get('Critical', 0)}  **High:** {counts.get('High', 0)}  **Medium:** {counts.get('Medium', 0)}  **Low:** {counts.get('Low', 0)}

---

## Incident Summary

"""
    if total:
        cover += (
            f"This report normalizes **{total}** SIEM event"
            f"{'' if total == 1 else 's'} from {', '.join(sources)}. "
            f"**{len(web_attacks)}** {'is a' if len(web_attacks) == 1 else 'are'} "
            f"web-attack alert{'' if len(web_attacks) == 1 else 's'} "
            f"(access-log rule 31xxx / `attack` group) — the class of alert "
            f"RedSee's own active scans generate against the target. Every event "
            f"below is a defender-side observation from the SIEM, not an inference.\n"
        )
    else:
        cover += "No events were ingested for this window — nothing to report.\n"

    body = f"""
## Events by Severity

{_severity_table(events)}

## MITRE ATT&CK® Framework Alignment

Observed activity is mapped to the [MITRE ATT&CK](https://attack.mitre.org)
Enterprise matrix using the tactic/technique metadata the SIEM itself attached
to each rule — never inferred or guessed by this tool.

{_mitre_section(events)}

## Top Source IPs

{_top_source_ips(events)}

## Web-Attack Alerts

{_events_table(web_attacks) if web_attacks else "_No web-attack alerts in this set._"}

## All Normalized Events

{_events_table(events)}

---

*Generated by RedSee. Every row is a normalized SIEM observation — no finding or
severity here is fabricated by a model. Defensive analysis only.*
"""
    return cover + body


def generate_deterministic_blue_report(events: list, report_id: str = None) -> tuple:
    """Build and render a deterministic (LLM-free) blue incident report from the
    ingested Event dicts. Returns (output_path, "pdf") — PDF-only, raises
    RuntimeError if weasyprint is unavailable. Never raises for "0 events" — an
    empty window still gets a real, downloadable report."""
    if not report_id:
        report_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    events = events or []
    md = _build_deterministic_blue_markdown(events, report_id)
    output_stem = str(OUTPUTS_DIR / f"blue_report_{report_id}")
    path, fmt = _render_report(md, "blue.css", output_stem)
    print(f"[BlueReport] deterministic report saved: {path} (format={fmt})")
    return path, fmt


# ── CLI Test ───────────────────────────────────────────
if __name__ == "__main__":
    import json
    print("=" * 60)
    print("RedSee — Blue Team Report Generator (Test Mode)")
    print("=" * 60)

    with open("sample_data/mock_wazuh_alerts.json") as f:
        mock_events = json.load(f)

    pdf = generate_blue_report(mock_events, report_id="incident_001")
    print(f"\nTest complete! Report at: {pdf}")
    print("Open the PDF and verify it contains all sections.")