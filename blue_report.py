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

import json
from datetime import datetime
from pathlib import Path
from dotenv import load_dotenv

# Reuse all LLM and PDF utilities from red_report — do NOT duplicate them
from red_report import call_llm, load_prompt, markdown_to_pdf

load_dotenv()

BASE_DIR = Path(__file__).parent
OUTPUTS_DIR = BASE_DIR / "outputs"
OUTPUTS_DIR.mkdir(exist_ok=True)


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