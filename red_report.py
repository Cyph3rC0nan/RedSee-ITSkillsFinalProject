# red_report.py
"""
Red Team Report Engine
Takes scan findings → calls LLM → generates professional pentest PDF report.

Usage (standalone test):
    python red_report.py

Usage (import):
    from red_report import generate_red_report
    pdf_path = generate_red_report(findings, scan_id="demo001")
"""

import os
import sys
import json

# ── Windows GTK3 DLL setup (for WeasyPrint) ──────────
if sys.platform == "win32":
    _gtk_paths = [
        os.environ.get("GTK3_BIN_PATH", ""),
        os.path.join(os.path.dirname(__file__), "..", "gtk3", "bin"),
        os.path.join(os.path.expanduser("~"), "gtk3", "bin"),
        r"C:\gtk3\bin",
    ]
    for _p in _gtk_paths:
        if _p and os.path.isdir(_p):
            os.environ["PATH"] = _p + ";" + os.environ.get("PATH", "")
            if hasattr(os, "add_dll_directory"):
                try:
                    os.add_dll_directory(_p)
                except OSError:
                    pass
            break

import markdown
from datetime import datetime, timezone
from pathlib import Path
from dotenv import load_dotenv

# weasyprint needs system libs (pango/cairo/gdk-pixbuf) that may be absent on a
# given host — imported gracefully so the DETERMINISTIC report path below (which
# needs neither weasyprint nor an LLM call) always works even when it's missing.
# generate_red_report() (the LLM-authored path) still requires it and degrades via
# its own caller (app.py) when absent.
try:
    import weasyprint
    _HAS_WEASYPRINT = True
except ImportError:                                   # pragma: no cover - env-dependent
    weasyprint = None
    _HAS_WEASYPRINT = False

load_dotenv()

BASE_DIR = Path(__file__).parent
PROMPTS_DIR = BASE_DIR / "prompts"
TEMPLATES_DIR = BASE_DIR / "pdf_templates"
OUTPUTS_DIR = BASE_DIR / "outputs"
OUTPUTS_DIR.mkdir(exist_ok=True)

LLM_PROVIDER = os.getenv("LLM_PROVIDER", "openrouter")

# OpenRouter (primary)
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY", "")
OPENROUTER_BASE_URL = os.getenv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1")
LLM_MODEL = os.getenv("LLM_MODEL", "deepseek/deepseek-v4-flash")
LLM_MODEL_DETAILED = os.getenv("LLM_MODEL_DETAILED", "anthropic/claude-sonnet-4-20250514")

# Legacy direct DeepSeek
DEEPSEEK_API_KEY = os.getenv("DEEPSEEK_API_KEY", "")
DEEPSEEK_BASE_URL = os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com")
DEEPSEEK_MODEL = os.getenv("DEEPSEEK_MODEL", "deepseek-chat")

# Ollama fallback
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "deepseek-r1:7b")


def load_prompt(prompt_file: str) -> str:
    """Load a prompt template from the prompts/ directory."""
    filepath = PROMPTS_DIR / prompt_file
    if not filepath.exists():
        raise FileNotFoundError(f"Prompt file not found: {filepath}")
    return filepath.read_text(encoding="utf-8")
def call_llm(system_prompt: str, user_message: str, use_detailed: bool = False) -> str:
    """
    Call the configured LLM provider.
    Returns raw text response (Markdown).
    Raises on failure — let callers handle fallback.

    Args:
        system_prompt: System-level instructions for the LLM
        user_message: The user message (findings/events data)
        use_detailed: If True, use LLM_MODEL_DETAILED (Claude) instead of primary model.
                      Only applies when LLM_PROVIDER=openrouter.
    """
    if LLM_PROVIDER == "openrouter":
        return _call_openrouter(system_prompt, user_message, use_detailed)
    elif LLM_PROVIDER == "deepseek":
        return _call_openai_compatible(
            system_prompt, user_message,
            api_key=DEEPSEEK_API_KEY,
            base_url=DEEPSEEK_BASE_URL,
            model=DEEPSEEK_MODEL
        )
    elif LLM_PROVIDER == "ollama":
        return _call_ollama(system_prompt, user_message)
    else:
        raise ValueError(
            f"Unknown LLM_PROVIDER: {LLM_PROVIDER}. "
            f"Set to 'openrouter', 'deepseek', or 'ollama'."
        )


def _call_openai_compatible(system_prompt: str, user_message: str,
                             api_key: str, base_url: str, model: str) -> str:
    """Generic OpenAI-compatible chat completions call (works for OpenRouter, DeepSeek, etc.)."""
    from openai import OpenAI
    client = OpenAI(api_key=api_key, base_url=base_url)
    response = client.chat.completions.create(
        model=model,
        max_tokens=4096,
        temperature=0.3,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_message}
        ]
    )
    return response.choices[0].message.content


def _call_openrouter(system_prompt: str, user_message: str,
                      use_detailed: bool = False) -> str:
    """Call OpenRouter API — supports DeepSeek V4 Flash (primary) and Claude (detailed)."""
    from openai import OpenAI
    model = LLM_MODEL_DETAILED if use_detailed else LLM_MODEL
    client = OpenAI(api_key=OPENROUTER_API_KEY, base_url=OPENROUTER_BASE_URL)
    response = client.chat.completions.create(
        model=model,
        max_tokens=4096,
        temperature=0.3,
        extra_headers={
            "HTTP-Referer": "https://github.com/Cyph3rC0nan/RedSee-ITSkillsFinalProject",
            "X-Title": "RedSee Security Scanner",
        },
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_message}
        ]
    )
    return response.choices[0].message.content


def _call_ollama(system_prompt: str, user_message: str) -> str:
    """Call local Ollama instance (free fallback, no API key needed)."""
    import requests
    response = requests.post(
        f"{OLLAMA_URL}/api/generate",
        json={
            "model": OLLAMA_MODEL,
            "system": system_prompt,
            "prompt": user_message,
            "stream": False,
            "options": {"temperature": 0.3, "num_predict": 4096}
        },
        timeout=180
    )
    response.raise_for_status()
    return response.json()["response"]


def markdown_to_pdf(md_text: str, css_file: str, output_path: str) -> str:
    """
    Convert Markdown text to a professional PDF.

    Args:
        md_text: Raw Markdown string
        css_file: CSS filename inside pdf_templates/ (e.g. "red.css")
        output_path: Full path for output PDF

    Returns:
        output_path
    """
    html_content = markdown.markdown(
        md_text,
        extensions=["tables", "fenced_code", "toc", "nl2br"]
    )

    css_path = TEMPLATES_DIR / css_file
    css_text = css_path.read_text(encoding="utf-8") if css_path.exists() else ""

    full_html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <style>{css_text}</style>
</head>
<body>
    <div class="report-container">
        {html_content}
    </div>
</body>
</html>"""

    weasyprint.HTML(string=full_html).write_pdf(output_path)
    return output_path


# ── Deterministic report (no LLM call, weasyprint OPTIONAL) ──────────────────
# generate_red_report() above ALWAYS needs a working LLM call (call_llm) AND
# weasyprint — a two-part dependency that fails closed the moment either is
# unavailable/misconfigured (no API key, no network, no system libs). The
# generator below builds the SAME kind of structured report directly from the
# scan's own data (deterministic string templates, not an LLM), and renders it
# via weasyprint when available or plain HTML when not (`markdown` — used here —
# is a lightweight pure-Python package, already a hard dependency of this module).
# This is the path app.py's /scan/<id>/report route calls: it must ALWAYS
# produce a real, downloadable file, never a dead click.

def _render_report(md_text: str, css_file: str, output_path_stem: str) -> tuple[str, str]:
    """Render `md_text` to a PDF (weasyprint, when importable) or a self-contained
    HTML file (always available). Returns (output_path, "pdf"|"html")."""
    html_content = markdown.markdown(
        md_text, extensions=["tables", "fenced_code", "toc", "nl2br"])
    css_path = TEMPLATES_DIR / css_file
    css_text = css_path.read_text(encoding="utf-8") if css_path.exists() else ""
    full_html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>RedSee Report</title>
    <style>{css_text}</style>
</head>
<body>
    <div class="report-container">
        {html_content}
    </div>
</body>
</html>"""
    if _HAS_WEASYPRINT:
        output_path = f"{output_path_stem}.pdf"
        weasyprint.HTML(string=full_html).write_pdf(output_path)
        return output_path, "pdf"
    # No weasyprint — write plain HTML instead. red.css's @page rules (paged-media
    # headers/footers) are weasyprint-specific and browsers simply ignore them, so
    # the SAME stylesheet still renders a clean, readable page; the operator can
    # use their browser's own Print -> Save as PDF for a physical PDF if they want
    # one.
    output_path = f"{output_path_stem}.html"
    Path(output_path).write_text(full_html, encoding="utf-8")
    return output_path, "html"


def _fmt_ts(iso: str | None) -> str:
    if not iso:
        return "—"
    try:
        return datetime.strptime(iso, "%Y-%m-%dT%H:%M:%SZ").strftime("%Y-%m-%d %H:%M:%S UTC")
    except ValueError:
        return iso


def _finding_section(f: dict, i: int) -> str:
    return f"""### Finding {i}: {f.get('type', 'Unknown')} in `{f.get('parameter', 'unknown')}`

- **Severity:** {f.get('severity', 'Unknown')}
- **Affected URL:** {f.get('url', 'unknown')}
- **Vulnerable Parameter:** {f.get('parameter', 'unknown')}
- **Payload:** `{f.get('payload', '(not recorded)')}`
- **Confirmed:** {_fmt_ts(f.get('timestamp'))}

**Evidence**

```
{(f.get('evidence') or '(no evidence text recorded)').strip()}
```
"""


def _tools_table(tools_run: list[dict]) -> str:
    if not tools_run:
        return "_No tool-execution data recorded for this scan._\n"
    rows = ["| Tool | Status | Count | Detail |", "|---|---|---|---|"]
    for t in tools_run:
        detail = (t.get("detail") or "").replace("|", "\\|")
        rows.append(f"| {t.get('name','?')} | {t.get('status','?')} | "
                    f"{t.get('count',0)} | {detail} |")
    return "\n".join(rows) + "\n"


def _recon_summary(recon: dict | None) -> str:
    recon = recon or {}
    observations = [o for o in (recon.get("observations") or [])
                     if o.get("status") == "observed"]
    nuclei_hits = [c for c in (recon.get("nuclei") or []) if c.get("status") == "found"]
    if not observations and not nuclei_hits:
        return "_No recon observations recorded._\n"
    rows = ["| Tool | Severity | Category | Title |", "|---|---|---|---|"]
    for c in nuclei_hits[:25]:
        rows.append(f"| nuclei | {c.get('severity','?')} | {c.get('template_id','template')} | "
                    f"{(c.get('name') or '').replace('|', chr(92)+'|')} |")
    for o in observations[:25]:
        rows.append(f"| {o.get('tool','?')} | {o.get('severity') or '—'} | "
                    f"{o.get('category','?')} | {(o.get('title') or '').replace('|', chr(92)+'|')} |")
    return "\n".join(rows) + "\n"


def _build_deterministic_markdown(record: dict, scan_id: str) -> str:
    """A structured pentest-style report built directly from a scan record —
    schemas.Finding data + (when available) the unified scan_<id>.json's
    target/mode/tools_run/recon/summary — no LLM involved, so it never fails on a
    missing API key/network/model and is fully reproducible from the record alone.
    """
    findings = record.get("findings") or []
    tools_run = record.get("tools_run") or []
    target = record.get("target") or "(unknown target)"
    mode = record.get("mode") or "—"
    started = _fmt_ts(record.get("started_at"))
    finished = _fmt_ts(record.get("finished_at"))
    by_sev = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for f in findings:
        sev = f.get("severity")
        if sev in by_sev:
            by_sev[sev] += 1

    cover = f"""# RedSee — Penetration Test Report

**Report ID:** {scan_id}
**Target:** {target}
**Scan mode:** {mode}
**Scan window:** {started} — {finished}
**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}
**Tool:** RedSee Automated Scanner (deterministic report — evidence-gated, no LLM narrative)
**Total Findings:** {len(findings)}
**Critical:** {by_sev['Critical']}  **High:** {by_sev['High']}  **Medium:** {by_sev['Medium']}  **Low:** {by_sev['Low']}

---

## Executive Summary
"""
    if findings:
        cover += (
            f"This automated scan of `{target}` confirmed **{len(findings)}** "
            f"vulnerabilit{'y' if len(findings) == 1 else 'ies'} via tool-parsed, "
            f"evidence-gated detection (sqlmap for SQL injection, Dalfox for "
            f"reflected XSS) — no finding here is a model's assertion; each is "
            f"backed by the raw tool evidence reproduced below.\n"
        )
    else:
        cover += (
            f"This automated scan of `{target}` confirmed **no vulnerabilities**. "
            f"See the **Methodology** section below for exactly what ran, what was "
            f"skipped, and why — a clean result only means what was actually "
            f"tested came back clean; it does not claim to have tested everything.\n"
        )

    methodology = f"""
## Methodology

The scan crawled the target, extracted injectable parameters (query-string keys
and form/body fields), and tested only parameter-bearing endpoints for SQL
injection and reflected XSS — a parameter-less endpoint is never a valid
injection target. Reconnaissance (template/CVE matching, HTTP fingerprinting,
TLS inspection, content discovery) ran independently. Tool-by-tool outcome:

{_tools_table(tools_run)}
"""

    findings_section = "\n## Findings\n\n"
    if findings:
        for i, f in enumerate(findings, 1):
            findings_section += _finding_section(f, i) + "\n"
    else:
        findings_section += "_No confirmed vulnerabilities — see Methodology above._\n"

    recon_section = f"""
## Reconnaissance Observations

{_recon_summary(record.get("recon"))}
"""

    footer = """
---

*This report was generated by RedSee. Every finding above is derived solely from
parsed positive output of the underlying security tool (sqlmap / Dalfox / nuclei /
httpx / tlsx / ffuf) — never fabricated or inferred by a model. Authorized testing
only.*
"""

    return cover + methodology + findings_section + recon_section + footer


def generate_deterministic_report(record: dict, scan_id: str | None = None) -> tuple[str, str]:
    """Build and render a deterministic (LLM-free) red report from `record` —
    either the full unified scan_<id>.json record, or a minimal wrapper carrying
    at least {"findings": [...]}. Returns (output_path, "pdf"|"html"). Never
    raises for "0 findings" — a clean scan gets a real report, not an error.
    """
    scan_id = scan_id or record.get("scan_id") or datetime.now().strftime("%Y%m%d_%H%M%S")
    md = _build_deterministic_markdown(record, scan_id)
    output_stem = str(OUTPUTS_DIR / f"red_report_{scan_id}")
    path, fmt = _render_report(md, "red.css", output_stem)
    print(f"[RedReport] deterministic report saved: {path} (format={fmt})")
    return path, fmt


def _summarize_findings(findings: list[dict]) -> str:
    """Create a summary line for each finding type/severity combination."""
    summary = {}
    for f in findings:
        key = f"{f.get('type', 'Unknown')} ({f.get('severity', 'Unknown')})"
        summary[key] = summary.get(key, 0) + 1
    return "\n".join(f"  - {k}: {v} finding(s)" for k, v in summary.items())


def generate_red_report(findings: list[dict], scan_id: str = None, use_detailed: bool = False) -> str:
    """
    Generate a complete red team pentest report PDF.

    Args:
        findings: List of Finding dicts (use Finding.to_dict() or load from JSON)
        scan_id: Optional identifier for filename uniqueness

    Returns:
        Path to the generated PDF file (str)
    """
    if not scan_id:
        scan_id = datetime.now().strftime("%Y%m%d_%H%M%S")

    system_prompt = load_prompt("red_prompt.txt")

    findings_json = json.dumps(findings, indent=2)
    user_message = f"""Analyze the following vulnerability scan findings and generate a comprehensive penetration testing report.

Target scan contained {len(findings)} findings across the following categories:
{_summarize_findings(findings)}

Complete findings data:
{findings_json}

Generate the full report now."""

    print(f"[RedReport] Calling LLM for scan_id={scan_id} with {len(findings)} findings...")
    md_report = call_llm(system_prompt, user_message, use_detailed=use_detailed)
    print(f"[RedReport] LLM response received ({len(md_report)} chars)")

    cover = f"""# RedSee — Penetration Test Report

**Report ID:** {scan_id}
**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Tool:** RedSee Automated Scanner
**Total Findings:** {len(findings)}
**Critical:** {sum(1 for f in findings if f.get('severity') == 'Critical')}
**High:** {sum(1 for f in findings if f.get('severity') == 'High')}
**Medium:** {sum(1 for f in findings if f.get('severity') == 'Medium')}
**Low:** {sum(1 for f in findings if f.get('severity') == 'Low')}

---

"""
    full_md = cover + md_report
    output_path = str(OUTPUTS_DIR / f"red_report_{scan_id}.pdf")
    markdown_to_pdf(full_md, "red.css", output_path)
    print(f"[RedReport] PDF saved: {output_path}")
    return output_path


# ── CLI Test ───────────────────────────────────────────
if __name__ == "__main__":
    import json
    print("=" * 60)
    print("RedSee — Red Team Report Generator (Test Mode)")
    print("=" * 60)

    with open("sample_data/mock_findings.json") as f:
        mock_findings = json.load(f)

    pdf = generate_red_report(mock_findings, scan_id="test_001")
    print(f"\nTest complete! Report at: {pdf}")
    print("Open the PDF and verify it contains all sections.")