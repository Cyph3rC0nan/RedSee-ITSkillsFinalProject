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
import weasyprint
from datetime import datetime
from pathlib import Path
from dotenv import load_dotenv

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