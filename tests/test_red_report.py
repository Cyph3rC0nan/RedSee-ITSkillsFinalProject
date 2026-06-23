# tests/test_red_report.py
"""Unit tests for red_report.py — runs without any other team member's code."""
import json
import os
import sys
from pathlib import Path

# Allow import from project root
sys.path.insert(0, str(Path(__file__).parent.parent))

from red_report import generate_red_report, markdown_to_pdf, _summarize_findings


def test_summarize_findings():
    findings = [
        {"type": "SQLi", "severity": "Critical"},
        {"type": "SQLi", "severity": "Critical"},
        {"type": "XSS", "severity": "High"},
    ]
    summary = _summarize_findings(findings)
    assert "SQLi (Critical): 2" in summary
    assert "XSS (High): 1" in summary
    print("test_summarize_findings passed")


def test_markdown_to_pdf_creates_file(tmp_path):
    md = "# Test Report\n\n## Section\n\nHello world."
    out = str(tmp_path / "test.pdf")
    # Use blank CSS for test — actual CSS tested in red_report test
    css_file = "red.css"
    result = markdown_to_pdf(md, css_file, out)
    assert os.path.exists(result), f"PDF not created at {result}"
    assert os.path.getsize(result) > 1000, "PDF file is suspiciously small"
    print(f"test_markdown_to_pdf_creates_file passed — {result}")


def test_generate_red_report_from_mock(tmp_path):
    # Load the shared mock data
    mock_path = Path(__file__).parent.parent / "sample_data" / "mock_findings.json"
    assert mock_path.exists(), f"Mock findings not found at {mock_path}"

    with open(mock_path) as f:
        findings = json.load(f)

    # Override output dir temporarily
    import red_report
    original_dir = red_report.OUTPUTS_DIR
    red_report.OUTPUTS_DIR = tmp_path

    pdf_path = generate_red_report(findings, scan_id="pytest_red_001")
    assert os.path.exists(pdf_path), f"PDF not generated at {pdf_path}"
    assert os.path.getsize(pdf_path) > 5000, "PDF too small — likely empty"

    red_report.OUTPUTS_DIR = original_dir
    print(f"test_generate_red_report_from_mock passed — {pdf_path}")


def test_finding_schema_fields():
    """Validate mock_findings.json matches the required Finding schema fields."""
    mock_path = Path(__file__).parent.parent / "sample_data" / "mock_findings.json"
    with open(mock_path) as f:
        findings = json.load(f)

    required_fields = {"type", "url", "parameter", "payload", "evidence", "severity", "timestamp"}
    valid_types = {"SQLi", "XSS", "IDOR", "BrokenAuth"}
    valid_severities = {"Critical", "High", "Medium", "Low"}

    for i, finding in enumerate(findings):
        missing = required_fields - finding.keys()
        assert not missing, f"Finding {i} missing fields: {missing}"
        assert finding["type"] in valid_types, f"Finding {i} has invalid type: {finding['type']}"
        assert finding["severity"] in valid_severities, f"Finding {i} has invalid severity: {finding['severity']}"

    print(f"test_finding_schema_fields passed — {len(findings)} findings validated")


if __name__ == "__main__":
    import tempfile, pathlib
    tmp = pathlib.Path(tempfile.mkdtemp())
    test_summarize_findings()
    test_markdown_to_pdf_creates_file(tmp)
    test_generate_red_report_from_mock(tmp)
    test_finding_schema_fields()
    print("\nAll red report tests passed!")