# tests/test_blue_report.py
"""Unit tests for blue_report.py."""
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from blue_report import generate_blue_report, _compute_severity_distribution


def test_severity_distribution():
    events = [
        {"severity_level": 12},  # Critical
        {"severity_level": 12},  # Critical
        {"severity_level": 8},   # High
        {"severity_level": 3},   # Low
    ]
    dist = _compute_severity_distribution(events)
    assert "Critical (10+): 2" in dist
    assert "High (7-9): 1" in dist
    assert "Low (1-3): 1" in dist
    print("test_severity_distribution passed")


def test_generate_blue_report_from_mock(tmp_path):
    mock_path = Path(__file__).parent.parent / "sample_data" / "mock_wazuh_alerts.json"
    assert mock_path.exists(), f"Mock events not found at {mock_path}"

    with open(mock_path) as f:
        events = json.load(f)

    import blue_report
    original_dir = blue_report.OUTPUTS_DIR
    blue_report.OUTPUTS_DIR = tmp_path

    pdf_path = generate_blue_report(events, report_id="pytest_blue_001")
    assert os.path.exists(pdf_path)
    assert os.path.getsize(pdf_path) > 5000

    blue_report.OUTPUTS_DIR = original_dir
    print(f"test_generate_blue_report_from_mock passed — {pdf_path}")


def test_event_schema_fields():
    """Validate mock_wazuh_alerts.json matches the required Event schema fields."""
    mock_path = Path(__file__).parent.parent / "sample_data" / "mock_wazuh_alerts.json"
    with open(mock_path) as f:
        events = json.load(f)

    required_fields = {"source", "timestamp", "rule_id", "description",
                       "severity_level", "src_ip", "target_url", "raw_payload"}
    valid_sources = {"Wazuh", "Splunk"}

    for i, event in enumerate(events):
        missing = required_fields - event.keys()
        assert not missing, f"Event {i} missing fields: {missing}"
        assert event["source"] in valid_sources, f"Event {i} invalid source: {event['source']}"
        assert isinstance(event["severity_level"], int), f"Event {i} severity_level must be int"

    print(f"test_event_schema_fields passed — {len(events)} events validated")


if __name__ == "__main__":
    import tempfile, pathlib
    tmp = pathlib.Path(tempfile.mkdtemp())
    test_severity_distribution()
    test_generate_blue_report_from_mock(tmp)
    test_event_schema_fields()
    print("\nAll blue report tests passed!")