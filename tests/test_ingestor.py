"""
Tests for log_ingestor.py

Run: python -m pytest tests/test_ingestor.py -v
"""
import json
import pytest
from pathlib import Path
from schemas import Event
from log_ingestor import ingest_log_file, ingest_log_data

WAZUH_SAMPLE = "sample_data/sample_wazuh_alerts.json"
SPLUNK_SAMPLE = "sample_data/sample_splunk_export.json"


def test_ingest_wazuh_file_returns_events():
    if not Path(WAZUH_SAMPLE).exists():
        pytest.skip(f"{WAZUH_SAMPLE} not found")
    events = ingest_log_file(WAZUH_SAMPLE)
    assert isinstance(events, list)
    assert len(events) > 0, "Should parse at least 1 event from Wazuh sample"


def test_wazuh_events_have_correct_schema():
    if not Path(WAZUH_SAMPLE).exists():
        pytest.skip(f"{WAZUH_SAMPLE} not found")
    events = ingest_log_file(WAZUH_SAMPLE)
    for e in events:
        ed = e.to_dict() if isinstance(e, Event) else e
        assert "source" in ed
        assert "timestamp" in ed
        assert "rule_id" in ed
        assert "description" in ed
        assert "severity_level" in ed
        assert "src_ip" in ed


def test_wazuh_events_source_is_wazuh():
    if not Path(WAZUH_SAMPLE).exists():
        pytest.skip(f"{WAZUH_SAMPLE} not found")
    events = ingest_log_file(WAZUH_SAMPLE)
    for e in events:
        src = e.source if isinstance(e, Event) else e["source"]
        assert src == "Wazuh", f"Expected source='Wazuh', got '{src}'"


def test_ingest_splunk_file():
    if not Path(SPLUNK_SAMPLE).exists():
        pytest.skip(f"{SPLUNK_SAMPLE} not found")
    events = ingest_log_file(SPLUNK_SAMPLE)
    assert isinstance(events, list)
    assert len(events) > 0


def test_splunk_events_source_is_splunk():
    if not Path(SPLUNK_SAMPLE).exists():
        pytest.skip(f"{SPLUNK_SAMPLE} not found")
    events = ingest_log_file(SPLUNK_SAMPLE)
    for e in events:
        src = e.source if isinstance(e, Event) else e["source"]
        assert src == "Splunk", f"Expected source='Splunk', got '{src}'"


def test_ingest_wazuh_data_from_dict():
    data = [
        {
            "timestamp": "2025-06-01T14:32:00Z",
            "rule": {"id": "31103", "description": "SQL injection attempt", "level": 10},
            "agent": {"name": "test-agent"},
            "data": {"srcip": "10.0.0.1", "url": "/login?id=1' OR 1=1--"}
        }
    ]
    events = ingest_log_data(data)
    assert len(events) == 1
    e = events[0]
    src = e.source if isinstance(e, Event) else e["source"]
    assert src == "Wazuh"


def test_ingest_raises_on_bad_format():
    with pytest.raises(ValueError, match="Unrecognized log format"):
        ingest_log_data({"completely": "wrong", "format": True})


def test_file_not_found_raises():
    with pytest.raises(FileNotFoundError):
        ingest_log_file("nonexistent_file_xyz.json")


def test_wazuh_count_matches_sample():
    """Verify we parse all 10 events from the sample file."""
    if not Path(WAZUH_SAMPLE).exists():
        pytest.skip(f"{WAZUH_SAMPLE} not found")
    events = ingest_log_file(WAZUH_SAMPLE)
    assert len(events) == 10, f"Expected 10 events, got {len(events)}"
