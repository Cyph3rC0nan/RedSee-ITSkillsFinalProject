"""
Tests for the Wazuh alerts.json (JSONL) blue-team ingest path.

Exercises log_ingestor against REAL Wazuh alert lines (captured from
/var/ossec/logs/alerts/alerts.json) plus a deliberately malformed line:
  * a web-attack alert (rule 31106) -> Event with correct severity/srcip/url/description
  * a malformed JSONL line is skipped (not crashed on)
  * the numeric level -> severity-bucket mapping is correct
  * the "last N" limit is respected
  * a non-web alert (sshd 5710) also maps

Fully offline — reads only the bundled fixture, never the live SIEM.

Run: PYTHONPATH=. python -m pytest tests/test_blue_ingest.py -v
"""
import json
from pathlib import Path

import pytest

from schemas import Event
from log_ingestor import (
    ingest_log_file, ingest_log_data, severity_bucket, is_web_attack,
    _clean_ip, _url_from_full_log,
)

FIXTURE = Path(__file__).parent / "fixtures" / "wazuh_alerts_sample.jsonl"


def _events():
    return ingest_log_file(str(FIXTURE))


# ── file / JSONL parsing ────────────────────────────────────────────────

def test_fixture_exists():
    assert FIXTURE.exists(), f"missing fixture {FIXTURE}"


def test_jsonl_parses_and_skips_malformed():
    events = _events()
    # 5 physical lines: 3 valid alerts, 1 malformed, 1 blank -> exactly 3 Events
    assert len(events) == 3, f"expected 3 events (malformed/blank skipped), got {len(events)}"
    assert all(isinstance(e, Event) for e in events)


def test_all_events_source_is_wazuh():
    for e in _events():
        assert e.source == "Wazuh"


# ── web-attack alert (31106) mapping ────────────────────────────────────

def test_web_attack_alert_mapped_correctly():
    events = _events()
    web = [e for e in events if e.rule_id == "31106"]
    assert web, "expected at least one rule 31106 web-attack event"

    # The first 31106 in the fixture is the real /rest/products/search XSS hit.
    e = next(e for e in web if "/rest/products/search" in e.target_url)
    assert e.severity_level == 6                       # rule.level preserved as int
    assert severity_bucket(e.severity_level) == "Medium"
    assert e.src_ip == "203.0.113.10"                  # ::ffff: prefix stripped
    assert e.target_url == "/rest/products/search?q=<script>alert(1)</script>"
    assert "web attack" in e.description.lower()
    # the injected payload is surfaced in the detail field
    assert "q=<script>alert(1)</script>" in e.raw_payload


def test_market_xss_attack_present():
    """The /market XSS attack event (the RedSee-scan-style hit) is surfaced."""
    events = _events()
    market = [e for e in events if "/market/search" in e.target_url]
    assert market, "expected the /market/search XSS attack event"
    e = market[0]
    assert e.rule_id == "31106"
    assert is_web_attack(e.rule_id)
    assert "<script>alert(1)</script>" in e.target_url


# ── non-web alert (sshd 5710) mapping ───────────────────────────────────

def test_sshd_non_web_alert_mapped():
    events = _events()
    ssh = [e for e in events if e.rule_id == "5710"]
    assert ssh, "expected the sshd 5710 event"
    e = ssh[0]
    assert e.source == "Wazuh"
    assert e.severity_level == 5
    assert severity_bucket(e.severity_level) == "Medium"
    assert "sshd" in e.description.lower()
    assert not is_web_attack(e.rule_id)               # 5710 is not a 31xxx web rule


# ── severity bucket mapping ─────────────────────────────────────────────

@pytest.mark.parametrize("level,expected", [
    (15, "Critical"), (12, "Critical"),
    (11, "High"), (7, "High"),
    (6, "Medium"), (4, "Medium"),
    (3, "Low"), (1, "Low"), (0, "Low"),
])
def test_severity_bucket_mapping(level, expected):
    assert severity_bucket(level) == expected


def test_severity_bucket_handles_garbage():
    assert severity_bucket("not-a-number") == "Low"
    assert severity_bucket(None) == "Low"


# ── last-N limiting ─────────────────────────────────────────────────────

def test_last_n_respected():
    all_events = _events()
    assert len(all_events) == 3
    limited = ingest_log_file(str(FIXTURE), last_n=1)
    assert len(limited) == 1
    # last_n takes the TAIL — Wazuh appends, so the newest alert is the /market hit
    assert "/market/search" in limited[0].target_url


def test_last_n_zero_returns_empty():
    assert ingest_log_file(str(FIXTURE), last_n=0) == []


# ── helpers ─────────────────────────────────────────────────────────────

def test_clean_ip_strips_ipv4_mapped_prefix():
    assert _clean_ip("::ffff:203.0.113.10") == "203.0.113.10"
    assert _clean_ip("10.0.0.1") == "10.0.0.1"
    assert _clean_ip("") == ""


def test_url_recovered_from_full_log():
    line = ('::ffff:1.2.3.4 - - [15/Jul/2026:08:11:38 +0000] '
            '"GET /rest/products/search?q=x HTTP/1.1" 200 30 "-" "curl/8.5.0"')
    assert _url_from_full_log(line) == "/rest/products/search?q=x"


def test_url_recovered_when_data_url_missing():
    """An alert with full_log but no data.url still yields a target_url."""
    alert = {
        "timestamp": "2026-07-15T10:11:40.212+0200",
        "rule": {"level": 6, "description": "A web attack returned code 200 (success).",
                 "id": "31106", "groups": ["web", "attack"],
                 "mitre": {"id": ["T1190"]}},
        "full_log": ('::ffff:8.8.8.8 - - [15/Jul/2026:08:11:38 +0000] '
                     '"GET /rest/x?p=1 HTTP/1.1" 200 30 "-" "curl/8.5.0"'),
        "data": {"srcip": "::ffff:8.8.8.8"},
    }
    events = ingest_log_data([alert])
    assert len(events) == 1
    assert events[0].target_url == "/rest/x?p=1"
    assert "T1190" in events[0].raw_payload           # MITRE marker carried in detail


# ── backward-compat: a JSON array (old sample shape) still parses ───────

def test_json_array_still_supported():
    data = [{
        "timestamp": "2025-06-01T14:32:00Z",
        "rule": {"id": "31103", "description": "SQL injection attempt", "level": 12},
        "data": {"srcip": "10.0.0.1", "url": "/login?id=1' OR 1=1--"},
    }]
    events = ingest_log_data(data)
    assert len(events) == 1
    assert events[0].source == "Wazuh"
    assert events[0].severity_level == 12
    assert severity_bucket(events[0].severity_level) == "Critical"


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
