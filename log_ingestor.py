"""
SIEM Log Ingestor — parses Wazuh and Splunk log formats into normalized Event objects.

Supports:
  - File ingestion: ingest_log_file(filepath) -> list[Event]
  - Raw data ingestion: ingest_log_data(data) -> list[Event]
  - Live Wazuh API fetch: fetch_wazuh_alerts(...) -> list[Event]

Owner: Member 4
"""

import json
import os
import re
import hashlib
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Union

try:
    import requests as _requests
except ImportError:
    _requests = None

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from schemas import Event


# ═══════════════════════════════════════════════════════════════
# PUBLIC API
# ═══════════════════════════════════════════════════════════════

def ingest_log_file(filepath: str) -> list[Event]:
    """
    Parse a SIEM log file (JSON) into normalized Event objects.
    Auto-detects Wazuh vs Splunk format.

    Args:
        filepath: path to JSON log file

    Returns:
        list[Event]

    Raises:
        FileNotFoundError: if file doesn't exist
        ValueError: if format is unrecognized
    """
    path = Path(filepath)
    if not path.exists():
        raise FileNotFoundError(f"Log file not found: {filepath}")

    with open(path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    return ingest_log_data(data)


def ingest_log_data(raw_data: Union[dict, list]) -> list[Event]:
    """
    Parse raw SIEM data (dict or list) into normalized Event objects.

    Args:
        raw_data: list of alerts or dict with results wrapper

    Returns:
        list[Event]

    Raises:
        ValueError: if format is unrecognized
    """
    fmt = _detect_format(raw_data)

    if fmt == "wazuh":
        return _parse_wazuh_alerts(raw_data)
    elif fmt == "splunk":
        return _parse_splunk_export(raw_data)
    elif fmt == "normalized":
        return _parse_normalized_events(raw_data)
    else:
        raise ValueError(
            f"Unrecognized log format. Data keys: "
            f"{list(raw_data.keys())[:5] if isinstance(raw_data, dict) else 'list'}"
        )


def fetch_wazuh_alerts(api_url=None, username=None, password=None,
                       minutes=30, limit=500) -> list[Event]:
    """
    Fetch live alerts from a running Wazuh API instance.

    Args:
        api_url: Wazuh API base URL (falls back to WAZUH_API_URL env var)
        username: Wazuh API username (falls back to WAZUH_API_USER env var)
        password: Wazuh API password (falls back to WAZUH_API_PASS env var)
        minutes: fetch alerts from the last N minutes
        limit: max number of alerts to return

    Returns:
        list[Event]

    Raises:
        ConnectionError: if Wazuh API is unreachable
        ValueError: if auth fails
    """
    api_url = api_url or os.getenv("WAZUH_API_URL", "")
    username = username or os.getenv("WAZUH_API_USER", "")
    password = password or os.getenv("WAZUH_API_PASS", "")

    if not api_url:
        raise ConnectionError("WAZUH_API_URL not set. Set in .env or pass api_url parameter.")

    if _requests is None:
        raise ImportError("requests library required for Wazuh API fetch")

    # Step 1: Authenticate and get JWT token
    auth_url = f"{api_url.rstrip('/')}/security/user/authenticate"
    try:
        auth_resp = _requests.post(
            auth_url,
            auth=(username, password),
            verify=False,
            timeout=30
        )
    except _requests.ConnectionError:
        raise ConnectionError(f"Cannot connect to Wazuh API at {api_url}")
    except Exception as e:
        raise ConnectionError(f"Wazuh API connection error: {e}")

    if auth_resp.status_code != 200:
        raise ValueError(f"Wazuh authentication failed: {auth_resp.status_code} — {auth_resp.text[:200]}")

    try:
        auth_data = auth_resp.json()
        token = auth_data.get("data", {}).get("token", "")
        if not token:
            raise ValueError("No token in Wazuh auth response")
    except (json.JSONDecodeError, KeyError) as e:
        raise ValueError(f"Failed to parse Wazuh auth response: {e}")

    # Step 2: Fetch alerts
    time_from = (datetime.now(timezone.utc) - timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%SZ")
    alerts_url = f"{api_url.rstrip('/')}/alerts"

    try:
        alerts_resp = _requests.get(
            alerts_url,
            headers={"Authorization": f"Bearer {token}"},
            params={
                "offset": 0,
                "limit": limit,
                "sort": "-timestamp",
                "q": f"timestamp>{time_from}"
            },
            verify=False,
            timeout=30
        )
    except Exception as e:
        raise ConnectionError(f"Wazuh alerts fetch failed: {e}")

    if alerts_resp.status_code != 200:
        raise ValueError(f"Wazuh alerts fetch failed: {alerts_resp.status_code}")

    try:
        alerts_data = alerts_resp.json()
        # Wazuh API wraps results in data.affected_items
        items = alerts_data.get("data", {}).get("affected_items", [])
        if not items and isinstance(alerts_data.get("data"), list):
            items = alerts_data["data"]
        if not items and isinstance(alerts_data, list):
            items = alerts_data
    except (json.JSONDecodeError, KeyError):
        raise ValueError("Failed to parse Wazuh alerts response")

    return _parse_wazuh_alerts(items)


# ═══════════════════════════════════════════════════════════════
# FORMAT DETECTION
# ═══════════════════════════════════════════════════════════════

def _detect_format(data) -> str:
    """
    Detect whether data is Wazuh, Splunk, or pre-normalized Event format.
    Returns: "wazuh" | "splunk" | "normalized" | "unknown"
    """
    # Handle dict-wrapped results
    items = data
    if isinstance(data, dict):
        if "results" in data:
            items = data["results"]
        elif "data" in data and isinstance(data["data"], list):
            items = data["data"]
        elif isinstance(data, list):
            items = data
        else:
            items = [data]

    if not isinstance(items, list) or len(items) == 0:
        return "unknown"

    first = items[0]
    if not isinstance(first, dict):
        return "unknown"

    # Splunk indicators
    splunk_keys = {"_raw", "sourcetype", "splunk_server", "_time"}
    if any(k in first for k in splunk_keys):
        return "splunk"

    # Wazuh indicators
    if "rule" in first and isinstance(first["rule"], dict):
        if "id" in first["rule"] or "level" in first["rule"]:
            return "wazuh"

    # Flattened Wazuh style: rule.id, agent.name
    if "rule.id" in first or "agent.name" in first:
        return "wazuh"

    # Pre-normalized Event format (matches schemas.Event shape):
    # has source, timestamp, rule_id, severity_level, src_ip, target_url, raw_payload
    normalized_keys = {"source", "timestamp", "rule_id", "severity_level",
                       "src_ip", "target_url", "raw_payload"}
    if normalized_keys.issubset(first.keys()):
        return "normalized"

    # Partial normalized match — at least source + rule_id + timestamp
    partial = {"source", "rule_id", "timestamp"}
    if partial.issubset(first.keys()):
        return "normalized"

    return "unknown"


# ═══════════════════════════════════════════════════════════════
# WAZUH PARSER
# ═══════════════════════════════════════════════════════════════

def _parse_wazuh_alerts(data) -> list[Event]:
    """
    Parse Wazuh alert format into list[Event].

    Expected Wazuh format:
    {
        "timestamp": "2025-06-01T14:30:00Z",
        "rule": {"id": "31103", "description": "...", "level": 12},
        "agent": {"name": "web-server-01"},
        "data": {"srcip": "192.168.1.100", "url": "/path"}
    }
    """
    items = data
    if isinstance(data, dict):
        items = data.get("data", data.get("items", [data]))
    if not isinstance(items, list):
        items = [items]

    events = []
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    for alert in items:
        if not isinstance(alert, dict):
            continue

        try:
            # timestamp
            timestamp = alert.get("timestamp", now_iso)

            # rule info — handle both nested and flattened formats
            rule = alert.get("rule", {})
            if isinstance(rule, dict):
                rule_id = str(rule.get("id", "0"))
                description = rule.get("description", "Unknown alert")
                severity_level = int(rule.get("level", 1))
            else:
                rule_id = str(alert.get("rule.id", "0"))
                description = alert.get("rule.description", "Unknown alert")
                severity_level = int(alert.get("rule.level", 1))

            # source IP — check multiple possible locations
            data_field = alert.get("data", {})
            if isinstance(data_field, dict):
                src_ip = (
                    data_field.get("srcip", "")
                    or data_field.get("src_ip", "")
                    or data_field.get("srcUser", "")
                    or alert.get("srcip", "")
                )
                target_url = (
                    data_field.get("url", "")
                    or data_field.get("uri", "")
                    or data_field.get("request", "")
                )
                raw_payload = data_field.get("payload", "")
            else:
                src_ip = ""
                target_url = ""
                raw_payload = ""

            # If no payload from data, try to extract query string from URL
            if not raw_payload and target_url and "?" in target_url:
                raw_payload = target_url.split("?", 1)[1]

            events.append(Event(
                source="Wazuh",
                timestamp=timestamp,
                rule_id=rule_id,
                description=description,
                severity_level=severity_level,
                src_ip=src_ip,
                target_url=target_url,
                raw_payload=raw_payload
            ))
        except Exception:
            # Skip malformed alerts silently — don't crash on one bad record
            continue

    return events


def _parse_normalized_events(data) -> list[Event]:
    """
    Parse pre-normalized Event-format data into list[Event].

    Accepts the exact dict shape produced by schemas.Event.to_dict():
    { "source": "Wazuh"|"Splunk", "timestamp": "...Z", "rule_id": "...",
      "description": "...", "severity_level": int, "src_ip": "...",
      "target_url": "...", "raw_payload": "..." }
    """
    items = data
    if isinstance(data, dict):
        items = data.get("data", data.get("items", data.get("events", [data])))
    if not isinstance(items, list):
        items = [items]

    events: list[Event] = []
    for entry in items:
        if not isinstance(entry, dict):
            continue
        try:
            src = entry.get("source", "Unknown")
            # Schema allows only Wazuh|Splunk; fall back to source title-case if unknown
            if src not in ("Wazuh", "Splunk"):
                src = src.capitalize() if isinstance(src, str) else "Unknown"
            events.append(Event(
                source=src,
                timestamp=str(entry.get("timestamp", "")),
                rule_id=str(entry.get("rule_id", "0")),
                description=str(entry.get("description", "")),
                severity_level=int(entry.get("severity_level", 1)),
                src_ip=str(entry.get("src_ip", "")),
                target_url=str(entry.get("target_url", "")),
                raw_payload=str(entry.get("raw_payload", ""))
            ))
        except Exception:
            continue
    return events


# ═══════════════════════════════════════════════════════════════
# SPLUNK PARSER
# ═══════════════════════════════════════════════════════════════

def _parse_splunk_export(data) -> list[Event]:
    """
    Parse Splunk export format into list[Event].

    Expected Splunk format:
    {
        "_time": "2025-06-01T14:30:00",
        "sourcetype": "web_attack",
        "src_ip": "192.168.1.100",
        "uri": "/path",
        "description": "...",
        "severity": "high",
        "_raw": "..."
    }
    """
    items = data
    if isinstance(data, dict):
        items = data.get("results", data.get("data", [data]))
    if not isinstance(items, list):
        items = [items]

    events = []

    for item in items:
        if not isinstance(item, dict):
            continue

        try:
            # timestamp
            timestamp = item.get("_time") or item.get("timestamp") or item.get("time", "")
            if timestamp and not timestamp.endswith("Z"):
                if "T" in timestamp and "+" not in timestamp and timestamp[-1] != "Z":
                    timestamp += "Z"

            # source IP
            src_ip = (
                item.get("src_ip", "")
                or item.get("src", "")
                or item.get("clientip", "")
                or item.get("source_ip", "")
            )

            # target URL
            target_url = (
                item.get("uri", "")
                or item.get("url", "")
                or item.get("uri_path", "")
                or item.get("request", "")
            )

            # description
            description = (
                item.get("description", "")
                or item.get("signature", "")
                or item.get("action", "")
            )

            # severity level — try int, else map from string
            severity_raw = item.get("severity", item.get("severity_level", 5))
            try:
                severity_level = int(severity_raw)
            except (ValueError, TypeError):
                severity_map = {
                    "critical": 12, "high": 9, "medium": 6,
                    "low": 3, "info": 1, "informational": 1
                }
                severity_level = severity_map.get(str(severity_raw).lower(), 5)

            # rule ID
            rule_id = (
                item.get("rule_id", "")
                or item.get("signature_id", "")
                or item.get("event_id", "")
            )
            if not rule_id:
                rule_id = hashlib.md5(description.encode()).hexdigest()[:8] if description else "unknown"

            # raw payload
            raw_payload = item.get("_raw", item.get("raw_payload", ""))
            if not raw_payload and target_url and "?" in target_url:
                raw_payload = target_url.split("?", 1)[1]

            events.append(Event(
                source="Splunk",
                timestamp=timestamp or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                rule_id=str(rule_id),
                description=description or "Unknown event",
                severity_level=severity_level,
                src_ip=src_ip,
                target_url=target_url,
                raw_payload=raw_payload
            ))
        except Exception:
            continue

    return events


def _parse_splunk_csv(csv_text: str) -> list[Event]:
    """
    Parse a Splunk CSV export into list[Event].
    Falls back gracefully if CSV parsing fails.
    """
    try:
        import csv
        import io

        reader = csv.DictReader(io.StringIO(csv_text))
        items = list(reader)
        return _parse_splunk_export(items)
    except Exception:
        # If CSV parsing fails, try to treat as JSON
        return []


# ═══════════════════════════════════════════════════════════════
# CLI QUICK TEST
# ═══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1:
        filepath = sys.argv[1]
    else:
        filepath = "sample_data/sample_wazuh_alerts.json"

    print("=" * 60)
    print("🛡️  SIEM Log Ingestor — Standalone Test")
    print("=" * 60)
    print(f"\nReading: {filepath}")

    try:
        events = ingest_log_file(filepath)
        print(f"\nParsed {len(events)} events:\n")

        for i, e in enumerate(events):
            print(f"  [{i+1}] [{e.source}] {e.timestamp}")
            print(f"       Rule: {e.rule_id} | Severity: {e.severity_level}")
            print(f"       {e.description}")
            print(f"       Src IP: {e.src_ip} | Target: {e.target_url}")
            if e.raw_payload:
                print(f"       Payload: {e.raw_payload[:100]}")
            print()

    except Exception as e:
        print(f"Error: {e}")

    print(f"{'=' * 60}")
    print("Standalone test complete.")
