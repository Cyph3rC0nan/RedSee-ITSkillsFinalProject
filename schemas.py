# schemas.py — SHARED ACROSS ALL MODULES
# DO NOT MODIFY AFTER DAY 3 WITHOUT TEAM-WIDE ANNOUNCEMENT

from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Optional
import json


@dataclass
class Endpoint:
    """Output of crawler.py — one discovered endpoint/form."""
    url: str
    method: str
    form_action: Optional[str]
    inputs: list[str]
    cookies_needed: list[str]
    endpoint_type: str  # "form" | "api" | "link" | "page"


@dataclass
class Finding:
    """Output of each vuln module — one discovered vulnerability."""
    type: str          # "SQLi" | "XSS" | "IDOR" | "BrokenAuth"
    url: str
    parameter: str
    payload: str
    evidence: str
    severity: str      # EXACTLY: "Critical" | "High" | "Medium" | "Low"
    timestamp: str     # ISO 8601: "2025-06-01T14:32:00Z"

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Event:
    """Normalized SIEM event — output of log_ingestor.py."""
    source: str          # "Wazuh" | "Splunk"
    timestamp: str
    rule_id: str
    description: str
    severity_level: int  # 1–15 (Wazuh) or 1–10 normalized
    src_ip: str
    target_url: str
    raw_payload: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Sitemap:
    """Full crawler output."""
    target_url: str
    crawl_timestamp: str
    endpoints: list[Endpoint]
    total_pages: int
    total_forms: int
    total_api_endpoints: int

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self, filepath: str):
        with open(filepath, 'w') as f:
            json.dump(self.to_dict(), f, indent=2)

    @classmethod
    def from_json(cls, filepath: str) -> 'Sitemap':
        with open(filepath, 'r') as f:
            data = json.load(f)
        endpoints = [Endpoint(**ep) for ep in data['endpoints']]
        return cls(
            target_url=data['target_url'],
            crawl_timestamp=data['crawl_timestamp'],
            endpoints=endpoints,
            total_pages=data['total_pages'],
            total_forms=data['total_forms'],
            total_api_endpoints=data['total_api_endpoints']
        )


@dataclass
class ScanResult:
    """Complete scan output — passed to red_report.py."""
    scan_id: str
    target_url: str
    scan_timestamp: str
    sitemap: Sitemap
    findings: list[Finding]
    modules_run: list[str]
    scan_duration_seconds: float

    def findings_to_json(self) -> str:
        return json.dumps([f.to_dict() for f in self.findings], indent=2)
