# engine/scope.py
"""
Authorization & scope-gating module — first layer of the RedSee agent engine.

Standalone and offline: no network calls, no subprocess, no Docker, no
scanner imports. Every active test must call require_authorization() and
assert_in_scope() before doing anything against a URL. Default-deny: if
scope is missing, empty, or unauthorized, nothing is in scope.
"""

import os
import urllib.parse
from dataclasses import dataclass, field


@dataclass
class ScopeConfig:
    target_url: str
    allowed_hosts: list[str]
    authorized: bool
    max_requests_per_min: int = 60
    allowed_url_prefixes: list[str] = field(default_factory=list)


class ScopeError(Exception):
    """Raised when an operation is attempted without authorization or out of scope."""
    pass


def load_scope_config() -> ScopeConfig:
    """Load a ScopeConfig from environment variables. Default-deny on missing/bad values."""
    target_url = os.environ.get("REDSEE_TARGET_URL", "").strip()

    hosts_raw = os.environ.get("REDSEE_ALLOWED_HOSTS", "")
    allowed_hosts = [h.strip() for h in hosts_raw.split(",") if h.strip()]

    authorized = os.environ.get("REDSEE_AUTHORIZED", "false").strip().lower() == "true"

    try:
        rate_limit = int(os.environ.get("REDSEE_RATE_LIMIT", "60").strip())
    except ValueError:
        rate_limit = 60

    return ScopeConfig(
        target_url=target_url,
        allowed_hosts=allowed_hosts,
        authorized=authorized,
        max_requests_per_min=rate_limit,
    )


def is_in_scope(url: str, config: ScopeConfig) -> bool:
    """True iff url's host exactly matches an allowed host (and prefix, if configured)."""
    if not config.allowed_hosts:
        return False

    try:
        normalized = url.strip().split("#", 1)[0]
        parsed = urllib.parse.urlparse(normalized)
        host = parsed.hostname
        if not host:
            return False
        host = host.lower()

        allowed = {h.lower() for h in config.allowed_hosts}
        if host not in allowed:
            return False

        if config.allowed_url_prefixes:
            if not any(normalized.startswith(prefix) for prefix in config.allowed_url_prefixes):
                return False

        return True
    except Exception:
        return False


def require_authorization(config: ScopeConfig) -> None:
    """Raise ScopeError unless the operator has attested authorization and defined a scope."""
    if not config.authorized or not config.allowed_hosts:
        raise ScopeError(
            "Scope not authorized: set REDSEE_AUTHORIZED=true and REDSEE_ALLOWED_HOSTS "
            "before running any active test."
        )


def assert_in_scope(url: str, config: ScopeConfig) -> None:
    """Raise ScopeError if url is not in scope. Call immediately before any request/tool run."""
    if not is_in_scope(url, config):
        raise ScopeError(f"URL is out of scope, refusing to test: {url}")
