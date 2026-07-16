# tests/test_console_settings.py
"""
Tests for console_settings.py — the Settings-tab-managed runtime config (LLM
engine, budget/guards, and the Wazuh SIEM source).

Fully offline: no network calls are exercised except test_connection/
test_wazuh_connection, which ARE network calls by design (reachability
checks) — those are marked and skipped by default in this suite since they'd
hit real external hosts; the rest (save/load/env-apply/masking) is pure logic.

Run: PYTHONPATH=. pytest tests/test_console_settings.py -v
"""
import os
import stat
import json

import pytest

import console_settings as cs


ENV_KEYS = [
    "REDSEE_LLM_BASE_URL", "REDSEE_LLM_MODEL", "REDSEE_LLM_API_KEY",
    "REDSEE_LLM_MAX_USD", "REDSEE_LLM_PRICE_IN_PER_1K", "REDSEE_LLM_PRICE_OUT_PER_1K",
    "REDSEE_LLM_TIMEOUT", "REDSEE_RATE_LIMIT", "REDSEE_MAX_PARALLEL_SANDBOXES",
    "REDSEE_WAZUH_ALERTS_PATH", "WAZUH_API_URL", "WAZUH_API_USER", "WAZUH_API_PASS",
]


@pytest.fixture(autouse=True)
def _isolated_settings(tmp_path, monkeypatch):
    """Every test gets a fresh settings.json path and a clean os.environ for
    all the keys this module manages, so tests can't see each other's state or
    whatever happens to be in this host's real .env."""
    monkeypatch.setattr(cs, "SETTINGS_PATH", tmp_path / "settings.json")
    for k in ENV_KEYS:
        monkeypatch.delenv(k, raising=False)
    yield


# ── LLM settings (regression — pre-existing behavior) ───────────────────────

def test_save_and_apply_llm_settings_to_env():
    cs.save_settings({"provider": "external", "base_url": "https://openrouter.ai/api/v1",
                       "model": "anthropic/claude-sonnet-4", "api_key": "sk-secret-abcd1234",
                       "max_usd": "0.50", "timeout_sec": "90"})
    assert os.environ["REDSEE_LLM_BASE_URL"] == "https://openrouter.ai/api/v1"
    assert os.environ["REDSEE_LLM_API_KEY"] == "sk-secret-abcd1234"
    assert os.environ["REDSEE_LLM_MAX_USD"] == "0.5"


def test_public_settings_masks_llm_api_key():
    cs.save_settings({"base_url": "https://x", "model": "m", "api_key": "sk-secret-abcd1234"})
    pub = cs.public_settings()
    assert pub["api_key_set"] is True
    assert pub["api_key_hint"] == "••••1234"
    assert "sk-secret" not in json.dumps(pub)


def test_blank_llm_api_key_keeps_existing():
    cs.save_settings({"base_url": "https://x", "model": "m", "api_key": "sk-secret-abcd1234"})
    cs.save_settings({"base_url": "https://x", "model": "m", "api_key": "", "max_usd": "0.75"})
    assert os.environ["REDSEE_LLM_API_KEY"] == "sk-secret-abcd1234"
    assert os.environ["REDSEE_LLM_MAX_USD"] == "0.75"


def test_switching_llm_provider_to_local_clears_api_key():
    cs.save_settings({"provider": "external", "base_url": "https://x", "model": "m",
                       "api_key": "sk-secret-abcd1234"})
    cs.save_settings({"provider": "local", "base_url": "http://localhost:11434/v1", "model": "llama3.2"})
    assert os.environ.get("REDSEE_LLM_API_KEY") is None
    assert cs.public_settings()["provider"] == "local"


def test_negative_cost_cap_rejected():
    with pytest.raises(cs.SettingsError, match="Cost cap"):
        cs.save_settings({"max_usd": "-3"})


def test_settings_file_written_owner_only():
    cs.save_settings({"base_url": "https://x", "model": "m"})
    mode = stat.S_IMODE(os.stat(cs.SETTINGS_PATH).st_mode)
    assert mode == 0o600


def test_apply_saved_to_env_restores_after_env_cleared():
    cs.save_settings({"base_url": "https://x", "model": "m", "max_usd": "0.5"})
    os.environ.pop("REDSEE_LLM_BASE_URL", None)
    cs.apply_saved_to_env()
    assert os.environ["REDSEE_LLM_BASE_URL"] == "https://x"


# ── Wazuh source settings (new) ──────────────────────────────────────────────

def test_save_wazuh_file_source():
    pub = cs.save_settings({"wazuh_source": "file", "wazuh_path": "/var/ossec/logs/alerts/alerts.json"})
    assert os.environ["REDSEE_WAZUH_ALERTS_PATH"] == "/var/ossec/logs/alerts/alerts.json"
    assert pub["wazuh_source"] == "file"
    assert pub["wazuh_path"] == "/var/ossec/logs/alerts/alerts.json"


def test_save_wazuh_api_source_and_mask_password():
    pub = cs.save_settings({
        "wazuh_source": "api", "wazuh_api_url": "https://wazuh-host:55000",
        "wazuh_api_user": "admin", "wazuh_api_pass": "s3cret-pass-9999",
    })
    assert os.environ["WAZUH_API_URL"] == "https://wazuh-host:55000"
    assert os.environ["WAZUH_API_USER"] == "admin"
    assert os.environ["WAZUH_API_PASS"] == "s3cret-pass-9999"
    assert pub["wazuh_source"] == "api"
    assert pub["wazuh_api_pass_set"] is True
    assert pub["wazuh_api_pass_hint"] == "••••9999"
    assert "s3cret-pass" not in json.dumps(pub)


def test_blank_wazuh_api_pass_keeps_existing():
    cs.save_settings({"wazuh_source": "api", "wazuh_api_url": "https://x",
                       "wazuh_api_pass": "s3cret-pass-9999"})
    cs.save_settings({"wazuh_source": "api", "wazuh_api_url": "https://x", "wazuh_api_pass": ""})
    assert os.environ["WAZUH_API_PASS"] == "s3cret-pass-9999"


def test_switching_wazuh_source_does_not_clear_the_other_sides_config():
    """Unlike the LLM provider (external/local are mutually exclusive), file
    path and API credentials are independent — switching the preferred source
    must not silently wipe the other one's saved config."""
    cs.save_settings({"wazuh_source": "file", "wazuh_path": "/custom/alerts.json"})
    cs.save_settings({"wazuh_source": "api", "wazuh_api_url": "https://wazuh-host:55000",
                       "wazuh_api_user": "admin", "wazuh_api_pass": "pw"})
    pub = cs.public_settings()
    assert pub["wazuh_source"] == "api"
    assert pub["wazuh_path"] == "/custom/alerts.json"          # NOT wiped
    assert os.environ["REDSEE_WAZUH_ALERTS_PATH"] == "/custom/alerts.json"


def test_wazuh_source_defaults_to_file_when_never_set():
    assert cs.public_settings()["wazuh_source"] == "file"


def test_invalid_wazuh_source_falls_back_to_file():
    pub = cs.save_settings({"wazuh_source": "not-a-real-source"})
    assert pub["wazuh_source"] == "file"


def test_wazuh_configured_reflects_source():
    # file mode: no URL needed to be "configured"
    pub = cs.save_settings({"wazuh_source": "file"})
    assert pub["wazuh_configured"] is True
    # api mode: needs a URL to count as configured
    pub = cs.save_settings({"wazuh_source": "api", "wazuh_api_url": ""})
    assert pub["wazuh_configured"] is False
    pub = cs.save_settings({"wazuh_source": "api", "wazuh_api_url": "https://x"})
    assert pub["wazuh_configured"] is True


# ── test_wazuh_connection (network calls — validated offline via mocking) ───

def test_wazuh_connection_requires_url():
    result = cs.test_wazuh_connection({})
    assert result["ok"] is False
    assert "URL" in result["detail"]


def test_wazuh_connection_reports_success(monkeypatch):
    class _Resp:
        status_code = 200

    class _FakeRequests:
        @staticmethod
        def post(url, auth, verify, timeout):
            assert url.endswith("/security/user/authenticate")
            return _Resp()

    import sys
    monkeypatch.setitem(sys.modules, "requests", _FakeRequests)
    result = cs.test_wazuh_connection({"wazuh_api_url": "https://wazuh-host:55000",
                                        "wazuh_api_user": "admin", "wazuh_api_pass": "pw"})
    assert result["ok"] is True


def test_wazuh_connection_reports_auth_rejected(monkeypatch):
    class _Resp:
        status_code = 401

    class _FakeRequests:
        @staticmethod
        def post(url, auth, verify, timeout):
            return _Resp()

    import sys
    monkeypatch.setitem(sys.modules, "requests", _FakeRequests)
    result = cs.test_wazuh_connection({"wazuh_api_url": "https://x", "wazuh_api_user": "a", "wazuh_api_pass": "b"})
    assert result["ok"] is False
    assert "401" in result["detail"] or "rejected" in result["detail"]


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
