"""
Console-managed runtime settings — lets the operator configure the LLM (external
BYOK key or a local Ollama endpoint), the per-scan cost cap, a few scan guards,
and the Wazuh SIEM source (local alerts.json path, or the live Wazuh API) from
the dashboard instead of editing `.env` by hand.

How it takes effect WITHOUT a restart: the engine/ingestor read every one of
these keys straight from `os.environ` at call time (`engine.llm.load_llm_config`,
`engine.scope.load_scope_config`, `modules.scan`, `log_ingestor.fetch_wazuh_
alerts`, app.py's `/analyze-logs`) and the console runs as a single gunicorn
worker, so writing `os.environ` here is visible to the very next call. Values
are also persisted to `outputs/settings.json` (0600, gitignored) and re-applied
at startup so they survive a restart. UI-set values win over `.env`.

Secrets (the LLM API key, the Wazuh API password) are stored server-side, never
returned to the browser in full (only a "set" flag + last-4 hint), and never
logged.
"""

import os
import json
import threading
from pathlib import Path

_BASE = Path(__file__).resolve().parent
SETTINGS_PATH = _BASE / "outputs" / "settings.json"
_LOCK = threading.Lock()

# form field -> (env var, kind). kind: str | secret | float | int
_ENV_MAP = {
    "base_url":     ("REDSEE_LLM_BASE_URL", "str"),
    "model":        ("REDSEE_LLM_MODEL", "str"),
    "api_key":      ("REDSEE_LLM_API_KEY", "secret"),
    "max_usd":      ("REDSEE_LLM_MAX_USD", "float"),
    "price_in":     ("REDSEE_LLM_PRICE_IN_PER_1K", "float"),
    "price_out":    ("REDSEE_LLM_PRICE_OUT_PER_1K", "float"),
    "timeout_sec":  ("REDSEE_LLM_TIMEOUT", "int"),
    "rate_limit":   ("REDSEE_RATE_LIMIT", "int"),
    "max_parallel": ("REDSEE_MAX_PARALLEL_SANDBOXES", "int"),
    # Wazuh SIEM source — read by log_ingestor.fetch_wazuh_alerts (api_url/
    # username/password) and app.py's /analyze-logs (REDSEE_WAZUH_ALERTS_PATH,
    # an override on top of log_ingestor.WAZUH_ALERTS_DEFAULT_PATH).
    "wazuh_path":     ("REDSEE_WAZUH_ALERTS_PATH", "str"),
    "wazuh_api_url":  ("WAZUH_API_URL", "str"),
    "wazuh_api_user": ("WAZUH_API_USER", "str"),
    "wazuh_api_pass": ("WAZUH_API_PASS", "secret"),
}
_SECRET_FIELDS = {"api_key", "wazuh_api_pass"}
# "provider" (external | local) and "wazuh_source" (file | api) are UI-only
# state (which panel/fields to emphasize) — neither is read by the engine.


class SettingsError(ValueError):
    """Invalid settings payload (bad number, missing required field, …)."""


# ── persistence ──────────────────────────────────────────────────────────────

def _read_file() -> dict:
    try:
        with open(SETTINGS_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {}


def _write_file(data: dict) -> None:
    SETTINGS_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = SETTINGS_PATH.with_suffix(".json.tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, SETTINGS_PATH)
    try:
        os.chmod(SETTINGS_PATH, 0o600)   # secrets file — owner-only
    except OSError:
        pass


# ── env application ──────────────────────────────────────────────────────────

def _apply_to_env(settings: dict) -> None:
    """Push managed settings into os.environ so the next scan reads them.
    An empty/absent api_key clears it from the environment (local mode)."""
    for field, (env, kind) in _ENV_MAP.items():
        if field not in settings:
            continue
        val = settings[field]
        if val is None or (isinstance(val, str) and val.strip() == ""):
            if kind == "secret":
                os.environ.pop(env, None)   # clear the key
            continue
        os.environ[env] = str(val).strip()


def apply_saved_to_env() -> None:
    """Called once at app startup (after load_env) so persisted UI settings win
    over .env. Silent no-op if nothing has been saved."""
    _apply_to_env(_read_file())


# ── validation + save ────────────────────────────────────────────────────────

def _coerce(field: str, kind: str, raw):
    if kind in ("str", "secret"):
        return "" if raw is None else str(raw).strip()
    s = "" if raw is None else str(raw).strip()
    if s == "":
        return None
    try:
        return float(s) if kind == "float" else int(s)
    except ValueError:
        raise SettingsError(f"{field} must be a {'number' if kind == 'float' else 'whole number'}.")


def save_settings(incoming: dict) -> dict:
    """Validate + persist + apply. `incoming` uses the form field names. A blank
    secret field (api_key, wazuh_api_pass) KEEPS the stored value (so the UI
    never has to re-enter it on every save); switching the LLM provider to
    'local' additionally clears the LLM api_key (no key needed there — this
    does NOT apply to wazuh_api_pass, since file/api Wazuh source config is
    independent and both may legitimately be kept configured at once).
    Returns the public (masked) view."""
    with _LOCK:
        stored = _read_file()
        provider = str(incoming.get("provider", stored.get("provider", "external"))).strip().lower()
        if provider not in ("external", "local"):
            provider = "external"
        wazuh_source = str(incoming.get("wazuh_source", stored.get("wazuh_source", "file"))).strip().lower()
        if wazuh_source not in ("file", "api"):
            wazuh_source = "file"

        out = dict(stored)
        out["provider"] = provider
        out["wazuh_source"] = wazuh_source

        for field, (_env, kind) in _ENV_MAP.items():
            if field in _SECRET_FIELDS:
                continue  # handled below (blank keeps existing)
            if field in incoming:
                out[field] = _coerce(field, kind, incoming.get(field))

        for field in _SECRET_FIELDS:
            submitted = incoming.get(field)
            if submitted is not None and str(submitted).strip() != "":
                out[field] = str(submitted).strip()
            # else: keep whatever was stored
        if provider == "local":
            out["api_key"] = ""

        # Numeric sanity
        if out.get("max_usd") is not None and out["max_usd"] < 0:
            raise SettingsError("Cost cap must be 0 or more.")
        if out.get("timeout_sec") is not None and out["timeout_sec"] <= 0:
            raise SettingsError("Timeout must be a positive number of seconds.")

        _write_file(out)
        _apply_to_env(out)
        return public_settings()


# ── read-back for the UI ─────────────────────────────────────────────────────

def _mask(key: str) -> str:
    key = key or ""
    if len(key) <= 4:
        return "••••"
    return "••••" + key[-4:]


def public_settings() -> dict:
    """The current EFFECTIVE config (what the next scan/ingest would use), read
    from os.environ, with secrets masked. provider/wazuh_source are UI-state
    read from the saved file (provider falls back to a base-URL heuristic when
    never explicitly set; wazuh_source defaults to "file")."""
    stored = _read_file()
    eff = {}
    for field, (env, kind) in _ENV_MAP.items():
        raw = os.environ.get(env, "")
        if kind == "secret":
            continue
        eff[field] = raw

    base = eff.get("base_url", "")
    api_key = os.environ.get("REDSEE_LLM_API_KEY", "")
    provider = stored.get("provider")
    if provider not in ("external", "local"):
        looks_local = any(h in base for h in ("localhost", "127.0.0.1", "11434", "host.docker.internal"))
        provider = "local" if (looks_local and not api_key) else ("external" if base else "external")

    wazuh_source = stored.get("wazuh_source")
    if wazuh_source not in ("file", "api"):
        wazuh_source = "file"
    wazuh_api_pass = os.environ.get("WAZUH_API_PASS", "")

    return {
        "provider": provider,
        "base_url": eff.get("base_url", ""),
        "model": eff.get("model", ""),
        "api_key_set": bool(api_key),
        "api_key_hint": _mask(api_key) if api_key else "",
        "max_usd": eff.get("max_usd", ""),
        "price_in": eff.get("price_in", ""),
        "price_out": eff.get("price_out", ""),
        "timeout_sec": eff.get("timeout_sec", ""),
        "rate_limit": eff.get("rate_limit", ""),
        "max_parallel": eff.get("max_parallel", ""),
        "configured": bool(eff.get("base_url") and eff.get("model")),
        "wazuh_source": wazuh_source,
        "wazuh_path": eff.get("wazuh_path", ""),
        "wazuh_api_url": eff.get("wazuh_api_url", ""),
        "wazuh_api_user": eff.get("wazuh_api_user", ""),
        "wazuh_api_pass_set": bool(wazuh_api_pass),
        "wazuh_api_pass_hint": _mask(wazuh_api_pass) if wazuh_api_pass else "",
        "wazuh_configured": bool(eff.get("wazuh_api_url")) if wazuh_source == "api" else True,
    }


def test_connection(incoming: dict) -> dict:
    """Reachability check for the endpoint being configured — a GET to
    {base_url}/models (cheap, non-billable). Uses the submitted values, falling
    back to the stored key when the field is left blank. Never persists."""
    import requests

    base = str(incoming.get("base_url", "") or os.environ.get("REDSEE_LLM_BASE_URL", "")).strip().rstrip("/")
    if not base:
        return {"ok": False, "detail": "Set a base URL first."}
    provider = str(incoming.get("provider", "external")).strip().lower()
    key = str(incoming.get("api_key", "")).strip()
    if not key and provider != "local":
        key = os.environ.get("REDSEE_LLM_API_KEY", "")

    headers = {}
    if key:
        headers["Authorization"] = f"Bearer {key}"
    try:
        r = requests.get(f"{base}/models", headers=headers, timeout=10)
    except requests.exceptions.RequestException as exc:
        return {"ok": False, "detail": f"Could not reach {base}: {exc}"}

    if r.status_code == 200:
        n = None
        try:
            body = r.json()
            data = body.get("data") if isinstance(body, dict) else None
            n = len(data) if isinstance(data, list) else None
        except ValueError:
            pass
        return {"ok": True, "detail": f"Reachable — {n} model(s) available." if n is not None else "Reachable."}
    if r.status_code in (401, 403):
        return {"ok": False, "detail": f"Reached the endpoint but auth was rejected (HTTP {r.status_code}). Check the API key."}
    return {"ok": False, "detail": f"Endpoint returned HTTP {r.status_code}."}


def test_wazuh_connection(incoming: dict) -> dict:
    """Reachability + auth check for the Wazuh API being configured — POSTs to
    {url}/security/user/authenticate, the same endpoint log_ingestor.
    fetch_wazuh_alerts uses. Uses the submitted values, falling back to the
    stored ones when a field is left blank. Never persists, never fetches real
    alerts (this only proves the credentials/URL work, same "cheap check"
    philosophy as test_connection above). verify=False matches fetch_wazuh_
    alerts' existing behavior — Wazuh installs commonly use a self-signed cert."""
    import requests

    url = str(incoming.get("wazuh_api_url", "") or os.environ.get("WAZUH_API_URL", "")).strip().rstrip("/")
    if not url:
        return {"ok": False, "detail": "Set a Wazuh API URL first."}
    user = str(incoming.get("wazuh_api_user", "") or os.environ.get("WAZUH_API_USER", "")).strip()
    pw = str(incoming.get("wazuh_api_pass", "")).strip() or os.environ.get("WAZUH_API_PASS", "")

    try:
        r = requests.post(f"{url}/security/user/authenticate",
                           auth=(user, pw), verify=False, timeout=10)
    except requests.exceptions.RequestException as exc:
        return {"ok": False, "detail": f"Could not reach {url}: {exc}"}

    if r.status_code == 200:
        return {"ok": True, "detail": "Reachable — authentication succeeded."}
    if r.status_code in (401, 403):
        return {"ok": False, "detail": f"Reached the API but authentication was rejected "
                f"(HTTP {r.status_code}). Check the username/password."}
    return {"ok": False, "detail": f"Wazuh API returned HTTP {r.status_code}."}
