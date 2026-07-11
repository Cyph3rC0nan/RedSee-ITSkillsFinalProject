"""
Tests for engine/llm.py

Offline unit tests mock requests.post, so no real network call is ever made.
An optional live smoke test against a local Ollama server is documented but
skipped by default.

Run: PYTHONPATH=. python -m pytest tests/test_llm.py -v
"""
import os

import pytest

import engine.llm as llm
from engine.llm import (
    LLMConfig, Usage, BudgetTracker, LLMClient, LLMError, BudgetExceededError,
    load_llm_config,
)


# ── Helpers ─────────────────────────────────────────────────────────────────

def _config(**overrides):
    defaults = dict(
        base_url="http://localhost:11434/v1",
        model="llama3.1",
        api_key=None,
        max_usd=1.00,
        price_in_per_1k=0.01,
        price_out_per_1k=0.03,
        timeout_sec=120,
    )
    defaults.update(overrides)
    return LLMConfig(**defaults)


def _fake_post_factory(calls, *, status_code=200, body=None, raise_exc=None):
    def fake_post(url, json=None, headers=None, timeout=None):
        calls.append({"url": url, "json": json, "headers": headers, "timeout": timeout})
        if raise_exc:
            raise raise_exc

        class _Resp:
            def __init__(self):
                self.status_code = status_code
                self.text = "error body"

            def json(self):
                return body if body is not None else {}

        return _Resp()

    return fake_post


_OK_BODY_WITH_USAGE = {
    "choices": [{"message": {"content": "hello there", "tool_calls": []}}],
    "usage": {"prompt_tokens": 100, "completion_tokens": 50},
}

_OK_BODY_WITH_TOOL_CALLS = {
    "choices": [{
        "message": {
            "content": None,
            "tool_calls": [
                {"id": "call_1", "type": "function",
                 "function": {"name": "run_sqlmap", "arguments": "{}"}},
            ],
        },
    }],
    "usage": {"prompt_tokens": 10, "completion_tokens": 5},
}

_OK_BODY_NO_USAGE = {
    "choices": [{"message": {"content": "a reply with no usage field", "tool_calls": []}}],
}


# ── load_llm_config ──────────────────────────────────────────────────────────

def test_load_llm_config_raises_when_base_url_missing(monkeypatch):
    monkeypatch.delenv("REDSEE_LLM_BASE_URL", raising=False)
    monkeypatch.setenv("REDSEE_LLM_MODEL", "llama3.1")
    with pytest.raises(LLMError):
        load_llm_config()


def test_load_llm_config_raises_when_model_missing(monkeypatch):
    monkeypatch.setenv("REDSEE_LLM_BASE_URL", "http://localhost:11434/v1")
    monkeypatch.delenv("REDSEE_LLM_MODEL", raising=False)
    with pytest.raises(LLMError):
        load_llm_config()


def test_load_llm_config_reads_all_keys(monkeypatch):
    monkeypatch.setenv("REDSEE_LLM_BASE_URL", "http://localhost:11434/v1")
    monkeypatch.setenv("REDSEE_LLM_MODEL", "llama3.1")
    monkeypatch.setenv("REDSEE_LLM_API_KEY", "")
    monkeypatch.setenv("REDSEE_LLM_MAX_USD", "2.50")
    monkeypatch.setenv("REDSEE_LLM_PRICE_IN_PER_1K", "0.001")
    monkeypatch.setenv("REDSEE_LLM_PRICE_OUT_PER_1K", "0.002")
    monkeypatch.setenv("REDSEE_LLM_TIMEOUT", "45")

    cfg = load_llm_config()
    assert cfg.base_url == "http://localhost:11434/v1"
    assert cfg.model == "llama3.1"
    assert cfg.api_key is None
    assert cfg.max_usd == 2.50
    assert cfg.price_in_per_1k == 0.001
    assert cfg.price_out_per_1k == 0.002
    assert cfg.timeout_sec == 45


# ── Authorization header behavior ───────────────────────────────────────────

def test_no_api_key_means_no_authorization_header(monkeypatch):
    calls = []
    monkeypatch.setattr(llm.requests, "post",
                        _fake_post_factory(calls, body=_OK_BODY_WITH_USAGE))

    cfg = _config(api_key=None)
    client = LLMClient(cfg, BudgetTracker(cfg))
    client.chat([{"role": "user", "content": "hi"}])

    assert len(calls) == 1
    assert "Authorization" not in calls[0]["headers"]


def test_api_key_configured_sends_bearer_header(monkeypatch):
    calls = []
    monkeypatch.setattr(llm.requests, "post",
                        _fake_post_factory(calls, body=_OK_BODY_WITH_USAGE))

    cfg = _config(api_key="sk-super-secret-test-key")
    client = LLMClient(cfg, BudgetTracker(cfg))
    client.chat([{"role": "user", "content": "hi"}])

    assert len(calls) == 1
    assert calls[0]["headers"].get("Authorization") == "Bearer sk-super-secret-test-key"


# ── Tracker updates from a mocked response ──────────────────────────────────

def test_response_updates_tracker_tokens_and_cost(monkeypatch):
    calls = []
    monkeypatch.setattr(llm.requests, "post",
                        _fake_post_factory(calls, body=_OK_BODY_WITH_USAGE))

    cfg = _config(price_in_per_1k=0.01, price_out_per_1k=0.03)
    tracker = BudgetTracker(cfg)
    client = LLMClient(cfg, tracker)
    result = client.chat([{"role": "user", "content": "hi"}])

    assert result["text"] == "hello there"
    assert tracker.usage.input_tokens == 100
    assert tracker.usage.output_tokens == 50
    expected_cost = (100 / 1000.0) * 0.01 + (50 / 1000.0) * 0.03
    assert tracker.usage.cost_usd == pytest.approx(expected_cost)
    assert tracker.usage.calls == 1


def test_missing_usage_falls_back_to_char_estimate(monkeypatch):
    calls = []
    monkeypatch.setattr(llm.requests, "post",
                        _fake_post_factory(calls, body=_OK_BODY_NO_USAGE))

    cfg = _config()
    tracker = BudgetTracker(cfg)
    client = LLMClient(cfg, tracker)
    client.chat([{"role": "user", "content": "some input text"}])

    assert tracker.usage.input_tokens > 0
    assert tracker.usage.output_tokens > 0
    assert tracker.usage.calls == 1


# ── Budget enforcement ───────────────────────────────────────────────────────

def test_over_budget_tracker_raises_and_makes_zero_http_calls(monkeypatch):
    calls = []
    monkeypatch.setattr(llm.requests, "post",
                        _fake_post_factory(calls, body=_OK_BODY_WITH_USAGE))

    cfg = _config(max_usd=1.00)
    tracker = BudgetTracker(cfg)
    # Simulate a tracker that's already over budget from prior calls this scan.
    tracker.usage.cost_usd = 1.50

    client = LLMClient(cfg, tracker)
    with pytest.raises(BudgetExceededError):
        client.chat([{"role": "user", "content": "hi"}])

    assert calls == [], "no HTTP call may happen once the budget is exhausted"


def test_cap_reached_after_call_blocks_the_next_call(monkeypatch):
    calls = []
    monkeypatch.setattr(llm.requests, "post",
                        _fake_post_factory(calls, body=_OK_BODY_WITH_USAGE))

    cfg = _config(max_usd=0.001, price_in_per_1k=1.0, price_out_per_1k=1.0)
    tracker = BudgetTracker(cfg)
    client = LLMClient(cfg, tracker)

    client.chat([{"role": "user", "content": "hi"}])
    assert len(calls) == 1
    assert tracker.remaining_usd() <= 0

    with pytest.raises(BudgetExceededError):
        client.chat([{"role": "user", "content": "hi again"}])
    assert len(calls) == 1, "second call must be refused before hitting the network"


# ── Tool definitions ─────────────────────────────────────────────────────────

def test_tools_definition_appears_in_request_body(monkeypatch):
    calls = []
    monkeypatch.setattr(llm.requests, "post",
                        _fake_post_factory(calls, body=_OK_BODY_WITH_USAGE))

    tools = [{"type": "function", "function": {"name": "run_sqlmap", "parameters": {}}}]
    cfg = _config()
    client = LLMClient(cfg, BudgetTracker(cfg))
    client.chat([{"role": "user", "content": "hi"}], tools=tools)

    assert calls[0]["json"]["tools"] == tools


def test_no_tools_means_no_tools_key_in_body(monkeypatch):
    calls = []
    monkeypatch.setattr(llm.requests, "post",
                        _fake_post_factory(calls, body=_OK_BODY_WITH_USAGE))

    cfg = _config()
    client = LLMClient(cfg, BudgetTracker(cfg))
    client.chat([{"role": "user", "content": "hi"}])

    assert "tools" not in calls[0]["json"]


def test_tool_calls_in_response_are_normalized(monkeypatch):
    calls = []
    monkeypatch.setattr(llm.requests, "post",
                        _fake_post_factory(calls, body=_OK_BODY_WITH_TOOL_CALLS))

    cfg = _config()
    client = LLMClient(cfg, BudgetTracker(cfg))
    result = client.chat([{"role": "user", "content": "hi"}])

    assert result["tool_calls"] == _OK_BODY_WITH_TOOL_CALLS["choices"][0]["message"]["tool_calls"]
    assert result["raw"] == _OK_BODY_WITH_TOOL_CALLS


# ── HTTP / protocol failures ─────────────────────────────────────────────────

def test_non_200_status_raises_llm_error(monkeypatch):
    calls = []
    monkeypatch.setattr(llm.requests, "post",
                        _fake_post_factory(calls, status_code=500, body={}))

    cfg = _config()
    client = LLMClient(cfg, BudgetTracker(cfg))
    with pytest.raises(LLMError):
        client.chat([{"role": "user", "content": "hi"}])


def test_network_exception_raises_llm_error(monkeypatch):
    import requests as _requests
    calls = []
    monkeypatch.setattr(
        llm.requests, "post",
        _fake_post_factory(calls, raise_exc=_requests.exceptions.ConnectionError("refused")),
    )

    cfg = _config()
    client = LLMClient(cfg, BudgetTracker(cfg))
    with pytest.raises(LLMError):
        client.chat([{"role": "user", "content": "hi"}])


# ── Optional live smoke test (skipped by default) ───────────────────────────
# To exercise against a real local Ollama server:
#   1. ollama pull llama3.1 && ollama serve
#   2. export REDSEE_LLM_LIVE_TEST=1
#   3. REDSEE_LLM_BASE_URL=http://localhost:11434/v1 REDSEE_LLM_MODEL=llama3.1 \
#        PYTHONPATH=. python -m pytest tests/test_llm.py -v -k live_ollama

@pytest.mark.skipif(not os.environ.get("REDSEE_LLM_LIVE_TEST"),
                    reason="set REDSEE_LLM_LIVE_TEST=1 to run against a real local Ollama server")
def test_live_ollama_smoke():
    cfg = load_llm_config()
    tracker = BudgetTracker(cfg)
    client = LLMClient(cfg, tracker)
    result = client.chat([{"role": "user", "content": "Reply with exactly: pong"}])
    assert result["text"]


if __name__ == "__main__":
    import types

    class _MP:
        """Minimal monkeypatch stand-in for __main__ runs (setattr/setenv/delenv + undo)."""
        def __init__(self):
            self._undo = []

        def setattr(self, obj, name, value):
            self._undo.append(("attr", obj, name, getattr(obj, name)))
            setattr(obj, name, value)

        def setenv(self, name, value):
            self._undo.append(("env", name, os.environ.get(name)))
            os.environ[name] = value

        def delenv(self, name, raising=False):
            self._undo.append(("env", name, os.environ.get(name)))
            os.environ.pop(name, None)

        def undo(self):
            for entry in reversed(self._undo):
                if entry[0] == "attr":
                    _, obj, name, old = entry
                    setattr(obj, name, old)
                else:
                    _, name, old = entry
                    if old is None:
                        os.environ.pop(name, None)
                    else:
                        os.environ[name] = old

    def _run(fn):
        mp = _MP()
        try:
            fn(mp)
            print(f"  ok  {fn.__name__}")
        finally:
            mp.undo()

    for _fn in (
        test_load_llm_config_raises_when_base_url_missing,
        test_load_llm_config_raises_when_model_missing,
        test_load_llm_config_reads_all_keys,
        test_no_api_key_means_no_authorization_header,
        test_api_key_configured_sends_bearer_header,
        test_response_updates_tracker_tokens_and_cost,
        test_missing_usage_falls_back_to_char_estimate,
        test_over_budget_tracker_raises_and_makes_zero_http_calls,
        test_cap_reached_after_call_blocks_the_next_call,
        test_tools_definition_appears_in_request_body,
        test_no_tools_means_no_tools_key_in_body,
        test_tool_calls_in_response_are_normalized,
        test_non_200_status_raises_llm_error,
        test_network_exception_raises_llm_error,
    ):
        _run(_fn)
    print("All LLM unit tests passed!")
