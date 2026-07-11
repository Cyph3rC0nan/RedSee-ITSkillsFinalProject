"""
Tests for engine/xss_agent.py — the reflected-XSS agent loop.

Fully offline: the LLM client is a scripted fake and run_in_sandbox is
monkeypatched, so no Docker, no network, and no real Dalfox ever run.

Run: PYTHONPATH=. python -m pytest tests/test_xss_agent.py -v
"""
import json

import pytest

import engine.xss_agent as xss
from engine.xss_agent import (
    run_xss_agent, XssAgentResult, XssCandidate,
    _build_dalfox_argv, _assert_no_forbidden_flags, _parse_dalfox_output,
    _sanitize_cookie, _FORBIDDEN_LITERAL, RUN_DALFOX_TOOL,
)
from engine.scope import ScopeConfig
from engine.llm import LLMConfig, BudgetTracker
from schemas import Endpoint


# ── Fixtures / fakes ────────────────────────────────────────────────────────

IN_SCOPE_URL = "http://redsees.com:8080/vulnerabilities/xss_r/?name=test"
OUT_SCOPE_URL = "http://evil.com/vulnerabilities/xss_r/?name=test"

# REAL Dalfox v2.13.0 positive shape (DVWA reflected XSS, security=low): a [POC]
# stdout line + a "[V] Triggered XSS Payload" stderr line + a reflected source line.
POSITIVE_STDOUT = """\
[I] Reflected name param => 42 chars
[I] Reflected Payloads: 1
[V] Triggered XSS Payload (found DOM Object): <svg/onload=alert(1)>
    47 line: 			<pre>Hello <svg/onload=alert(1)></pre>
[POC][V][GET][inHTML-none(1)] http://redsees.com:8080/vulnerabilities/xss_r/?name=<svg/onload=alert(1)>
[*] [duration: 3.21s][issues: 1] Finish Scan!
"""

# REAL clean run — Dalfox actually ran, nothing confirmed.
CLEAN_STDOUT = """\
[I] Testing URL: http://redsees.com:8080/vulnerabilities/xss_r/?name=test
[I] Reflected name param => 9 chars
[*] [duration: 2.10s][issues: 0] Finish Scan!
"""

# Mentions XSS + a reflected parameter but NO [POC]/[V] confirmation — the
# negative guard: this must NEVER be read as injectable.
NEGATIVE_GUARD_STDOUT = """\
[I] Reflected name param => 9 chars
[I] Found a reflection but the XSS payload was filtered / HTML-encoded
[W] Weak protection observed; not a confirmed XSS
[*] [duration: 1.50s][issues: 0] Finish Scan!
"""


def _scope():
    return ScopeConfig(
        target_url="http://redsees.com:8080/",
        allowed_hosts=["redsees.com"],
        authorized=True,
    )


def _tracker(max_usd=100.0):
    cfg = LLMConfig(base_url="http://x/v1", model="m", max_usd=max_usd,
                    price_in_per_1k=0.0, price_out_per_1k=0.0)
    return BudgetTracker(cfg)


def _tool_reply(url, param=None, call_id="call_1"):
    args = {"url": url}
    if param is not None:
        args["param"] = param
    return {
        "text": "",
        "tool_calls": [{
            "id": call_id, "type": "function",
            "function": {"name": "run_dalfox", "arguments": json.dumps(args)},
        }],
        "raw": {},
    }


def _final_reply(text="done, all endpoints tested"):
    return {"text": text, "tool_calls": [], "raw": {}}


class FakeLLMClient:
    """Scripted chat client that shares a real BudgetTracker with the agent."""

    def __init__(self, replies=None, tracker=None, default_reply=None):
        self._replies = list(replies or [])
        self.tracker = tracker or _tracker()
        self.default_reply = default_reply or _final_reply()
        self.chat_calls = 0
        self.tools_seen = []

    def chat(self, messages, tools=None, max_tokens=1024):
        self.chat_calls += 1
        self.tools_seen.append(tools)
        self.tracker.check_before_call()
        self.tracker.record(1, 1)
        if self._replies:
            return self._replies.pop(0)
        return self.default_reply


def _fake_sandbox(calls, stdout, *, stderr="", exit_code=0, timed_out=False):
    from engine.sandbox import SandboxResult

    def fake(argv, *, target_url, config, timeout_sec=180, **kwargs):
        calls.append({"argv": list(argv), "target_url": target_url, "timeout": timeout_sec})
        return SandboxResult(exit_code=exit_code, stdout=stdout, stderr=stderr,
                             timed_out=timed_out, target_ip="10.0.0.9")

    return fake


def _raising_sandbox(calls, message="isolation self-test FAILED — target_unreachable=7"):
    from engine.sandbox import SandboxError

    def fake(argv, *, target_url, config, timeout_sec=180, **kwargs):
        calls.append({"argv": list(argv), "target_url": target_url})
        raise SandboxError(message)

    return fake


def _endpoint(url=IN_SCOPE_URL, method="GET", inputs=("name",)):
    return Endpoint(url=url, method=method, form_action=None,
                    inputs=list(inputs), cookies_needed=[], endpoint_type="page")


# ── Parser: positive / clean / negative-guard (source of truth) ─────────────

def test_parse_positive_fixture():
    parsed = _parse_dalfox_output(POSITIVE_STDOUT)
    assert parsed["injectable"] is True
    assert parsed["parameter"] == "name"
    assert parsed["context"] == "inHTML-none(1)"
    assert parsed["payload"] and "svg" in parsed["payload"].lower()
    assert "[POC]" in parsed["evidence"]


def test_parse_clean_fixture():
    parsed = _parse_dalfox_output(CLEAN_STDOUT)
    assert parsed["injectable"] is False
    assert parsed["payload"] is None
    assert parsed["evidence"] == ""


def test_parse_negative_guard_reflection_without_poc_is_not_injectable():
    parsed = _parse_dalfox_output(NEGATIVE_GUARD_STDOUT)
    assert parsed["injectable"] is False, "reflection/XSS mention without [POC]/[V] must not confirm"


def test_parse_only_poc_or_v_confirm_never_bare_xss_mention():
    # The banner/help text mentions "XSS scanner" — must not be a confirmation.
    banner = "Dalfox v2.13.0\nPowerful open-source XSS scanner and utility.\n[*] Finish Scan!"
    assert _parse_dalfox_output(banner)["injectable"] is False
    # A [V] Triggered line alone (stderr) confirms even without a [POC] line.
    v_only = "[V] Triggered XSS Payload (found dialog in headless)\n[*] [issues: 1] Finish Scan!"
    assert _parse_dalfox_output(v_only)["injectable"] is True


# ── argv builder / forbidden-flag guard (detection-only) ────────────────────

def test_detection_only_base_profile_argv():
    argv = _build_dalfox_argv(IN_SCOPE_URL)
    assert argv[:3] == ["dalfox", "url", IN_SCOPE_URL]
    assert "--no-color" in argv
    assert "--format" in argv and "plain" in argv
    for bad in _FORBIDDEN_LITERAL:
        assert bad not in argv


def test_forbidden_flag_assertion_trips():
    for bad in ("--blind", "-b", "--exploit", "--remote-payloads",
                "--custom-payload", "-o", "--output", "--cookie-from-raw"):
        with pytest.raises(AssertionError):
            _assert_no_forbidden_flags(["dalfox", "url", "http://h/x", bad, "x"])
    # A fully harness-built argv (param + cookie) is always clean.
    _assert_no_forbidden_flags(
        _build_dalfox_argv("http://h/x?name=1", param="name", auth_cookie="PHPSESSID=a; security=low"))


def test_param_focus_added_as_p_flag():
    argv = _build_dalfox_argv(IN_SCOPE_URL, param="name")
    assert "-p" in argv and argv[argv.index("-p") + 1] == "name"


def test_sanitize_cookie_accepts_safe_rejects_dangerous():
    assert _sanitize_cookie("PHPSESSID=abc123; security=low") == "PHPSESSID=abc123; security=low"
    assert _sanitize_cookie("") is None
    assert _sanitize_cookie(None) is None
    assert _sanitize_cookie("-b http://evil") is None        # flag-like
    assert _sanitize_cookie("a=b\nc=d") is None               # newline injection
    assert _sanitize_cookie("x" * 5000) is None               # too long


def test_tool_schema_exposes_only_url_param_note():
    props = RUN_DALFOX_TOOL["function"]["parameters"]["properties"]
    assert set(props) == {"url", "param", "note"}
    assert RUN_DALFOX_TOOL["function"]["parameters"]["required"] == ["url"]


# ── Loop: model-driven confirmation ─────────────────────────────────────────

def test_model_confirms_injectable_is_done(monkeypatch):
    calls = []
    monkeypatch.setattr(xss, "run_in_sandbox", _fake_sandbox(calls, POSITIVE_STDOUT))

    client = FakeLLMClient(replies=[_tool_reply(IN_SCOPE_URL, param="name"), _final_reply()])
    result = run_xss_agent([_endpoint()], scope_config=_scope(), llm_client=client)

    assert isinstance(result, XssAgentResult)
    assert len(calls) == 1                          # confirmed once, completion skips it
    injectable = [c for c in result.candidates if c.injectable]
    assert len(injectable) == 1
    assert injectable[0].parameter == "name"
    assert injectable[0].context == "inHTML-none(1)"
    assert injectable[0].payload and "svg" in injectable[0].payload.lower()
    assert injectable[0].status == "injectable"
    assert result.stopped_reason == "done"


def test_clean_scan_yields_no_injectable(monkeypatch):
    calls = []
    monkeypatch.setattr(xss, "run_in_sandbox", _fake_sandbox(calls, CLEAN_STDOUT))

    client = FakeLLMClient(replies=[_tool_reply(IN_SCOPE_URL), _final_reply()])
    result = run_xss_agent([_endpoint()], scope_config=_scope(), llm_client=client)

    assert result.candidates
    assert not any(c.injectable for c in result.candidates)
    assert all(c.status == "clean" for c in result.candidates)
    assert result.stopped_reason == "done"


def test_stdout_and_stderr_are_both_parsed(monkeypatch):
    # Real Dalfox puts [POC] on stdout and [V] on stderr — the agent must combine them.
    calls = []
    poc_stdout = ("[POC][V][GET][inHTML-none(1)] "
                  "http://redsees.com:8080/vulnerabilities/xss_r/?name=<svg/onload=alert(1)>")
    v_stderr = "[V] Triggered XSS Payload (found DOM Object): <svg/onload=alert(1)>"
    monkeypatch.setattr(xss, "run_in_sandbox",
                        _fake_sandbox(calls, poc_stdout, stderr=v_stderr))

    client = FakeLLMClient(replies=[_tool_reply(IN_SCOPE_URL), _final_reply()])
    result = run_xss_agent([_endpoint()], scope_config=_scope(), llm_client=client)

    injectable = [c for c in result.candidates if c.injectable]
    assert injectable and injectable[0].payload and "svg" in injectable[0].payload.lower()


# ── Loop: out of scope, sandbox error ───────────────────────────────────────

def test_out_of_scope_url_is_not_scanned(monkeypatch):
    calls = []
    monkeypatch.setattr(xss, "run_in_sandbox", _fake_sandbox(calls, POSITIVE_STDOUT))

    client = FakeLLMClient(replies=[_tool_reply(OUT_SCOPE_URL), _final_reply()])
    result = run_xss_agent([_endpoint(url=OUT_SCOPE_URL)], scope_config=_scope(),
                           llm_client=client)

    assert calls == [], "out-of-scope URL must never reach the sandbox"
    steps = [s for s in result.transcript if s.get("action") == "run_dalfox"]
    assert steps and all(s["status"] == "out_of_scope" for s in steps)
    assert not any(c.injectable for c in result.candidates)


def test_sandbox_error_is_error_not_clean(monkeypatch):
    calls = []
    monkeypatch.setattr(xss, "run_in_sandbox", _raising_sandbox(calls))

    client = FakeLLMClient(replies=[_tool_reply(IN_SCOPE_URL), _final_reply()])
    result = run_xss_agent([_endpoint()], scope_config=_scope(), llm_client=client)

    assert result.candidates
    assert all(c.status == "error" for c in result.candidates)
    assert not any(c.status == "clean" for c in result.candidates)   # NOT clean
    assert not any(c.injectable for c in result.candidates)          # NOT a finding
    assert all(c.error and "self-test" in c.error.lower() for c in result.candidates)


def test_sandbox_timeout_is_error_not_clean(monkeypatch):
    calls = []
    monkeypatch.setattr(xss, "run_in_sandbox",
                        _fake_sandbox(calls, CLEAN_STDOUT, timed_out=True))

    client = FakeLLMClient(replies=[_tool_reply(IN_SCOPE_URL), _final_reply()])
    result = run_xss_agent([_endpoint()], scope_config=_scope(), llm_client=client)

    assert any(c.status == "error" for c in result.candidates)
    assert not any(c.status == "clean" for c in result.candidates)


# ── auth cookie threading ───────────────────────────────────────────────────

def test_auth_cookie_threaded_into_dalfox_argv(monkeypatch):
    calls = []
    monkeypatch.setattr(xss, "run_in_sandbox", _fake_sandbox(calls, CLEAN_STDOUT))

    cookie = "PHPSESSID=deadbeef; security=low"
    client = FakeLLMClient(replies=[_tool_reply(IN_SCOPE_URL), _final_reply()])
    run_xss_agent([_endpoint()], scope_config=_scope(), llm_client=client,
                  auth_cookie=cookie)

    assert calls
    argv = calls[0]["argv"]
    assert "--cookie" in argv
    assert argv[argv.index("--cookie") + 1] == cookie


def test_no_cookie_means_no_cookie_flag(monkeypatch):
    calls = []
    monkeypatch.setattr(xss, "run_in_sandbox", _fake_sandbox(calls, CLEAN_STDOUT))

    client = FakeLLMClient(replies=[_tool_reply(IN_SCOPE_URL), _final_reply()])
    run_xss_agent([_endpoint()], scope_config=_scope(), llm_client=client)

    assert calls and "--cookie" not in calls[0]["argv"]


# ── Deterministic completion pass ───────────────────────────────────────────

def test_completion_pass_catches_when_model_idle(monkeypatch):
    # Model makes NO tool call (weak model) — the completion pass must scan and
    # catch the injectable endpoint; stopped_reason completed_by_ladder.
    calls = []
    monkeypatch.setattr(xss, "run_in_sandbox", _fake_sandbox(calls, POSITIVE_STDOUT))

    client = FakeLLMClient(replies=[_final_reply("I think it's fine")])
    result = run_xss_agent([_endpoint()], scope_config=_scope(), llm_client=client)

    assert len(calls) == 1
    assert result.stopped_reason == "completed_by_ladder"
    injectable = [c for c in result.candidates if c.injectable]
    assert injectable and injectable[0].parameter == "name"


def test_completion_pass_all_clean_no_finding(monkeypatch):
    calls = []
    monkeypatch.setattr(xss, "run_in_sandbox", _fake_sandbox(calls, CLEAN_STDOUT))

    client = FakeLLMClient(replies=[_final_reply("nothing to do")])
    result = run_xss_agent([_endpoint()], scope_config=_scope(), llm_client=client)

    assert result.candidates
    assert not any(c.injectable for c in result.candidates)
    assert result.stopped_reason == "done"          # nothing confirmed, model concluded


def test_scans_bounded_by_per_endpoint_cap(monkeypatch):
    # Model hammers the same endpoint forever; runs are capped.
    calls = []
    monkeypatch.setattr(xss, "run_in_sandbox", _fake_sandbox(calls, CLEAN_STDOUT))

    client = FakeLLMClient(default_reply=_tool_reply(IN_SCOPE_URL, call_id="loop"))
    result = run_xss_agent([_endpoint()], max_iterations=10, scope_config=_scope(),
                           llm_client=client)

    assert len(calls) <= xss._MAX_XSS_RUNS_PER_ENDPOINT
    assert any("scan ceiling" in s.get("summary", "").lower() for s in result.transcript)


# ── Budget cap ──────────────────────────────────────────────────────────────

def test_budget_stop_no_scan_no_completion(monkeypatch):
    calls = []
    monkeypatch.setattr(xss, "run_in_sandbox", _fake_sandbox(calls, POSITIVE_STDOUT))

    tracker = _tracker(max_usd=1.0)
    tracker.usage.cost_usd = 5.0  # already over budget before the run starts
    client = FakeLLMClient(replies=[_tool_reply(IN_SCOPE_URL)], tracker=tracker)

    result = run_xss_agent([_endpoint()], scope_config=_scope(), llm_client=client)

    assert result.stopped_reason == "budget"
    assert client.chat_calls == 0
    assert calls == [], "no sandbox execution once over budget"
    assert result.candidates == []
    assert not any(s.get("action") == "completion_pass" for s in result.transcript)


if __name__ == "__main__":
    class _MP:
        def __init__(self):
            self._undo = []

        def setattr(self, obj, name, value):
            self._undo.append((obj, name, getattr(obj, name)))
            setattr(obj, name, value)

        def undo(self):
            for obj, name, old in reversed(self._undo):
                setattr(obj, name, old)

    def _run(fn):
        needs_mp = fn.__code__.co_argcount == 1
        mp = _MP()
        try:
            fn(mp) if needs_mp else fn()
            print(f"  ok  {fn.__name__}")
        finally:
            mp.undo()

    for _fn in (
        test_parse_positive_fixture,
        test_parse_clean_fixture,
        test_parse_negative_guard_reflection_without_poc_is_not_injectable,
        test_parse_only_poc_or_v_confirm_never_bare_xss_mention,
        test_detection_only_base_profile_argv,
        test_forbidden_flag_assertion_trips,
        test_param_focus_added_as_p_flag,
        test_sanitize_cookie_accepts_safe_rejects_dangerous,
        test_tool_schema_exposes_only_url_param_note,
        test_model_confirms_injectable_is_done,
        test_clean_scan_yields_no_injectable,
        test_stdout_and_stderr_are_both_parsed,
        test_out_of_scope_url_is_not_scanned,
        test_sandbox_error_is_error_not_clean,
        test_sandbox_timeout_is_error_not_clean,
        test_auth_cookie_threaded_into_dalfox_argv,
        test_no_cookie_means_no_cookie_flag,
        test_completion_pass_catches_when_model_idle,
        test_completion_pass_all_clean_no_finding,
        test_scans_bounded_by_per_endpoint_cap,
        test_budget_stop_no_scan_no_completion,
    ):
        _run(_fn)
    print("All XSS agent unit tests passed!")
