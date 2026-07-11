"""
Tests for engine/agent.py — the SQLi agent loop.

Fully offline: the LLM client is a scripted fake and run_in_sandbox is
monkeypatched, so no Docker, no network, and no real sqlmap ever run.

Run: PYTHONPATH=. python -m pytest tests/test_agent.py -v
"""
import json

import pytest

import engine.agent as agent
from engine.agent import (
    run_sqli_agent, SqliAgentResult, _build_sqlmap_argv, _build_rung_argv,
    _assert_no_forbidden_flags, _parse_sqlmap_output, _FORBIDDEN_LITERAL,
    LADDER, LadderRung, _runnable_rungs, _select_rung,
    default_probe_values, _improve_url_probes, _MAX_PROBE_VALUES,
)
from engine.scope import ScopeConfig
from engine.llm import LLMConfig, BudgetTracker
from schemas import Endpoint


# ── Fixtures / fakes ────────────────────────────────────────────────────────

IN_SCOPE_URL = "http://redsees.com:3000/rest/products/search?q=1"
OUT_SCOPE_URL = "http://evil.com/rest/products/search?q=1"

VULN_STDOUT = """
[INFO] testing connection to the target URL
sqlmap identified the following injection point(s) with a total of 84 HTTP(s) requests:
---
Parameter: q (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: q=1 AND 1=1
---
[INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.0
current user: 'root@localhost'
current database: 'juiceshop'
"""

CLEAN_STDOUT = """
[INFO] testing 'MySQL >= 5.0 boolean-based blind - WHERE, HAVING'
[WARNING] GET parameter 'q' does not seem to be injectable
[INFO] testing 'Generic UNION query'
all tested parameters do not appear to be injectable.
"""

# Real captured sqlmap 1.9.6 output — a genuinely VULNERABLE Juice Shop search run.
VULN_196_STDOUT = """
[INFO] testing connection to the target URL
[INFO] testing if GET parameter 'q' is dynamic
[INFO] GET parameter 'q' appears to be dynamic
[INFO] heuristic (basic) test shows that GET parameter 'q' might be injectable
[INFO] testing for SQL injection on GET parameter 'q'
GET parameter 'q' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 169 HTTP(s) requests:
---
Parameter: q (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: q=apple%' AND 7278=7278 AND 'dmyG%'='dmyG

    Type: time-based blind
    Title: SQLite > 2.0 AND time-based blind (heavy query)
    Payload: q=apple%' AND 6159=LIKE(CHAR(65,66,67),UPPER(HEX(RANDOMBLOB(50000000)))) AND 'lpWn%'='lpWn
---
[INFO] the back-end DBMS is SQLite
back-end DBMS: SQLite
banner: '3.44.2'
"""

# Real captured sqlmap 1.9.6 output — a CLEAN run (nothing injectable).
CLEAN_196_STDOUT = """
[INFO] testing connection to the target URL
[INFO] testing for SQL injection on GET parameter 'q'
[WARNING] GET parameter 'q' does not seem to be injectable
[ERROR] all tested parameters do not appear to be injectable. Try to increase values for '--level'/'--risk' options if you wish to perform more tests.
"""


def _scope():
    return ScopeConfig(
        target_url="http://redsees.com:3000/",
        allowed_hosts=["redsees.com"],
        authorized=True,
    )


def _tracker(max_usd=100.0):
    cfg = LLMConfig(base_url="http://x/v1", model="m", max_usd=max_usd,
                    price_in_per_1k=0.0, price_out_per_1k=0.0)
    return BudgetTracker(cfg)


def _tool_reply(url, data=None, depth=None, probe_value=None, call_id="call_1"):
    args = {"url": url}
    if data:
        args["data"] = data
    if depth is not None:
        args["depth"] = depth
    if probe_value is not None:
        args["probe_value"] = probe_value
    return {
        "text": "",
        "tool_calls": [{
            "id": call_id, "type": "function",
            "function": {"name": "run_sqlmap", "arguments": json.dumps(args)},
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
        # Mirror the real client's budget behavior at a minimal level.
        self.tracker.check_before_call()
        self.tracker.record(1, 1)
        if self._replies:
            return self._replies.pop(0)
        return self.default_reply


def _fake_sandbox(calls, stdout):
    from engine.sandbox import SandboxResult

    def fake(argv, *, target_url, config, timeout_sec=180, **kwargs):
        calls.append({"argv": list(argv), "target_url": target_url, "timeout": timeout_sec})
        return SandboxResult(exit_code=0, stdout=stdout, stderr="",
                             timed_out=False, target_ip="10.0.0.9")

    return fake


def _leveled_sandbox(calls, by_level, default=CLEAN_STDOUT):
    """Fake sandbox whose stdout depends on the --level in the argv (rung-aware)."""
    from engine.sandbox import SandboxResult

    def fake(argv, *, target_url, config, timeout_sec=180, **kwargs):
        calls.append({"argv": list(argv), "target_url": target_url, "timeout": timeout_sec})
        lvl = agent._numeric_flag_value(argv, "--level")
        return SandboxResult(exit_code=0, stdout=by_level.get(lvl, default), stderr="",
                             timed_out=False, target_ip="10.0.0.9")

    return fake


def _u(argv):
    """The -u URL value from a captured argv."""
    return argv[argv.index("-u") + 1] if "-u" in argv else None


def _value_sandbox(calls, injectable_value, param="q"):
    """Fake sandbox that reports injectable ONLY when the tested param equals a value."""
    import urllib.parse
    from engine.sandbox import SandboxResult

    def fake(argv, *, target_url, config, timeout_sec=180, **kwargs):
        calls.append({"argv": list(argv), "target_url": target_url, "timeout": timeout_sec})
        u = _u(argv) or target_url
        q = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(u).query)).get(param)
        stdout = VULN_STDOUT if q == injectable_value else CLEAN_STDOUT
        return SandboxResult(exit_code=0, stdout=stdout, stderr="",
                             timed_out=False, target_ip="10.0.0.9")

    return fake


def _status_sandbox(calls, stdout=CLEAN_STDOUT, exit_code=0, timed_out=False):
    """Fake sandbox with a configurable exit_code / timed_out for status tests."""
    from engine.sandbox import SandboxResult

    def fake(argv, *, target_url, config, timeout_sec=180, **kwargs):
        calls.append({"argv": list(argv), "target_url": target_url})
        return SandboxResult(exit_code=exit_code, stdout=stdout, stderr="",
                             timed_out=timed_out, target_ip="10.0.0.9")

    return fake


def _raising_sandbox(calls, message="isolation self-test FAILED — target_unreachable=7"):
    """Fake sandbox that raises SandboxError (target down / isolation abort)."""
    from engine.sandbox import SandboxError

    def fake(argv, *, target_url, config, timeout_sec=180, **kwargs):
        calls.append({"argv": list(argv), "target_url": target_url})
        raise SandboxError(message)

    return fake


def _endpoint(url=IN_SCOPE_URL, method="GET", inputs=("q",)):
    return Endpoint(url=url, method=method, form_action=None,
                    inputs=list(inputs), cookies_needed=[], endpoint_type="api")


# ── argv builder / forbidden-flag guard (unit) ──────────────────────────────

def test_safe_profile_argv_has_detection_flags_and_no_forbidden():
    argv = _build_sqlmap_argv(IN_SCOPE_URL)
    assert argv[:3] == ["sqlmap", "-u", IN_SCOPE_URL]
    assert "--batch" in argv
    assert "--level=1" in argv
    assert "--risk=1" in argv
    for bad in _FORBIDDEN_LITERAL:
        assert bad not in argv


def test_build_argv_with_data_adds_data_flag():
    argv = _build_sqlmap_argv("http://redsees.com/login", data="user=1&pass=1")
    assert "--data" in argv
    assert "user=1&pass=1" in argv


def test_forbidden_flag_assertion_trips():
    # Destructive/exfil flags are ALWAYS banned — even under the most permissive ceiling.
    for bad in ("--dump", "--os-shell", "--file-read", "--sql-shell", "--eval"):
        with pytest.raises(AssertionError):
            _assert_no_forbidden_flags(["sqlmap", "-u", "x", bad], max_level=5, max_risk=3)
    # level/risk above the CONFIGURED ceiling trip (default ceiling is 3/2).
    with pytest.raises(AssertionError):
        _assert_no_forbidden_flags(["sqlmap", "-u", "x", "--level=5"])
    with pytest.raises(AssertionError):
        _assert_no_forbidden_flags(["sqlmap", "-u", "x", "--risk=3"])
    # a --technique outside {B,E,U,S,T} trips.
    with pytest.raises(AssertionError):
        _assert_no_forbidden_flags(["sqlmap", "-u", "x", "--technique=Q"])
    # at/below the ceiling with an allowed technique is fine.
    _assert_no_forbidden_flags(
        ["sqlmap", "-u", "x", "--level=3", "--risk=2", "--technique=U"])


# ── Ladder shape + ceiling gating ───────────────────────────────────────────

def test_ladder_is_ordered_and_every_rung_is_clean():
    depths = [r.depth for r in LADDER]
    assert depths == list(range(len(LADDER)))          # ordered, contiguous
    levels = [r.level for r in LADDER]
    risks = [r.risk for r in LADDER]
    assert levels == sorted(levels)                    # non-decreasing depth
    assert risks == sorted(risks)
    for r in LADDER:
        argv = _build_rung_argv(IN_SCOPE_URL, r, max_level=5, max_risk=3)
        for bad in _FORBIDDEN_LITERAL:
            assert bad not in argv
        assert f"--level={r.level}" in argv
        assert f"--risk={r.risk}" in argv
        if r.technique:
            assert set(r.technique) <= set("BEUST")


def test_default_ceiling_blocks_aggressive_rung():
    aggressive_depth = LADDER[-1].depth
    default_runnable = _runnable_rungs(3, 2)
    assert aggressive_depth not in [r.depth for r in default_runnable]  # 5/3 rung blocked
    assert all(r.level <= 3 and r.risk <= 2 for r in default_runnable)

    lifted_runnable = _runnable_rungs(5, 3)
    assert aggressive_depth in [r.depth for r in lifted_runnable]       # runnable once lifted

    # A too-high requested depth clamps down to the highest runnable rung.
    assert _select_rung(9, 3, 2).depth == default_runnable[-1].depth
    assert _select_rung(9, 5, 3).depth == aggressive_depth
    assert _select_rung(0, 3, 2).depth == 0


def test_aggressive_rung_argv_only_builds_when_ceiling_lifted():
    aggressive = LADDER[-1]
    assert (aggressive.level, aggressive.risk) == (5, 3)
    # Under the default ceiling the aggressive rung would trip the guard.
    with pytest.raises(AssertionError):
        _build_rung_argv(IN_SCOPE_URL, aggressive)
    # With the ceiling lifted it builds cleanly.
    argv = _build_rung_argv(IN_SCOPE_URL, aggressive, max_level=5, max_risk=3)
    assert "--level=5" in argv and "--risk=3" in argv


# ── sqlmap output parsing (source of truth) ─────────────────────────────────

def test_parse_vulnerable_output():
    parsed = _parse_sqlmap_output(VULN_STDOUT)
    assert parsed["injectable"] is True
    assert parsed["parameter"] == "q"
    assert "boolean-based blind" in parsed["technique"]
    assert "MySQL" in parsed["dbms"]
    assert parsed["evidence"].strip() != ""
    # a confirmed injection is never also an escalation hint.
    assert parsed["escalation_hint"] is False


def test_parse_clean_output():
    parsed = _parse_sqlmap_output(CLEAN_STDOUT)
    assert parsed["injectable"] is False
    # "not injectable" verdict flags that escalating depth may be worthwhile,
    # but must NOT flip injectable to True on its own.
    assert parsed["escalation_hint"] is True


# ── Real sqlmap 1.9.6 verdict format (the actual bug this fixes) ─────────────

def test_parse_real_sqlmap_196_vulnerable():
    parsed = _parse_sqlmap_output(VULN_196_STDOUT)
    assert parsed["injectable"] is True
    assert parsed["parameter"] == "q"
    # both techniques from the Parameter block are captured.
    assert "boolean-based blind" in parsed["technique"]
    assert "time-based blind" in parsed["technique"]
    assert parsed["dbms"] == "SQLite"
    # evidence is the human-verifiable proof block.
    assert "Parameter: q (GET)" in parsed["evidence"]
    assert "Payload:" in parsed["evidence"]
    # a confirmed injection is never also an escalation hint.
    assert parsed["escalation_hint"] is False


def test_parse_real_sqlmap_196_clean():
    parsed = _parse_sqlmap_output(CLEAN_196_STDOUT)
    assert parsed["injectable"] is False
    assert parsed["escalation_hint"] is True
    # nothing fabricated on a clean run.
    assert parsed["parameter"] is None
    assert parsed["dbms"] is None
    assert parsed["technique"] is None


def test_parse_negative_guard_not_injectable_never_positive():
    # The explicit negative guard: an "injectable" substring inside a "not ...
    # injectable" verdict must NEVER be read as a positive result.
    for clean in (
        "[WARNING] GET parameter 'q' does not seem to be injectable",
        "[ERROR] all tested parameters do not appear to be injectable.",
        "parameter 'id' does not seem to be injectable",
        "GET parameter 'q' is not injectable",
    ):
        parsed = _parse_sqlmap_output(clean)
        assert parsed["injectable"] is False, f"false positive on: {clean!r}"
        assert parsed["parameter"] is None


def test_parse_dbms_both_wordings():
    colon = _parse_sqlmap_output(
        "sqlmap identified the following injection point(s)\nback-end DBMS: SQLite\n")
    assert colon["injectable"] is True and colon["dbms"] == "SQLite"

    is_form = _parse_sqlmap_output(
        "sqlmap identified the following injection point(s)\n"
        "[INFO] the back-end DBMS is SQLite\n")
    assert is_form["injectable"] is True and is_form["dbms"] == "SQLite"


# ── Loop: in-scope run uses the safe profile ────────────────────────────────

def test_in_scope_url_runs_safe_profile(monkeypatch):
    calls = []
    monkeypatch.setattr(agent, "run_in_sandbox", _fake_sandbox(calls, VULN_STDOUT))

    client = FakeLLMClient(replies=[_tool_reply(IN_SCOPE_URL), _final_reply()])
    result = run_sqli_agent([_endpoint()], scope_config=_scope(), llm_client=client)

    assert isinstance(result, SqliAgentResult)
    assert len(calls) == 1
    argv = calls[0]["argv"]
    assert "--batch" in argv and "--level=1" in argv and "--risk=1" in argv
    for bad in _FORBIDDEN_LITERAL:
        assert bad not in argv
    # the dead q=1 probe was replaced with a value that returns rows.
    assert "redsees.com" in calls[0]["target_url"]
    assert "q=apple" in calls[0]["target_url"] and "q=1" not in calls[0]["target_url"]
    assert calls[0]["timeout"] == 180

    assert result.stopped_reason == "done"
    assert len(result.candidates) == 1
    cand = result.candidates[0]
    assert cand.injectable is True
    assert cand.parameter == "q"
    assert cand.evidence.strip() != ""


# ── Loop: out-of-scope URL is skipped, loop continues ───────────────────────

def test_out_of_scope_url_is_skipped(monkeypatch):
    calls = []
    monkeypatch.setattr(agent, "run_in_sandbox", _fake_sandbox(calls, VULN_STDOUT))

    client = FakeLLMClient(replies=[
        _tool_reply(OUT_SCOPE_URL, call_id="c1"),   # refused, not run
        _tool_reply(IN_SCOPE_URL, call_id="c2"),    # runs
        _final_reply(),
    ])
    result = run_sqli_agent([_endpoint()], scope_config=_scope(), llm_client=client)

    # sqlmap ran exactly once, only for the in-scope URL.
    assert len(calls) == 1
    assert "redsees.com" in calls[0]["target_url"]
    assert all("evil.com" not in c["target_url"] for c in calls)
    # The out-of-scope attempt was recorded but produced no candidate.
    assert any("out of scope" in step["summary"].lower() for step in result.transcript)
    assert result.stopped_reason == "done"
    assert len(result.candidates) == 1


# ── Loop: clean output yields a non-injectable candidate (no fabrication) ────

def test_clean_output_not_injectable(monkeypatch):
    calls = []
    monkeypatch.setattr(agent, "run_in_sandbox", _fake_sandbox(calls, CLEAN_STDOUT))

    client = FakeLLMClient(replies=[_tool_reply(IN_SCOPE_URL), _final_reply()])
    result = run_sqli_agent([_endpoint()], scope_config=_scope(), llm_client=client)

    # The agent run plus the deterministic completion pass may add clean candidates,
    # but NOTHING is ever fabricated as injectable from clean sqlmap output.
    assert result.candidates
    assert not any(c.injectable for c in result.candidates)
    assert result.stopped_reason == "done"


# ── Loop: bounded by max_iterations ─────────────────────────────────────────

def test_stops_at_max_iterations(monkeypatch):
    calls = []
    monkeypatch.setattr(agent, "run_in_sandbox", _fake_sandbox(calls, CLEAN_STDOUT))

    # default_reply always requests another tool call -> never says "done".
    client = FakeLLMClient(default_reply=_tool_reply(IN_SCOPE_URL, call_id="loop"))
    result = run_sqli_agent([_endpoint()], max_iterations=3,
                            scope_config=_scope(), llm_client=client)

    assert result.stopped_reason == "max_iterations"
    assert result.iterations == 3
    assert client.chat_calls == 3
    # The agent phase plus the deterministic completion pass stay within the cap.
    assert len(calls) <= len(LADDER) * _MAX_PROBE_VALUES


# ── Loop: budget cap stops the run, zero sandbox calls ──────────────────────

def test_budget_stop(monkeypatch):
    calls = []
    monkeypatch.setattr(agent, "run_in_sandbox", _fake_sandbox(calls, VULN_STDOUT))

    tracker = _tracker(max_usd=1.0)
    tracker.usage.cost_usd = 5.0  # already over budget before the run starts
    client = FakeLLMClient(replies=[_tool_reply(IN_SCOPE_URL)], tracker=tracker)

    result = run_sqli_agent([_endpoint()], scope_config=_scope(), llm_client=client)

    assert result.stopped_reason == "budget"
    assert client.chat_calls == 0, "no LLM call once already over budget"
    assert calls == [], "no sandbox execution once over budget"
    assert result.candidates == []


# ── No forbidden flag ever appears across a multi-call run ───────────────────

def test_no_forbidden_flag_in_any_argv(monkeypatch):
    calls = []
    monkeypatch.setattr(agent, "run_in_sandbox", _fake_sandbox(calls, VULN_STDOUT))

    client = FakeLLMClient(replies=[
        _tool_reply(IN_SCOPE_URL, call_id="a"),
        _tool_reply("http://redsees.com:3000/login", data="email=1&password=1", call_id="b"),
        _final_reply(),
    ])
    run_sqli_agent([_endpoint()], approve_dump=False,
                   scope_config=_scope(), llm_client=client)

    assert len(calls) == 2
    for c in calls:
        argv = c["argv"]
        for bad in _FORBIDDEN_LITERAL:
            assert bad not in argv, f"forbidden flag {bad} leaked into argv"
        assert "--dump" not in argv
        assert agent._numeric_flag_value(argv, "--level") <= 2
        assert agent._numeric_flag_value(argv, "--risk") <= 1


# ── Deterministic fallback when the model never tool-calls ───────────────────

def test_fallback_runs_profile_per_endpoint(monkeypatch):
    calls = []
    monkeypatch.setattr(agent, "run_in_sandbox", _fake_sandbox(calls, VULN_STDOUT))

    # Model immediately gives final text with no tool call.
    client = FakeLLMClient(replies=[_final_reply("I think it's fine")])
    endpoints = [
        _endpoint(url="http://redsees.com:3000/rest/products/search?q=1"),
        _endpoint(url="http://redsees.com:3000/rest/user/whoami"),
    ]
    result = run_sqli_agent(endpoints, scope_config=_scope(), llm_client=client)

    # The model tool-called nothing; the completion pass produced every finding.
    assert result.stopped_reason == "completed_by_ladder"
    assert len(calls) == 2  # one safe run per endpoint
    assert len(result.candidates) == 2
    assert all(c.injectable for c in result.candidates)


def test_fallback_skips_out_of_scope_endpoints(monkeypatch):
    calls = []
    monkeypatch.setattr(agent, "run_in_sandbox", _fake_sandbox(calls, VULN_STDOUT))

    client = FakeLLMClient(replies=[_final_reply("nothing to do")])
    endpoints = [
        _endpoint(url=IN_SCOPE_URL),
        _endpoint(url=OUT_SCOPE_URL),  # out of scope -> never run
    ]
    result = run_sqli_agent(endpoints, scope_config=_scope(), llm_client=client)

    assert result.stopped_reason == "completed_by_ladder"
    assert len(calls) == 1
    assert "redsees.com" in calls[0]["target_url"]
    assert all("evil.com" not in c["target_url"] for c in calls)


# ── Agent-driven escalation ─────────────────────────────────────────────────

def test_agent_escalates_when_not_injectable_then_confirms(monkeypatch):
    calls = []
    # rung 0 (level 1) is clean + hints escalation; rung 1 (level 3) confirms.
    monkeypatch.setattr(agent, "run_in_sandbox",
                        _leveled_sandbox(calls, {1: CLEAN_STDOUT, 3: VULN_STDOUT}))

    client = FakeLLMClient(replies=[
        _tool_reply(IN_SCOPE_URL, depth=0, call_id="d0"),
        _tool_reply(IN_SCOPE_URL, depth=1, call_id="d1"),
        _final_reply(),
    ])
    result = run_sqli_agent([_endpoint()], scope_config=_scope(), llm_client=client)

    assert len(calls) == 2
    assert agent._numeric_flag_value(calls[0]["argv"], "--level") == 1
    assert agent._numeric_flag_value(calls[1]["argv"], "--level") == 3

    injectable = [c for c in result.candidates if c.injectable]
    assert len(injectable) == 1
    assert injectable[0].depth == 1
    assert injectable[0].evidence.strip() != ""

    # transcript records the escalation path (depth 0 -> depth 1).
    path = [s["depth"] for s in result.transcript if s.get("action") == "run_sqlmap"]
    assert path == [0, 1]


def test_injectable_at_rung0_does_not_escalate(monkeypatch):
    calls = []
    monkeypatch.setattr(agent, "run_in_sandbox", _fake_sandbox(calls, VULN_STDOUT))

    client = FakeLLMClient(replies=[_tool_reply(IN_SCOPE_URL, depth=0), _final_reply()])
    result = run_sqli_agent([_endpoint()], scope_config=_scope(), llm_client=client)

    assert len(calls) == 1                       # confirmed at baseline, no deeper run
    assert result.candidates[0].injectable is True
    assert result.candidates[0].depth == 0


def test_clean_at_every_rung_yields_no_finding(monkeypatch):
    calls = []
    monkeypatch.setattr(agent, "run_in_sandbox", _fake_sandbox(calls, CLEAN_STDOUT))

    client = FakeLLMClient(replies=[
        _tool_reply(IN_SCOPE_URL, depth=0, call_id="a"),
        _tool_reply(IN_SCOPE_URL, depth=1, call_id="b"),
        _tool_reply(IN_SCOPE_URL, depth=2, call_id="c"),
        _final_reply(),
    ])
    result = run_sqli_agent([_endpoint()], scope_config=_scope(), llm_client=client)

    # Agent phase + completion pass, still bounded by the per-endpoint cap.
    assert len(calls) <= len(LADDER) * _MAX_PROBE_VALUES
    assert not any(c.injectable for c in result.candidates)
    assert all(c.injectable is False for c in result.candidates)
    assert result.stopped_reason == "done"


def test_escalation_capped_per_url(monkeypatch):
    calls = []
    monkeypatch.setattr(agent, "run_in_sandbox", _fake_sandbox(calls, CLEAN_STDOUT))

    # Model keeps hammering the same URL forever; runs are capped at
    # len(LADDER) * _MAX_PROBE_VALUES sqlmap executions for that endpoint.
    cap = len(LADDER) * _MAX_PROBE_VALUES
    client = FakeLLMClient(
        default_reply=_tool_reply(IN_SCOPE_URL, depth=3, call_id="cap"))
    result = run_sqli_agent([_endpoint()], max_iterations=cap + 5,
                            scope_config=_scope(), llm_client=client)

    assert len(calls) == cap
    assert result.stopped_reason == "max_iterations"
    # once the ceiling is hit, further calls are refused (recorded, not run).
    assert any("escalation ceiling" in step["summary"].lower()
               for step in result.transcript)


# ── Deterministic ladder-walk fallback ──────────────────────────────────────

def test_fallback_walks_ladder_and_stops_at_first_injectable(monkeypatch):
    calls = []
    # baseline clean, deeper rung confirms — fallback should climb then stop.
    monkeypatch.setattr(agent, "run_in_sandbox",
                        _leveled_sandbox(calls, {1: CLEAN_STDOUT, 3: VULN_STDOUT}))

    client = FakeLLMClient(replies=[_final_reply("nothing to do")])
    result = run_sqli_agent([_endpoint()], scope_config=_scope(), llm_client=client)

    assert result.stopped_reason == "completed_by_ladder"
    levels = [agent._numeric_flag_value(c["argv"], "--level") for c in calls]
    assert levels == [1, 3]                       # rung 0 then rung 1, then stop
    assert result.candidates[-1].injectable is True
    assert len(calls) <= len(LADDER) * _MAX_PROBE_VALUES


# ── Probe-value selection ────────────────────────────────────────────────────

def test_default_probe_values_by_param_kind():
    assert default_probe_values("q") == ["apple", "a", "test"]
    assert default_probe_values("search") == ["apple", "a", "test"]
    assert default_probe_values("id") == ["1", "2"]
    assert default_probe_values("productid") == ["1", "2"]
    assert default_probe_values("email")[0] == "test@test.com"
    assert default_probe_values("user")[0] == "test@test.com"
    assert default_probe_values("userid") == ["1", "2"]      # id-like beats 'user'
    assert default_probe_values("mystery") == ["1", "apple", "test"]


def test_improve_url_probes_substitutes_weak_only():
    # weak "1" -> deterministic default
    new_url, applied = _improve_url_probes("http://h/s?q=1")
    assert "q=apple" in new_url
    assert applied == [{"parameter": "q", "value": "apple", "source": "default"}]
    # a value that already returns rows is left alone
    _, applied2 = _improve_url_probes("http://h/s?q=apple")
    assert applied2 == []
    # a valid agent-proposed value wins even over a non-weak value
    new_url3, applied3 = _improve_url_probes("http://h/s?q=apple", proposed_value="banana")
    assert "q=banana" in new_url3 and applied3[0]["source"] == "agent"


def test_sanitize_probe_value_accepts_safe_rejects_dangerous():
    assert agent._sanitize_probe_value("apple") == "apple"
    assert agent._sanitize_probe_value("admin@juice-sh.op") == "admin@juice-sh.op"
    assert agent._sanitize_probe_value("apple; DROP TABLE") is None   # space + ';'
    assert agent._sanitize_probe_value("--dump") is None              # flag-like
    assert agent._sanitize_probe_value("a" * 65) is None              # too long
    assert agent._sanitize_probe_value("a b") is None                 # space


def test_weak_value_substituted_and_recorded_in_transcript(monkeypatch):
    calls = []
    monkeypatch.setattr(agent, "run_in_sandbox", _fake_sandbox(calls, VULN_STDOUT))

    client = FakeLLMClient(replies=[_tool_reply(IN_SCOPE_URL), _final_reply()])
    result = run_sqli_agent([_endpoint()], scope_config=_scope(), llm_client=client)

    u = _u(calls[0]["argv"])
    assert "q=apple" in u and "q=1" not in u
    steps = [s for s in result.transcript if s.get("action") == "run_sqlmap"]
    assert steps and steps[0]["probe_value"] == "apple"


def test_agent_valid_probe_value_is_used(monkeypatch):
    calls = []
    monkeypatch.setattr(agent, "run_in_sandbox", _value_sandbox(calls, "banana"))

    client = FakeLLMClient(replies=[
        _tool_reply(IN_SCOPE_URL, probe_value="banana"), _final_reply()])
    result = run_sqli_agent([_endpoint()], scope_config=_scope(), llm_client=client)

    assert "q=banana" in _u(calls[0]["argv"])
    assert result.candidates[0].injectable is True


def test_agent_invalid_probe_value_is_rejected_and_defaults_used(monkeypatch):
    calls = []
    # only the default "apple" returns injectable; the malicious value must not run.
    monkeypatch.setattr(agent, "run_in_sandbox", _value_sandbox(calls, "apple"))

    client = FakeLLMClient(replies=[
        _tool_reply(IN_SCOPE_URL, probe_value="apple'; DROP TABLE users;--"),
        _final_reply()])
    result = run_sqli_agent([_endpoint()], scope_config=_scope(), llm_client=client)

    # the rejected value never reaches the tested URL (the only place a probe value
    # could land) — the harness-owned base flags are fixed and never carry it.
    for c in calls:
        u = _u(c["argv"]) or ""
        assert "DROP" not in u and ";" not in u and " " not in u
    # …and the harness fell back to the deterministic default probe value.
    assert "q=apple" in _u(calls[0]["argv"])
    assert result.candidates[0].injectable is True


def test_no_forced_union_and_default_rungs_pass_no_technique():
    assert all(r.technique != "U" for r in LADDER)          # no forced-UNION rung
    for r in _runnable_rungs(3, 2):                          # default-ceiling rungs
        assert r.technique is None
        argv = _build_rung_argv(IN_SCOPE_URL, r)
        assert agent._string_flag_value(argv, "--technique") is None


def test_fallback_tries_next_probe_value_until_injectable(monkeypatch):
    calls = []
    # clean at value "apple", injectable only at the SECOND default value "a".
    monkeypatch.setattr(agent, "run_in_sandbox", _value_sandbox(calls, "a"))

    client = FakeLLMClient(replies=[_final_reply("nothing to do")])
    result = run_sqli_agent([_endpoint()], scope_config=_scope(), llm_client=client)

    assert result.stopped_reason == "completed_by_ladder"
    probes = [s["probe_value"] for s in result.transcript if s.get("action") == "run_sqlmap"]
    assert "apple" in probes and "a" in probes           # both probe values tried
    assert result.candidates[-1].injectable is True
    assert any(c.injectable and c.evidence.strip() for c in result.candidates)
    assert len(calls) <= len(LADDER) * _MAX_PROBE_VALUES


def test_fallback_all_values_clean_no_finding(monkeypatch):
    calls = []
    # injectable value never matches any probe -> everything comes back clean.
    monkeypatch.setattr(agent, "run_in_sandbox", _value_sandbox(calls, "NEVERMATCHES"))

    client = FakeLLMClient(replies=[_final_reply("nothing to do")])
    result = run_sqli_agent([_endpoint()], scope_config=_scope(), llm_client=client)

    # Nothing confirmed by model OR completion pass, and the model concluded first,
    # so the run resolves to a clean "done" (not completed_by_ladder).
    assert result.stopped_reason == "done"
    assert result.candidates, "each attempted rung still yields a (clean) candidate"
    assert not any(c.injectable for c in result.candidates)   # no fabrication
    assert len(calls) <= len(LADDER) * _MAX_PROBE_VALUES


# ── Task D: completion pass closes the escalation gap ────────────────────────

def test_detection_only_base_profile_excludes_retrieval_and_blocks_auto_exploit():
    # No data-retrieval flags in the fixed base profile — detection stops at the
    # confirmed injection point (no banner/db/user retrieval).
    for retrieval in ("--banner", "--current-db", "--current-user"):
        assert retrieval not in agent._BASE_PROFILE
    # --answers forces "no" so --batch cannot auto-proceed into exploitation.
    answers = agent._string_flag_value(agent._BASE_PROFILE, "--answers") or ""
    assert "exploit=N" in answers and "keep testing=N" in answers
    # every rung's argv is likewise retrieval-free, even at the lifted ceiling.
    for r in LADDER:
        argv = _build_rung_argv(IN_SCOPE_URL, r, max_level=5, max_risk=3)
        for bad in ("--banner", "--current-db", "--current-user", "--dump", "--users"):
            assert bad not in argv


def test_enumeration_flags_are_permanently_forbidden():
    # Data enumeration/retrieval flags trip the guard regardless of ceiling.
    for bad in ("--banner", "--current-db", "--current-user", "--hostname",
                "--users", "--dbs", "--tables", "--columns", "--schema"):
        assert bad in _FORBIDDEN_LITERAL
        with pytest.raises(AssertionError):
            _assert_no_forbidden_flags(["sqlmap", "-u", "x", bad], max_level=5, max_risk=3)


def test_model_clean_then_completion_pass_finds_deep_injection(monkeypatch):
    # The model tool-calls once at a shallow depth, gets a clean result, and STOPS.
    # The completion pass must escalate and surface the deeper injection: a shallow
    # "clean" answer can no longer end detection while permitted combos remain.
    calls = []
    monkeypatch.setattr(agent, "run_in_sandbox",
                        _leveled_sandbox(calls, {1: CLEAN_STDOUT, 3: VULN_STDOUT}))

    client = FakeLLMClient(replies=[
        _tool_reply(IN_SCOPE_URL, depth=0, call_id="shallow"),
        _final_reply("looks clean to me"),
    ])
    result = run_sqli_agent([_endpoint()], scope_config=_scope(), llm_client=client)

    assert result.stopped_reason == "completed_by_ladder"
    injectable = [c for c in result.candidates if c.injectable]
    assert injectable and injectable[0].depth == 1
    levels = [agent._numeric_flag_value(c["argv"], "--level") for c in calls]
    assert 1 in levels and 3 in levels           # shallow rung then the deeper rung
    assert len(calls) <= len(LADDER) * _MAX_PROBE_VALUES


def test_model_confirmation_is_done_and_completion_adds_nothing(monkeypatch):
    calls = []
    monkeypatch.setattr(agent, "run_in_sandbox", _fake_sandbox(calls, VULN_STDOUT))

    client = FakeLLMClient(replies=[_tool_reply(IN_SCOPE_URL, depth=0), _final_reply()])
    result = run_sqli_agent([_endpoint()], scope_config=_scope(), llm_client=client)

    # model confirmed at rung 0 -> "done", and the completion pass skips the
    # already-confirmed endpoint (no extra sandbox runs).
    assert result.stopped_reason == "done"
    assert len(calls) == 1
    assert sum(1 for c in result.candidates if c.injectable) == 1


def test_run_cap_holds_across_agent_and_completion_phases(monkeypatch):
    # A few clean agent runs plus the completion pass must never exceed the cap.
    calls = []
    monkeypatch.setattr(agent, "run_in_sandbox", _fake_sandbox(calls, CLEAN_STDOUT))

    client = FakeLLMClient(replies=[
        _tool_reply(IN_SCOPE_URL, depth=0, call_id="a"),
        _tool_reply(IN_SCOPE_URL, depth=1, call_id="b"),
        _final_reply(),
    ])
    result = run_sqli_agent([_endpoint()], scope_config=_scope(), llm_client=client)

    assert len(calls) <= len(LADDER) * _MAX_PROBE_VALUES
    assert not any(c.injectable for c in result.candidates)
    assert result.stopped_reason == "done"


def test_completion_transcript_records_actual_probe_value(monkeypatch):
    # Every completion-pass run records the probe value the URL ACTUALLY carried,
    # never None while the URL held e.g. q=apple.
    calls = []
    monkeypatch.setattr(agent, "run_in_sandbox", _fake_sandbox(calls, CLEAN_STDOUT))

    client = FakeLLMClient(replies=[_final_reply("nothing to do")])
    result = run_sqli_agent([_endpoint()], scope_config=_scope(), llm_client=client)

    steps = [s for s in result.transcript if s.get("action") == "run_sqlmap"]
    assert steps
    for s in steps:
        assert s["probe_value"] is not None
        assert s["probe_value"] in ("apple", "a")


def test_budget_stop_suppresses_completion_pass(monkeypatch):
    # A budget stop is terminal: the completion pass must NOT run afterward.
    calls = []
    monkeypatch.setattr(agent, "run_in_sandbox", _fake_sandbox(calls, VULN_STDOUT))

    tracker = _tracker(max_usd=1.0)
    tracker.usage.cost_usd = 5.0
    client = FakeLLMClient(replies=[_tool_reply(IN_SCOPE_URL)], tracker=tracker)
    result = run_sqli_agent([_endpoint()], scope_config=_scope(), llm_client=client)

    assert result.stopped_reason == "budget"
    assert calls == []
    assert result.candidates == []
    assert not any(s.get("action") == "completion_pass" for s in result.transcript)


# ── Scan status: error vs clean vs injectable (a dead target is NOT clean) ───

def test_target_unreachable_is_error_not_clean(monkeypatch):
    # sqlmap never runs (sandbox isolation abort / target unreachable). This must be
    # an ERROR with the reason recorded — NEVER a clean "not injectable" verdict.
    calls = []
    monkeypatch.setattr(agent, "run_in_sandbox", _raising_sandbox(calls))

    client = FakeLLMClient(replies=[_tool_reply(IN_SCOPE_URL), _final_reply()])
    result = run_sqli_agent([_endpoint()], scope_config=_scope(), llm_client=client)

    assert result.candidates, "an errored attempt is still recorded"
    assert all(c.status == "error" for c in result.candidates)
    assert not any(c.status == "clean" for c in result.candidates)   # NOT clean
    assert not any(c.injectable for c in result.candidates)
    assert all(c.error and "self-test" in c.error.lower() for c in result.candidates)
    # nothing actually scanned -> surfaced as "error", not "done".
    assert result.stopped_reason == "error"
    # the transcript carries the error status, not a bare injectable=False.
    steps = [s for s in result.transcript if s.get("action") == "run_sqlmap"]
    assert steps and all(s["status"] == "error" and s["error"] for s in steps)


def test_real_not_injectable_output_is_clean(monkeypatch):
    # sqlmap actually ran (exit 0) and returned a genuine not-injectable verdict.
    calls = []
    monkeypatch.setattr(agent, "run_in_sandbox", _status_sandbox(calls, CLEAN_196_STDOUT))

    client = FakeLLMClient(replies=[_tool_reply(IN_SCOPE_URL), _final_reply()])
    result = run_sqli_agent([_endpoint()], scope_config=_scope(), llm_client=client)

    assert result.candidates
    assert all(c.status == "clean" for c in result.candidates)
    assert not any(c.injectable for c in result.candidates)
    assert not any(c.status == "error" for c in result.candidates)
    assert result.stopped_reason == "done"


def test_injectable_output_is_status_injectable(monkeypatch):
    calls = []
    monkeypatch.setattr(agent, "run_in_sandbox", _status_sandbox(calls, VULN_196_STDOUT))

    client = FakeLLMClient(replies=[_tool_reply(IN_SCOPE_URL, depth=1), _final_reply()])
    result = run_sqli_agent([_endpoint()], scope_config=_scope(), llm_client=client)

    injectable = [c for c in result.candidates if c.status == "injectable"]
    assert injectable and injectable[0].injectable is True
    assert injectable[0].error is None
    assert all(c.status in ("clean", "injectable") for c in result.candidates)
    assert result.stopped_reason == "done"


def test_sqlmap_timeout_is_error_not_clean(monkeypatch):
    calls = []
    monkeypatch.setattr(agent, "run_in_sandbox",
                        _status_sandbox(calls, CLEAN_STDOUT, timed_out=True))

    client = FakeLLMClient(replies=[_tool_reply(IN_SCOPE_URL), _final_reply()])
    result = run_sqli_agent([_endpoint()], scope_config=_scope(), llm_client=client)

    assert any(c.status == "error" for c in result.candidates)
    assert not any(c.status == "clean" for c in result.candidates)
    assert any("timed out" in (c.error or "") for c in result.candidates)


def test_sqlmap_nonzero_exit_is_error_not_clean(monkeypatch):
    calls = []
    monkeypatch.setattr(agent, "run_in_sandbox",
                        _status_sandbox(calls, CLEAN_STDOUT, exit_code=1))

    client = FakeLLMClient(replies=[_tool_reply(IN_SCOPE_URL), _final_reply()])
    result = run_sqli_agent([_endpoint()], scope_config=_scope(), llm_client=client)

    assert any(c.status == "error" for c in result.candidates)
    assert not any(c.status == "clean" for c in result.candidates)
    assert any("non-zero" in (c.error or "") for c in result.candidates)


def test_injectable_wins_over_nonzero_exit(monkeypatch):
    # A confirmed injection is a real finding even if the process exits non-zero:
    # injectable is derived solely from parsed positive output.
    calls = []
    monkeypatch.setattr(agent, "run_in_sandbox",
                        _status_sandbox(calls, VULN_196_STDOUT, exit_code=1))

    client = FakeLLMClient(replies=[_tool_reply(IN_SCOPE_URL, depth=1), _final_reply()])
    result = run_sqli_agent([_endpoint()], scope_config=_scope(), llm_client=client)

    injectable = [c for c in result.candidates if c.injectable]
    assert injectable and injectable[0].status == "injectable"


if __name__ == "__main__":
    import types

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
        test_safe_profile_argv_has_detection_flags_and_no_forbidden,
        test_build_argv_with_data_adds_data_flag,
        test_forbidden_flag_assertion_trips,
        test_ladder_is_ordered_and_every_rung_is_clean,
        test_default_ceiling_blocks_aggressive_rung,
        test_aggressive_rung_argv_only_builds_when_ceiling_lifted,
        test_parse_vulnerable_output,
        test_parse_clean_output,
        test_parse_real_sqlmap_196_vulnerable,
        test_parse_real_sqlmap_196_clean,
        test_parse_negative_guard_not_injectable_never_positive,
        test_parse_dbms_both_wordings,
        test_in_scope_url_runs_safe_profile,
        test_out_of_scope_url_is_skipped,
        test_clean_output_not_injectable,
        test_stops_at_max_iterations,
        test_budget_stop,
        test_no_forbidden_flag_in_any_argv,
        test_fallback_runs_profile_per_endpoint,
        test_fallback_skips_out_of_scope_endpoints,
        test_agent_escalates_when_not_injectable_then_confirms,
        test_injectable_at_rung0_does_not_escalate,
        test_clean_at_every_rung_yields_no_finding,
        test_escalation_capped_per_url,
        test_fallback_walks_ladder_and_stops_at_first_injectable,
        test_default_probe_values_by_param_kind,
        test_improve_url_probes_substitutes_weak_only,
        test_sanitize_probe_value_accepts_safe_rejects_dangerous,
        test_weak_value_substituted_and_recorded_in_transcript,
        test_agent_valid_probe_value_is_used,
        test_agent_invalid_probe_value_is_rejected_and_defaults_used,
        test_no_forced_union_and_default_rungs_pass_no_technique,
        test_fallback_tries_next_probe_value_until_injectable,
        test_fallback_all_values_clean_no_finding,
        test_detection_only_base_profile_excludes_retrieval_and_blocks_auto_exploit,
        test_enumeration_flags_are_permanently_forbidden,
        test_model_clean_then_completion_pass_finds_deep_injection,
        test_model_confirmation_is_done_and_completion_adds_nothing,
        test_run_cap_holds_across_agent_and_completion_phases,
        test_completion_transcript_records_actual_probe_value,
        test_budget_stop_suppresses_completion_pass,
        test_target_unreachable_is_error_not_clean,
        test_real_not_injectable_output_is_clean,
        test_injectable_output_is_status_injectable,
        test_sqlmap_timeout_is_error_not_clean,
        test_sqlmap_nonzero_exit_is_error_not_clean,
        test_injectable_wins_over_nonzero_exit,
    ):
        _run(_fn)
    print("All agent unit tests passed!")
