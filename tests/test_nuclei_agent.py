"""
Tests for engine/nuclei_agent.py — the template-scan (nuclei) agent loop.

Fully offline: the LLM client is a scripted fake and run_in_sandbox is
monkeypatched, so no Docker, no network, and no real nuclei ever run. The
"found" ground-truth is exercised against REAL captured nuclei -jsonl output
(tests/fixtures/nuclei_dvwa_real.jsonl), not just synthetic strings.

Run: PYTHONPATH=. python -m pytest tests/test_nuclei_agent.py -v
"""
import json
from pathlib import Path

import pytest

import engine.nuclei_agent as nuclei
from engine.nuclei_agent import (
    run_nuclei_agent, NucleiAgentResult, NucleiCandidate,
    _build_nuclei_argv, _assert_no_forbidden_flags, _sanitize_tags,
    _sanitize_cookie, _validate_target, _parse_nuclei_output,
    _execute_run_nuclei, _FORBIDDEN_LITERAL, _DEFAULT_TAGS, _MAX_NUCLEI_RUNS_PER_TARGET,
)
from engine.scope import ScopeConfig
from engine.llm import LLMConfig, BudgetTracker, Usage
from schemas import Endpoint


# ── Real captured nuclei -jsonl fixtures ────────────────────────────────────

_FIXTURE = Path(__file__).resolve().parent / "fixtures" / "nuclei_dvwa_real.jsonl"
_REAL_LINES = [ln for ln in _FIXTURE.read_text(encoding="utf-8").splitlines() if ln.strip()]

# The medium-severity result is the primary "found" ground truth (the default profile
# excludes info-only). Its fields, read straight from the real captured JSONL:
_CONFIG_LISTING_LINE = next(
    ln for ln in _REAL_LINES if json.loads(ln)["template-id"] == "configuration-listing")
_REAL_MULTI_STDOUT = "\n".join(_REAL_LINES)   # a real 3-result scan (medium + 2 info)

# A realistic nuclei stdout that INTERLEAVES banner/log lines with the JSON result line —
# the parser must ignore the non-JSON chatter and never miscount it as a result.
_REAL_WITH_LOGS = (
    "\n"
    "                     __     _\n"
    "   ____  __  _______/ /__  (_)\n"
    "[INF] Current nuclei version: v3.11.0\n"
    "[INF] Templates loaded for current scan: 317\n"
    f"{_CONFIG_LISTING_LINE}\n"
    "[INF] Scan completed in 34s. 1 matches found.\n"
)

CLEAN_STDOUT = (
    "[INF] Current nuclei version: v3.11.0\n"
    "[INF] Templates loaded for current scan: 317\n"
    "[INF] No results found. Better luck next time!\n"
)


# ── Fixtures / fakes ────────────────────────────────────────────────────────

IN_SCOPE_URL = "http://localhost:8080/"
OUT_SCOPE_URL = "http://evil.com/"


def _scope():
    return ScopeConfig(
        target_url="http://localhost:8080/",
        allowed_hosts=["localhost"],
        authorized=True,
    )


def _tracker(max_usd=100.0):
    cfg = LLMConfig(base_url="http://x/v1", model="m", max_usd=max_usd,
                    price_in_per_1k=0.0, price_out_per_1k=0.0)
    return BudgetTracker(cfg)


def _tool_reply(target, tags=None, note=None, call_id="call_1"):
    args = {"target": target}
    if tags is not None:
        args["tags"] = tags
    if note is not None:
        args["note"] = note
    return {
        "text": "",
        "tool_calls": [{
            "id": call_id, "type": "function",
            "function": {"name": "run_nuclei", "arguments": json.dumps(args)},
        }],
        "raw": {},
    }


def _final_reply(text="done, all targets scanned"):
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


def _fake_sandbox(calls, stdout, *, exit_code=0, timed_out=False):
    from engine.sandbox import SandboxResult

    def fake(argv, *, target_url, config, timeout_sec=300, **kwargs):
        calls.append({"argv": list(argv), "target_url": target_url, "timeout": timeout_sec})
        return SandboxResult(exit_code=exit_code, stdout=stdout, stderr="",
                             timed_out=timed_out, target_ip="10.0.0.9")

    return fake


def _raising_sandbox(calls, message="isolation self-test FAILED — target_unreachable=7"):
    from engine.sandbox import SandboxError

    def fake(argv, *, target_url, config, timeout_sec=300, **kwargs):
        calls.append({"argv": list(argv), "target_url": target_url})
        raise SandboxError(message)

    return fake


def _endpoint(url=IN_SCOPE_URL):
    return Endpoint(url=url, method="GET", form_action=None,
                    inputs=[], cookies_needed=[], endpoint_type="page")


# ── argv builder / forbidden-flag guard (unit) ──────────────────────────────

def test_safe_profile_argv_has_detection_flags_and_no_forbidden():
    argv = _build_nuclei_argv(IN_SCOPE_URL)
    assert argv[:3] == ["nuclei", "-target", IN_SCOPE_URL]
    # fixed, detection-only profile
    for flag in ("-jsonl", "-disable-update-check", "-no-interactsh", "-omit-raw"):
        assert flag in argv
    assert "-t" in argv and "/opt/nuclei-templates" in argv
    # severity floor excludes info by default
    assert "-severity" in argv
    assert argv[argv.index("-severity") + 1] == "low,medium,high,critical"
    # dos/intrusive/fuzz/brute/oob are always excluded
    assert "-exclude-tags" in argv
    excl = argv[argv.index("-exclude-tags") + 1]
    for bad in ("dos", "intrusive", "fuzz", "brute", "oob"):
        assert bad in excl
    # default tags applied when the model supplies none
    assert "-tags" in argv
    assert argv[argv.index("-tags") + 1] == ",".join(_DEFAULT_TAGS)
    for bad in _FORBIDDEN_LITERAL:
        assert bad not in argv


def test_argv_never_contains_update_or_oob_flags():
    argv = _build_nuclei_argv(IN_SCOPE_URL, tags=["tech", "exposure"])
    for bad in ("-up", "-update", "-ut", "-update-templates",
                "-iserver", "-interactsh-server", "-itoken", "-code", "-headless"):
        assert bad not in argv


def test_forbidden_flag_assertion_trips():
    for bad in ("-up", "-ut", "-interactsh-server", "-code", "-headless", "-reset",
                "-dashboard-upload", "-i"):
        with pytest.raises(AssertionError):
            _assert_no_forbidden_flags(["nuclei", "-target", "x", bad])


def test_header_injection_other_than_cookie_trips():
    # A harness Cookie header is fine...
    _assert_no_forbidden_flags(["nuclei", "-target", "x", "-H", "Cookie: a=b"])
    # ...but any other injected header is refused.
    with pytest.raises(AssertionError):
        _assert_no_forbidden_flags(["nuclei", "-target", "x", "-H", "X-Evil: 1"])
    with pytest.raises(AssertionError):
        _assert_no_forbidden_flags(["nuclei", "-target", "x", "-header", "Authorization: Bearer x"])


def test_auth_cookie_threaded_as_cookie_header():
    argv = _build_nuclei_argv(IN_SCOPE_URL, auth_cookie="PHPSESSID=abc; security=low")
    assert "-H" in argv
    assert argv[argv.index("-H") + 1] == "Cookie: PHPSESSID=abc; security=low"


# ── Tag allowlist / smuggling guard (unit) ──────────────────────────────────

def test_sanitize_tags_keeps_allowlisted_drops_unknown():
    # allowlisted kept, de-duplicated; clean-but-unknown silently dropped
    assert _sanitize_tags(["tech", "exposure", "tech"]) == ["tech", "exposure"]
    assert _sanitize_tags(["totally-unknown-safe-tag"]) == []
    assert _sanitize_tags(None) == []
    assert _sanitize_tags([]) == []


def test_sanitize_tags_raises_only_on_forbidden_or_flaglike():
    # DANGEROUS category or FLAG-LIKE token -> deliberate smuggle -> RAISES.
    for bad in ("dos", "intrusive", "fuzz", "brute", "oob", "exploit", "rce", "code"):
        with pytest.raises(AssertionError):
            _sanitize_tags(["tech", bad])
    for smuggled in ("-H", "-interactsh-server", "--update"):
        with pytest.raises(AssertionError):
            _sanitize_tags([smuggled])


def test_sanitize_tags_drops_malformed_noise_without_crashing():
    # Weak-model noise (NOT flag-like, NOT a dangerous category) must DROP, never
    # raise — a bad model returning junk tags must not crash the scan. "[]" is the
    # exact value a local llama3.2 returned in a live run (a stringified empty array).
    for junk in ("[]", "a b", "tag;rm", '"x"', "tech,dos", "{}"):
        assert _sanitize_tags([junk]) == []          # dropped, no exception
    assert _sanitize_tags("[]") == []                # a bare string, too
    assert _sanitize_tags([123, None, "tech"]) == ["tech"]   # non-strings dropped
    assert _sanitize_tags(42) == []                  # non-list -> ignored, not fatal


def test_validate_target_rejects_flaglike_and_nonurl():
    assert _validate_target("http://localhost:8080/") == "http://localhost:8080/"
    for bad in ("-interactsh-server", "-u", "not a url", "ftp://x/", "http://", "", "  "):
        with pytest.raises(AssertionError):
            _validate_target(bad)


def test_sanitize_cookie_rejects_dangerous():
    assert _sanitize_cookie("PHPSESSID=abc; security=low") == "PHPSESSID=abc; security=low"
    assert _sanitize_cookie("") is None
    assert _sanitize_cookie("-flag=1") is None
    assert _sanitize_cookie("a=b\r\nX-Evil: 1") is None   # header-injection guard
    assert _sanitize_cookie("x" * 5000) is None
    assert _sanitize_cookie(None) is None


# ── nuclei JSONL parsing (source of truth for "found") ──────────────────────

def test_parse_real_jsonl_result_line():
    results = _parse_nuclei_output(_CONFIG_LISTING_LINE)
    assert len(results) == 1
    r = results[0]
    assert r["template_id"] == "configuration-listing"
    assert r["severity"] == "medium"
    assert r["matched_at"] == "http://localhost:8080/config/"


def test_parse_ignores_log_and_banner_lines():
    # Real result line surrounded by real banner/log chatter -> exactly one result.
    results = _parse_nuclei_output(_REAL_WITH_LOGS)
    assert len(results) == 1
    assert results[0]["template_id"] == "configuration-listing"


def test_parse_multiple_real_results():
    results = _parse_nuclei_output(_REAL_MULTI_STDOUT)
    ids = {r["template_id"] for r in results}
    assert {"configuration-listing", "tech-detect", "ssh-sha1-hmac-algo"} <= ids
    assert len(results) == len(_REAL_LINES)


def test_parse_clean_output_is_empty():
    assert _parse_nuclei_output(CLEAN_STDOUT) == []
    assert _parse_nuclei_output("") == []


def test_parse_skips_json_without_template_id():
    # Valid JSON, but not a nuclei result object -> not counted.
    assert _parse_nuclei_output('{"msg": "hello", "level": "info"}') == []
    assert _parse_nuclei_output('{"template-id": ""}') == []


# ── Agent loop: found / clean / error / out-of-scope ────────────────────────

def test_real_result_yields_found_candidate(monkeypatch):
    calls = []
    monkeypatch.setattr(nuclei, "run_in_sandbox", _fake_sandbox(calls, _CONFIG_LISTING_LINE))

    client = FakeLLMClient(replies=[_tool_reply(IN_SCOPE_URL), _final_reply()])
    result = run_nuclei_agent([_endpoint()], scope_config=_scope(), llm_client=client)

    found = [c for c in result.candidates if c.status == "found"]
    assert len(found) == 1
    c = found[0]
    assert c.template_id == "configuration-listing"
    assert c.severity == "medium"
    assert c.matched_at == "http://localhost:8080/config/"
    assert c.evidence and "configuration-listing" in c.evidence
    assert c.error is None
    assert result.stopped_reason == "done"     # model-driven find


def test_multiple_results_yield_multiple_found_candidates(monkeypatch):
    calls = []
    monkeypatch.setattr(nuclei, "run_in_sandbox", _fake_sandbox(calls, _REAL_MULTI_STDOUT))

    client = FakeLLMClient(replies=[_tool_reply(IN_SCOPE_URL), _final_reply()])
    result = run_nuclei_agent([_endpoint()], scope_config=_scope(), llm_client=client)

    found = [c for c in result.candidates if c.status == "found"]
    assert len(found) == len(_REAL_LINES)
    assert {c.template_id for c in found} >= {"configuration-listing", "tech-detect"}


def test_clean_scan_yields_clean_candidate(monkeypatch):
    calls = []
    monkeypatch.setattr(nuclei, "run_in_sandbox", _fake_sandbox(calls, CLEAN_STDOUT))

    client = FakeLLMClient(replies=[_tool_reply(IN_SCOPE_URL), _final_reply()])
    result = run_nuclei_agent([_endpoint()], scope_config=_scope(), llm_client=client)

    assert result.candidates
    assert all(c.status == "clean" for c in result.candidates)
    assert not any(c.status == "found" for c in result.candidates)
    assert not any(c.status == "error" for c in result.candidates)
    assert result.stopped_reason == "done"


def test_sandbox_error_is_error_not_clean(monkeypatch):
    # nuclei never runs (isolation abort / target unreachable) -> ERROR, not clean/found.
    calls = []
    monkeypatch.setattr(nuclei, "run_in_sandbox", _raising_sandbox(calls))

    client = FakeLLMClient(replies=[_tool_reply(IN_SCOPE_URL), _final_reply()])
    result = run_nuclei_agent([_endpoint()], scope_config=_scope(), llm_client=client)

    assert result.candidates, "an errored attempt is still recorded"
    assert all(c.status == "error" for c in result.candidates)
    assert not any(c.status == "clean" for c in result.candidates)   # NOT clean
    assert not any(c.status == "found" for c in result.candidates)   # NOT found
    assert all(c.error and "self-test" in c.error.lower() for c in result.candidates)
    steps = [s for s in result.transcript if s.get("action") == "run_nuclei"]
    assert steps and all(s["status"] == "error" and s["error"] for s in steps)


def test_timeout_is_error_not_clean(monkeypatch):
    calls = []
    monkeypatch.setattr(nuclei, "run_in_sandbox",
                        _fake_sandbox(calls, CLEAN_STDOUT, timed_out=True))

    client = FakeLLMClient(replies=[_tool_reply(IN_SCOPE_URL), _final_reply()])
    result = run_nuclei_agent([_endpoint()], scope_config=_scope(), llm_client=client)

    assert any(c.status == "error" for c in result.candidates)
    assert not any(c.status == "clean" for c in result.candidates)
    assert any("timed out" in (c.error or "") for c in result.candidates)


def test_nonzero_exit_is_error_not_clean(monkeypatch):
    calls = []
    monkeypatch.setattr(nuclei, "run_in_sandbox",
                        _fake_sandbox(calls, CLEAN_STDOUT, exit_code=1))

    client = FakeLLMClient(replies=[_tool_reply(IN_SCOPE_URL), _final_reply()])
    result = run_nuclei_agent([_endpoint()], scope_config=_scope(), llm_client=client)

    assert any(c.status == "error" for c in result.candidates)
    assert not any(c.status == "clean" for c in result.candidates)
    assert any("non-zero" in (c.error or "") for c in result.candidates)


def test_found_wins_over_nonzero_exit(monkeypatch):
    # A real matched template is a finding even if the process exits non-zero:
    # found is derived solely from parsed JSONL result lines.
    calls = []
    monkeypatch.setattr(nuclei, "run_in_sandbox",
                        _fake_sandbox(calls, _CONFIG_LISTING_LINE, exit_code=1))

    client = FakeLLMClient(replies=[_tool_reply(IN_SCOPE_URL), _final_reply()])
    result = run_nuclei_agent([_endpoint()], scope_config=_scope(), llm_client=client)

    found = [c for c in result.candidates if c.status == "found"]
    assert found and found[0].template_id == "configuration-listing"


def test_out_of_scope_target_not_scanned(monkeypatch):
    calls = []
    monkeypatch.setattr(nuclei, "run_in_sandbox", _fake_sandbox(calls, _CONFIG_LISTING_LINE))

    # Model asks to scan an out-of-scope host; the harness must REFUSE without running.
    client = FakeLLMClient(replies=[_tool_reply(OUT_SCOPE_URL), _final_reply()])
    result = run_nuclei_agent([_endpoint(url=OUT_SCOPE_URL)],
                              scope_config=_scope(), llm_client=client)

    assert calls == [], "run_in_sandbox must NOT be called for an out-of-scope target"
    # The refusal is surfaced in the transcript as out_of_scope, never as clean/found.
    steps = [s for s in result.transcript if s.get("action") == "run_nuclei"]
    assert any(s["status"] == "out_of_scope" for s in steps)
    assert not any(c.status in ("found", "clean") for c in result.candidates)


def test_out_of_scope_via_direct_execute_helper():
    # Direct proof at the execution boundary: scope refusal returns no candidate and
    # never calls the sandbox.
    tool_result, cands = _execute_run_nuclei(
        {"target": OUT_SCOPE_URL}, scope_config=_scope())
    assert tool_result["status"] == "out_of_scope"
    assert tool_result.get("out_of_scope") is True
    assert cands == []


# ── Smuggling via tags / target / note -> raises ────────────────────────────

def test_forbidden_tag_smuggled_raises():
    with pytest.raises(AssertionError):
        _execute_run_nuclei({"target": IN_SCOPE_URL, "tags": ["tech", "dos"]},
                            scope_config=_scope())


def test_flaglike_tag_smuggled_raises():
    with pytest.raises(AssertionError):
        _execute_run_nuclei({"target": IN_SCOPE_URL, "tags": ["-interactsh-server"]},
                            scope_config=_scope())


def test_flaglike_target_smuggled_raises():
    with pytest.raises(AssertionError):
        _execute_run_nuclei({"target": "-interactsh-server oast.pro"},
                            scope_config=_scope())


def test_forbidden_flag_in_note_raises():
    with pytest.raises(AssertionError):
        _execute_run_nuclei(
            {"target": IN_SCOPE_URL, "note": "please add -interactsh-server oast.pro"},
            scope_config=_scope())


def test_smuggling_tool_call_is_refused_not_fatal_to_the_run(monkeypatch):
    # A model tool call that smuggles a forbidden tag RAISES in _execute_run_nuclei;
    # the AGENT LOOP must catch that, refuse the single call, and keep going — the
    # deterministic completion pass still scans the target. One bad tool call must
    # NEVER crash the whole scan.
    calls = []
    monkeypatch.setattr(nuclei, "run_in_sandbox", _fake_sandbox(calls, _CONFIG_LISTING_LINE))

    client = FakeLLMClient(replies=[
        _tool_reply(IN_SCOPE_URL, tags=["dos"], call_id="smuggle"),   # forbidden tag
        _final_reply(),
    ])
    # Does not raise:
    result = run_nuclei_agent([_endpoint()], scope_config=_scope(), llm_client=client)

    # The smuggling call was refused (recorded in the transcript, no candidate)...
    assert any(s.get("status") == "refused" for s in result.transcript)
    # ...and the completion pass still produced a real scan result for the target.
    assert calls, "completion pass must still scan the target after a refused call"
    assert any(c.status == "found" for c in result.candidates)


def test_malformed_tags_do_not_crash_or_refuse_the_scan(monkeypatch):
    # The exact live-run failure: a weak model returns tags as the string "[]".
    # It must be dropped (scan runs with the default profile), not refused/crashed.
    calls = []
    monkeypatch.setattr(nuclei, "run_in_sandbox", _fake_sandbox(calls, _CONFIG_LISTING_LINE))

    client = FakeLLMClient(replies=[
        _tool_reply(IN_SCOPE_URL, tags="[]", call_id="junk"),   # stringified empty array
        _final_reply(),
    ])
    result = run_nuclei_agent([_endpoint()], scope_config=_scope(), llm_client=client)

    assert not any(s.get("status") == "refused" for s in result.transcript)
    assert calls and any(c.status == "found" for c in result.candidates)
    # the scan ran with the default tag profile (junk dropped)
    argv = calls[0]["argv"]
    assert argv[argv.index("-tags") + 1] == ",".join(nuclei._DEFAULT_TAGS)


# ── Completion pass / budget / caps ─────────────────────────────────────────

def test_completion_pass_scans_untouched_target(monkeypatch):
    # Model does nothing; the deterministic completion pass scans the target and, on a
    # find, the run is "completed_by_ladder".
    calls = []
    monkeypatch.setattr(nuclei, "run_in_sandbox", _fake_sandbox(calls, _CONFIG_LISTING_LINE))

    client = FakeLLMClient(replies=[_final_reply("nothing to do")])
    result = run_nuclei_agent([_endpoint()], scope_config=_scope(), llm_client=client)

    assert len(calls) == 1
    assert any(c.status == "found" for c in result.candidates)
    assert result.stopped_reason == "completed_by_ladder"


def test_completion_pass_skips_out_of_scope(monkeypatch):
    calls = []
    monkeypatch.setattr(nuclei, "run_in_sandbox", _fake_sandbox(calls, _CONFIG_LISTING_LINE))

    client = FakeLLMClient(replies=[_final_reply("nothing to do")])
    result = run_nuclei_agent(
        [_endpoint(url=IN_SCOPE_URL), _endpoint(url=OUT_SCOPE_URL)],
        scope_config=_scope(), llm_client=client)

    assert len(calls) == 1
    assert "localhost" in calls[0]["target_url"]
    assert all("evil.com" not in c["target_url"] for c in calls)


def test_budget_stop_suppresses_completion_pass(monkeypatch):
    calls = []
    monkeypatch.setattr(nuclei, "run_in_sandbox", _fake_sandbox(calls, _CONFIG_LISTING_LINE))

    tracker = _tracker(max_usd=1.0)
    tracker.usage.cost_usd = 5.0
    client = FakeLLMClient(replies=[_tool_reply(IN_SCOPE_URL)], tracker=tracker)
    result = run_nuclei_agent([_endpoint()], scope_config=_scope(), llm_client=client)

    assert result.stopped_reason == "budget"
    assert calls == []
    assert result.candidates == []
    assert not any(s.get("action") == "completion_pass" for s in result.transcript)


def test_scan_capped_per_target(monkeypatch):
    calls = []
    monkeypatch.setattr(nuclei, "run_in_sandbox", _fake_sandbox(calls, CLEAN_STDOUT))

    # Model hammers the same target forever; runs are capped per target.
    client = FakeLLMClient(default_reply=_tool_reply(IN_SCOPE_URL, call_id="cap"))
    result = run_nuclei_agent([_endpoint()], max_iterations=_MAX_NUCLEI_RUNS_PER_TARGET + 5,
                              scope_config=_scope(), llm_client=client)

    assert len(calls) <= _MAX_NUCLEI_RUNS_PER_TARGET


def test_targets_accept_plain_url_strings(monkeypatch):
    calls = []
    monkeypatch.setattr(nuclei, "run_in_sandbox", _fake_sandbox(calls, _CONFIG_LISTING_LINE))

    client = FakeLLMClient(replies=[_final_reply("nothing to do")])
    # bare URL string target (not an Endpoint) must work too
    result = run_nuclei_agent([IN_SCOPE_URL], scope_config=_scope(), llm_client=client)

    assert len(calls) == 1
    assert any(c.status == "found" for c in result.candidates)


def test_auth_cookie_reaches_sandbox_argv(monkeypatch):
    calls = []
    monkeypatch.setattr(nuclei, "run_in_sandbox", _fake_sandbox(calls, CLEAN_STDOUT))

    client = FakeLLMClient(replies=[_tool_reply(IN_SCOPE_URL), _final_reply()])
    run_nuclei_agent([_endpoint()], scope_config=_scope(), llm_client=client,
                     auth_cookie="PHPSESSID=abc; security=low")

    assert calls
    argv = calls[0]["argv"]
    assert "-H" in argv
    assert argv[argv.index("-H") + 1] == "Cookie: PHPSESSID=abc; security=low"


def test_result_shape_and_stopped_reasons(monkeypatch):
    calls = []
    monkeypatch.setattr(nuclei, "run_in_sandbox", _fake_sandbox(calls, CLEAN_STDOUT))
    client = FakeLLMClient(replies=[_final_reply()])
    result = run_nuclei_agent([_endpoint()], scope_config=_scope(), llm_client=client)

    assert isinstance(result, NucleiAgentResult)
    assert isinstance(result.usage, Usage)
    assert result.stopped_reason in {"done", "completed_by_ladder", "budget", "max_iterations"}
    assert isinstance(result.transcript, list) and result.transcript


# ── Standalone runner (mirrors the repo convention) ─────────────────────────

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

    _tests = [v for k, v in sorted(globals().items())
              if k.startswith("test_") and callable(v)]
    print(f"Running {len(_tests)} nuclei-agent tests...")
    for _fn in _tests:
        _run(_fn)
    print("All nuclei-agent tests passed!")
