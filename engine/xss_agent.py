# engine/xss_agent.py
"""
Reflected-XSS agent — a parallel to engine/agent.py (the SQLi agent), driving
Dalfox instead of sqlmap inside the same isolated sandbox.

Same proven shape: the model PLANS which endpoint/parameter to test, Dalfox
EXECUTES inside engine.sandbox (egress-restricted, non-root, read-only), and
engine.scope BOUNDS every action. The model never supplies Dalfox flags — the
harness owns a fixed, DETECTION-ONLY profile and refuses forbidden flags. An
"injectable" conclusion is derived ONLY from parsed Dalfox positive output
([POC]/[V] lines), never from the model's assertion. The loop is bounded by
iterations and budget, backed by a deterministic completion pass, and never runs
anything out of scope or outside the sandbox.

This layer produces a structured intermediate result (XssAgentResult) plus a
transcript for run.json. It does NOT map results into schemas.Finding and does
NOT wire into integration.py / modules/xss.py — that is the next layer.
"""

import json
import re
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path

from engine.scope import ScopeConfig, ScopeError, assert_in_scope, load_scope_config
from engine.sandbox import SandboxError, run_in_sandbox
from engine.llm import (
    BudgetExceededError, BudgetTracker, LLMClient, LLMError, Usage, load_llm_config,
)
# Genuinely-generic helpers shared with the SQLi agent — imported, not copied.
from engine.agent import (
    _endpoint_field, _parse_tool_call, _endpoint_key, _primary_param,
)

_PROMPT_PATH = Path(__file__).resolve().parent.parent / "prompts" / "xss_agent.txt"

_SANDBOX_TIMEOUT_SEC = 180

# Completion-pass / per-endpoint scan cap. Dalfox tests every parameter itself,
# so a couple of runs per endpoint (whole-URL + one focused retry) is plenty.
_MAX_XSS_RUNS_PER_ENDPOINT = 2

# Fixed, safe, DETECTION-ONLY base flags shared by EVERY scan. Dalfox generates
# its own payloads; the harness owns every flag — the model supplies none. Plain
# output so the [POC]/[V] verdict lines are machine-parseable.
_BASE_PROFILE = ["--no-color", "--format", "plain"]

# Flags that must NEVER appear at ANY scan — anything that turns Dalfox from
# LOCAL DETECTION into exploitation, a blind/remote callback (data exfil), remote
# payload/wordlist fetching, or writing output off-box. Enforced by assertion in
# the argv builder so a regression cannot smuggle an exfil/exploit action into a
# "detection" run. (Some are v3-only / not in v2.13.0 — banned defensively.)
_FORBIDDEN_LITERAL = {
    "-b", "--blind",                                  # blind-XSS callback (remote exfil)
    "--exploit",                                      # exploitation mode
    "--remote-payloads", "--remote-wordlists",        # fetch from remote hosts
    "--custom-payload", "--custom-blind-xss-payload",  # load arbitrary payload files
    "--cookie-from-raw",                              # read an arbitrary file
    "-o", "--output", "--output-all",                 # write output off the sandbox
    "--output-request", "--output-response",
    "--har-file-path",                                # write a HAR file
    "--grep",                                         # load a custom grep file
    "--server",                                       # API/server mode
}


# ── The single tool exposed to the model ────────────────────────────────────

RUN_DALFOX_TOOL = {
    "type": "function",
    "function": {
        "name": "run_dalfox",
        "description": (
            "Run Dalfox against ONE in-scope URL inside an isolated sandbox using a "
            "fixed, safe, detection-only profile. You do not control Dalfox flags — "
            "you only choose the URL and, optionally, a single parameter to focus on. "
            "Any configured authentication cookie is attached automatically. Returns "
            "whether Dalfox CONFIRMED reflected XSS, plus the vulnerable parameter, "
            "the injection context, and the triggering payload when found."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": (
                        "Full in-scope URL to test. Include the query string with the "
                        "parameter to test, e.g. "
                        "'http://host/vulnerabilities/xss_r/?name=test'."
                    ),
                },
                "param": {
                    "type": "string",
                    "description": "Optional single parameter name to focus the scan on.",
                },
                "note": {
                    "type": "string",
                    "description": "Optional short note on what you are testing and why.",
                },
            },
            "required": ["url"],
        },
    },
}


# ── Result types ────────────────────────────────────────────────────────────

@dataclass
class XssCandidate:
    endpoint_url: str
    parameter: str | None
    injectable: bool
    context: str | None          # e.g. "inHTML-none", "inHTML-URL", "inJS"
    payload: str | None          # the triggering payload, when confirmed
    evidence: str                # raw [POC]/[V] excerpt (empty for non-injectable)
    # Outcome of the scan: "injectable" (parsed [POC]/[V] positive), "clean"
    # (Dalfox actually ran, exit 0, no positive), "error" (sandbox/isolation abort,
    # target unreachable, timeout, or non-zero exit — no verdict), or "out_of_scope"
    # (refused before running). "error"/"out_of_scope" are NEVER presented as clean.
    status: str = "clean"
    error: str | None = None     # reason string when status == "error"
    dalfox_argv: list = field(default_factory=list)


@dataclass
class XssAgentResult:
    candidates: list[XssCandidate]
    usage: Usage
    iterations: int
    transcript: list[dict]       # each step: {role, action, summary} for run.json
    stopped_reason: str          # "done"|"completed_by_ladder"|"budget"|"max_iterations"


# ── Dalfox argv builder + forbidden-flag guard ──────────────────────────────

def _assert_no_forbidden_flags(argv: list[str]) -> list[str]:
    """Fail loudly if the argv contains any exploitation / remote-callback /
    off-box-output flag. Detection-only is a hard invariant."""
    for tok in argv:
        flag = tok.split("=", 1)[0]
        assert flag not in _FORBIDDEN_LITERAL, f"forbidden dalfox flag in argv: {tok!r}"
    return argv


def _sanitize_cookie(cookie) -> str | None:
    """Validate a caller-supplied auth cookie; return the safe value or None.

    Rejects non-strings, empties, anything with a newline/NUL, anything over 4096
    chars, or a value that looks like a flag (leading '-'). The cookie is passed as
    a single argv token (no shell), so ';'/spaces inside it are safe.
    """
    if not isinstance(cookie, str):
        return None
    c = cookie.strip()
    if not c or len(c) > 4096 or c.startswith("-"):
        return None
    if any(ch in c for ch in ("\n", "\r", "\x00")):
        return None
    return c


def _build_dalfox_argv(url: str, *, param: str | None = None,
                       auth_cookie: str | None = None) -> list[str]:
    """Construct the harness-owned, detection-only Dalfox argv for one URL."""
    argv = ["dalfox", "url", url, *_BASE_PROFILE]
    if param:
        argv += ["-p", param]
    if auth_cookie:
        argv += ["--cookie", auth_cookie]
    return _assert_no_forbidden_flags(argv)


# ── Dalfox output parsing (SOLE source of "injectable" truth) ────────────────

# The authoritative PoC line Dalfox prints on stdout for a CONFIRMED finding:
#   [POC][<Type>][<Method>][<InjectType>] <Data-URL>
# (format straight from dalfox v2.13.0 internal/printing/poc.go + logger.go).
_POC_STRUCT_RE = re.compile(r"\[POC\]\[([^\]]*)\]\[([^\]]*)\]\[([^\]]*)\]\s*(\S.*)")
_POC_ANY_RE = re.compile(r"\[POC\]")
# The confirmed-vuln stderr line: "[V] Triggered XSS Payload (found ...): <payload>".
_VULN_TRIGGER_RE = re.compile(r"\[V\]\s*Triggered XSS Payload[^\n:]*(?::\s*(.+))?")
_VULN_ANY_RE = re.compile(r"\[V\]\s*Triggered XSS Payload")
# Advisory reflected-parameter line (NOT a confirmation on its own).
_REFLECTED_PARAM_RE = re.compile(r"[Rr]eflected\s+(\S+)\s+param")

# Payload-ish markers used to pick the injected parameter out of a PoC URL.
_PAYLOAD_MARKERS = ("<", ">", "\"", "'", "(", ")", "script", "alert",
                    "onerror", "onload", "svg", "javascript:", "prompt", "confirm")


def _payload_param_from_url(poc_url: str):
    """From a PoC URL, return (param, value) for the query param carrying the
    payload (value contains a payload marker), else the first param, else None."""
    try:
        pairs = urllib.parse.parse_qsl(urllib.parse.urlsplit(poc_url).query,
                                       keep_blank_values=True)
    except (ValueError, AttributeError):
        return None, None
    if not pairs:
        return None, None
    for k, v in pairs:
        low = v.lower()
        if any(m in low for m in _PAYLOAD_MARKERS):
            return k, v
    return pairs[0][0], pairs[0][1]


def _parse_dalfox_output(stdout: str) -> dict:
    """Decide XSS injectability and extract parameter/context/payload/evidence.

    'injectable' comes STRICTLY from Dalfox's own positive signals — a [POC] line
    (stdout) and/or a "[V] Triggered XSS Payload" line (stderr). NEGATIVE GUARD:
    text that merely mentions XSS, or reports a reflected parameter, WITHOUT a
    [POC]/[V] confirmation is never injectable. A clean run ("[issues: 0]") has
    neither signal.
    """
    text = stdout or ""

    struct = _POC_STRUCT_RE.search(text)
    injectable = bool(struct or _POC_ANY_RE.search(text) or _VULN_ANY_RE.search(text))

    # Context + PoC URL from the structured [POC] line, when present.
    context, poc_url = None, None
    if struct:
        context = (struct.group(3) or "").strip() or None
        data = (struct.group(4) or "").strip()
        poc_url = data.split()[0] if data else None

    # Parameter: prefer the injected param from the PoC URL, else the reflected line.
    parameter = None
    url_param, url_payload = (_payload_param_from_url(poc_url) if poc_url else (None, None))
    if url_param:
        parameter = url_param
    else:
        m = _REFLECTED_PARAM_RE.search(text)
        if m:
            parameter = m.group(1).strip()

    # Payload: prefer the explicit "[V] Triggered ...: <payload>", else the PoC URL value.
    payload = None
    vt = _VULN_TRIGGER_RE.search(text)
    if vt and vt.group(1):
        payload = vt.group(1).strip()
    if not payload and url_payload:
        payload = url_payload

    # Evidence: the confirming [POC]/[V]/reflected lines, capped ~600 chars. Only
    # meaningful for a real finding — empty for a clean/negative run.
    if injectable:
        ev_lines = [ln.strip() for ln in text.splitlines()
                    if ln.strip() and ("[POC]" in ln or "[V]" in ln or "Reflected" in ln)]
        evidence = ("\n".join(ev_lines)[:600].strip()) or text[-400:].strip()
    else:
        evidence = ""

    return {
        "injectable": injectable,
        "parameter": parameter,
        "context": context,
        "payload": payload,
        "evidence": evidence,
    }


# ── Harness-owned tool execution ────────────────────────────────────────────

def _run_one_scan(url: str, *, param: str | None, scope_config: ScopeConfig,
                  auth_cookie: str | None = None,
                  timeout_sec: int = _SANDBOX_TIMEOUT_SEC):
    """Execute a single Dalfox scan. Returns (tool_result, candidate).

    candidate is non-None whenever Dalfox actually ran in the sandbox (whether
    injectable, clean, or errored). A scope refusal returns (tool_result, None)
    with status "out_of_scope" and NO sandbox execution.
    """
    # Scope gate BEFORE any execution. Refuse (don't run) if out of scope.
    try:
        assert_in_scope(url, scope_config)
    except ScopeError:
        return {
            "ok": False,
            "status": "out_of_scope",
            "out_of_scope": True,
            "error": f"URL is out of scope and was NOT tested: {url}",
        }, None

    argv = _build_dalfox_argv(url, param=param, auth_cookie=auth_cookie)

    # ALL Dalfox execution goes through the sandbox — never the host. A sandbox
    # failure (isolation abort, target unreachable, ...) is an ERROR, not a clean
    # verdict: a dead target can never masquerade as "no XSS".
    try:
        sr = run_in_sandbox(argv, target_url=url, config=scope_config,
                            timeout_sec=timeout_sec)
    except (SandboxError, ScopeError) as exc:
        reason = f"sandbox execution failed: {exc}"
        candidate = XssCandidate(
            endpoint_url=url, parameter=param, injectable=False, context=None,
            payload=None, evidence="", status="error", error=reason, dalfox_argv=argv)
        tool_result = {"ok": False, "status": "error", "error": reason,
                       "url": url, "injectable": False}
        return tool_result, candidate

    # Dalfox writes the [POC] line to stdout and [V]/[I] lines to stderr — parse both.
    combined = (sr.stdout or "") + "\n" + (sr.stderr or "")
    parsed = _parse_dalfox_output(combined)

    # 'injectable' ALWAYS comes from parsed [POC]/[V]; a confirmed finding wins even
    # over an odd exit code. Otherwise a timeout / non-zero exit means the scan did
    # not complete → ERROR; only a real exit-0 run with no positive is "clean".
    if parsed["injectable"]:
        status, error = "injectable", None
    elif sr.timed_out:
        status, error = "error", "dalfox timed out before returning a verdict"
    elif sr.exit_code != 0:
        status, error = "error", f"dalfox exited with non-zero code {sr.exit_code}"
    else:
        status, error = "clean", None

    candidate = XssCandidate(
        endpoint_url=url,
        parameter=parsed["parameter"] or param,
        injectable=parsed["injectable"],
        context=parsed["context"],
        payload=parsed["payload"],
        evidence=parsed["evidence"],
        status=status,
        error=error,
        dalfox_argv=argv,
    )
    tool_result = {
        "ok": status != "error",
        "status": status,
        "error": error,
        "url": url,
        "injectable": parsed["injectable"],
        "parameter": parsed["parameter"] or param,
        "context": parsed["context"],
        "payload": parsed["payload"],
        "timed_out": sr.timed_out,
        "exit_code": sr.exit_code,
        "evidence_excerpt": parsed["evidence"][:400],
    }
    return tool_result, candidate


def _execute_run_dalfox(arguments: dict, *, scope_config: ScopeConfig,
                        auth_cookie: str | None = None,
                        timeout_sec: int = _SANDBOX_TIMEOUT_SEC):
    """Dispatch a model tool call to a Dalfox scan. Returns (tool_result, candidate).

    The model supplies only url/param/note — never flags. Malformed args return
    (tool_result, None).
    """
    args = arguments or {}
    url = args.get("url")
    if not url or not isinstance(url, str):
        return {"ok": False, "error": "run_dalfox requires a string 'url'"}, None

    param = args.get("param")
    param = param.strip() if isinstance(param, str) and param.strip() else None

    tool_result, candidate = _run_one_scan(
        url, param=param, scope_config=scope_config,
        auth_cookie=auth_cookie, timeout_sec=timeout_sec)
    tool_result["target_url"] = url
    tool_result["requested_param"] = param
    return tool_result, candidate


# ── Helpers ─────────────────────────────────────────────────────────────────

def _load_system_prompt() -> str:
    try:
        return _PROMPT_PATH.read_text(encoding="utf-8")
    except OSError:
        return (
            "You are RedSee's reflected-XSS agent. Use ONLY the run_dalfox tool on "
            "in-scope URLs, one at a time; base conclusions on tool output; stop when done."
        )


def _format_endpoints_user_message(endpoints: list, auth_cookie: str | None = None) -> str:
    lines = [
        "Test the following authorized in-scope endpoints for REFLECTED XSS using the "
        "run_dalfox tool, one at a time:",
        "",
    ]
    for i, ep in enumerate(endpoints, 1):
        url = _endpoint_field(ep, "url", "")
        method = _endpoint_field(ep, "method", "GET") or "GET"
        inputs = _endpoint_field(ep, "inputs", []) or []
        lines.append(f"{i}. [{method}] {url}  params={list(inputs)}")
    if len(endpoints) == 0:
        lines.append("(no endpoints provided)")
    if auth_cookie:
        lines.append("")
        lines.append("An authenticated session cookie is configured and is attached to "
                     "every scan automatically — you do not need to supply it yourself.")
    return "\n".join(lines)


def _summarize_tool_result(arguments: dict, tool_result: dict) -> str:
    url = (arguments or {}).get("url", "?")
    if not tool_result.get("ok"):
        return f"{url}: {tool_result.get('error', 'skipped')}"
    inj = "XSS INJECTABLE" if tool_result.get("injectable") else "no XSS"
    param = tool_result.get("parameter")
    ctx = tool_result.get("context")
    tail = f" (param={param})" if param else ""
    if ctx:
        tail += f" context={ctx}"
    return f"{url}: {inj}{tail}"


def _scan_transcript(url: str, tool_result: dict) -> dict:
    """Structured transcript step recording one Dalfox scan for run.json."""
    return {
        "role": "tool",
        "action": "run_dalfox",
        "url": url,
        "target_url": tool_result.get("target_url", url),
        "parameter": tool_result.get("parameter"),
        "context": tool_result.get("context"),
        "payload": tool_result.get("payload"),
        "injectable": bool(tool_result.get("injectable")),
        "status": tool_result.get("status")
                  or ("error" if not tool_result.get("ok") else "clean"),
        "error": tool_result.get("error"),
        "summary": _summarize_tool_result({"url": url}, tool_result),
    }


# ── Entry point ─────────────────────────────────────────────────────────────

def run_xss_agent(endpoints: list, *, max_iterations: int = 6, scope_config=None,
                  llm_config=None, llm_client=None,
                  auth_cookie: str | None = None) -> XssAgentResult:
    """Drive the LLM to hunt REFLECTED XSS across `endpoints` via the sandboxed
    run_dalfox tool.

    The model picks endpoints/parameters; if it stops early or never emits a usable
    tool call, a deterministic completion pass scans every unconfirmed endpoint once
    with the safe Dalfox profile. `auth_cookie` (e.g. "PHPSESSID=..; security=low")
    is threaded into every scan via --cookie — REQUIRED for authenticated targets
    like DVWA, optional for open ones. Scanning is bounded: at most
    _MAX_XSS_RUNS_PER_ENDPOINT Dalfox runs per endpoint.

    Fakes may be injected for tests via scope_config / llm_config / llm_client.
    injectable is derived SOLELY from parsed Dalfox [POC]/[V] output.
    """
    if scope_config is None:
        scope_config = load_scope_config()

    # ONE budget tracker for the whole run.
    if llm_client is None:
        if llm_config is None:
            llm_config = load_llm_config()
        tracker = BudgetTracker(llm_config)
        llm_client = LLMClient(llm_config, tracker)
    else:
        tracker = getattr(llm_client, "tracker", None)
        if tracker is None:
            tracker = BudgetTracker(llm_config if llm_config is not None else load_llm_config())

    auth_cookie = _sanitize_cookie(auth_cookie)

    system_prompt = _load_system_prompt()
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": _format_endpoints_user_message(endpoints, auth_cookie)},
    ]

    transcript: list[dict] = [
        {"role": "system", "action": "prompt", "summary": "loaded XSS agent system prompt"},
        {"role": "user", "action": "list_endpoints",
         "summary": f"{len(endpoints)} endpoint(s) queued for reflected-XSS testing"},
    ]
    candidates: list[XssCandidate] = []
    tool_executions = 0
    runs_per_endpoint: dict[str, int] = {}   # bounds scans per endpoint
    run_cap = _MAX_XSS_RUNS_PER_ENDPOINT
    executed_combos: set = set()             # (target_url, requested_param) already run
    confirmed_endpoints: set = set()         # endpoint keys Dalfox confirmed injectable
    model_confirmed = False                  # did the AGENT-driven phase confirm anything?
    iterations = 0
    stopped_reason = "max_iterations"

    for i in range(max_iterations):
        iterations = i + 1

        # Budget checked BEFORE each call — refuse rather than overspend.
        try:
            tracker.check_before_call()
        except BudgetExceededError:
            stopped_reason = "budget"
            transcript.append({"role": "system", "action": "budget_stop",
                               "summary": "budget exhausted before LLM call"})
            break

        try:
            reply = llm_client.chat(messages, tools=[RUN_DALFOX_TOOL])
        except BudgetExceededError:
            stopped_reason = "budget"
            transcript.append({"role": "system", "action": "budget_stop",
                               "summary": "budget exhausted during LLM call"})
            break
        except LLMError as exc:
            stopped_reason = "done"
            transcript.append({"role": "assistant", "action": "llm_error",
                               "summary": f"LLM call failed, stopping: {exc}"})
            break

        tool_calls = reply.get("tool_calls") or []
        if not tool_calls:
            transcript.append({"role": "assistant", "action": "final",
                               "summary": (reply.get("text") or "").strip()[:300]})
            stopped_reason = "done"
            break

        # Keep the conversation coherent for real providers.
        messages.append({"role": "assistant", "content": reply.get("text") or "",
                         "tool_calls": tool_calls})

        for tc in tool_calls:
            name, arguments, call_id = _parse_tool_call(tc)
            url_key = (arguments or {}).get("url")
            ep_key = _endpoint_key(url_key) if isinstance(url_key, str) else None
            if name != "run_dalfox":
                tool_result, candidate = {"ok": False, "error": f"unknown tool: {name}"}, None
            elif ep_key is not None and runs_per_endpoint.get(ep_key, 0) >= run_cap:
                # Per-endpoint scan ceiling — refuse, do not run Dalfox again.
                tool_result, candidate = {
                    "ok": False,
                    "scan_ceiling": True,
                    "error": f"scan ceiling reached for {url_key}; no further runs",
                }, None
            else:
                tool_result, candidate = _execute_run_dalfox(
                    arguments, scope_config=scope_config, auth_cookie=auth_cookie)
                if candidate is not None:
                    candidates.append(candidate)
                    tool_executions += 1
                    runs_per_endpoint[ep_key] = runs_per_endpoint.get(ep_key, 0) + 1
                    executed_combos.add((tool_result.get("target_url"),
                                         tool_result.get("requested_param")))
                    if candidate.injectable:
                        model_confirmed = True
                        confirmed_endpoints.add(ep_key)

            if candidate is not None or tool_result.get("status"):
                transcript.append(_scan_transcript(url_key, tool_result))
            else:
                transcript.append({"role": "tool", "action": name or "unknown",
                                   "summary": _summarize_tool_result(arguments, tool_result)})
            messages.append({
                "role": "tool",
                "tool_call_id": call_id,
                "name": "run_dalfox",
                "content": json.dumps(tool_result),
            })

    # ── Deterministic completion pass ────────────────────────────────────────
    # Runs at loop end for ANY non-budget stop (not only when the model emitted no
    # tool call). It scans every endpoint the agent-driven phase did NOT already
    # confirm injectable, SKIPPING combos already executed and respecting the
    # per-endpoint cap. This guarantees a real result even when a weak model stops
    # early or never makes a usable tool call. It never runs after a budget stop.
    entered_reason = stopped_reason
    ladder_confirmed = False
    if entered_reason != "budget":
        transcript.append({"role": "system", "action": "completion_pass",
                           "summary": "scanning endpoints not yet confirmed injectable "
                                      "with the safe Dalfox profile"})
        for ep in endpoints:
            url = _endpoint_field(ep, "url", "")
            inputs = _endpoint_field(ep, "inputs", []) or []
            param = _primary_param(url, inputs)
            ep_key = _endpoint_key(url)
            if ep_key in confirmed_endpoints:
                continue                              # agent phase already confirmed it
            if runs_per_endpoint.get(ep_key, 0) >= run_cap:
                continue                              # per-endpoint budget exhausted
            if (url, param) in executed_combos:
                continue                              # already run in the agent phase

            tool_result, candidate = _run_one_scan(
                url, param=param, scope_config=scope_config, auth_cookie=auth_cookie)
            tool_result["target_url"] = url
            transcript.append(_scan_transcript(url, tool_result))
            if candidate is not None:
                candidates.append(candidate)
                executed_combos.add((url, param))
                runs_per_endpoint[ep_key] = runs_per_endpoint.get(ep_key, 0) + 1
                if candidate.injectable:
                    ladder_confirmed = True
                    confirmed_endpoints.add(ep_key)

    # Final stopped_reason: a model-driven confirmation is a clean "done"; a
    # confirmation ONLY the completion pass produced is "completed_by_ladder";
    # otherwise the reason the loop exited (done / max_iterations) stands. A budget
    # stop is terminal and never reaches the completion pass, so it is preserved.
    if model_confirmed:
        stopped_reason = "done"
    elif ladder_confirmed:
        stopped_reason = "completed_by_ladder"
    else:
        stopped_reason = entered_reason

    return XssAgentResult(
        candidates=candidates,
        usage=tracker.usage,
        iterations=iterations,
        transcript=transcript,
        stopped_reason=stopped_reason,
    )


# ── Opt-in live smoke test ──────────────────────────────────────────────────
if __name__ == "__main__":
    # Requires: .env configured (scope + LLM), sandbox image built
    # (bash docker/sandbox/build.sh), a running Ollama, and a reachable DVWA with
    # its database created + Security level set to Low. .env is loaded automatically
    # below — no need to `source .env` first; real exported env vars still win.
    #
    # DVWA's reflected-XSS endpoint requires an authenticated session, so pass the
    # PHPSESSID + security=low cookies via REDSEE_XSS_COOKIE (the same env var
    # modules/xss.py's agent-backed scan_xss reads), e.g.:
    #   REDSEE_XSS_COOKIE="PHPSESSID=<sid>; security=low" \
    #   REDSEE_AUTHORIZED=true REDSEE_ALLOWED_HOSTS=redsees.com \
    #   REDSEE_LLM_BASE_URL=http://localhost:11434/v1 REDSEE_LLM_MODEL=llama3.2 \
    #   REDSEE_LLM_MAX_USD=5 PYTHONPATH=. python engine/xss_agent.py
    import os

    from engine.env import load_env
    load_env()

    from schemas import Endpoint

    cookie = os.environ.get("REDSEE_XSS_COOKIE") or None
    demo_endpoints = [
        Endpoint(
            url="http://redsees.com:8080/vulnerabilities/xss_r/?name=test",
            method="GET", form_action=None, inputs=["name"],
            cookies_needed=["PHPSESSID", "security"], endpoint_type="page",
        ),
    ]
    result = run_xss_agent(demo_endpoints, max_iterations=6, auth_cookie=cookie)
    print(f"stopped_reason={result.stopped_reason} iterations={result.iterations} "
          f"calls={result.usage.calls} cost=${result.usage.cost_usd:.4f}")
    if not cookie:
        print("  (no REDSEE_XSS_COOKIE set — DVWA's xss_r route needs auth; expect a "
              "login redirect and a clean/negative result)")
    print("scan path:")
    for step in result.transcript:
        if step.get("action") == "run_dalfox":
            print(f"  status={step.get('status')} param={step.get('parameter')!r} "
                  f"context={step.get('context')!r} injectable={step.get('injectable')}")
    for c in result.candidates:
        tag = c.status.upper()
        print(f"  [{tag}] {c.endpoint_url} param={c.parameter} context={c.context}")
        if c.injectable:
            print(f"    payload: {c.payload}")
            print("    evidence:", c.evidence[:200].replace("\n", " "))
