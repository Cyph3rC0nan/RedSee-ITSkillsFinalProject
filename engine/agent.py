# engine/agent.py
"""
SQLi agent loop — Layer 4 of the RedSee agent engine (the reasoning core).

Ties the three lower layers together in a plan -> act -> observe loop:
  * engine.llm     — the model PLANS which endpoint/parameter to test next.
  * engine.sandbox — sqlmap EXECUTES inside the isolated, egress-restricted box.
  * engine.scope   — every action is BOUNDED by the authorized scope gate.

Profile: detection-first and safe-by-default. The model never supplies sqlmap
flags — the harness owns a fixed read-only profile and refuses forbidden flags.
An "injectable" conclusion is derived ONLY from parsed sqlmap output, never from
the model's assertion. The loop is bounded by iterations and budget and never
runs anything out of scope or outside the sandbox.

This layer produces a structured intermediate result (SqliAgentResult) plus a
transcript for run.json. It does NOT map results into schemas.Finding and does
NOT wire into integration.py / modules/sqli.py — that is the next layer.
"""

import json
import re
import urllib.parse
from dataclasses import dataclass
from pathlib import Path

from engine.scope import ScopeConfig, ScopeError, assert_in_scope, load_scope_config
from engine.sandbox import SandboxError, run_in_sandbox
from engine.llm import (
    BudgetExceededError, BudgetTracker, LLMClient, LLMError, Usage, load_llm_config,
)

_PROMPT_PATH = Path(__file__).resolve().parent.parent / "prompts" / "sqli_agent.txt"

# Fixed, safe, DETECTION-ONLY base flags shared by EVERY rung. The --level/--risk
# (and optional --technique) come from the ladder rung, never from the model.
# NOTE: no --banner / --current-db / --current-user here — those make sqlmap RETRIEVE
# data (banner, db name, user) AFTER confirming injection, i.e. light exploitation.
# We only need the injection verdict, which sqlmap prints without them. --answers
# forces "no" to every post-confirmation prompt so --batch cannot auto-proceed into
# exploitation: detection stops the instant the injection point is confirmed.
_BASE_PROFILE = [
    "--batch", "--threads=1", "--disable-coloring",
    "--answers=exploit=N,keep testing=N,dump=N,follow=N",
]

# The ONLY sqlmap detection techniques a rung may request, mapped 1:1 to sqlmap's
# --technique letters: Boolean, Error, Union, Stacked, Time. A rung may only ever
# ADD techniques from this set (never restrict to a single one) — and by default
# rungs pass NO --technique so sqlmap uses its full default set, which is what
# actually detects the blind (boolean/time-based) injection on the Juice Shop lab.
_ALLOWED_TECHNIQUES = frozenset("BEUST")

# Flags that must NEVER appear at ANY rung — enforced by assertion in the argv
# builder so a regression cannot smuggle a destructive/exfil action into a
# "detection" run, no matter how high the level/risk ceiling is raised. This covers
# BOTH exploitation (shells/file/eval) AND data enumeration/retrieval (banner, users,
# dbs, tables, ...) — anything beyond confirming the injection point is out of scope.
_FORBIDDEN_LITERAL = {
    "--os-shell", "--os-cmd", "--os-pwn", "--sql-shell",
    "--file-read", "--file-write", "--file-dest",
    "--dump", "--dump-all", "--passwords", "--privileges",
    "--udf-inject", "--eval",
    "--banner", "--current-db", "--current-user", "--hostname",
    "--users", "--dbs", "--tables", "--columns", "--schema",
}

# Default level/risk CEILING for a run. Deliberately the SAFER level 3 / risk 2,
# NOT sqlmap's maximum — a caller must opt in to the aggressive rung explicitly.
_DEFAULT_MAX_LEVEL = 3
_DEFAULT_MAX_RISK = 2

# How many distinct probe values the deterministic fallback may try per endpoint.
# The per-endpoint run cap is len(LADDER) * this, keeping escalation bounded.
_MAX_PROBE_VALUES = 2

_SANDBOX_TIMEOUT_SEC = 180


# ── Detection-depth ladder ──────────────────────────────────────────────────

@dataclass(frozen=True)
class LadderRung:
    """One rung of the detection escalation ladder (detection-only, no exfil)."""
    depth: int
    level: int
    risk: int
    technique: str | None = None   # ADDED sqlmap techniques (subset of BEUST), or None


# Ordered lowest -> highest. Each rung reuses _BASE_PROFILE and escalates purely by
# DEPTH (level/risk). No rung forces a single technique — sqlmap chooses techniques
# from its full default set, which is what detects the blind SQLi. rung 2
# (level 5 / risk 3) is the aggressive ceiling, only runnable when the caller lifts
# max_level/max_risk to 5/3.
LADDER = [
    LadderRung(depth=0, level=1, risk=1, technique=None),  # fast baseline
    LadderRung(depth=1, level=3, risk=2, technique=None),  # deeper (confirms blind SQLi)
    LadderRung(depth=2, level=5, risk=3, technique=None),  # aggressive (ceiling)
]

# The single tool exposed to the model. It supplies only a URL (+ optional POST
# body / note) — never sqlmap flags.
RUN_SQLMAP_TOOL = {
    "type": "function",
    "function": {
        "name": "run_sqlmap",
        "description": (
            "Run sqlmap against ONE in-scope URL inside an isolated sandbox using a "
            "fixed, safe, detection-only profile. You do not control sqlmap flags — "
            "you only choose the URL, the escalation depth, and optionally a probe "
            "value likely to return real results. Higher depth means a deeper "
            "(slower) detection scan. Returns whether sqlmap confirmed the parameter "
            "injectable, plus the parameter, technique, and DBMS when found, an "
            "escalation hint, the probe value used, and the rung that actually ran."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "Full in-scope URL to test (include the query string for GET parameters).",
                },
                "data": {
                    "type": "string",
                    "description": "Optional POST body to test POST parameters (e.g. 'id=1&submit=1').",
                },
                "depth": {
                    "type": "integer",
                    "description": (
                        "Detection depth / escalation rung (0 = fast baseline, higher = "
                        "deeper). Start at 0; only raise it if the previous run was not "
                        "injectable and the result said escalation is allowed. Values "
                        "above the allowed ceiling are automatically clamped down."
                    ),
                },
                "probe_value": {
                    "type": "string",
                    "description": (
                        "Optional value to inject for the tested parameter, chosen to "
                        "return REAL results (e.g. a common word like 'apple' for a "
                        "search param, an existing id like '3' for an id param). A value "
                        "that returns rows gives sqlmap a baseline to compare against; a "
                        "dead value (empty / '1' that returns nothing) makes blind SQLi "
                        "undetectable. Must be a short URL-safe scalar (no spaces, "
                        "quotes, or flag characters); invalid values are ignored and the "
                        "harness picks a sensible default."
                    ),
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
class SqliCandidate:
    endpoint_url: str
    parameter: str | None
    injectable: bool
    technique: str | None
    dbms: str | None
    evidence: str            # raw sqlmap excerpt (empty allowed for non-injectable)
    sqlmap_argv: list[str]
    depth: int = 0           # ladder rung that produced this result
    # Outcome of the rung: "injectable" (parsed positive), "clean" (sqlmap actually
    # ran, exit 0, no positive), or "error" (sandbox/isolation abort, target
    # unreachable, sqlmap timeout, or non-zero exit — the scan did NOT produce a
    # verdict). "error" must NEVER be presented as a clean not-injectable result.
    status: str = "clean"
    error: str | None = None   # reason string when status == "error"


@dataclass
class SqliAgentResult:
    candidates: list[SqliCandidate]
    usage: Usage
    iterations: int
    transcript: list[dict]   # each step: {role, action, summary} for run.json
    stopped_reason: str      # done|max_iterations|budget|completed_by_ladder|error


# ── sqlmap argv builder + forbidden-flag guard ──────────────────────────────

def _numeric_flag_value(argv: list[str], name: str):
    """Return the int value of --name=N or (--name N), or None if absent/unparsable."""
    for i, tok in enumerate(argv):
        if tok == name and i + 1 < len(argv):
            try:
                return int(argv[i + 1])
            except ValueError:
                return None
        if tok.startswith(name + "="):
            try:
                return int(tok.split("=", 1)[1])
            except ValueError:
                return None
    return None


def _string_flag_value(argv: list[str], name: str):
    """Return the string value of --name=V or (--name V), or None if absent."""
    for i, tok in enumerate(argv):
        if tok == name and i + 1 < len(argv):
            return argv[i + 1]
        if tok.startswith(name + "="):
            return tok.split("=", 1)[1]
    return None


def _assert_no_forbidden_flags(argv: list[str], *,
                               max_level: int = _DEFAULT_MAX_LEVEL,
                               max_risk: int = _DEFAULT_MAX_RISK) -> list[str]:
    """Fail loudly if the argv would exceed the safety envelope.

    Destructive/exfil flags are ALWAYS banned regardless of ceiling. --level and
    --risk may not exceed the configured ceiling. --technique, if present, may only
    use letters from the allowed detection set {B,E,U,S,T}.
    """
    for tok in argv:
        flag = tok.split("=", 1)[0]
        assert flag not in _FORBIDDEN_LITERAL, f"forbidden sqlmap flag in argv: {tok!r}"
    level = _numeric_flag_value(argv, "--level")
    assert level is None or level <= max_level, \
        f"--level={level} exceeds ceiling {max_level}"
    risk = _numeric_flag_value(argv, "--risk")
    assert risk is None or risk <= max_risk, \
        f"--risk={risk} exceeds ceiling {max_risk}"
    technique = _string_flag_value(argv, "--technique")
    assert technique is None or (technique and set(technique) <= set(_ALLOWED_TECHNIQUES)), \
        f"forbidden sqlmap --technique in argv: {technique!r}"
    return argv


def _build_rung_argv(url: str, rung: LadderRung, data: str | None = None, *,
                     max_level: int = _DEFAULT_MAX_LEVEL,
                     max_risk: int = _DEFAULT_MAX_RISK) -> list[str]:
    """Construct the harness-owned sqlmap argv for one ladder rung."""
    argv = ["sqlmap", "-u", url, *_BASE_PROFILE,
            f"--level={rung.level}", f"--risk={rung.risk}"]
    if rung.technique:
        argv.append(f"--technique={rung.technique}")
    if data:
        argv += ["--data", data]
    return _assert_no_forbidden_flags(argv, max_level=max_level, max_risk=max_risk)


def _build_sqlmap_argv(url: str, data: str | None = None) -> list[str]:
    """Backward-compatible builder: the fast baseline rung (level 1 / risk 1)."""
    return _build_rung_argv(url, LADDER[0], data=data)


# ── Ladder selection under the configured ceiling ───────────────────────────

def _runnable_rungs(max_level: int, max_risk: int) -> list[LadderRung]:
    """Rungs permitted by the ceiling, lowest -> highest."""
    return [r for r in LADDER if r.level <= max_level and r.risk <= max_risk]


def _coerce_depth(value) -> int:
    """Best-effort int for a model-supplied depth; anything unusable -> 0."""
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


def _select_rung(depth: int, max_level: int, max_risk: int) -> LadderRung:
    """Pick the highest runnable rung whose depth <= requested depth.

    Requests above the ceiling are clamped down; the baseline rung is always
    available for any sane ceiling.
    """
    runnable = _runnable_rungs(max_level, max_risk)
    if not runnable:                       # pathological ceiling below rung 0
        return LADDER[0]
    eligible = [r for r in runnable if r.depth <= depth]
    return eligible[-1] if eligible else runnable[0]


# ── Probe-value selection (what we TRY — never how we CONCLUDE) ──────────────

# Ordered candidate values keyed by the KIND of parameter. A value that returns
# real rows gives sqlmap a baseline for blind detection; a dead value (empty / a
# bare "1" that matches nothing) silently defeats detection.
_SEARCH_PARAMS = {"q", "query", "search", "name", "term", "title", "keyword"}
_ID_PARAMS = {"id", "pid", "productid", "userid", "uid", "itemid"}
_EMAIL_PARAMS = {"email", "mail", "user", "username", "login"}

# Only short, URL-safe scalars: letters, digits, and the handful of symbols that
# appear in emails (a leading '-' is rejected separately so a value can't look like
# a flag). No spaces, quotes, or shell/flag metacharacters.
_PROBE_VALUE_RE = re.compile(r"^[A-Za-z0-9@._+-]+$")


def default_probe_values(param_name: str) -> list[str]:
    """Ordered default probe-value candidates for a parameter name (harness-owned)."""
    name = (param_name or "").strip().lower()
    if name in _SEARCH_PARAMS:
        return ["apple", "a", "test"]
    if name in _ID_PARAMS:
        return ["1", "2"]
    if name in _EMAIL_PARAMS:
        return ["test@test.com", "admin@juice-sh.op"]
    # Suggestive-but-unlisted names fall back to a kind heuristic.
    if "email" in name or "mail" in name:
        return ["test@test.com", "admin@juice-sh.op"]
    if name.endswith("id"):
        return ["1", "2"]
    if any(tok in name for tok in ("search", "query", "term", "name", "title", "keyword")):
        return ["apple", "a", "test"]
    return ["1", "apple", "test"]


def _sanitize_probe_value(value):
    """Validate a model-proposed probe value; return the safe value or None.

    Rejects non-strings, empties, anything over 64 chars, values that look like a
    flag (leading '-'), or that contain any character outside the URL-safe set.
    """
    if not isinstance(value, str):
        return None
    v = value.strip()
    if not v or len(v) > 64 or v.startswith("-"):
        return None
    return v if _PROBE_VALUE_RE.fullmatch(v) else None


def _is_weak_value(value) -> bool:
    """A value that gives sqlmap nothing to compare against: empty or a bare '1'."""
    if value is None:
        return True
    s = str(value).strip()
    return s == "" or s == "1"


def _set_query_param(url: str, param: str, value: str) -> str:
    """Return url with query parameter `param` set to `value` (added if absent)."""
    try:
        parts = urllib.parse.urlsplit(url)
    except (ValueError, AttributeError):
        return url
    pairs = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    out, found = [], False
    for k, v in pairs:
        if k == param:
            out.append((k, value))
            found = True
        else:
            out.append((k, v))
    if not found:
        out.append((param, value))
    return urllib.parse.urlunsplit(parts._replace(query=urllib.parse.urlencode(out)))


def _primary_param(url: str, inputs) -> str | None:
    """Best guess at the parameter under test: a declared input, else a query key."""
    for name in (inputs or []):
        if name:
            return name
    try:
        pairs = urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query,
                                       keep_blank_values=True)
    except (ValueError, AttributeError):
        pairs = []
    return pairs[0][0] if pairs else None


def _first_param_value(url: str) -> str | None:
    """Return the value of the first query parameter in `url`, or None.

    Used to record the probe value ACTUALLY carried by the tested URL — even when
    no substitution was made (the value was already fine), so the transcript never
    shows None while the URL carried e.g. q=apple.
    """
    try:
        pairs = urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query,
                                       keep_blank_values=True)
    except (ValueError, AttributeError):
        return None
    return pairs[0][1] if pairs else None


def _endpoint_key(url: str) -> str:
    """Stable per-ENDPOINT identity for the run cap: scheme+host+path+param NAMES.

    Query VALUES are stripped so q=1, q=apple and q=a all map to the same endpoint
    and share one per-endpoint escalation budget. Probe-value variation must not let
    a single endpoint exceed the run cap.
    """
    try:
        parts = urllib.parse.urlsplit(url)
        names = sorted(k for k, _ in urllib.parse.parse_qsl(parts.query,
                                                            keep_blank_values=True))
    except (ValueError, AttributeError):
        return url or ""
    return "|".join([parts.scheme, parts.netloc, parts.path, ",".join(names)])


def _improve_url_probes(url: str, *, proposed_value: str | None = None):
    """Substitute better probe values into a URL's query. Returns (new_url, applied).

    `applied` lists {parameter, value, source} for each substitution made. A valid
    agent-proposed value wins; otherwise weak values ('', bare '1') are replaced
    with the deterministic default for that parameter kind. Values already fine are
    left untouched.
    """
    try:
        parts = urllib.parse.urlsplit(url)
    except (ValueError, AttributeError):
        return url, []
    pairs = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    if not pairs:
        return url, []

    out, applied = [], []
    for k, v in pairs:
        if proposed_value is not None:
            candidate, source = proposed_value, "agent"
        elif _is_weak_value(v):
            candidate, source = default_probe_values(k)[0], "default"
        else:
            candidate, source = None, None
        if candidate is not None and candidate != v:
            out.append((k, candidate))
            applied.append({"parameter": k, "value": candidate, "source": source})
        else:
            out.append((k, v))
    new_url = urllib.parse.urlunsplit(parts._replace(query=urllib.parse.urlencode(out)))
    return new_url, applied


# ── sqlmap output parsing (source of truth for "injectable") ─────────────────

# Positive verdict signals in sqlmap's REAL output (validated against sqlmap 1.9.6).
# None of these is a bare "injectable" token, so a clean phrase like
# "does not seem to be injectable" cannot match a positive.
_POS_PARAM_VULN_RE = re.compile(
    r"(?:GET|POST|URI|COOKIE)?\s*parameter\s+'([^']+)'\s+is\s+vulnerable", re.I)
_POS_IDENTIFIED_RE = re.compile(r"identified the following injection point", re.I)

# The authoritative "Parameter: <name> (<METHOD>)" block and its "Type:" lines.
_PARAM_LINE_RE = re.compile(r"^\s*Parameter:\s*([^\s(]+)", re.I | re.M)
_TYPE_LINE_RE = re.compile(r"^\s*Type:\s*(.+?)\s*$", re.I | re.M)
_PARAM_BLOCK_START_RE = re.compile(r"^\s*Parameter:\s", re.I | re.M)

# DBMS — both wordings sqlmap uses: "back-end DBMS: X" and "the back-end DBMS is X".
_DBMS_PATTERNS = [
    re.compile(r"back-end DBMS:\s*(.+)", re.I),
    re.compile(r"back-end DBMS is\s+([^\n.]+)", re.I),
]

# "not injectable" verdicts — these NEVER set injectable=True. They double as the
# explicit NEGATIVE GUARD: any line asserting non-injectability is stripped before
# positive matching, so an "injectable" substring inside "not ... injectable" can
# never flip the result true. They also (separately) drive the escalation hint.
_NOT_INJECTABLE_PATTERNS = [
    re.compile(r"does not seem to be injectable", re.I),
    re.compile(r"do(?:es)? not appear to be injectable", re.I),
    re.compile(r"\bnot injectable\b", re.I),
]
# sqlmap's own suggestion to raise the detection depth.
_ESCALATE_PATTERNS = [
    re.compile(r"(?:increase|higher).{0,40}(?:--level|--risk|\blevel\b|\brisk\b)", re.I | re.S),
    re.compile(r"(?:--level|--risk).{0,40}(?:option|switch|value)", re.I | re.S),
    re.compile(r"rerun sqlmap.{0,80}(?:--level|--risk)", re.I | re.S),
]


def _strip_clean_verdict_lines(text: str) -> str:
    """Drop lines that assert non-injectability (the explicit negative guard).

    Removing these lines before positive matching means a clean per-parameter
    verdict can never contribute an "injectable" substring to a positive signal,
    while any genuine "is vulnerable" / injection-point lines are preserved.
    """
    return "\n".join(
        line for line in text.splitlines()
        if not any(neg.search(line) for neg in _NOT_INJECTABLE_PATTERNS)
    )


def _parse_sqlmap_output(stdout: str) -> dict:
    """Decide injectability and extract parameter/technique(s)/dbms/evidence.

    'injectable' comes strictly from sqlmap's own positive injection signals —
    never from a caller's claim, never from DBMS detection, never from the
    escalation hint. The escalation_hint / dbms fields are advisory only and
    cannot flip injectable to True.
    """
    text = stdout or ""

    # Negative guard first: strip clean-verdict lines, THEN look for positives.
    scan = _strip_clean_verdict_lines(text)
    injectable = bool(
        _POS_PARAM_VULN_RE.search(scan)
        or _POS_IDENTIFIED_RE.search(scan)
        or (_PARAM_LINE_RE.search(scan) and _TYPE_LINE_RE.search(scan))
    )

    # Parameter: prefer the authoritative "Parameter:" block, else the verdict line.
    parameter = None
    m = _PARAM_LINE_RE.search(text)
    if m:
        parameter = m.group(1).strip()
    else:
        m = _POS_PARAM_VULN_RE.search(text)
        if m:
            parameter = m.group(1).strip()

    # Technique(s): every "Type:" value under the Parameter block, in order.
    types = [t.strip() for t in _TYPE_LINE_RE.findall(text) if t.strip()]
    technique = ", ".join(types) if types else None

    # DBMS: first of the two wordings that matches.
    dbms = None
    for p in _DBMS_PATTERNS:
        m = p.search(text)
        if m:
            dbms = m.group(1).strip()
            break

    # Evidence: the "Parameter:" block through its Payload line(s), capped ~600
    # chars; else the injection-point / verdict line; else a short tail excerpt.
    block = _PARAM_BLOCK_START_RE.search(text)
    if block:
        evidence = text[block.start():block.start() + 600].strip()
    else:
        lowered = text.lower()
        idx = lowered.find("identified the following injection point")
        if idx == -1:
            idx = lowered.find(" is vulnerable")
        evidence = text[idx:idx + 600].strip() if idx != -1 else text[-400:].strip()

    # Advisory only: suggest escalation when sqlmap declared "not injectable" at this
    # depth or hinted at raising --level/--risk. Never when injection was confirmed.
    escalation_hint = (not injectable) and (
        any(p.search(text) for p in _NOT_INJECTABLE_PATTERNS)
        or any(p.search(text) for p in _ESCALATE_PATTERNS)
    )

    return {
        "injectable": injectable,
        "parameter": parameter,
        "technique": technique,
        "dbms": dbms,
        "evidence": evidence,
        "escalation_hint": escalation_hint,
    }


# ── Harness-owned tool execution ────────────────────────────────────────────

def _run_one_rung(url: str, data: str | None, rung: LadderRung, *,
                  scope_config: ScopeConfig, max_level: int, max_risk: int,
                  timeout_sec: int = _SANDBOX_TIMEOUT_SEC):
    """Execute a single ladder rung. Returns (tool_result, candidate).

    candidate is non-None ONLY when sqlmap actually ran in the sandbox (scope
    passed and execution succeeded), regardless of injectable True/False. Scope
    refusals and sandbox failures return (tool_result, None).
    """
    # Scope gate BEFORE any execution. Refuse (don't run) if out of scope. This is a
    # REFUSAL, not a scan — status "out_of_scope" so it is never read as "clean".
    try:
        assert_in_scope(url, scope_config)
    except ScopeError:
        return {
            "ok": False,
            "status": "out_of_scope",
            "out_of_scope": True,
            "error": f"URL is out of scope and was NOT tested: {url}",
        }, None

    argv = _build_rung_argv(url, rung, data, max_level=max_level, max_risk=max_risk)

    # ALL sqlmap execution goes through the sandbox — never the host. A sandbox
    # failure (isolation abort, target unreachable, etc.) is an ERROR, not a verdict:
    # record status="error" with the reason so a dead target can never masquerade as
    # a clean "not injectable" result.
    try:
        sr = run_in_sandbox(argv, target_url=url, config=scope_config,
                            timeout_sec=timeout_sec)
    except (SandboxError, ScopeError) as exc:
        reason = f"sandbox execution failed: {exc}"
        candidate = SqliCandidate(
            endpoint_url=url, parameter=None, injectable=False, technique=None,
            dbms=None, evidence="", sqlmap_argv=argv, depth=rung.depth,
            status="error", error=reason,
        )
        tool_result = {
            "ok": False, "status": "error", "error": reason,
            "url": url, "depth": rung.depth, "level": rung.level, "risk": rung.risk,
            "injectable": False,
        }
        return tool_result, candidate

    parsed = _parse_sqlmap_output(sr.stdout)
    # 'injectable' ALWAYS comes from parsed positive output; a confirmed injection
    # wins even over an odd exit code. Otherwise a timeout or a non-zero exit means
    # the scan did not complete → ERROR; only a real exit-0 run with no positive is
    # a genuine "clean" not-injectable verdict.
    if parsed["injectable"]:
        status, error = "injectable", None
    elif sr.timed_out:
        status, error = "error", "sqlmap timed out before returning a verdict"
    elif sr.exit_code != 0:
        status, error = "error", f"sqlmap exited with non-zero code {sr.exit_code}"
    else:
        status, error = "clean", None

    candidate = SqliCandidate(
        endpoint_url=url,
        parameter=parsed["parameter"],
        injectable=parsed["injectable"],
        technique=parsed["technique"],
        dbms=parsed["dbms"],
        evidence=parsed["evidence"],
        sqlmap_argv=argv,
        depth=rung.depth,
        status=status,
        error=error,
    )
    tool_result = {
        "ok": status != "error",
        "status": status,
        "error": error,
        "url": url,
        "depth": rung.depth,
        "level": rung.level,
        "risk": rung.risk,
        "technique_flag": rung.technique,
        "injectable": parsed["injectable"],
        "parameter": parsed["parameter"],
        "technique": parsed["technique"],
        "dbms": parsed["dbms"],
        "escalation_hint": parsed["escalation_hint"],
        "max_depth_available": _runnable_rungs(max_level, max_risk)[-1].depth,
        "timed_out": sr.timed_out,
        "exit_code": sr.exit_code,
        "evidence_excerpt": parsed["evidence"][:400],
    }
    return tool_result, candidate


def _execute_run_sqlmap(arguments: dict, *, scope_config: ScopeConfig,
                        max_level: int = _DEFAULT_MAX_LEVEL,
                        max_risk: int = _DEFAULT_MAX_RISK,
                        timeout_sec: int = _SANDBOX_TIMEOUT_SEC):
    """Dispatch a model tool call to a ladder rung. Returns (tool_result, candidate, rung).

    The model supplies only url/data/note/depth/probe_value — never flags. `depth`
    selects a rung (clamped to the ceiling); a valid `probe_value` (or a
    deterministic default for weak values) is substituted into the query so blind
    SQLi is detectable. Malformed args return (tool_result, None, None).
    """
    args = arguments or {}
    url = args.get("url")
    data = args.get("data")

    if not url or not isinstance(url, str):
        return {"ok": False, "error": "run_sqlmap requires a string 'url'"}, None, None

    raw_probe = args.get("probe_value")
    proposed = _sanitize_probe_value(raw_probe)
    probe_rejected = raw_probe is not None and proposed is None

    target_url, applied = _improve_url_probes(url, proposed_value=proposed)
    rung = _select_rung(_coerce_depth(args.get("depth")), max_level, max_risk)
    data_val = data if isinstance(data, str) and data else None
    tool_result, candidate = _run_one_rung(
        target_url, data_val, rung, scope_config=scope_config,
        max_level=max_level, max_risk=max_risk, timeout_sec=timeout_sec)

    # Annotate which probe value(s) were actually used (never changes injectable).
    # probe_value reflects the value the URL ACTUALLY carries into sqlmap: the
    # substituted one if we changed it, else whatever was already there (so it is
    # never None while the URL carries e.g. q=apple).
    tool_result["target_url"] = target_url
    tool_result["probe_values"] = applied
    tool_result["probe_value"] = (applied[0]["value"] if applied
                                  else _first_param_value(target_url))
    if probe_rejected:
        tool_result["probe_value_rejected"] = True
    return tool_result, candidate, rung


# ── Helpers ─────────────────────────────────────────────────────────────────

def _endpoint_field(ep, name: str, default=None):
    if hasattr(ep, name):
        return getattr(ep, name)
    if isinstance(ep, dict):
        return ep.get(name, default)
    return default


def _load_system_prompt() -> str:
    try:
        return _PROMPT_PATH.read_text(encoding="utf-8")
    except OSError:
        return (
            "You are RedSee's SQL-injection agent. Use ONLY the run_sqlmap tool on "
            "in-scope URLs, one at a time; base conclusions on tool output; stop when done."
        )


def _format_endpoints_user_message(endpoints: list) -> str:
    lines = [
        "Test the following authorized in-scope endpoints for SQL injection using the "
        "run_sqlmap tool, one at a time:",
        "",
    ]
    for i, ep in enumerate(endpoints, 1):
        url = _endpoint_field(ep, "url", "")
        method = _endpoint_field(ep, "method", "GET") or "GET"
        inputs = _endpoint_field(ep, "inputs", []) or []
        lines.append(f"{i}. [{method}] {url}  params={list(inputs)}")
    if len(endpoints) == 0:
        lines.append("(no endpoints provided)")
    return "\n".join(lines)


def _parse_tool_call(tc: dict):
    """Extract (name, arguments_dict, call_id) from an OpenAI-shaped tool call."""
    fn = tc.get("function", {}) if isinstance(tc, dict) else {}
    name = fn.get("name")
    raw_args = fn.get("arguments")
    if isinstance(raw_args, str):
        try:
            arguments = json.loads(raw_args) if raw_args.strip() else {}
        except json.JSONDecodeError:
            arguments = {}
    elif isinstance(raw_args, dict):
        arguments = raw_args
    else:
        arguments = {}
    call_id = (tc.get("id") if isinstance(tc, dict) else None) or "call_0"
    return name, arguments, call_id


def _summarize_tool_result(arguments: dict, tool_result: dict) -> str:
    url = (arguments or {}).get("url", "?")
    if not tool_result.get("ok"):
        return f"{url}: {tool_result.get('error', 'skipped')}"
    depth = tool_result.get("depth")
    inj = "INJECTABLE" if tool_result.get("injectable") else "not injectable"
    param = tool_result.get("parameter")
    probe = tool_result.get("probe_value")
    tail = f" (param={param})" if param else ""
    if probe is not None:
        tail += f" probe={probe!r}"
    if not tool_result.get("injectable") and tool_result.get("escalation_hint"):
        tail += " [escalation hint]"
    return f"{url} @depth{depth}: {inj}{tail}"


def _rung_transcript(url: str, rung, tool_result: dict) -> dict:
    """Structured transcript step recording one rung attempt for run.json."""
    return {
        "role": "tool",
        "action": "run_sqlmap",
        "url": url,
        "target_url": tool_result.get("target_url", url),
        "probe_value": tool_result.get("probe_value"),
        "depth": rung.depth if rung is not None else None,
        "level": rung.level if rung is not None else None,
        "risk": rung.risk if rung is not None else None,
        "technique": rung.technique if rung is not None else None,
        "injectable": bool(tool_result.get("injectable")),
        "status": tool_result.get("status")
                  or ("error" if not tool_result.get("ok") else "clean"),
        "error": tool_result.get("error"),
        "dbms": tool_result.get("dbms"),
        "escalation_hint": bool(tool_result.get("escalation_hint")),
        "summary": _summarize_tool_result({"url": url}, tool_result),
    }


# ── Entry point ─────────────────────────────────────────────────────────────

def run_sqli_agent(endpoints: list, *, max_iterations: int = 6,
                   approve_dump: bool = False, max_level: int = _DEFAULT_MAX_LEVEL,
                   max_risk: int = _DEFAULT_MAX_RISK, scope_config=None,
                   llm_config=None, llm_client=None) -> SqliAgentResult:
    """Drive the LLM to hunt SQLi across `endpoints` via the sandboxed run_sqlmap tool.

    Detection escalates along a bounded ladder of increasing depth. The model may
    escalate on its own by passing a higher `depth`; if it never does, a
    deterministic fallback walks the ladder. `max_level`/`max_risk` cap how deep
    escalation is allowed (default 3/2 — the safer ceiling; pass 5/3 to permit the
    aggressive rung). Escalation is bounded: at most len(LADDER) sqlmap runs per URL.

    Fakes may be injected for tests via scope_config / llm_config / llm_client.
    approve_dump is reserved for a future human-in-the-loop step; while False
    (default) no data-dumping flags are ever added (none are implemented here).
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

    system_prompt = _load_system_prompt()
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": _format_endpoints_user_message(endpoints)},
    ]

    transcript: list[dict] = [
        {"role": "system", "action": "prompt", "summary": "loaded SQLi agent system prompt"},
        {"role": "user", "action": "list_endpoints",
         "summary": f"{len(endpoints)} endpoint(s) queued for testing"},
    ]
    candidates: list[SqliCandidate] = []
    tool_executions = 0
    # Per-ENDPOINT run budget (values stripped) so q=1/q=apple/q=a share one cap.
    runs_per_endpoint: dict[str, int] = {}
    run_cap = len(LADDER) * _MAX_PROBE_VALUES   # rungs x probe-value candidates
    executed_combos: set = set()        # (target_url, depth) already run this session
    confirmed_endpoints: set = set()    # endpoint keys sqlmap confirmed injectable
    model_confirmed = False             # did the AGENT-driven phase confirm anything?
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
            reply = llm_client.chat(messages, tools=[RUN_SQLMAP_TOOL])
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
            rung = None
            url_key = (arguments or {}).get("url")
            ep_key = _endpoint_key(url_key) if isinstance(url_key, str) else None
            if name != "run_sqlmap":
                tool_result, candidate = {"ok": False, "error": f"unknown tool: {name}"}, None
            elif ep_key is not None and runs_per_endpoint.get(ep_key, 0) >= run_cap:
                # Escalation ceiling per ENDPOINT — refuse, do not run sqlmap again.
                tool_result, candidate = {
                    "ok": False,
                    "escalation_ceiling": True,
                    "error": f"escalation ceiling reached for {url_key}; no further runs",
                }, None
            else:
                tool_result, candidate, rung = _execute_run_sqlmap(
                    arguments, scope_config=scope_config,
                    max_level=max_level, max_risk=max_risk)
                if candidate is not None:
                    candidates.append(candidate)
                    tool_executions += 1
                    runs_per_endpoint[ep_key] = runs_per_endpoint.get(ep_key, 0) + 1
                    executed_combos.add((tool_result.get("target_url"), rung.depth))
                    if candidate.injectable:
                        model_confirmed = True
                        confirmed_endpoints.add(ep_key)

            if rung is not None:
                transcript.append(_rung_transcript(url_key, rung, tool_result))
            else:
                transcript.append({"role": "tool", "action": name or "unknown",
                                   "summary": _summarize_tool_result(arguments, tool_result)})
            messages.append({
                "role": "tool",
                "tool_call_id": call_id,
                "name": "run_sqlmap",
                "content": json.dumps(tool_result),
            })

    # ── Deterministic completion pass ────────────────────────────────────────
    # Runs at loop end for ANY non-budget stop (not only when the model emitted no
    # tool call). It walks the detection ladder x probe values for every endpoint the
    # agent-driven phase did NOT already confirm injectable, SKIPPING combos already
    # executed and respecting the per-endpoint run cap. This closes the escalation
    # gap: a weak model that stops at a shallow "clean" result can no longer suppress
    # deeper detection while permitted combos remain. It never runs after a budget
    # stop (that state is terminal) and cannot exceed the per-endpoint run cap.
    entered_reason = stopped_reason
    ladder_confirmed = False
    if entered_reason != "budget":
        rungs = _runnable_rungs(max_level, max_risk)
        transcript.append({"role": "system", "action": "completion_pass",
                           "summary": "walking detection ladder x probe values for "
                                      "endpoints not yet confirmed injectable"})
        for ep in endpoints:
            url = _endpoint_field(ep, "url", "")
            method = (_endpoint_field(ep, "method", "GET") or "GET").upper()
            inputs = _endpoint_field(ep, "inputs", []) or []
            param = _primary_param(url, inputs)
            ep_key = _endpoint_key(url)
            if ep_key in confirmed_endpoints:
                continue                              # agent phase already confirmed it

            if method == "POST":
                data = "&".join(f"{name}=1" for name in inputs) or None
                probe_values = [None]                 # body probing kept deterministic
            else:
                data = None
                probe_values = (default_probe_values(param)[:_MAX_PROBE_VALUES]
                                if param else [None])

            done = False
            for value in probe_values:                # try the next value when clean
                target = _set_query_param(url, param, value) if (
                    param and value is not None and method != "POST") else url
                for rung in rungs:
                    if runs_per_endpoint.get(ep_key, 0) >= run_cap:
                        done = True                   # per-endpoint budget exhausted
                        break
                    combo = (target, rung.depth)
                    if combo in executed_combos:
                        continue                      # already run in the agent phase
                    tool_result, candidate = _run_one_rung(
                        target, data, rung, scope_config=scope_config,
                        max_level=max_level, max_risk=max_risk)
                    # Record the probe value the URL ACTUALLY carried (never None
                    # while the URL had e.g. q=apple).
                    tool_result["target_url"] = target
                    tool_result["probe_value"] = (value if value is not None
                                                  else _first_param_value(target))
                    transcript.append(_rung_transcript(url, rung, tool_result))
                    if candidate is not None:
                        candidates.append(candidate)
                        executed_combos.add(combo)
                        runs_per_endpoint[ep_key] = runs_per_endpoint.get(ep_key, 0) + 1
                        if candidate.injectable:
                            ladder_confirmed = True
                            confirmed_endpoints.add(ep_key)
                            done = True               # confirmed — stop this endpoint
                            break
                        if candidate.status == "error":
                            done = True               # infra error — don't hammer it
                            break
                    if tool_result.get("out_of_scope"):
                        done = True                   # never in scope — skip endpoint
                        break
                if done:
                    break

    # Final stopped_reason: a model-driven confirmation is a clean "done"; a
    # confirmation ONLY the completion pass produced is "completed_by_ladder";
    # if NOTHING actually scanned (every attempt errored — e.g. target unreachable)
    # that is surfaced as "error", never a clean "done"; otherwise the reason the
    # loop exited (done / max_iterations) stands. A budget stop is terminal and never
    # reaches the completion pass, so it is preserved.
    #
    # An endpoint counts as genuinely scanned ("clean" or "injectable") only when a
    # rung actually executed and sqlmap returned a real verdict.
    scanned_ok = any(c.status in ("clean", "injectable") for c in candidates)
    had_error = any(c.status == "error" for c in candidates)
    if model_confirmed:
        stopped_reason = "done"
    elif ladder_confirmed:
        stopped_reason = "completed_by_ladder"
    elif had_error and not scanned_ok:
        stopped_reason = "error"
    else:
        stopped_reason = entered_reason

    return SqliAgentResult(
        candidates=candidates,
        usage=tracker.usage,
        iterations=iterations,
        transcript=transcript,
        stopped_reason=stopped_reason,
    )


# ── Opt-in live smoke test ──────────────────────────────────────────────────
if __name__ == "__main__":
    # Requires: .env configured (scope + LLM), sandbox image built
    # (bash docker/sandbox/build.sh), a running Ollama, and a reachable Juice Shop.
    # .env is loaded automatically below — no need to `source .env` first;
    # real exported env vars still win (load_env uses override=False).
    #   REDSEE_AUTHORIZED=true REDSEE_ALLOWED_HOSTS=redsees.com \
    #   REDSEE_LLM_BASE_URL=http://localhost:11434/v1 REDSEE_LLM_MODEL=llama3.1 \
    #   PYTHONPATH=. python engine/agent.py
    from engine.env import load_env
    load_env()

    from schemas import Endpoint

    demo_endpoints = [
        # Realistic probe value: q=apple returns rows, giving sqlmap a baseline so
        # the boolean/time-based blind injection is detectable (q=1 returns nothing).
        Endpoint(
            url="http://redsees.com:3000/rest/products/search?q=apple",
            method="GET", form_action=None, inputs=["q"],
            cookies_needed=[], endpoint_type="api",
        ),
    ]
    # LAB ONLY: lift the ceiling to the aggressive rung (level 5 / risk 3). Do NOT
    # do this against production targets — the default 3/2 ceiling is the safe one.
    result = run_sqli_agent(demo_endpoints, max_iterations=6,
                            max_level=5, max_risk=3)
    print(f"stopped_reason={result.stopped_reason} iterations={result.iterations} "
          f"calls={result.usage.calls} cost=${result.usage.cost_usd:.4f}")
    if result.stopped_reason == "completed_by_ladder":
        print("  (the deterministic completion pass caught it after the model stopped early)")
    if result.stopped_reason == "error":
        print("  (NO endpoint was successfully scanned — every attempt errored; "
              "this is NOT a clean result)")
    print("escalation path:")
    caught = None
    for step in result.transcript:
        if step.get("action") == "run_sqlmap":
            status = step.get("status") or ("error" if step.get("error") else "clean")
            line = (f"  depth={step.get('depth')} level={step.get('level')} "
                    f"risk={step.get('risk')} probe={step.get('probe_value')!r} "
                    f"status={status}")
            if status == "injectable":
                line += f" dbms={step.get('dbms')}"
            elif status == "error":
                line += f" error={step.get('error')!r}"
            print(line)
            if status == "injectable" and caught is None:
                caught = step
    if caught is not None:
        print(f"caught at: depth={caught.get('depth')} level={caught.get('level')} "
              f"risk={caught.get('risk')} probe={caught.get('probe_value')!r}")

    # Errored endpoints (never actually scanned) are reported separately from both
    # clean and injectable results — a dead target is not a clean bill of health.
    errored, seen = [], set()
    for c in result.candidates:
        if c.status == "error" and c.endpoint_url not in seen:
            seen.add(c.endpoint_url)
            errored.append(c)
    if errored:
        print(f"errored (not scanned): {len(errored)} endpoint(s)")
        for c in errored:
            print(f"  [ERROR] {c.endpoint_url} depth={c.depth} reason={c.error}")

    for c in result.candidates:
        if c.status == "error":
            continue
        print(f"  [{c.status.upper()}] {c.endpoint_url} "
              f"depth={c.depth} param={c.parameter} technique={c.technique} dbms={c.dbms}")
        if c.injectable:
            print("    caught at:", c.endpoint_url, "rung depth", c.depth)
            print("    evidence:", c.evidence[:200].replace("\n", " "))
