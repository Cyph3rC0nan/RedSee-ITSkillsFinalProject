# engine/nuclei_agent.py
"""
Template-scan agent — a parallel to engine/agent.py (SQLi) and engine/xss_agent.py
(reflected XSS), driving nuclei instead of sqlmap/Dalfox inside the same isolated
sandbox.

Same proven shape: the model PLANS which target to scan (and optionally which
template TAGS to focus on), nuclei EXECUTES inside engine.sandbox (egress-restricted,
non-root, read-only), and engine.scope BOUNDS every action. The model never supplies
nuclei flags — the harness owns a fixed, DETECTION-ONLY profile (JSONL, no
OOB/interactsh, bundled templates, a severity floor that drops info-only noise, and an
exclude-tags list covering dos/intrusive/fuzz/brute/oob) and refuses forbidden
flags/tags. A "found" conclusion is derived ONLY from parsed nuclei JSONL result lines,
never from the model's assertion. The loop is bounded by iterations and budget, backed
by a deterministic completion pass, and never runs anything out of scope or outside the
sandbox.

This layer produces a structured intermediate result (NucleiAgentResult) plus a
transcript for run.json. It does NOT map results into schemas.Finding and does NOT wire
into integration.py / modules/ — that is the next layer (Prompt 3).
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
# Genuinely-generic helpers shared with the SQLi/XSS agents — imported, not copied.
from engine.agent import _endpoint_field, _parse_tool_call, _endpoint_key

_PROMPT_PATH = Path(__file__).resolve().parent.parent / "prompts" / "nuclei_agent.txt"

# nuclei can run a lot of templates against one host, so give it more headroom than
# the single-parameter Dalfox/sqlmap scans. Still a hard ceiling — a runaway scan is
# killed and surfaced as status="error", never a false "clean".
_SANDBOX_TIMEOUT_SEC = 300

# Completion-pass / per-target scan cap. One comprehensive scan covers a whole target,
# so a couple of runs per target (default profile + one focused-tags retry) is plenty.
_MAX_NUCLEI_RUNS_PER_TARGET = 2

# The bundled, offline template set baked into the sandbox image (see
# docker/sandbox/Dockerfile).
_TEMPLATES_DIR = "/opt/nuclei-templates"

# Which template DIRECTORIES are actually loaded (each passed with its own -t).
# This is a HARD memory bound, not a nicety: engine.sandbox caps every run at
# 256 MB (frozen), and nuclei loads the templates it is pointed at INTO MEMORY
# before scanning. Pointing -t at the whole corpus (thousands of templates, esp.
# the ~4000 CVE templates) blows past 256 MB and the container is OOM-killed
# (exit 137) a few seconds into loading — THAT is the "nuclei times out" failure.
# Empirically verified against the BUILT image under `--memory 256m`:
#   exposures+misconfiguration (~1163 templates) -> exit 0, fits;
#   +technologies                                 -> exit 137 (OOM);
#   +cve (~4000)                                  -> exit 137 (OOM).
# So the default, memory-safe load is the two highest-signal HTTP categories
# (exposed files/secrets + server misconfigurations). -tags below further scopes
# WITHIN these dirs; it never widens the load.
_DEFAULT_TEMPLATE_PATHS = (
    "/opt/nuclei-templates/http/exposures",
    "/opt/nuclei-templates/http/misconfiguration",
)

# Per-request execution bounds (all confirmed against `nuclei -h` in the BUILT
# redsee-sandbox image, not guessed). These are what keep a template scan from
# hanging on a slow/unresponsive target long enough to blow the sandbox
# wall-clock: without a tight per-request -timeout and -retries=0, one slow
# endpoint stalls the whole run. Verified live against redsees.com:3000 — the
# scoped tech/exposure/misconfig/cve set completes in ~75s (vs ~116s untuned)
# and never times out. Detection-only, harness-owned; the model supplies none.
#   -timeout   seconds to wait per request before giving up (default nuclei 10)
#   -retries   never re-issue a failed request (default nuclei 1)
#   -c         templates executed in parallel (nuclei default 25)
#   -rl        max requests/second, a politeness/wall-clock bound (default 150)
_NUCLEI_REQUEST_TIMEOUT_SEC = "5"
_NUCLEI_RETRIES = "0"
_NUCLEI_CONCURRENCY = "15"        # lower than nuclei's default 25 — keeps the
                                 # in-flight footprint comfortably under 256 MB
_NUCLEI_RATE_LIMIT = "150"

# Severity floor: exclude info-only templates by default — they are noise, not
# findings. The model cannot widen this; the harness owns it.
_SEVERITIES = "low,medium,high,critical"

# Tags ALWAYS excluded, no matter what the model asks for: anything that turns a
# passive detection scan into denial-of-service, intrusive probing, request fuzzing,
# credential brute-forcing, or an out-of-band/OAST callback.
_EXCLUDE_TAGS = ["dos", "intrusive", "fuzz", "fuzzing", "brute", "oob", "network-dos"]

# Fixed, safe, DETECTION-ONLY base flags shared by EVERY scan. The harness owns every
# flag — the model supplies none.
#   -jsonl                 machine-parseable one-object-per-finding output (SOLE evidence)
#   -omit-raw              do NOT retain full HTTP request/response blobs in the output
#   -disable-update-check  never phone home to check for engine/template updates
#   -no-interactsh         disable interactsh/OAST — no out-of-band callbacks, ever
_BASE_PROFILE = ["-jsonl", "-omit-raw", "-disable-update-check", "-no-interactsh"]

# Default template tags when the model supplies none — aligned with the memory-safe
# template DIRECTORIES loaded above (exposures + misconfiguration). Tags scope
# WITHIN the loaded dirs; they can never widen the load past the 256 MB bound.
_DEFAULT_TAGS = ["exposure", "misconfig"]

# Safe tags the model may request. Default-deny: anything not here is dropped (a clean
# unknown tag) or refused (a dangerous/flag-like one — see _sanitize_tags). Every tag
# here names a nuclei template CATEGORY that DETECTS (matches on) a condition; none of
# them exploit. Intentionally excludes dos/intrusive/fuzz/brute/oob (also in
# _EXCLUDE_TAGS) and anything that would run code-protocol templates.
_ALLOWED_TAGS = {
    "tech", "exposure", "exposures", "misconfig", "misconfiguration", "config",
    "panel", "login", "disclosure", "listing", "ssl", "tls", "headers", "cve",
    "cves", "xss", "sqli", "injection", "lfi", "rfi", "ssrf", "redirect",
    "takeover", "backup", "debug", "error", "git", "exposed", "default-page",
    "apache", "nginx", "iis", "tomcat", "php", "wordpress", "wp-plugin", "jira",
    "wordpress", "detect", "tech-detect", "favicon", "waf",
}

# Tags that are NEVER allowed even if a caller lists them — a hard, explicit deny that
# _sanitize_tags RAISES on (a smuggling attempt), distinct from silently-dropped unknowns.
_FORBIDDEN_TAGS = {
    "dos", "network-dos", "intrusive", "fuzz", "fuzzing", "fuzzer", "brute",
    "bruteforce", "brute-force", "oob", "oast", "interactsh", "exploit", "rce",
    "code", "headless", "deserialization",
}

# Flags that must NEVER appear in the argv — the model cannot introduce these (it only
# supplies a target and tag VALUES), but this is the hard backstop that trips if a
# regression or a smuggled token ever produced one. Covers: engine/template auto-update,
# interactsh/OAST servers (out-of-band exfil), code-protocol/headless execution, cloud
# upload / PDCP, and config-wiping. (Both long and short nuclei aliases are listed.)
_FORBIDDEN_LITERAL = {
    "-up", "-update", "-ut", "-update-templates", "-ud", "-update-template-dir",
    "-iserver", "-interactsh-server", "-itoken", "-interactsh-token",
    "-code", "-headless", "-hl", "-sb", "-system-resolvers",
    "-reset", "-auth", "-pdu", "-dashboard-upload", "-cloud-upload", "-cup",
    "-i", "-interface",
}

# Header flags (-H/-header) are how the HARNESS attaches the auth cookie — legitimate.
# The ONLY -H/-header the argv may carry is a harness-built "Cookie: ..." value; any
# other header (a model-smuggled injection) trips the guard in _assert_no_forbidden_flags.
_HEADER_FLAGS = {"-H", "-header"}

# A clean nuclei tag token: starts alphanumeric, then alphanumerics / dot / dash /
# underscore. A smuggled flag ("-H", "-interactsh-url") or anything with spaces/quotes
# fails this and is refused.
_TAG_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*$")


# ── The single tool exposed to the model ────────────────────────────────────

RUN_NUCLEI_TOOL = {
    "type": "function",
    "function": {
        "name": "run_nuclei",
        "description": (
            "Run nuclei against ONE in-scope target inside an isolated sandbox using a "
            "fixed, safe, detection-only profile (bundled templates, no out-of-band "
            "callbacks, info-severity noise and dos/intrusive/fuzz/brute templates "
            "excluded). You do not control nuclei flags — you only choose the target "
            "and, optionally, a few template tags to focus on. Any configured "
            "authentication cookie is attached automatically. Returns whether nuclei "
            "matched any templates, and for each match the template id, severity, and "
            "where it matched."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": (
                        "Full in-scope target URL to scan, e.g. 'http://host:8080/'."
                    ),
                },
                "tags": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": (
                        "Optional list of template tags to focus the scan on, e.g. "
                        "['tech', 'exposure', 'misconfig']. Only tags from the safe "
                        "allowlist are used; dangerous ones are refused. Omit to run the "
                        "default detection profile."
                    ),
                },
                "note": {
                    "type": "string",
                    "description": "Optional short note on what you are scanning and why.",
                },
            },
            "required": ["target"],
        },
    },
}


# ── Result types (local to this module — NOT in schemas.py) ──────────────────

@dataclass
class NucleiCandidate:
    target: str
    template_id: str | None
    name: str | None
    severity: str | None          # nuclei's severity: info/low/medium/high/critical
    matched_at: str | None        # where nuclei matched (matched-at / host)
    evidence: str                 # concise real excerpt built from the JSONL result
    # Outcome of the scan: "found" (a parsed nuclei JSONL result line), "clean" (nuclei
    # actually ran, exit 0, zero result lines), "error" (sandbox/isolation abort, target
    # unreachable, timeout, or non-zero exit — no verdict), or "out_of_scope" (refused
    # before running). "error"/"out_of_scope" are NEVER presented as clean.
    status: str = "clean"
    error: str | None = None      # reason string when status == "error"
    nuclei_argv: list = field(default_factory=list)


@dataclass
class NucleiAgentResult:
    candidates: list[NucleiCandidate]
    usage: Usage
    iterations: int
    transcript: list[dict]        # each step: {role, action, summary} for run.json
    stopped_reason: str           # "done"|"completed_by_ladder"|"budget"|"max_iterations"


# ── nuclei argv builder + forbidden-flag/tag guards ─────────────────────────

def _assert_no_forbidden_flags(argv: list[str]) -> list[str]:
    """Fail loudly if the argv contains any auto-update / OOB-callback / code-exec /
    cloud-upload flag, or any header injection other than the harness auth cookie.
    Detection-only, harness-owned flags is a hard invariant."""
    for tok in argv:
        flag = tok.split("=", 1)[0]
        assert flag not in _FORBIDDEN_LITERAL, f"forbidden nuclei flag in argv: {tok!r}"
    # The only permissible -H/-header is a harness-built "Cookie: ..." value; anything
    # else is a smuggled header injection.
    for i, tok in enumerate(argv):
        if tok in _HEADER_FLAGS:
            value = argv[i + 1] if i + 1 < len(argv) else ""
            assert value.startswith("Cookie: "), \
                f"forbidden header injection in argv: {value!r}"
    return argv


def _sanitize_tags(tags) -> list[str]:
    """Validate model-supplied template tags against the safe allowlist.

    Two distinct outcomes, on purpose:
      * A DELIBERATE smuggling attempt RAISES — a flag-like token (leading '-',
        e.g. a smuggled '-H'/'-interactsh-server') or a hard-denied dangerous
        category (dos/intrusive/fuzz/brute/oob/exploit/rce/code/...). These are
        security events, surfaced loudly.
      * Everything else that is not a clean allowlist tag is DROPPED, not fatal:
        a non-string entry, an unknown-but-clean tag, or malformed model noise
        (e.g. a weak model passing the literal string "[]", "a b", "tag;rm"). Such
        junk can never reach the argv (it is not in the allowlist), so it is safe
        to ignore — crashing the whole scan over model noise would be wrong.

    Returns the de-duplicated list of accepted allowlist tags (possibly empty, in
    which case the caller falls back to the default detection profile).
    """
    if tags is None:
        return []
    if isinstance(tags, str):
        tags = [tags]
    if not isinstance(tags, (list, tuple)):
        # A non-list tags value is model noise, not a smuggle — ignore it.
        return []

    accepted: list[str] = []
    for raw in tags:
        if not isinstance(raw, str):
            continue                              # noise — drop
        tag = raw.strip().lower()
        if not tag:
            continue
        # Hard-deny (RAISE): a flag-like token or a dangerous template category is
        # a deliberate injection attempt, never innocent noise.
        assert not tag.startswith("-"), f"forbidden/flag-like nuclei tag: {raw!r}"
        assert tag not in _FORBIDDEN_TAGS, f"forbidden nuclei tag: {raw!r}"
        # Keep only clean, allowlisted tags; unknown/malformed tokens simply drop
        # (they cannot reach the argv, so they are harmless).
        if _TAG_RE.fullmatch(tag) and tag in _ALLOWED_TAGS and tag not in accepted:
            accepted.append(tag)
    return accepted


def _sanitize_cookie(cookie) -> str | None:
    """Validate a caller-supplied auth cookie; return the safe value or None.

    Rejects non-strings, empties, anything with a newline/CR/NUL (header-injection
    guard), anything over 4096 chars, or a value that looks like a flag (leading '-').
    Passed as a single argv token ("Cookie: <value>"), so ';'/spaces inside are safe.
    """
    if not isinstance(cookie, str):
        return None
    c = cookie.strip()
    if not c or len(c) > 4096 or c.startswith("-"):
        return None
    if any(ch in c for ch in ("\n", "\r", "\x00")):
        return None
    return c


def _assert_note_safe(note) -> None:
    """A free-text note never enters the argv, but reject one that whitespace-tokenizes
    into an actual forbidden flag anyway — so a smuggling attempt via `note` is a hard
    error rather than a silent no-op."""
    if not isinstance(note, str) or not note:
        return
    for tok in note.split():
        flag = tok.split("=", 1)[0]
        assert flag not in _FORBIDDEN_LITERAL, f"forbidden flag smuggled via note: {tok!r}"


def _validate_target(target) -> str:
    """Validate a scan target is a well-formed http(s) URL — never a smuggled flag.

    Rejects non-strings, empties, a leading '-' (flag-like), embedded whitespace, and
    anything without an http/https scheme + host. Scope is enforced separately by
    assert_in_scope; this only refuses structurally-bogus / smuggled targets.
    """
    if not isinstance(target, str):
        raise AssertionError(f"nuclei target must be a string, got {target!r}")
    t = target.strip()
    assert t and not t.startswith("-"), f"invalid/flag-like nuclei target: {target!r}"
    assert not any(ch.isspace() for ch in t), f"nuclei target contains whitespace: {target!r}"
    parsed = urllib.parse.urlparse(t)
    assert parsed.scheme in ("http", "https") and parsed.hostname, \
        f"nuclei target must be an http(s) URL with a host: {target!r}"
    return t


def _build_nuclei_argv(target: str, *, tags: list[str] | None = None,
                       auth_cookie: str | None = None) -> list[str]:
    """Construct the harness-owned, detection-only nuclei argv for one target.

    `target` is validated, `tags` are already sanitized (allowlist only). The auth
    cookie, when present, is attached harness-side as a single Cookie header — never
    model-controlled.
    """
    argv = ["nuclei", "-target", target, *_BASE_PROFILE]
    for path in _DEFAULT_TEMPLATE_PATHS:       # one -t per dir; bounds what nuclei loads
        argv += ["-t", path]
    argv += ["-severity", _SEVERITIES,
             "-exclude-tags", ",".join(_EXCLUDE_TAGS),
             "-timeout", _NUCLEI_REQUEST_TIMEOUT_SEC,
             "-retries", _NUCLEI_RETRIES,
             "-c", _NUCLEI_CONCURRENCY,
             "-rl", _NUCLEI_RATE_LIMIT]
    run_tags = tags if tags else _DEFAULT_TAGS
    if run_tags:
        argv += ["-tags", ",".join(run_tags)]
    if auth_cookie:
        argv += ["-H", f"Cookie: {auth_cookie}"]
    return _assert_no_forbidden_flags(argv)


# ── nuclei JSONL parsing (SOLE source of "found" truth) ──────────────────────

def _parse_nuclei_output(stdout: str) -> list[dict]:
    """Parse nuclei -jsonl stdout into a list of result dicts. This is the SOLE source
    of status="found".

    Each nuclei result is ONE JSON object per line. Non-JSON log/banner lines and any
    JSON object without a real `template-id` are skipped — never counted as a result, so
    a chatty scan can never be mistaken for a finding. Returns [] when nothing matched.
    """
    results: list[dict] = []
    for line in (stdout or "").splitlines():
        line = line.strip()
        if not line or line[0] != "{":
            continue                                  # log/banner line, not a result
        try:
            obj = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            continue                                  # not JSON — skip
        if not isinstance(obj, dict):
            continue
        template_id = obj.get("template-id") or obj.get("templateID")
        if not isinstance(template_id, str) or not template_id.strip():
            continue                                  # not a nuclei result object

        info = obj.get("info")
        if not isinstance(info, dict):
            info = {}
        severity = info.get("severity") or "unknown"
        name = info.get("name") or template_id
        matched_at = (obj.get("matched-at") or obj.get("matched_at")
                      or obj.get("host") or obj.get("url") or "")

        results.append({
            "template_id": template_id.strip(),
            "name": str(name).strip(),
            "severity": str(severity).strip().lower(),
            "matched_at": str(matched_at).strip(),
            "type": str(obj.get("type") or "").strip(),
        })
    return results


def _evidence_for(result: dict) -> str:
    """A concise, human-verifiable evidence line built from the JSONL result itself."""
    parts = [f"[{result.get('severity', 'unknown')}]", result.get("template_id", "")]
    name = result.get("name")
    if name and name != result.get("template_id"):
        parts.append(f"({name})")
    matched = result.get("matched_at")
    if matched:
        parts.append(f"matched-at {matched}")
    return " ".join(p for p in parts if p).strip()[:600]


# ── Harness-owned tool execution ────────────────────────────────────────────

def _run_one_scan(target: str, *, tags: list[str] | None, scope_config: ScopeConfig,
                  auth_cookie: str | None = None,
                  timeout_sec: int = _SANDBOX_TIMEOUT_SEC):
    """Execute a single nuclei scan. Returns (tool_result, candidates).

    `candidates` is a list: one "found" candidate PER matched template on a hit, a single
    "clean" candidate when nuclei ran and matched nothing, or a single "error" candidate
    when the sandbox/scan failed. A scope refusal returns (tool_result, []) with status
    "out_of_scope" and NO sandbox execution. `tags` must already be sanitized.
    """
    # Scope gate BEFORE any execution. Refuse (don't run) if out of scope.
    try:
        assert_in_scope(target, scope_config)
    except ScopeError:
        return {
            "ok": False,
            "status": "out_of_scope",
            "out_of_scope": True,
            "error": f"target is out of scope and was NOT scanned: {target}",
        }, []

    argv = _build_nuclei_argv(target, tags=tags, auth_cookie=auth_cookie)

    # ALL nuclei execution goes through the sandbox — never the host. A sandbox failure
    # (isolation abort, target unreachable, ...) is an ERROR, not a clean verdict: a dead
    # target can never masquerade as "no vulnerabilities".
    try:
        sr = run_in_sandbox(argv, target_url=target, config=scope_config,
                            timeout_sec=timeout_sec)
    except (SandboxError, ScopeError) as exc:
        reason = f"sandbox execution failed: {exc}"
        candidate = NucleiCandidate(
            target=target, template_id=None, name=None, severity=None, matched_at=None,
            evidence="", status="error", error=reason, nuclei_argv=argv)
        tool_result = {"ok": False, "status": "error", "error": reason,
                       "target": target, "found": False}
        return tool_result, [candidate]

    results = _parse_nuclei_output(sr.stdout)

    # 'found' ALWAYS comes from parsed JSONL result lines; a real match wins even over an
    # odd exit code. Otherwise a timeout / non-zero exit means the scan did not complete
    # → ERROR; only a real exit-0 run with zero result lines is "clean".
    if results:
        candidates = [
            NucleiCandidate(
                target=target,
                template_id=r["template_id"],
                name=r["name"],
                severity=r["severity"],
                matched_at=r["matched_at"] or None,
                evidence=_evidence_for(r),
                status="found",
                error=None,
                nuclei_argv=argv,
            )
            for r in results
        ]
        tool_result = {
            "ok": True,
            "status": "found",
            "found": True,
            "target": target,
            "count": len(results),
            "results": [
                {"template_id": r["template_id"], "severity": r["severity"],
                 "matched_at": r["matched_at"]}
                for r in results[:25]
            ],
            "timed_out": sr.timed_out,
            "exit_code": sr.exit_code,
        }
        return tool_result, candidates

    if sr.timed_out:
        status, error = "error", "nuclei timed out before completing the scan"
    elif sr.exit_code != 0:
        status, error = "error", f"nuclei exited with non-zero code {sr.exit_code}"
    else:
        status, error = "clean", None

    candidate = NucleiCandidate(
        target=target, template_id=None, name=None, severity=None, matched_at=None,
        evidence="", status=status, error=error, nuclei_argv=argv)
    tool_result = {
        "ok": status != "error",
        "status": status,
        "error": error,
        "target": target,
        "found": False,
        "count": 0,
        "timed_out": sr.timed_out,
        "exit_code": sr.exit_code,
    }
    return tool_result, [candidate]


def _execute_run_nuclei(arguments: dict, *, scope_config: ScopeConfig,
                        auth_cookie: str | None = None,
                        timeout_sec: int = _SANDBOX_TIMEOUT_SEC):
    """Dispatch a model tool call to a nuclei scan. Returns (tool_result, candidates).

    The model supplies only target/tags/note — never flags. Malformed args, a
    flag-like/out-of-structure target, a smuggled forbidden tag, or a forbidden flag
    hidden in the note all fail closed (AssertionError from the validators, or a
    tool_result with ok=False for a plain missing/invalid target).
    """
    args = arguments or {}
    raw_target = args.get("target")
    if not raw_target or not isinstance(raw_target, str):
        return {"ok": False, "error": "run_nuclei requires a string 'target'"}, []

    # Validate model-controlled inputs BEFORE any execution. These RAISE on a smuggling
    # attempt (flag-like target, forbidden/flag-like tag, forbidden flag in the note).
    target = _validate_target(raw_target)
    _assert_note_safe(args.get("note"))
    tags = _sanitize_tags(args.get("tags"))

    tool_result, candidates = _run_one_scan(
        target, tags=tags, scope_config=scope_config,
        auth_cookie=auth_cookie, timeout_sec=timeout_sec)
    tool_result["target"] = target
    tool_result["requested_tags"] = tags
    return tool_result, candidates


# ── Helpers ─────────────────────────────────────────────────────────────────

def _target_url(t) -> str:
    """The URL for a target entry — a bare URL string, or an Endpoint-like object/dict
    exposing `url` (so run_nuclei_agent accepts either shape)."""
    if isinstance(t, str):
        return t
    return _endpoint_field(t, "url", "") or ""


def _load_system_prompt() -> str:
    try:
        return _PROMPT_PATH.read_text(encoding="utf-8")
    except OSError:
        return (
            "You are RedSee's template-scan agent. Use ONLY the run_nuclei tool on "
            "in-scope targets, one at a time; base conclusions on tool output; stop "
            "when done."
        )


def _format_targets_user_message(targets: list, auth_cookie: str | None = None) -> str:
    lines = [
        "Scan the following authorized in-scope targets for known vulnerabilities, "
        "misconfigurations, and exposures using the run_nuclei tool, one at a time:",
        "",
    ]
    for i, t in enumerate(targets, 1):
        url = _target_url(t)
        lines.append(f"{i}. {url}")
    if len(targets) == 0:
        lines.append("(no targets provided)")
    if auth_cookie:
        lines.append("")
        lines.append("An authenticated session cookie is configured and is attached to "
                     "every scan automatically — you do not need to supply it yourself.")
    return "\n".join(lines)


def _summarize_tool_result(arguments: dict, tool_result: dict) -> str:
    target = (arguments or {}).get("target", "?")
    if not tool_result.get("ok"):
        return f"{target}: {tool_result.get('error', 'skipped')}"
    if tool_result.get("found"):
        n = tool_result.get("count", 0)
        sev = ", ".join(sorted({r["severity"] for r in tool_result.get("results", [])}))
        return f"{target}: {n} match(es) [{sev}]"
    return f"{target}: no matches"


def _scan_transcript(target: str, tool_result: dict) -> dict:
    """Structured transcript step recording one nuclei scan for run.json."""
    return {
        "role": "tool",
        "action": "run_nuclei",
        "target": tool_result.get("target", target),
        "found": bool(tool_result.get("found")),
        "count": tool_result.get("count", 0),
        "results": tool_result.get("results", []),
        "status": tool_result.get("status")
                  or ("error" if not tool_result.get("ok") else "clean"),
        "error": tool_result.get("error"),
        "summary": _summarize_tool_result({"target": target}, tool_result),
    }


# ── Entry point ─────────────────────────────────────────────────────────────

def run_nuclei_agent(targets: list, *, max_iterations: int = 6, scope_config=None,
                     llm_config=None, llm_client=None,
                     auth_cookie: str | None = None,
                     default_tags: list | None = None,
                     timeout_sec: int | None = None) -> NucleiAgentResult:
    """Drive the LLM to scan `targets` with nuclei via the sandboxed run_nuclei tool.

    The model picks targets (and optional focus tags); if it stops early or never emits a
    usable tool call, a deterministic completion pass scans every target not yet scanned
    once with the safe default profile. `auth_cookie` (e.g. "PHPSESSID=..; security=low")
    is attached to every scan as a Cookie header — for authenticated targets like DVWA.
    Scanning is bounded: at most _MAX_NUCLEI_RUNS_PER_TARGET nuclei runs per target.

    `default_tags` (optional) SCOPES the deterministic completion-pass template set for
    the caller's scan mode (e.g. the orchestrator's standard profile passes
    ["exposure", "misconfig", "tech", "cve"]); it is sanitized through the same safe
    allowlist as any model-supplied tag and falls back to _DEFAULT_TAGS when None/empty.
    `timeout_sec` (optional) is the per-scan sandbox wall-clock bound (default
    _SANDBOX_TIMEOUT_SEC) — the outer limit on top of the per-request -timeout baked into
    the argv.

    `targets` may be bare URL strings or Endpoint-like objects exposing `.url`. Fakes may
    be injected for tests via scope_config / llm_config / llm_client. "found" is derived
    SOLELY from parsed nuclei JSONL result lines.
    """
    if scope_config is None:
        scope_config = load_scope_config()

    # Scope the completion-pass tags to the caller's mode (sanitized to the safe
    # allowlist, exactly like a model-supplied tag); None/empty -> the default profile.
    completion_tags = _sanitize_tags(default_tags) or None
    scan_timeout = timeout_sec if timeout_sec is not None else _SANDBOX_TIMEOUT_SEC

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
        {"role": "user", "content": _format_targets_user_message(targets, auth_cookie)},
    ]

    transcript: list[dict] = [
        {"role": "system", "action": "prompt", "summary": "loaded nuclei agent system prompt"},
        {"role": "user", "action": "list_targets",
         "summary": f"{len(targets)} target(s) queued for template scanning"},
    ]
    candidates: list[NucleiCandidate] = []
    runs_per_target: dict[str, int] = {}      # bounds scans per target
    run_cap = _MAX_NUCLEI_RUNS_PER_TARGET
    executed_default: set = set()             # target keys already run with the default profile
    scanned_targets: set = set()              # target keys nuclei actually ran against
    confirmed_targets: set = set()            # target keys that produced >=1 found result
    model_found = False                       # did the AGENT-driven phase find anything?
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
            reply = llm_client.chat(messages, tools=[RUN_NUCLEI_TOOL])
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
            target_key = None
            raw_target = (arguments or {}).get("target")
            if isinstance(raw_target, str):
                target_key = _endpoint_key(raw_target)
            if name != "run_nuclei":
                tool_result, cands = {"ok": False, "error": f"unknown tool: {name}"}, []
            elif target_key is not None and runs_per_target.get(target_key, 0) >= run_cap:
                # Per-target scan ceiling — refuse, do not run nuclei again.
                tool_result, cands = {
                    "ok": False,
                    "scan_ceiling": True,
                    "error": f"scan ceiling reached for {raw_target}; no further runs",
                }, []
            else:
                # A deliberate smuggling attempt (forbidden tag / flag-like target /
                # forbidden flag in the note) RAISES in the validators — refuse THIS
                # one tool call and let the model try again; never crash the whole
                # scan over one bad tool call. The completion pass still runs.
                try:
                    tool_result, cands = _execute_run_nuclei(
                        arguments, scope_config=scope_config, auth_cookie=auth_cookie,
                        timeout_sec=scan_timeout)
                except AssertionError as exc:
                    tool_result, cands = {
                        "ok": False,
                        "status": "refused",
                        "error": f"refused unsafe run_nuclei arguments: {exc}",
                    }, []
                if cands:
                    candidates.extend(cands)
                    ran = tool_result.get("status") in ("found", "clean", "error")
                    if ran and target_key is not None:
                        runs_per_target[target_key] = runs_per_target.get(target_key, 0) + 1
                        scanned_targets.add(target_key)
                        if not tool_result.get("requested_tags"):
                            executed_default.add(target_key)
                    if tool_result.get("found"):
                        model_found = True
                        if target_key is not None:
                            confirmed_targets.add(target_key)

            if cands or tool_result.get("status"):
                transcript.append(_scan_transcript(raw_target, tool_result))
            else:
                transcript.append({"role": "tool", "action": name or "unknown",
                                   "summary": _summarize_tool_result(arguments, tool_result)})
            messages.append({
                "role": "tool",
                "tool_call_id": call_id,
                "name": "run_nuclei",
                "content": json.dumps(tool_result),
            })

    # ── Deterministic completion pass ────────────────────────────────────────
    # Runs at loop end for ANY non-budget stop (not only when the model emitted no tool
    # call). It scans every target the agent-driven phase did NOT already scan with the
    # default profile, SKIPPING targets already covered and respecting the per-target cap.
    # This guarantees a real result even when a weak model stops early or never makes a
    # usable tool call. It never runs after a budget stop.
    entered_reason = stopped_reason
    ladder_found = False
    if entered_reason != "budget":
        transcript.append({"role": "system", "action": "completion_pass",
                           "summary": "scanning targets not yet covered with the safe "
                                      "default nuclei profile"})
        for t in targets:
            url = _target_url(t)
            if not url:
                continue
            target_key = _endpoint_key(url)
            if target_key in confirmed_targets:
                continue                              # agent phase already found something
            if runs_per_target.get(target_key, 0) >= run_cap:
                continue                              # per-target budget exhausted
            if target_key in executed_default:
                continue                              # already run with the default profile

            tool_result, cands = _run_one_scan(
                url, tags=completion_tags, scope_config=scope_config,
                auth_cookie=auth_cookie, timeout_sec=scan_timeout)
            tool_result["target"] = url
            transcript.append(_scan_transcript(url, tool_result))
            if cands:
                candidates.extend(cands)
                ran = tool_result.get("status") in ("found", "clean", "error")
                if ran:
                    runs_per_target[target_key] = runs_per_target.get(target_key, 0) + 1
                    scanned_targets.add(target_key)
                    executed_default.add(target_key)
                if tool_result.get("found"):
                    ladder_found = True
                    confirmed_targets.add(target_key)

    # Final stopped_reason: a model-driven finding is a clean "done"; a finding ONLY the
    # completion pass produced is "completed_by_ladder"; otherwise the reason the loop
    # exited (done / max_iterations) stands. A budget stop is terminal and never reaches
    # the completion pass, so it is preserved. (A failed scan surfaces ONLY as a
    # per-candidate status="error" — there is no "error" stopped_reason, matching XSS.)
    if model_found:
        stopped_reason = "done"
    elif ladder_found:
        stopped_reason = "completed_by_ladder"
    else:
        stopped_reason = entered_reason

    return NucleiAgentResult(
        candidates=candidates,
        usage=tracker.usage,
        iterations=iterations,
        transcript=transcript,
        stopped_reason=stopped_reason,
    )


# ── Opt-in live smoke test ──────────────────────────────────────────────────
if __name__ == "__main__":
    # Requires: .env configured (scope + LLM), sandbox image built
    # (bash docker/sandbox/build.sh), a running Ollama, and a reachable target in scope.
    # .env is loaded automatically below — no need to `source .env` first; real exported
    # env vars still win (load_env uses override=False).
    #
    #   REDSEE_AUTHORIZED=true REDSEE_ALLOWED_HOSTS=localhost \
    #   REDSEE_LLM_BASE_URL=http://localhost:11434/v1 REDSEE_LLM_MODEL=llama3.2 \
    #   REDSEE_LLM_MAX_USD=0.50 PYTHONPATH=. python -m engine.nuclei_agent
    #
    # An optional auth cookie for authenticated targets can be supplied via
    # REDSEE_NUCLEI_COOKIE (e.g. "PHPSESSID=<sid>; security=low").
    import os

    from engine.env import load_env
    load_env()

    cookie = os.environ.get("REDSEE_NUCLEI_COOKIE") or None
    target = os.environ.get("REDSEE_TARGET_URL") or "http://localhost:8080/"
    demo_targets = [target]

    result = run_nuclei_agent(demo_targets, max_iterations=6, auth_cookie=cookie)
    print(f"stopped_reason={result.stopped_reason} iterations={result.iterations} "
          f"calls={result.usage.calls} cost=${result.usage.cost_usd:.4f}")
    print("scan path:")
    for step in result.transcript:
        if step.get("action") == "run_nuclei":
            print(f"  status={step.get('status')} found={step.get('found')} "
                  f"count={step.get('count')} target={step.get('target')}")
    found = [c for c in result.candidates if c.status == "found"]
    errored = [c for c in result.candidates if c.status == "error"]
    if errored:
        print(f"errored (not scanned): {len(errored)}")
        for c in errored:
            print(f"  [ERROR] {c.target} reason={c.error}")
    print(f"found templates ({len(found)}):")
    for c in found:
        print(f"  [{(c.severity or '').upper()}] {c.template_id} @ {c.matched_at}")
