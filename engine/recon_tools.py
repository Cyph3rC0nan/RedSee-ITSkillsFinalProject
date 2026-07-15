# engine/recon_tools.py
"""
Deterministic sandboxed recon runners — httpx (HTTP fingerprinting), tlsx
(TLS/certificate inspection), and ffuf (content discovery / directory brute-
force).

Reuses the SHAPE of engine/nuclei_agent.py (scope-gate-first, sandbox-only via
engine.sandbox.run_in_sandbox, evidence-gated JSON parsing) but WITHOUT the LLM,
the agent plan/act/observe loop, a BudgetTracker, or any tool-mediation: these
recon tools run ONE FIXED, harness-owned command per target, deterministically.
No model is ever in this loop, so there is nothing to sanitize/refuse from a
caller — the argv is entirely built by this module.

httpx, tlsx, and ffuf findings are BROADER than the frozen schemas.py Finding
enum (same reasoning as nuclei — see DECISIONS.md D-017), so ReconObservation
is a LOCAL dataclass, never mapped to schemas.Finding. Surfacing into
SARIF/recon_<id>.json/run.json happens in engine/report_io.py, mirroring the
nuclei_candidates channel.
"""

import json
import urllib.parse
from dataclasses import dataclass, field

from engine.scope import ScopeConfig, ScopeError, assert_in_scope
from engine.sandbox import SandboxError, run_in_sandbox

# Both tools are single-target, single-shot probes (no escalation ladder, no
# multi-run budget) — a generous but bounded ceiling; a runaway probe is killed
# and surfaced as status="error", never fabricated data.
_SANDBOX_TIMEOUT_SEC = 120

# ── httpx: fixed, read-only, detection-only profile ──────────────────────────
#   -json                  one JSON object per probed host (SOLE evidence source)
#   -silent                suppress the banner (does NOT suppress JSON results)
#   -no-color              plain text, no ANSI codes
#   -disable-update-check  never phone home to check for an httpx update
# Safe fingerprint set: status code, title, web server, tech-detect, content
# length, and CDN/TLS info. GET/HEAD probing only — `-x`/`-path` (other HTTP
# methods / path bruteforce) are NEVER passed and are hard-forbidden below.
_HTTPX_RATE_LIMIT = "50"
_HTTPX_TIMEOUT_SEC = "10"
_HTTPX_BASE_PROFILE = [
    "-json", "-silent", "-no-color", "-disable-update-check",
    "-status-code", "-title", "-web-server", "-tech-detect",
    "-content-length", "-cdn", "-tls-grab",
]

# Flags that must NEVER appear in the httpx argv — a hard backstop (this argv is
# entirely harness-built, no model/user input reaches it, so this guards against
# a future coding regression, not an adversarial caller). Covers: engine
# auto-update, fuzzing/bruteforcing (other HTTP methods via -x, path bruteforce
# via -path), and write/upload options (local file output, response storage,
# PDCP cloud dashboard upload, result-database persistence).
_HTTPX_FORBIDDEN = {
    "-up", "-update",
    "-x", "-path",
    "-o", "-output", "-oa", "-output-all",
    "-sr", "-store-response", "-srd", "-store-response-dir",
    "-pd", "-dashboard", "-pdu", "-dashboard-upload",
    "-auth", "-rdb", "-result-db", "-rdbc", "-result-db-config",
    "-ss", "-screenshot",
}

# ── tlsx: fixed, read-only, detection-only profile ──────────────────────────
#   -json/-silent/-no-color/-disable-update-check — same rationale as httpx.
# Cert fields + misconfiguration flags. NOTE: `-san`/`-cn`/`-so` are excluded on
# purpose — this tlsx build rejects combining them with any other probe flag
# ("san or cn flag cannot be used with other probes", confirmed by running the
# built image); subject_cn/subject_dn/subject_an already appear in the default
# JSON output via Go's omitempty, so nothing is lost by omitting them.
# `-cipher-enum -cipher-type weak` performs a BOUNDED weak-cipher-only probe
# (not a full cipher enumeration) — still detection, not exploitation.
_TLSX_TIMEOUT_SEC = "10"
_TLSX_BASE_PROFILE = [
    "-json", "-silent", "-no-color", "-disable-update-check",
    "-tls-version", "-cipher", "-serial",
    "-expired", "-self-signed", "-mismatched",
    "-cipher-enum", "-cipher-type", "weak",
]

# Flags that must NEVER appear in the tlsx argv — same hard-backstop rationale
# as httpx above. Covers: engine auto-update and write/upload options (local
# file output, PDCP cloud dashboard upload).
_TLSX_FORBIDDEN = {
    "-up", "-update",
    "-o", "-output",
    "-pd", "-dashboard", "-pdu", "-dashboard-upload", "-auth",
}

# ── ffuf: fixed, read-only, detection-only content-discovery profile ────────
#   -json           newline-delimited JSON hit objects on stdout (SOLE evidence
#                   source); confirmed by running the built image against a
#                   throwaway local test site that the "[2K" progress-clear
#                   escapes ffuf writes go to STDERR only — stdout is clean
#                   JSON, one hit object per line, no trailing banner line, and
#                   exit code stays 0 (verified against `ffuf -h` in the BUILT
#                   image, not guessed — see docs/nuclei_sandbox.md).
#   -s              silent mode (suppresses the banner/progress text ffuf would
#                   otherwise also try to print; does not affect JSON hits).
#   -noninteractive disables the interactive keypress console (irrelevant/
#                   risky in a non-tty sandboxed run).
#   -mc             match ONLY real "something is there" status codes — the
#                   filtering step that keeps output to genuine hits instead of
#                   every single probed word.
#   -ac             auto-calibrate: ffuf probes a few random/nonexistent paths
#                   first, learns THIS TARGET's "nothing here" response shape
#                   (size/words/lines), and filters any match that looks like
#                   it — REQUIRED, not optional. Confirmed via a real live
#                   smoke run against a single-page-app target (Juice Shop):
#                   without -ac, the SPA's client-side-routing catch-all serves
#                   its index.html (identical 200 response) for EVERY probed
#                   path, so -mc alone floods 4741/4750 words as "hits" — noise,
#                   not evidence. With -ac, that flood drops to 0 (correct: a
#                   pure client-routed SPA has no real server-side paths to
#                   discover), while re-verified against a differentiated test
#                   site (real distinct files, including a deliberately planted
#                   .git/config and .env) that genuinely sensitive hits still
#                   surface — see docs/nuclei_sandbox.md.
# Bundled wordlist (see docker/sandbox/Dockerfile / DECISIONS.md D-020):
# SecLists' Discovery/Web-Content/common.txt, ~4750 entries, pinned + sha256-
# verified at build time. GET-only (`-X`/`-d` are NEVER passed and are hard-
# forbidden below); `-recursion` is NEVER passed (ffuf defaults it to off) and
# is likewise hard-forbidden, so a scan never explodes into sub-paths.
_FFUF_WORDLIST = "/opt/wordlists/common.txt"
# 308 (Permanent Redirect) is included alongside 301/302/307: a path that a reverse
# proxy/app redirects to its canonical form (e.g. /market -> 308 -> /market/) is a
# real discovered path — omitting 308 silently dropped exactly such an endpoint on
# the live target (the gateway 308-redirects /market to the marketplace).
_FFUF_MATCH_CODES = "200,204,301,302,307,308,401,403"
_FFUF_BASE_PROFILE = ["-json", "-s", "-noninteractive", "-mc", _FFUF_MATCH_CODES, "-ac"]

# Directory brute-forcing is inherently noisier than a single httpx/tlsx probe
# (thousands of requests vs. one), so both concurrency and pace are bounded
# independently of ffuf's own (much higher) defaults (-t defaults to 40,
# -rate defaults to 0/unlimited).
_FFUF_THREADS = "20"
_FFUF_REQUEST_TIMEOUT_SEC = "10"
# REDSEE_RATE_LIMIT (scope_config.max_requests_per_min) was sized for
# occasional-probe tools (a handful of requests per SQLi/XSS/httpx target).
# Content discovery legitimately issues thousands of requests per target, so
# applying the configured number literally as a PER-MINUTE cap would make the
# bundled ~4750-word wordlist take a prohibitive amount of time (at the
# default 60/min -> 1 req/s, ~79 minutes for one target). ffuf's own `-rate`
# flag is requests PER SECOND, so the configured number is honored directly as
# that per-second cap instead (a stricter operator setting is still respected
# 1:1) — bounded by a hard ceiling well below ffuf's unthrottled default so a
# large/unset configured value can never turn this into an unbounded flood.
_FFUF_RATE_CEILING = 50
# ffuf's own `-maxtime` backstop is set to fire BEFORE run_in_sandbox's harder
# subprocess-kill timeout, so a scan that can't finish the full wordlist in the
# time budget exits ITSELF (exit=0, whatever hits were already found intact on
# stdout) instead of being killed mid-run and surfaced as a bare error with
# nothing recovered. Confirmed (not assumed) that `-maxtime` produces a clean
# exit=0 with the JSON already written — see docs/nuclei_sandbox.md.
_FFUF_MAXTIME_BUFFER_SEC = 15
_FFUF_SANDBOX_TIMEOUT_SEC = 150  # more headroom than httpx/tlsx's single-probe 120s

# Flags that must NEVER appear in the ffuf argv — same hard-backstop rationale
# as httpx/tlsx above (this argv is entirely harness-built, no model/user input
# reaches it). Covers: write/output (local file, debug log), recursion
# (explosion into sub-paths), non-GET methods/POST data, proxying (could route
# sandboxed traffic around the egress firewall), external-command wordlist
# generation (`-input-cmd`/`-input-shell` would let ffuf exec an arbitrary
# shell command), and loading an external config file.
_FFUF_FORBIDDEN = {
    "-o", "-od", "-of", "-debug-log",
    "-recursion", "-recursion-depth", "-recursion-strategy",
    "-X", "-d",
    "-x", "-replay-proxy",
    "-input-cmd", "-input-shell",
    "-config",
}

# Path substrings that turn a content-discovery hit into a Medium-severity
# observation instead of an informational Low one — a deliberately small,
# high-confidence list of exposures worth flagging on sight (VCS metadata,
# secrets/env files, backups, admin panels), never a guess about the app.
_SENSITIVE_PATH_MARKERS = (
    ".git", ".env", "backup", "admin", ".svn", ".htpasswd", ".ssh", "id_rsa",
)


# ── Result type (local to this module — NOT in schemas.py) ───────────────────

@dataclass
class ReconObservation:
    tool: str                      # "httpx" | "tlsx" | "ffuf"
    target: str
    category: str                  # e.g. "http-fingerprint", "tls-info",
                                    # "tls-self-signed", "tls-expired",
                                    # "tls-hostname-mismatch", "tls-weak-cipher",
                                    # "content-discovery" (ffuf),
                                    # or "error"/"out_of_scope" for non-observed rows
    title: str
    severity: str | None           # "Low" | "Medium" for observed rows; None for
                                    # error/out_of_scope (no verdict was reached)
    evidence: str                  # concise excerpt built from the real JSON result
    # "observed" (a parsed, real httpx/tlsx JSON result), "error" (sandbox
    # failure/timeout/non-zero exit — NEVER fabricated data), or "out_of_scope"
    # (refused before running). "error"/"out_of_scope" are NEVER "observed".
    status: str = "observed"
    error: str | None = None       # reason string when status == "error"
    argv: list = field(default_factory=list)


# ── argv builders + forbidden-flag guards ────────────────────────────────────

def _assert_no_forbidden_flags(argv: list[str], forbidden: set, *, tool: str) -> list[str]:
    for tok in argv:
        flag = tok.split("=", 1)[0]
        assert flag not in forbidden, f"forbidden {tool} flag in argv: {tok!r}"
    return argv


def _build_httpx_argv(target: str) -> list[str]:
    """Construct the fixed, harness-owned httpx argv for one target URL."""
    argv = ["httpx", "-target", target, *_HTTPX_BASE_PROFILE,
            "-rate-limit", _HTTPX_RATE_LIMIT, "-timeout", _HTTPX_TIMEOUT_SEC]
    return _assert_no_forbidden_flags(argv, _HTTPX_FORBIDDEN, tool="httpx")


def _host_port_from_target(target: str) -> tuple[str, int]:
    """Derive (host, port) for tlsx (which takes -host/-port, not a URL).

    Uses the EXACT SAME formula engine.sandbox.run_in_sandbox itself uses to
    resolve the port it opens egress for (explicit URL port, else 443 for
    https, else 80) — critical so tlsx always probes the SAME port the
    sandbox's egress firewall actually allows for this target_url.
    """
    parsed = urllib.parse.urlparse(target.strip().split("#", 1)[0])
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return host, port


def _build_tlsx_argv(target: str) -> list[str]:
    """Construct the fixed, harness-owned tlsx argv for one target URL."""
    host, port = _host_port_from_target(target)
    argv = ["tlsx", "-host", host, "-port", str(port), *_TLSX_BASE_PROFILE,
            "-timeout", _TLSX_TIMEOUT_SEC]
    return _assert_no_forbidden_flags(argv, _TLSX_FORBIDDEN, tool="tlsx")


def _ffuf_rate(scope_config: ScopeConfig) -> str:
    """The ffuf `-rate` (requests/sec) value: the configured
    REDSEE_RATE_LIMIT honored DIRECTLY as a per-second cap (see the constant
    block above for why per-minute would be impractically slow for content
    discovery), floored at 1 and hard-capped at _FFUF_RATE_CEILING."""
    configured = getattr(scope_config, "max_requests_per_min", None) or 60
    return str(max(1, min(int(configured), _FFUF_RATE_CEILING)))


def _build_ffuf_target_url(target: str) -> str:
    """Append the literal FUZZ keyword ffuf substitutes the wordlist into,
    ensuring exactly one '/' before it regardless of whether `target` already
    ends in one."""
    base = target.strip()
    if not base.endswith("/"):
        base += "/"
    return base + "FUZZ"


def _build_ffuf_argv(target: str, *, scope_config: ScopeConfig,
                     timeout_sec: int) -> list[str]:
    """Construct the fixed, harness-owned ffuf argv for one target URL."""
    fuzz_url = _build_ffuf_target_url(target)
    maxtime = max(10, timeout_sec - _FFUF_MAXTIME_BUFFER_SEC)
    argv = [
        "ffuf", "-u", fuzz_url, "-w", _FFUF_WORDLIST,
        *_FFUF_BASE_PROFILE,
        "-t", _FFUF_THREADS,
        "-rate", _ffuf_rate(scope_config),
        "-timeout", _FFUF_REQUEST_TIMEOUT_SEC,
        "-maxtime", str(maxtime),
    ]
    return _assert_no_forbidden_flags(argv, _FFUF_FORBIDDEN, tool="ffuf")


# ── Output parsing (SOLE source of "observed" truth) ─────────────────────────

def _parse_json_lines(stdout: str) -> list[dict]:
    """Parse one-JSON-object-per-line stdout into a list of dicts. Non-JSON
    log/banner lines are skipped — never counted as a result."""
    objs: list[dict] = []
    for line in (stdout or "").splitlines():
        line = line.strip()
        if not line or line[0] != "{":
            continue
        try:
            obj = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            continue
        if isinstance(obj, dict):
            objs.append(obj)
    return objs


def _httpx_observation_for(target: str, obj: dict, argv: list) -> ReconObservation:
    """Build one ReconObservation from a real httpx JSON result object."""
    status_code = obj.get("status_code")
    title = obj.get("title")
    webserver = obj.get("webserver")
    tech = obj.get("tech") or []
    content_length = obj.get("content_length")
    cdn = obj.get("cdn")
    cdn_name = obj.get("cdn_name")
    url = obj.get("url") or target

    parts = [f"status={status_code}"]
    if title:
        parts.append(f"title={title!r}")
    if webserver:
        parts.append(f"server={webserver}")
    if tech:
        parts.append(f"tech={','.join(tech)}")
    if content_length is not None:
        parts.append(f"content_length={content_length}")
    if cdn:
        parts.append(f"cdn={cdn_name or 'yes'}")
    evidence = " ".join(parts)[:600]

    title_line = (title or webserver or url or "").strip()
    return ReconObservation(
        tool="httpx", target=target, category="http-fingerprint",
        title=f"{status_code} {title_line}".strip(),
        severity="Low",                      # informational fingerprint, not a verdict
        evidence=evidence, status="observed", error=None, argv=argv,
    )


def _tlsx_observations_for(target: str, obj: dict, argv: list) -> list[ReconObservation]:
    """Build ReconObservation(s) from a real tlsx JSON result object.

    Always emits one baseline "tls-info" observation for a successful probe
    (severity Low), PLUS one additional observation per detected misconfig
    condition tlsx's own fields report (self-signed / expired / hostname
    mismatch / weak cipher — severity Medium). Severity is derived SOLELY from
    tlsx's own JSON fields — never fabricated.
    """
    observations: list[ReconObservation] = []
    host = obj.get("host") or ""
    port = obj.get("port") or ""
    tls_version = obj.get("tls_version")
    cipher = obj.get("cipher")
    subject_cn = obj.get("subject_cn")
    serial = obj.get("serial")
    not_before = obj.get("not_before")
    not_after = obj.get("not_after")

    base_evidence = (
        f"host={host} port={port} tls_version={tls_version} cipher={cipher} "
        f"subject_cn={subject_cn} serial={serial} "
        f"not_before={not_before} not_after={not_after}"
    ).strip()[:600]
    observations.append(ReconObservation(
        tool="tlsx", target=target, category="tls-info",
        title=f"TLS {tls_version or 'unknown'} — {subject_cn or host}",
        severity="Low", evidence=base_evidence, status="observed",
        error=None, argv=argv,
    ))

    if obj.get("self_signed"):
        observations.append(ReconObservation(
            tool="tlsx", target=target, category="tls-self-signed",
            title=f"Self-signed certificate on {host}:{port}",
            severity="Medium",
            evidence=f"subject_cn={subject_cn} issuer_cn={obj.get('issuer_cn')}"[:600],
            status="observed", error=None, argv=argv,
        ))

    if obj.get("expired"):
        observations.append(ReconObservation(
            tool="tlsx", target=target, category="tls-expired",
            title=f"Expired certificate on {host}:{port}",
            severity="Medium", evidence=f"not_after={not_after}"[:600],
            status="observed", error=None, argv=argv,
        ))

    if obj.get("mismatched"):
        observations.append(ReconObservation(
            tool="tlsx", target=target, category="tls-hostname-mismatch",
            title=f"Certificate hostname mismatch on {host}:{port}",
            severity="Medium",
            evidence=f"subject_cn={subject_cn} sni={obj.get('sni')}"[:600],
            status="observed", error=None, argv=argv,
        ))

    weak_ciphers = []
    for ce in obj.get("cipher_enum") or []:
        if not isinstance(ce, dict):
            continue
        ciphers = ce.get("ciphers")
        if ciphers:
            names = list(ciphers.keys()) if isinstance(ciphers, dict) else list(ciphers)
            weak_ciphers.append(f"{ce.get('version')}: {', '.join(str(n) for n in names)}")
    if weak_ciphers:
        observations.append(ReconObservation(
            tool="tlsx", target=target, category="tls-weak-cipher",
            title=f"Weak TLS ciphers supported on {host}:{port}",
            severity="Medium", evidence="; ".join(weak_ciphers)[:600],
            status="observed", error=None, argv=argv,
        ))

    return observations


def _is_sensitive_path(path: str) -> bool:
    lowered = (path or "").lower()
    return any(marker in lowered for marker in _SENSITIVE_PATH_MARKERS)


def _ffuf_observation_for(target: str, obj: dict, argv: list) -> ReconObservation:
    """Build one ReconObservation from a real ffuf JSON hit object.

    Severity is derived SOLELY from the discovered path string matching a
    known-sensitive marker (see _SENSITIVE_PATH_MARKERS) — Medium for a
    sensitive exposure (.git/.env/backup/admin/...), Low (informational) for
    any other discovered path. Never fabricated: only paths ffuf itself
    reported a matching status code for ever produce an observation."""
    url = obj.get("url") or target
    status = obj.get("status")
    length = obj.get("length")
    path = urllib.parse.urlparse(url).path or "/"
    evidence = f"path={path} status={status} length={length}"[:600]
    return ReconObservation(
        tool="ffuf", target=target, category="content-discovery",
        title=f"{status} {path}",
        severity="Medium" if _is_sensitive_path(path) else "Low",
        evidence=evidence, status="observed", error=None, argv=argv,
    )


# ── Helpers ─────────────────────────────────────────────────────────────────

def _target_url(t) -> str:
    """The URL for a target entry — a bare URL string, or an object/dict
    exposing `url` (mirrors engine.nuclei_agent's convention, kept local here
    to avoid an import dependency on that module)."""
    if isinstance(t, str):
        return t
    if isinstance(t, dict):
        return t.get("url", "") or ""
    return getattr(t, "url", "") or ""


def _out_of_scope_observation(tool: str, target: str) -> ReconObservation:
    return ReconObservation(
        tool=tool, target=target, category="out_of_scope",
        title=f"{target} is out of scope", severity=None, evidence="",
        status="out_of_scope",
        error=f"target is out of scope and was NOT scanned: {target}",
        argv=[],
    )


def _error_observation(tool: str, target: str, argv: list, reason: str) -> ReconObservation:
    return ReconObservation(
        tool=tool, target=target, category="error",
        title=f"{tool} scan failed for {target}", severity=None, evidence="",
        status="error", error=reason, argv=argv,
    )


# ── Entry points ──────────────────────────────────────────────────────────────

def run_httpx(targets: list, *, scope_config: ScopeConfig,
             timeout_sec: int = _SANDBOX_TIMEOUT_SEC) -> list[ReconObservation]:
    """Run httpx deterministically against every target, sandboxed, in-scope only.

    assert_in_scope(target, scope_config) runs before EVERY target; an
    out-of-scope target is refused (status="out_of_scope") and run_in_sandbox is
    NEVER called for it. All execution goes through engine.sandbox.run_in_sandbox
    — never the host, never a raw subprocess. A sandbox failure, timeout, or
    non-zero exit is status="error" (no fabricated observation data). A
    successful probe that surfaces no parseable JSON result yields no
    observation for that target (not an error — there is simply nothing to
    report; ReconObservation has no "clean" status).

    `targets` may be bare URL strings or objects/dicts exposing `.url`/`["url"]`.
    """
    observations: list[ReconObservation] = []
    for t in targets:
        target = _target_url(t)
        if not target:
            continue

        try:
            assert_in_scope(target, scope_config)
        except ScopeError:
            observations.append(_out_of_scope_observation("httpx", target))
            continue

        argv = _build_httpx_argv(target)

        try:
            sr = run_in_sandbox(argv, target_url=target, config=scope_config,
                                timeout_sec=timeout_sec)
        except (SandboxError, ScopeError) as exc:
            observations.append(_error_observation(
                "httpx", target, argv, f"sandbox execution failed: {exc}"))
            continue

        if sr.timed_out:
            observations.append(_error_observation(
                "httpx", target, argv, "httpx timed out before completing the probe"))
            continue
        if sr.exit_code != 0:
            observations.append(_error_observation(
                "httpx", target, argv, f"httpx exited with non-zero code {sr.exit_code}"))
            continue

        for obj in _parse_json_lines(sr.stdout):
            if not (obj.get("url") or obj.get("host")):
                continue                          # not a probe result object
            observations.append(_httpx_observation_for(target, obj, argv))

    return observations


def run_tlsx(targets: list, *, scope_config: ScopeConfig,
            timeout_sec: int = _SANDBOX_TIMEOUT_SEC) -> list[ReconObservation]:
    """Run tlsx deterministically against every target, sandboxed, in-scope only.

    Same scope-gate/sandbox-only/error-handling contract as run_httpx (see
    above). tlsx probes host:port (derived from the target URL via the SAME
    port formula engine.sandbox.run_in_sandbox uses internally, so the sandbox's
    egress firewall always allows the exact port tlsx connects to), not the
    full URL. Severity hints (expired/self-signed/hostname-mismatch/weak-cipher
    -> "Medium", plain TLS info -> "Low") come SOLELY from tlsx's own parsed
    JSON fields, never fabricated.
    """
    observations: list[ReconObservation] = []
    for t in targets:
        target = _target_url(t)
        if not target:
            continue

        try:
            assert_in_scope(target, scope_config)
        except ScopeError:
            observations.append(_out_of_scope_observation("tlsx", target))
            continue

        argv = _build_tlsx_argv(target)

        try:
            sr = run_in_sandbox(argv, target_url=target, config=scope_config,
                                timeout_sec=timeout_sec)
        except (SandboxError, ScopeError) as exc:
            observations.append(_error_observation(
                "tlsx", target, argv, f"sandbox execution failed: {exc}"))
            continue

        if sr.timed_out:
            observations.append(_error_observation(
                "tlsx", target, argv, "tlsx timed out before completing the probe"))
            continue
        if sr.exit_code != 0:
            observations.append(_error_observation(
                "tlsx", target, argv, f"tlsx exited with non-zero code {sr.exit_code}"))
            continue

        for obj in _parse_json_lines(sr.stdout):
            if not obj.get("host"):
                continue                          # not a probe result object
            observations.extend(_tlsx_observations_for(target, obj, argv))

    return observations


def run_ffuf(targets: list, *, scope_config: ScopeConfig,
            timeout_sec: int = _FFUF_SANDBOX_TIMEOUT_SEC) -> list[ReconObservation]:
    """Run ffuf deterministically against every target, sandboxed, in-scope only.

    Content discovery (directory/file brute-force) using the bundled pinned
    wordlist (/opt/wordlists/common.txt — see docker/sandbox/Dockerfile,
    DECISIONS.md D-020). Same scope-gate/sandbox-only/error-handling contract
    as run_httpx/run_tlsx (see above): out-of-scope targets are refused
    (status="out_of_scope") before any sandbox call; a sandbox failure,
    timeout, or non-zero exit is status="error" (never a fabricated hit); a
    clean run with no matching hits yields no observation for that target (not
    an error). `status="observed"` is derived SOLELY from parsed ffuf `-json`
    hit lines on stdout.

    `targets` are typically the LIVE base URLs httpx already confirmed (see
    modules/recon.py's chaining: httpx -> ffuf), falling back to the raw seed
    target when none are available — this function itself is agnostic to that
    provenance and simply probes whichever URLs it is given, each with the
    literal FUZZ keyword appended to its path.
    """
    observations: list[ReconObservation] = []
    for t in targets:
        target = _target_url(t)
        if not target:
            continue

        try:
            assert_in_scope(target, scope_config)
        except ScopeError:
            observations.append(_out_of_scope_observation("ffuf", target))
            continue

        argv = _build_ffuf_argv(target, scope_config=scope_config, timeout_sec=timeout_sec)

        try:
            sr = run_in_sandbox(argv, target_url=target, config=scope_config,
                                timeout_sec=timeout_sec)
        except (SandboxError, ScopeError) as exc:
            observations.append(_error_observation(
                "ffuf", target, argv, f"sandbox execution failed: {exc}"))
            continue

        if sr.timed_out:
            observations.append(_error_observation(
                "ffuf", target, argv, "ffuf timed out before completing the scan"))
            continue
        if sr.exit_code != 0:
            observations.append(_error_observation(
                "ffuf", target, argv, f"ffuf exited with non-zero code {sr.exit_code}"))
            continue

        for obj in _parse_json_lines(sr.stdout):
            if "url" not in obj or "status" not in obj:
                continue                          # not a hit result object
            observations.append(_ffuf_observation_for(target, obj, argv))

    return observations


# ── Opt-in live smoke test ──────────────────────────────────────────────────
if __name__ == "__main__":
    # Requires: .env configured (scope), sandbox image built
    # (bash docker/sandbox/build.sh), and a reachable target in scope.
    #   REDSEE_AUTHORIZED=true REDSEE_ALLOWED_HOSTS=localhost \
    #   REDSEE_TARGET_URL=http://localhost:8080/ PYTHONPATH=. python -m engine.recon_tools
    import os

    from engine.env import load_env
    load_env()
    from engine.scope import load_scope_config

    scope = load_scope_config()
    target = os.environ.get("REDSEE_TARGET_URL") or "http://localhost:8080/"

    print(f"running httpx + tlsx + ffuf recon against {target!r} ...")
    httpx_obs = run_httpx([target], scope_config=scope)
    tlsx_obs = run_tlsx([target], scope_config=scope)
    ffuf_obs = run_ffuf([target], scope_config=scope)

    for label, obs_list in (("httpx", httpx_obs), ("tlsx", tlsx_obs), ("ffuf", ffuf_obs)):
        print(f"\n{label}: {len(obs_list)} observation(s)")
        for o in obs_list:
            tag = o.status.upper()
            print(f"  [{tag}] {o.category}: {o.title} (severity={o.severity})")
            if o.status == "error":
                print(f"    error: {o.error}")
            elif o.status == "observed":
                print(f"    evidence: {o.evidence[:200]}")
