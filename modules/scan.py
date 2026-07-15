# modules/scan.py
"""
Unified scan orchestrator — the aggregation spine.

`run_scan(target_url, *, mode=...)` runs ONE authorized target end-to-end:

    crawl -> extract injectable params -> vuln agents (sqli, xss) on PARAM-BEARING
    targets only -> recon (scoped nuclei, httpx, tlsx, ffuf) -> aggregate

Independent tools run CONCURRENTLY under a conservative sandbox-parallelism bound,
and a scan MODE (fast / standard / deep) tunes how many endpoints are injected, how
deep the injection goes, and which recon runs. The orchestrator drives the engine
agents (run_sqli_agent / run_xss_agent / run_nuclei_agent) DIRECTLY so it can set
per-mode depth/timeout — it does not go through modules/sqli.py's fixed-signature
scan_sqli (which cannot carry mode/depth). Injection targets come from
engine.params (query-string + form/body params); a param-less endpoint is never
handed to sqlmap/Dalfox (wasted sandbox time, only ever an empty result).

It writes ONE new `outputs/scan_<id>.json` that unifies everything, ALONGSIDE (never
instead of) the existing per-tool outputs from `engine.report_io.write_outputs`
(`findings_<id>.json` / `.sarif` / `run_<id>.json` / `nuclei_<id>.json` /
`recon_<id>.json`). All artifacts from ONE run share ONE bare scan_id — directly
addressing the "two differently-named findings files" known-limitation in AGENTS.md:
the unified view is keyed by a single id, `scan_<id>.json`.

Why modules/scan.py (not engine/orchestrator.py):
  storage/scan_store.py imports this module, so the dependency direction is
  storage -> modules -> engine; nothing in engine/ imports modules/. This spine is
  a COMPOSITION over the engine layer (crawl + agents + recon + aggregation) — a
  higher-level concern than any single engine module — and `modules/recon.py`
  already establishes the "run several tools + write outputs" runner pattern here.
  Live entry point is `python -m modules.scan`.

Discipline (mirrors modules/recon.py + the recon_tools status="error" contract):
  * Authorization + scope gate FIRST — an unauthorized/out-of-scope target is refused
    (ScopeError) before ANY artifact is written. No partial run.
  * Every tool is wrapped: a single tool's failure is recorded as an "error" entry and
    the scan CONTINUES — one tool never aborts the whole scan, and a failed tool never
    fabricates results (its section stays empty, exactly like status="error").
  * schemas.py is FROZEN: the unified record is a NEW json artifact, not a schema type.
  * report_io is reused untouched (write_outputs + its secret scrubber + its per-tool
    serializers), so the existing per-tool outputs stay byte-for-byte as they are today.

NOT wired into integration.py's resolver or app.py — that is a later task.
"""

import json
import os
import re
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from urllib.parse import urljoin, urlsplit

from crawler import crawl
from engine.params import select_injection_targets, build_seed_targets, load_seed_params
from engine.agent import run_sqli_agent
from engine.xss_agent import run_xss_agent
from engine.finding_map import candidate_to_finding, xss_candidate_to_finding
from engine.nuclei_agent import run_nuclei_agent
from engine.recon_tools import run_httpx, run_tlsx, run_ffuf
from engine.report_io import (
    write_outputs, _scrub_secrets,
    _nuclei_candidate_dict, _recon_observation_dict,
)
from engine.scope import load_scope_config, require_authorization, assert_in_scope, ScopeError
from engine.llm import Usage

try:
    from engine.llm import load_llm_config as _load_llm_config, LLMError as _LLMError
    _HAS_LLM = True
except ImportError:                                   # pragma: no cover - defensive
    _HAS_LLM = False

# Canonical Finding severities (schemas.py: exactly these four). The rollup always
# reports all four (0 when absent) so the dashboard gets a stable shape.
_SEVERITIES = ("Critical", "High", "Medium", "Low")

# The full, fixed order tools_run is reported in — INDEPENDENT of the order the
# concurrent stages actually finish, so the record shape is deterministic and a
# deep-mode scan is byte-stable vs. the serial version.
_TOOL_ORDER = ("crawl", "sqli", "xss", "nuclei", "httpx", "tlsx", "ffuf")


# ── Scan modes ───────────────────────────────────────────────────────────────
# A scan MODE tunes breadth (how many endpoints are injected), depth (how hard the
# injection agents push), and which recon runs. It is a RUNTIME profile, never a
# schemas.py field. Deep == the pre-mode behavior (all param-bearing endpoints, the
# agents' own default caps, every recon tool).

@dataclass(frozen=True)
class ScanProfile:
    name: str
    # None = no cap (inject every param-bearing endpoint); an int caps how many of
    # the deterministically-ranked injection targets get the sqlmap/Dalfox treatment.
    max_injection_targets: int | None
    sqli_max_level: int
    sqli_max_risk: int
    sqli_max_iterations: int
    xss_max_iterations: int
    # Per-sandbox-run wall-clock for the injection agents; None = the agents' default.
    injection_timeout_sec: int | None
    run_httpx: bool
    run_tlsx: bool
    run_ffuf: bool
    run_nuclei: bool
    # Scoped template tags for nuclei's deterministic pass; None = its default profile.
    nuclei_tags: tuple[str, ...] | None
    # Per-scan wall-clock bound for nuclei; None = the nuclei agent's default.
    nuclei_timeout_sec: int | None
    # ── Discovery loop (D-025) ──
    # Re-crawl ffuf-discovered paths (not linked from the root) to surface THEIR
    # params. `max_discovered_paths` caps how many; the crawl of each is BOUNDED to
    # `discovered_crawl_pages`/`discovered_crawl_depth` (just its immediate surface).
    discover: bool
    max_discovered_paths: int
    discovered_crawl_pages: int
    discovered_crawl_depth: int
    # ── Common-parameter seeding (D-025/D-026) ──
    # Seed common params onto param-LESS API paths. `seed_params`=None means the
    # whole list; an int caps params/path. `seed_paths` caps how many API paths get
    # seeded; `seed_batch` = params packed per sandboxed run (one URL) for whatever
    # isn't isolated. `seed_isolate_top` = the first N (highest-signal) params EACH
    # get their OWN clean single-param request (e.g. `?q=1`) instead of being packed
    # with the rest — sqlmap/Dalfox attribute a signal to ONE param far more reliably
    # that way (D-026: a packed 25-param URL missed a hand-confirmed error-based SQLi
    # on `q` that a clean `?q=1` request would have hit cleanly). Seeded injection is
    # always SHALLOW (level 1) — a broad candidate sweep, not a deep audit — so it
    # stays runtime-bounded regardless of param count (see _SEED_*).
    seed: bool
    seed_params: int | None
    seed_paths: int
    seed_batch: int
    seed_isolate_top: int


_PROFILES = {
    # ~2 min: only the top few param-bearing endpoints from the ROOT crawl, a shallow
    # single-rung injection, and the two cheap deterministic recon probes only. NO
    # ffuf, so NO discovery loop and NO seeding — fast is a quick look at what the
    # crawl already sees, nothing more.
    "fast": ScanProfile(
        name="fast", max_injection_targets=5,
        sqli_max_level=1, sqli_max_risk=1, sqli_max_iterations=2, xss_max_iterations=2,
        injection_timeout_sec=60,
        run_httpx=True, run_tlsx=True, run_ffuf=False, run_nuclei=False,
        nuclei_tags=None, nuclei_timeout_sec=None,
        discover=False, max_discovered_paths=0, discovered_crawl_pages=0, discovered_crawl_depth=0,
        seed=False, seed_params=0, seed_paths=0, seed_batch=15, seed_isolate_top=0,
    ),
    # ~5-8 min: ffuf discovery + a BOUNDED re-crawl of discovered paths + a LEAN,
    # tight common-param seed on the SINGLE highest-signal param-less API path
    # (query/search-ranked — see engine.params._seed_path_rank), medium injection
    # depth, and the full recon set with a scoped, memory-bounded nuclei scan.
    # D-026: right-sized for an 8 GB host running the target itself (Juice Shop) —
    # a wider seed sweep put real memory pressure on the HOST target's own process
    # (not just the 256 MB-capped sandbox containers), not just on this box.
    "standard": ScanProfile(
        name="standard", max_injection_targets=10,
        sqli_max_level=3, sqli_max_risk=2, sqli_max_iterations=4, xss_max_iterations=3,
        injection_timeout_sec=120,
        run_httpx=True, run_tlsx=True, run_ffuf=True, run_nuclei=True,
        nuclei_tags=("exposure", "misconfig"), nuclei_timeout_sec=300,
        # max_discovered_paths 8 -> 4 (D-026 follow-up, live-evidenced): a live run
        # against a Juice Shop already stressed from repeated same-day testing got
        # OOM-killed DURING these re-crawls (plain host-side HTTP requests, no
        # sandbox involved) — every discovered path past the root came back 502.
        # Fewer re-crawls is pure request-volume reduction against the TARGET's own
        # process, independent of sandbox/container memory.
        discover=True, max_discovered_paths=4, discovered_crawl_pages=6, discovered_crawl_depth=1,
        # top 3 params (q, id, search — the highest-signal names) tested in ISOLATION
        # (clean single-param requests), the remaining ~22 packed into one batch.
        seed=True, seed_params=None, seed_paths=1, seed_batch=30, seed_isolate_top=3,
    ),
    # Full: every param-bearing endpoint, agent-default injection depth, full recon,
    # a wider discovery re-crawl, and the full (still lean, 25-name) seed list on a
    # few more API paths — still bounded, not "every path/param". For a target with
    # NO extra discoverable paths/params (discover/seed surface nothing), deep ==
    # the pre-D-025 behavior.
    "deep": ScanProfile(
        name="deep", max_injection_targets=None,
        sqli_max_level=3, sqli_max_risk=2, sqli_max_iterations=6, xss_max_iterations=6,
        injection_timeout_sec=None,
        run_httpx=True, run_tlsx=True, run_ffuf=True, run_nuclei=True,
        nuclei_tags=None, nuclei_timeout_sec=None,
        discover=True, max_discovered_paths=15, discovered_crawl_pages=20, discovered_crawl_depth=2,
        seed=True, seed_params=None, seed_paths=3, seed_batch=30, seed_isolate_top=5,
    ),
}

DEFAULT_MODE = "standard"

# Seeded injection is a SHALLOW candidate sweep (a seeded param is a guess, not a
# crawled fact): always level 1 / risk 1, few iterations, so each seeded path costs
# ~one sandboxed run testing all its packed params at once — bounded regardless of
# how many params are seeded. (A crawled, param-bearing target still gets the mode's
# full depth.) Deep's extra thoroughness comes from seeding MORE params/paths, not
# from going deeper per seeded param.
_SEED_MAX_LEVEL = 1
_SEED_MAX_RISK = 1
_SEED_MAX_ITERATIONS = 2

# Isolated seeded targets (isolate_top — each carrying exactly ONE param in its own
# clean request) get a DEEPER ceiling than the packed batch: engine.agent's own
# detection ladder documents rung 1 (level=3/risk=2) as what actually "confirms
# blind SQLi", vs. rung 0 (level=1/risk=1) being only a "fast baseline". Live-
# evidenced against redsees.com: `/rest/products/search`'s `q` came back "clean" at
# rung 0 even with a clean isolated request AND a realistic probe value (`apple`) —
# the vulnerability is blind and genuinely needs rung 1 to confirm, not an
# attribution problem isolate_top already fixed. The packed low-confidence batch
# (many params, one broad sweep) stays at rung-0-only — cheap and bounded.
_SEED_ISOLATED_MAX_LEVEL = 3
_SEED_ISOLATED_MAX_RISK = 2

# HARD ceiling on total injection targets (crawled + seeded) dispatched per scan,
# regardless of mode/profile misconfiguration — the last line of defense against a
# pathological target (e.g. a future "deep"-like profile with max_injection_targets
# raised too high, or an unusually param-rich site) spawning dozens of sandboxed
# sqlmap/Dalfox runs in one scan. Ranking (crawled — real, confirmed params — before
# seeded — candidate guesses) is preserved when trimming to this ceiling.
_MAX_TOTAL_INJECTION_TARGETS = 20


def resolve_profile(mode) -> ScanProfile:
    """The ScanProfile for `mode`; an unknown/empty mode falls back to the default
    (never raises — a bad mode string should degrade to a sane scan, not abort)."""
    key = (mode or "").strip().lower()
    return _PROFILES.get(key, _PROFILES[DEFAULT_MODE])


def _max_parallel_sandboxes() -> int:
    """Conservative bound on how many stages (and therefore sandboxes) run at once.

    Default 2 — each sandboxed tool container is itself capped at 256 MB
    (engine.sandbox, frozen), so 2 concurrent stages is a bounded, verified-safe
    ceiling. D-026 tried defaulting this to 1 (fully serial) to address memory
    pressure on this project's 8 GB host, which also runs the scanned target
    itself — but live-measured, serial-by-default pushed a standard scan's
    wall-clock from ~6-7 min to >18 min (timed out) with NO measured memory
    benefit over just shrinking the seeded work itself (the lean 25-name param
    list + seed_paths=1/3 + the hard _MAX_TOTAL_INJECTION_TARGETS ceiling below —
    those cut TOTAL request/container volume, which serial-only concurrency does
    not). Reverted to 2. Set REDSEE_MAX_PARALLEL_SANDBOXES=1 for the safest,
    slowest, fully-serial mode on an even more constrained host, or higher on a
    bigger one. Kept conservative rather than higher by default on purpose:
    run_in_sandbox sets up per-run iptables egress rules, and stray rules from a
    KILLED run have collided before."""
    try:
        return max(1, int(os.environ.get("REDSEE_MAX_PARALLEL_SANDBOXES", "2")))
    except (ValueError, TypeError):
        return 2


def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ── Per-tool wrapper: a failure is an error entry, never a scan abort ────────

# Sentinel distinguishing "the tool raised" from "the tool returned None/[]".
_FAILED = object()


def _safe(fn):
    """Run fn(); return (result, None) on success or (_FAILED, reason) on ANY
    exception. NEVER re-raises — a single tool's failure must not abort the scan,
    and its caller records an error entry instead of fabricating a result."""
    try:
        return fn(), None
    except Exception as exc:                          # noqa: BLE001 - deliberate catch-all
        return _FAILED, f"{type(exc).__name__}: {exc}"


def _record(tools_run: list, name: str, status: str, count: int, detail: str) -> None:
    tools_run.append({"name": name, "status": status,
                      "count": int(count), "detail": detail})


def _classify_results(items: list, positive: str) -> tuple:
    """(status, count, detail) for a tools_run entry from a list of
    status-bearing results (recon ReconObservations or nuclei NucleiCandidates).

    `positive` is the status that counts as a real result ("observed" or
    "found"). The recon/nuclei tools do NOT raise on a sandbox/isolation failure
    — they return a status="error" result instead — so this classifier surfaces
    that honestly rather than reporting a misleading "ran, 0":
      * any positives          -> "ran"    (count = number of positives)
      * results, ALL errored   -> "error"  (e.g. sandbox unreachable — the real
                                             per-result error reason is the detail)
      * results, ALL out-of-scope -> "skipped"
      * ran but nothing positive (e.g. nuclei clean) -> "ran", count 0
      * no results at all       -> "ran", count 0 ("no results")
    """
    n = len(items)
    if n == 0:
        return "ran", 0, "no results"
    statuses = [getattr(i, "status", None) for i in items]
    pos = sum(1 for s in statuses if s == positive)
    err = sum(1 for s in statuses if s == "error")
    oos = sum(1 for s in statuses if s == "out_of_scope")
    if pos == 0 and err == n:
        reason = next((getattr(i, "error", None) for i in items
                       if getattr(i, "status", None) == "error"), None)
        return "error", 0, (reason or "all targets errored")[:300]
    if pos == 0 and oos == n:
        return "skipped", 0, "out of scope"
    detail = f"{pos} {positive}"
    if err:
        detail += f", {err} errored"
    if oos:
        detail += f", {oos} out-of-scope"
    return "ran", pos, detail


# ── Small helpers ───────────────────────────────────────────────────────────

def _severity_rollup(findings: list) -> dict:
    """Counts by Finding severity — all four canonical levels always present."""
    roll = {sev: 0 for sev in _SEVERITIES}
    for f in findings:
        sev = getattr(f, "severity", None)
        roll[sev] = roll.get(sev, 0) + 1
    return roll


def _build_llm_meta():
    """Non-secret LLM run metadata (provider/model/spend-cap), mirroring
    modules/sqli.py's block. A module-level function so tests can override it to
    prove the secret scrub is wired. The result is ALWAYS run through
    report_io._scrub_secrets before it reaches any artifact."""
    if not _HAS_LLM:
        return None
    try:
        cfg = _load_llm_config()
    except Exception:                                 # noqa: BLE001 - LLM optional
        return None
    return {"provider": cfg.base_url, "model": cfg.model, "max_usd": cfg.max_usd}


def _redsee_version():
    """Installed RedSee package version if it happens to be installed, else None
    (this repo ships no version metadata today)."""
    try:
        from importlib.metadata import version, PackageNotFoundError
        try:
            return version("redsee")
        except PackageNotFoundError:
            return None
    except Exception:                                 # noqa: BLE001 - defensive
        return None


class _EmptyAgentResult:
    """Stand-in agent_result for write_outputs when the nuclei agent itself
    failed (so run_<id>.json is still produced). Carries the same
    candidates/usage/iterations/transcript/stopped_reason shape write_outputs
    reads, all empty — never fabricated scan data."""

    def __init__(self, stopped_reason: str = "error"):
        self.candidates: list = []
        self.usage = Usage(input_tokens=0, output_tokens=0, cost_usd=0.0, calls=0)
        self.iterations = 0
        self.transcript: list = []
        self.stopped_reason = stopped_reason


# ── Injection drivers (agents -> Findings) ──────────────────────────────────
# The orchestrator drives run_sqli_agent / run_xss_agent DIRECTLY (not via
# modules/sqli.py) so it can set per-mode depth/iterations/timeout. injectable is
# still derived SOLELY from the agents' parsed tool output: only status=="injectable"
# candidates become Findings (engine.finding_map enforces this), so the evidence
# gate is intact — this holds for SEEDED candidate params exactly as for crawled
# ones: a seeded param the tool reports not-injectable never becomes a finding.
#
# `crawled` targets carry the mode's FULL injection depth; `seeded` (candidate
# common params on param-less API paths) get a SHALLOW pass (_SEED_* — level 1,
# few iterations) so a broad seed sweep stays runtime-bounded. Both feed the ONE
# "sqli"/"xss" tools_run entry (findings merged); no new tool names.

def _sqli_candidate_summary(c) -> dict:
    """A compact, evidence-only summary of ONE SqliCandidate — status/parameter/
    technique/dbms plus a truncated evidence excerpt — for EVERY candidate tested,
    not just confirmed ones. Mirrors how recon already exposes clean/error results
    alongside found ones (D-017); sqli/xss had no equivalent transparency before —
    a "0 findings" result was a black box with no visibility into what was actually
    tested or why it came back clean. Never a finding on its own; purely diagnostic."""
    return {
        "url": c.endpoint_url, "parameter": c.parameter, "status": c.status,
        "technique": c.technique, "dbms": c.dbms, "depth": c.depth,
        "error": c.error, "evidence": (c.evidence or "")[:300],
    }


def _xss_candidate_summary(c) -> dict:
    return {
        "url": c.endpoint_url, "parameter": c.parameter, "status": c.status,
        "context": c.context, "payload": c.payload,
        "error": c.error, "evidence": (c.evidence or "")[:300],
    }


def _scan_sqli_targets(crawled: list, seeded: list = None, *, scope_config,
                       profile: ScanProfile, scan_id: str) -> tuple:
    """SQLi agent over crawled (full depth) + seeded injection targets. Seeded
    targets are further split: ISOLATED (isolate_top — one param, one clean
    request) get a deeper ceiling (_SEED_ISOLATED_MAX_*, ladder rung 1 — needed to
    confirm a blind SQLi); the packed low-confidence BATCH stays at the shallow
    rung-0-only ceiling (_SEED_MAX_*). Returns (findings, candidate_summaries) —
    the summaries cover EVERY candidate tested (clean/error included), for
    scan-record transparency (see _sqli_candidate_summary)."""
    findings: list = []
    candidates: list = []
    if crawled:
        result = run_sqli_agent(
            list(crawled), scope_config=scope_config,
            max_iterations=profile.sqli_max_iterations,
            max_level=profile.sqli_max_level, max_risk=profile.sqli_max_risk,
            timeout_sec=profile.injection_timeout_sec)
        tgt = getattr(crawled[0], "url", "") or ""
        findings += [candidate_to_finding(c, target_url=tgt, scan_id=scan_id)
                     for c in result.candidates if c.status == "injectable"]
        candidates += [_sqli_candidate_summary(c) for c in result.candidates]
    if seeded:
        isolated = [t for t in seeded if len(t.param_names) == 1]
        batched = [t for t in seeded if len(t.param_names) != 1]
        for group, max_level, max_risk in (
            (isolated, _SEED_ISOLATED_MAX_LEVEL, _SEED_ISOLATED_MAX_RISK),
            (batched, _SEED_MAX_LEVEL, _SEED_MAX_RISK),
        ):
            if not group:
                continue
            result = run_sqli_agent(
                list(group), scope_config=scope_config,
                max_iterations=_SEED_MAX_ITERATIONS,
                max_level=max_level, max_risk=max_risk,
                timeout_sec=profile.injection_timeout_sec)
            tgt = getattr(group[0], "url", "") or ""
            findings += [candidate_to_finding(c, target_url=tgt, scan_id=scan_id)
                         for c in result.candidates if c.status == "injectable"]
            candidates += [_sqli_candidate_summary(c) for c in result.candidates]
    return findings, candidates


def _scan_xss_targets(crawled: list, seeded: list = None, *, scope_config,
                      profile: ScanProfile, scan_id: str) -> tuple:
    """XSS agent over crawled (full depth) + seeded (shallow) targets. REDSEE_XSS_COOKIE
    (if set) is threaded through for authenticated targets, mirroring modules/xss.py.
    Returns (findings, candidate_summaries) — see _scan_sqli_targets."""
    auth_cookie = os.environ.get("REDSEE_XSS_COOKIE") or None
    findings: list = []
    candidates: list = []
    if crawled:
        result = run_xss_agent(
            list(crawled), scope_config=scope_config,
            max_iterations=profile.xss_max_iterations,
            auth_cookie=auth_cookie, timeout_sec=profile.injection_timeout_sec)
        tgt = getattr(crawled[0], "url", "") or ""
        findings += [xss_candidate_to_finding(c, target_url=tgt, scan_id=scan_id)
                     for c in result.candidates if c.status == "injectable"]
        candidates += [_xss_candidate_summary(c) for c in result.candidates]
    if seeded:
        result = run_xss_agent(
            list(seeded), scope_config=scope_config,
            max_iterations=_SEED_MAX_ITERATIONS,
            auth_cookie=auth_cookie, timeout_sec=profile.injection_timeout_sec)
        tgt = getattr(seeded[0], "url", "") or ""
        findings += [xss_candidate_to_finding(c, target_url=tgt, scan_id=scan_id)
                     for c in result.candidates if c.status == "injectable"]
        candidates += [_xss_candidate_summary(c) for c in result.candidates]
    return findings, candidates


# ── Discovery helpers ────────────────────────────────────────────────────────

def _discovered_urls_from_ffuf(ffuf_obs: list) -> list:
    """The distinct URLs ffuf discovered (content-discovery hits), first-seen order.
    Each ffuf ReconObservation records the hit path in its `evidence` (`path=<p> ...`);
    reconstruct the absolute URL as urljoin(base, path). These are top-level paths the
    ROOT crawl can't reach because nothing links to them (e.g. /market) — the discovery
    loop re-crawls them to surface their params."""
    urls: list = []
    seen: set = set()
    for o in ffuf_obs:
        if getattr(o, "status", None) != "observed":
            continue
        if getattr(o, "category", None) != "content-discovery":
            continue
        evidence = getattr(o, "evidence", "") or ""
        m = re.search(r"path=(\S+)", evidence)
        if not m:
            continue
        base = getattr(o, "target", None) or ""
        url = urljoin(base, m.group(1))
        if url and url not in seen:
            seen.add(url)
            urls.append(url)
    return urls


# Static/leaf markers that rarely hide further crawlable APP surface: known static
# files (a security policy, robots directive, a hashed bundle) and generic static-
# asset directory names common across real webapps (not Juice-Shop-specific) — a
# hit on these is far more likely to be a plain file server than a dynamic app
# section with its own links/forms/params.
_DISCOVERY_STATIC_LEAF_MARKERS = (
    ".well-known", "robots.txt", "security.txt", "favicon", "sitemap",
    "humans.txt", "manifest.json", "browserconfig.xml",
    "assets", "static", "media", "images", "img", "css", "js", "fonts",
    "uploads", "downloads", "backup", "backups", "cache", "tmp", "temp",
    "logs", "log", "video", "videos", "ftp",
)


def _discovery_path_rank(url: str) -> tuple:
    """Ranking key for a DISCOVERED (ffuf) path when capping discovery-loop
    re-crawls (mode-bounded, so which paths get the cheap slots matters): a short,
    extension-less, non-static-leaf path (e.g. `/market`) is far more likely to be a
    real APP SECTION worth re-crawling than a known static leaf file (`.well-known/
    security.txt`, `favicon.ico`) or a deep/file-looking one — those rarely reveal
    further links/forms/params. Ascending sort = higher priority first: non-leaf
    before leaf, no-extension before extension, shallower before deeper, then URL
    for a total, deterministic (never random) order."""
    try:
        path = urlsplit(url).path.strip("/")
    except (ValueError, AttributeError):
        path = url or ""
    lowered = path.lower()
    is_static_leaf = any(m in lowered for m in _DISCOVERY_STATIC_LEAF_MARKERS)
    segments = [s for s in path.split("/") if s]
    has_ext = bool(segments) and "." in segments[-1]
    return (1 if is_static_leaf else 0, 1 if has_ext else 0, len(segments), url)


def _endpoint_paths(endpoints: list) -> set:
    """The set of normalized scheme://host/path for a list of endpoints — used to skip
    re-crawling a discovered path the root crawl already covers."""
    out: set = set()
    for e in endpoints:
        url = getattr(e, "url", "") or ""
        try:
            p = urlsplit(url)
            out.add(f"{p.scheme}://{p.netloc}{p.path}")
        except (ValueError, AttributeError):
            continue
    return out


# ── Orchestrator ────────────────────────────────────────────────────────────

def _run_stages(stages: dict, max_parallel: int) -> dict:
    """Run each stage callable in `stages` (name -> zero-arg fn) concurrently under
    a ThreadPoolExecutor bounded to `max_parallel` workers, each wrapped in _safe.

    Returns name -> (result_or__FAILED, error_reason). A stage that raises never
    aborts the others — its failure becomes an error entry (mirrors _safe). Bounded
    on purpose: at most `max_parallel` stages (hence isolated sandboxes) coexist."""
    if not stages:
        return {}
    workers = max(1, min(max_parallel, len(stages)))
    with ThreadPoolExecutor(max_workers=workers,
                            thread_name_prefix="redsee-scan-stage") as ex:
        futures = {name: ex.submit(_safe, fn) for name, fn in stages.items()}
        return {name: fut.result() for name, fut in futures.items()}


def run_scan(target_url: str, *, scope_config=None, scan_id: str | None = None,
             out_dir: str = "outputs", mode: str = DEFAULT_MODE) -> dict:
    """Run a full end-to-end scan of ONE authorized target and write the unified
    outputs/scan_<id>.json (plus the existing per-tool artifacts, all sharing the
    one scan_id).

    `mode` (fast / standard / deep) tunes breadth (how many param-bearing endpoints
    are injected), depth (injection level/risk/iterations/timeout), and which recon
    runs — see the ScanProfile table above. An unknown mode degrades to the default.

    Gating (engine.scope, reused — never reimplemented) runs FIRST:
    require_authorization + assert_in_scope. An unauthorized or out-of-scope
    target raises ScopeError and NOTHING is written (no partial run).

    Flow is DISCOVERY-FIRST (D-025): crawl the root, then ffuf + httpx run BEFORE
    injection so discovered paths feed it — each ffuf-discovered path (not linked
    from the root) is re-crawled (bounded, scope-checked) to surface its params, and
    param-LESS API paths are SEEDED with common param names (engine.params) so a JSON
    API endpoint the crawler can't read params off (e.g. /rest/products/search?q=)
    still gets injection-tested. Injection then runs on crawled (full-depth) + seeded
    (shallow) targets, concurrently with nuclei/tlsx. Seeding proposes CANDIDATES
    only — a finding still derives solely from the tool confirming injection on that
    (url, param). Discovery/seeding are mode-bounded (fast: off; standard: moderate;
    deep: full). Each stage is wrapped so a single failure is an "error" tools_run
    entry and the scan continues; nothing is fabricated.

    Returns the unified record dict (also written to outputs/scan_<id>.json).
    """
    # 1. GATE FIRST — refuse before writing anything.
    if scope_config is None:
        scope_config = load_scope_config()
    require_authorization(scope_config)
    assert_in_scope(target_url, scope_config)

    profile = resolve_profile(mode)
    max_parallel = _max_parallel_sandboxes()

    # 2. ONE bare scan_id for EVERY artifact this run (unified file is scan_<id>.json;
    #    per-tool files are findings_<id>.json / run_<id>.json / nuclei_<id>.json /
    #    recon_<id>.json — same id).
    scan_id = scan_id or uuid.uuid4().hex[:8]
    started_at = _ts()
    tool_status: dict = {}          # name -> (status, count, detail), assembled in
                                    # _TOOL_ORDER at the end regardless of finish order

    # 3. Crawl the ROOT -> seed endpoints (serial; discovery/injection depend on it).
    res, err = _safe(lambda: crawl(target_url))
    if err is not None:
        endpoints: list = []
        crawl_error = err
    else:
        endpoints = list(res.endpoints)
        crawl_error = None
    root_endpoint_count = len(endpoints)

    # 4. DISCOVERY (before injection): ffuf + httpx run concurrently. ffuf discovers
    #    top-level paths the ROOT crawl can't reach (nothing links to them, e.g.
    #    /market); httpx confirms reachability (also feeds the skip reason below).
    disc_stages: dict = {}
    if profile.run_httpx:
        disc_stages["httpx"] = lambda: run_httpx([target_url], scope_config=scope_config)
    if profile.run_ffuf:
        disc_stages["ffuf"] = lambda: run_ffuf([target_url], scope_config=scope_config)
    disc_results = _run_stages(disc_stages, max_parallel)

    httpx_obs: list = []
    if "httpx" in disc_stages:
        res, err = disc_results["httpx"]
        if err is not None:
            tool_status["httpx"] = ("error", 0, err)
        else:
            httpx_obs = list(res or [])
            tool_status["httpx"] = _classify_results(httpx_obs, "observed")
    else:
        tool_status["httpx"] = ("skipped", 0, f"disabled in {profile.name} profile")

    ffuf_obs: list = []
    if "ffuf" in disc_stages:
        res, err = disc_results["ffuf"]
        if err is not None:
            tool_status["ffuf"] = ("error", 0, err)
        else:
            ffuf_obs = list(res or [])
            tool_status["ffuf"] = _classify_results(ffuf_obs, "observed")
    else:
        tool_status["ffuf"] = ("skipped", 0, f"disabled in {profile.name} profile")

    # 5. DISCOVERY LOOP: re-crawl each ffuf-discovered path not already covered —
    #    BOUNDED (mode caps + a shallow per-path crawl) and SCOPE-CHECKED on every
    #    fetch — to surface its links/forms/query params for injection. RANKED
    #    (_discovery_path_rank) before the cap so a tight max_discovered_paths still
    #    reaches likely app sections (e.g. /market) over static leaf files ffuf's
    #    raw hit order would otherwise let crowd out the cheap slots.
    discovered_urls = _discovered_urls_from_ffuf(ffuf_obs)
    discovered_urls_ranked = sorted(discovered_urls, key=_discovery_path_rank)
    paths_recrawled = 0
    if profile.discover and discovered_urls_ranked:
        covered = _endpoint_paths(endpoints)
        for durl in discovered_urls_ranked:
            if paths_recrawled >= profile.max_discovered_paths:
                break
            try:                                   # discovery NEVER leaves the allow-list
                assert_in_scope(durl, scope_config)
            except ScopeError:
                continue
            try:
                npath = urlsplit(durl)
                npath = f"{npath.scheme}://{npath.netloc}{npath.path}"
            except (ValueError, AttributeError):
                continue
            if npath in covered:
                continue
            covered.add(npath)
            r, e = _safe(lambda u=durl: crawl(
                u, max_pages=profile.discovered_crawl_pages,
                max_depth=profile.discovered_crawl_depth))
            if e is None and r is not None:
                new_eps = list(r.endpoints)
                endpoints.extend(new_eps)
                covered |= _endpoint_paths(new_eps)
                paths_recrawled += 1

    # Record crawl status now (reflecting the discovery-loop re-crawls too).
    if crawl_error is not None:
        tool_status["crawl"] = ("error", 0, crawl_error)
    else:
        detail = f"{len(endpoints)} endpoints"
        if paths_recrawled:
            detail += (f" ({root_endpoint_count} from root + {paths_recrawled} "
                       f"discovered path(s))")
        tool_status["crawl"] = ("ran", len(endpoints), detail)

    # 6. Build injection targets:
    #    * crawled — param-bearing endpoints (from the root + discovered-path crawls),
    #      deterministically ranked + capped; tested at the mode's FULL depth.
    #    * seeded — common params paired onto param-LESS API paths (engine.params),
    #      tested SHALLOW. A seeded param is a candidate: a finding still derives
    #      solely from the tool confirming injection on that (url, param).
    crawled_targets = select_injection_targets(endpoints, limit=profile.max_injection_targets)
    seeded_targets: list = []
    if profile.seed:
        seed_names = load_seed_params(profile.seed_params)
        seeded_targets = build_seed_targets(
            endpoints, param_names=seed_names, max_paths=profile.seed_paths,
            batch_size=profile.seed_batch, isolate_top=profile.seed_isolate_top,
            crawled_target_urls=[t.url for t in crawled_targets])

    # HARD ceiling — the last line of defense against a pathological target/profile
    # spawning too many sandboxed injection runs in one scan (see
    # _MAX_TOTAL_INJECTION_TARGETS). Crawled (real, confirmed params) are trimmed
    # last — seeded (candidate guesses) give way first if the total is over budget.
    total_targets = len(crawled_targets) + len(seeded_targets)
    if total_targets > _MAX_TOTAL_INJECTION_TARGETS:
        seed_budget = max(0, _MAX_TOTAL_INJECTION_TARGETS - len(crawled_targets))
        seeded_targets = seeded_targets[:seed_budget]
        crawled_targets = crawled_targets[:_MAX_TOTAL_INJECTION_TARGETS]

    # 7. INJECTION + remaining recon (nuclei, tlsx) — concurrent, bounded. sqli/xss
    #    each test crawled (full depth) + seeded (shallow) in ONE stage.
    inj_stages: dict = {}
    if crawled_targets or seeded_targets:
        inj_stages["sqli"] = lambda: _scan_sqli_targets(
            crawled_targets, seeded_targets, scope_config=scope_config,
            profile=profile, scan_id=scan_id)
        inj_stages["xss"] = lambda: _scan_xss_targets(
            crawled_targets, seeded_targets, scope_config=scope_config,
            profile=profile, scan_id=scan_id)
    if profile.run_nuclei:
        _nuclei_cookie = os.environ.get("REDSEE_NUCLEI_COOKIE") or None
        _nuclei_tags = list(profile.nuclei_tags) if profile.nuclei_tags else None
        inj_stages["nuclei"] = lambda: run_nuclei_agent(
            [target_url], scope_config=scope_config, default_tags=_nuclei_tags,
            timeout_sec=profile.nuclei_timeout_sec, auth_cookie=_nuclei_cookie)
    if profile.run_tlsx:
        inj_stages["tlsx"] = lambda: run_tlsx([target_url], scope_config=scope_config)

    inj_results = _run_stages(inj_stages, max_parallel)

    tlsx_obs: list = []
    if "tlsx" in inj_stages:
        res, err = inj_results["tlsx"]
        if err is not None:
            tool_status["tlsx"] = ("error", 0, err)
        else:
            tlsx_obs = list(res or [])
            tool_status["tlsx"] = _classify_results(tlsx_obs, "observed")
    else:
        tool_status["tlsx"] = ("skipped", 0, f"disabled in {profile.name} profile")

    # Injection (sqli/xss): a "skipped" here means there was nothing to inject — no
    # crawled param AND nothing seedable — CORRECT behavior, made legible with a
    # 3-way reason (uses httpx's reachability, gathered in the discovery phase).
    httpx_reached = any(getattr(o, "status", None) == "observed" for o in httpx_obs)
    if endpoints:
        inj_skip = (f"crawled {len(endpoints)} endpoint(s); none carry an injectable "
                    f"parameter and no param-less API path was seedable — nothing to inject")
    elif httpx_reached:
        inj_skip = ("target responded (see httpx/tlsx recon below) but crawl "
                    "discovered 0 endpoints — possible app-level failure behind "
                    "a proxy/gateway, not a connectivity issue — nothing to inject")
    else:
        inj_skip = ("target appears unreachable — crawl and httpx both got no "
                    "live response (0 pages crawled, 0 recon observations) — "
                    "nothing to inject")

    sqli_findings: list = []
    xss_findings: list = []
    sqli_candidates: list = []
    xss_candidates: list = []
    for name in ("sqli", "xss"):
        if name not in inj_stages:
            tool_status[name] = ("skipped", 0, inj_skip)
            continue
        res, err = inj_results[name]
        if err is not None:
            tool_status[name] = ("error", 0, err)
        else:
            found, cands = res if res else ([], [])
            found = list(found or [])
            tool_status[name] = ("ran", len(found), f"{len(found)} finding(s)")
            if name == "sqli":
                sqli_findings = found
                sqli_candidates = list(cands or [])
            else:
                xss_findings = found
                xss_candidates = list(cands or [])

    nuclei_result = None
    nuclei_candidates: list = []
    if "nuclei" not in inj_stages:
        tool_status["nuclei"] = ("skipped", 0, f"disabled in {profile.name} profile")
    else:
        res, err = inj_results["nuclei"]
        if err is not None:
            tool_status["nuclei"] = ("error", 0, err)
        else:
            nuclei_result = res
            nuclei_candidates = list(res.candidates)
            tool_status["nuclei"] = _classify_results(nuclei_candidates, "found")

    findings = sqli_findings + xss_findings
    recon_observations = httpx_obs + tlsx_obs + ffuf_obs
    finished_at = _ts()

    # Discovery/seeding transparency for the operator.
    seeded_api_paths = len({t.url.split("?", 1)[0] for t in seeded_targets})
    params_seeded = len({p for t in seeded_targets for p in t.param_names})

    # tools_run assembled in a FIXED order (independent of concurrent finish order).
    tools_run: list = []
    for name in _TOOL_ORDER:
        status, count, detail = tool_status[name]
        _record(tools_run, name, status, count, detail)

    # 8. Existing per-tool outputs, UNCHANGED — reuse write_outputs as-is, under the
    #    ONE shared scan_id. Empty lists (not None) are passed so nuclei_<id>.json and
    #    recon_<id>.json are always produced even if that tool errored (empty, not
    #    fabricated). llm_meta is passed raw; write_outputs scrubs it for run.json.
    llm_meta_raw = _build_llm_meta()
    agent_result = nuclei_result if nuclei_result is not None else _EmptyAgentResult()
    paths = write_outputs(
        agent_result, findings,
        scan_id=scan_id, target_url=target_url, out_dir=out_dir,
        llm_meta=llm_meta_raw,
        nuclei_candidates=nuclei_candidates,
        recon_observations=recon_observations,
    )

    # 9. Unified record. Tool sections reuse report_io's OWN serializers, so the
    #    shapes match nuclei_<id>.json / recon_<id>.json exactly. Secret-scrubbed
    #    with report_io's scrubber, same as run_<id>.json.
    observed = sum(1 for o in recon_observations if getattr(o, "status", None) == "observed")
    record = {
        "scan_id": scan_id,
        "target": target_url,
        "mode": profile.name,
        "started_at": started_at,
        "finished_at": finished_at,
        "redsee_version": _redsee_version(),
        "tools_run": tools_run,
        "findings": [f.to_dict() for f in findings],
        "recon": {
            "nuclei": [_nuclei_candidate_dict(c) for c in nuclei_candidates],
            "observations": [_recon_observation_dict(o) for o in recon_observations],
        },
        # EVERY sqli/xss candidate actually tested (clean/error included, not just
        # confirmed findings) — evidence-only diagnostic transparency, mirroring how
        # recon already exposes clean/error results alongside found ones (D-017).
        # Lets an operator see WHY a target came back clean (wrong technique tried,
        # sandbox error, ...) instead of a "0 findings" black box.
        "injection_candidates": {
            "sqli": sqli_candidates,
            "xss": xss_candidates,
        },
        # Discovery→injection loop transparency: "discovered N, re-crawled M, seeded
        # P params on Q API paths, tested T injection targets".
        "discovery": {
            "paths_discovered": len(discovered_urls),
            "paths_recrawled": paths_recrawled,
            "endpoints_from_root": root_endpoint_count,
            "endpoints_total": len(endpoints),
            "params_from_crawl": len(crawled_targets),
            "seeded_api_paths": seeded_api_paths,
            "params_seeded": params_seeded,
            "seed_targets": len(seeded_targets),
            "injection_targets_tested": len(crawled_targets) + len(seeded_targets),
        },
        # Effective caps this mode applied — so a reader can see exactly how the scan
        # was tuned (endpoints crawled vs. injected, injection depth, discovery/seeding).
        "caps": {
            "mode": profile.name,
            "endpoints_crawled": len(endpoints),
            "injection_targets_selected": len(crawled_targets),
            "max_injection_targets": profile.max_injection_targets,
            "sqli_max_level": profile.sqli_max_level,
            "sqli_max_risk": profile.sqli_max_risk,
            "sqli_max_iterations": profile.sqli_max_iterations,
            "xss_max_iterations": profile.xss_max_iterations,
            "injection_timeout_sec": profile.injection_timeout_sec,
            "recon": {"httpx": profile.run_httpx, "tlsx": profile.run_tlsx,
                      "ffuf": profile.run_ffuf, "nuclei": profile.run_nuclei},
            "nuclei_tags": list(profile.nuclei_tags) if profile.nuclei_tags else None,
            "discover": profile.discover,
            "max_discovered_paths": profile.max_discovered_paths,
            "seed": profile.seed,
            "seed_params": profile.seed_params,
            "seed_paths": profile.seed_paths,
            "seed_inject_max_level": _SEED_MAX_LEVEL,
            "max_total_injection_targets": _MAX_TOTAL_INJECTION_TARGETS,
            "max_parallel_sandboxes": max_parallel,
        },
        "summary": {
            "mode": profile.name,
            "findings_total": len(findings),
            "findings_by_severity": _severity_rollup(findings),
            "recon_observations": observed,
            "endpoints_crawled": len(endpoints),
            "injection_targets": len(crawled_targets) + len(seeded_targets),
            "params_seeded": params_seeded,
            "seeded_api_paths": seeded_api_paths,
            "paths_discovered": len(discovered_urls),
            "tools_ok": sum(1 for t in tools_run if t["status"] == "ran"),
            "tools_error": sum(1 for t in tools_run if t["status"] == "error"),
            "tools_skipped": sum(1 for t in tools_run if t["status"] == "skipped"),
            "tools_total": len(tools_run),
        },
        "outputs": {**paths, "scan": None},   # "scan" filled in just below
    }
    scrubbed_meta = _scrub_secrets(llm_meta_raw)
    if scrubbed_meta:
        record["llm"] = scrubbed_meta

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    scan_path = out / f"scan_{scan_id}.json"
    record["outputs"]["scan"] = str(scan_path)
    scan_path.write_text(json.dumps(record, indent=2), encoding="utf-8")

    return record


# ── Opt-in live entry point ─────────────────────────────────────────────────
if __name__ == "__main__":
    # Requires: .env configured (scope + LLM), sandbox image built
    # (bash docker/sandbox/build.sh), a running Ollama, and a reachable in-scope
    # target. .env is loaded automatically (override=False, so real env wins).
    #
    #   REDSEE_AUTHORIZED=true REDSEE_ALLOWED_HOSTS=redsees.com \
    #   REDSEE_TARGET_URL=http://redsees.com:3000/ \
    #   REDSEE_LLM_BASE_URL=http://localhost:11434/v1 REDSEE_LLM_MODEL=llama3.2 \
    #   REDSEE_LLM_MAX_USD=0.50 PYTHONPATH=. python -m modules.scan
    import os

    from engine.env import load_env
    load_env()

    target = os.environ.get("REDSEE_TARGET_URL") or "http://localhost:8080/"
    mode = os.environ.get("REDSEE_SCAN_MODE") or DEFAULT_MODE

    record = run_scan(target, mode=mode)
    print(f"scan_id={record['scan_id']} target={record['target']} mode={record['mode']}")
    print(f"caps: {json.dumps(record['caps'])}")
    print(f"started={record['started_at']} finished={record['finished_at']}")
    print("tools_run:")
    for t in record["tools_run"]:
        print(f"  {t['name']:<7} {t['status']:<8} count={t['count']:<3} {t['detail']}")
    s = record["summary"]
    print(f"findings: {s['findings_total']} {s['findings_by_severity']}")
    print(f"recon observations: {s['recon_observations']}")
    print(f"tools ok/err/skip: {s['tools_ok']}/{s['tools_error']}/{s['tools_skipped']}")
    print("outputs:")
    for kind, path in record["outputs"].items():
        print(f"  {kind}: {path}")
