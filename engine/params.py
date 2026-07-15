# engine/params.py
"""
Injectable-parameter extraction — turns raw crawler output into the subset of
endpoints worth handing to the SQLi/XSS agents, and nothing else.

sqlmap (engine/agent.py) and Dalfox (engine/xss_agent.py) test INJECTABLE
PARAMETERS — query-string params and form/body fields — never a bare, param-less
URL. Pointing them at an endpoint that carries no parameter is wasted sandbox
time that can only ever return an empty result. This module extracts, per
endpoint, the set of injectable parameter NAMES and keeps only the endpoints that
actually have at least one, so the orchestrator feeds the agents real work.

What counts as an injectable parameter (documented contract):
  * QUERY-STRING params — every distinct key in the URL's query string
    (`?id=1&q=x` -> id, q).
  * HTML FORM fields — the crawler already collects each <form>'s input/textarea/
    select `name`s into Endpoint.inputs (endpoint_type "form"); each is a body (or
    query, for a GET form) parameter.
  * LINK params — the crawler records a query-bearing <a href> as a "link"
    endpoint whose `inputs` are the query keys; those are query params.
  * JSON body keys — WHERE AVAILABLE. The crawler surfaces an API endpoint's body
    field names (when it can parse them) into `inputs`, so anything in `inputs` is
    treated as a testable parameter regardless of endpoint_type.

What is NOT a parameter (excluded — the agents would only waste time):
  * PATH-only API endpoints like `/api/Users/1` — no query string, no `inputs`.
    Path-position injection needs information the crawl does not give us, and our
    tools test named params, so these feed recon only, never injection.
  * Non-injectable CONTROL inputs — submit buttons, CSRF/anti-forgery tokens, file
    upload sentinels, etc. (`_SKIP_PARAMS`). These mirror the skip sets
    modules/sqli.py and modules/xss.py already apply internally, kept here so
    extraction and the agents agree on what is testable.

The result is duck-compatible with schemas.Endpoint (exposes `.url`, `.method`,
`.inputs`), so it drops straight into run_sqli_agent / run_xss_agent, which read
exactly those three attributes — no agent signature change, no schemas.py change
(InjectionTarget is a runtime concern, not a schema type).
"""

from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode

# ── Common-parameter seeding (D-025) ─────────────────────────────────────────
# A curated param-name wordlist lets injection test a discovered API path that
# exposes NO crawlable parameter (a JSON API like /rest/products/search has no
# HTML form advertising its `q` param, so extract_params() returns () and it would
# otherwise never be injection-tested). Seeding PAIRS such a path with common param
# names to produce candidate (url, param) targets. It proposes CANDIDATES only —
# a finding STILL derives solely from sqlmap/Dalfox confirming injection (D-013);
# a seeded param that isn't injectable is simply not a finding.
#
# The list lives at docker/sandbox/params.txt (the pinned, sha256'd source of
# truth) and is COPY'd into the sandbox image at /opt/wordlists/params.txt
# (Dockerfile). The orchestrator runs host-side, so it reads the repo copy here;
# the sandbox copy exists for parity/reproducibility with the ffuf wordlist.
_PARAM_WORDLIST_PATH = Path(__file__).resolve().parent.parent / "docker" / "sandbox" / "params.txt"
_SANDBOX_PARAM_WORDLIST = "/opt/wordlists/params.txt"   # image mirror (documented)

# A path is "API-looking" (hence seedable when param-less) if the crawler tagged it
# api, or its path carries one of these markers. A static check — no extra requests.
_API_PATH_MARKERS = ("/api/", "/rest/", "/v1/", "/v2/", "/graphql", "/gql/")

# Path substrings that mark an endpoint as a likely QUERY/SEARCH sink — one that
# actually consumes a parameter (vs. a plain collection GET). Seeded paths are ranked
# so these come FIRST, so a tight per-mode path cap still reaches the high-value ones
# (e.g. /rest/products/SEARCH — the endpoint carrying the injectable `q`).
#
# Split into two tiers, not one flat set: STRONG markers are query/search VERBS —
# a path containing one almost certainly consumes a param (a dedicated search/filter
# endpoint). WEAK markers are plain collection NOUNS (`/api/Products`) — a bare
# `GET /api/Products` frequently takes NO meaningful query param at all, so it must
# not out-rank a path that also matches a strong verb. Without this split,
# `/api/Products` (weak-only) and `/rest/products/search` (strong + weak) landed in
# the SAME tier and the alphabetical tie-break ("api" < "rest") picked the wrong one
# under a tight `seed_paths=1` cap — live-evidenced: the real `/rest/products/search`
# SQLi target was starved out in favor of `/api/Products`.
_QUERY_PATH_MARKERS_STRONG = ("search", "query", "find", "lookup", "filter")
_QUERY_PATH_MARKERS_WEAK = ("list", "fetch", "get", "products", "users", "orders")

_seed_params_cache: list | None = None

# Non-injectable control inputs — the union of the skip sets modules/sqli.py and
# modules/xss.py already apply, so a form whose only fields are a submit button
# and a CSRF token is correctly treated as carrying NO testable parameter.
_SKIP_PARAMS = {
    "submit", "login", "btnsign", "btnsubmit", "seclev_submit",
    "user_token", "csrf_token", "csrf", "_token", "authenticity_token",
    "upload", "uploaded", "max_file_size", "change", "reset", "clear",
}

# endpoint_type -> selection rank (LOWER is tested first when a scan mode caps the
# number of injection targets). Forms carry explicit, server-consumed input fields
# (the richest injection surface); links carry query-string params; api/page/other
# come after. Purely deterministic — never random.
_TYPE_RANK = {"form": 0, "link": 1, "api": 2, "page": 3}
_DEFAULT_TYPE_RANK = 4


@dataclass(frozen=True)
class InjectionTarget:
    """One endpoint that carries at least one injectable parameter.

    Duck-compatible with schemas.Endpoint for the agents: `.url`, `.method`, and
    `.inputs` (an alias of `param_names`) are exactly what run_sqli_agent /
    run_xss_agent read. `param_names` is also exposed explicitly for the scan
    record and tests.
    """
    url: str
    method: str
    param_names: tuple[str, ...]
    endpoint_type: str = "link"
    form_action: str | None = None
    cookies_needed: tuple[str, ...] = field(default_factory=tuple)

    @property
    def inputs(self) -> list[str]:
        """Alias read by the agents (they expect Endpoint.inputs)."""
        return list(self.param_names)

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "method": self.method,
            "param_names": list(self.param_names),
            "endpoint_type": self.endpoint_type,
        }


def _field(ep, name, default=None):
    """Read a field off an Endpoint object or a plain dict."""
    if hasattr(ep, name):
        return getattr(ep, name)
    if isinstance(ep, dict):
        return ep.get(name, default)
    return default


def _query_param_names(url: str) -> list[str]:
    """Distinct query-string keys of `url`, in first-seen order."""
    try:
        query = urlsplit(url).query
    except (ValueError, AttributeError):
        return []
    seen: set = set()
    names: list[str] = []
    for key, _ in parse_qsl(query, keep_blank_values=True):
        if key and key not in seen:
            seen.add(key)
            names.append(key)
    return names


def extract_params(endpoint) -> tuple[str, ...]:
    """The ordered, de-duplicated set of injectable parameter names for ONE
    endpoint: query-string keys first (URL order), then any `inputs` field names
    not already seen, with non-injectable control inputs (_SKIP_PARAMS) removed.

    Returns an empty tuple for a param-less endpoint (which must NOT be handed to
    the injection agents).
    """
    url = _field(endpoint, "url", "") or ""
    inputs = _field(endpoint, "inputs", []) or []

    ordered: list[str] = []
    seen: set = set()
    for name in list(_query_param_names(url)) + list(inputs):
        if not isinstance(name, str):
            continue
        clean = name.strip()
        if not clean or clean.lower() in _SKIP_PARAMS:
            continue
        if clean in seen:
            continue
        seen.add(clean)
        ordered.append(clean)
    return tuple(ordered)


def extract_injection_targets(endpoints) -> list[InjectionTarget]:
    """Every endpoint that carries >=1 injectable parameter, as an InjectionTarget.

    Param-less endpoints are excluded (they cannot be injected). De-duplicated by
    (method, url, param_names) so the same testable endpoint is never queued twice.
    Order follows the input list (ranking is a separate, explicit step).
    """
    targets: list[InjectionTarget] = []
    seen: set = set()
    for ep in endpoints or []:
        params = extract_params(ep)
        if not params:
            continue
        url = _field(ep, "url", "") or ""
        method = (_field(ep, "method", "GET") or "GET").upper()
        key = (method, url, params)
        if key in seen:
            continue
        seen.add(key)
        cookies = _field(ep, "cookies_needed", []) or []
        targets.append(InjectionTarget(
            url=url,
            method=method,
            param_names=params,
            endpoint_type=_field(ep, "endpoint_type", "link") or "link",
            form_action=_field(ep, "form_action", None),
            cookies_needed=tuple(cookies),
        ))
    return targets


def _rank_key(t: InjectionTarget):
    """Deterministic ranking: forms first, then links, then api/page/other
    (endpoint-type rank); within a type, MORE parameters first; ties broken by URL
    so the ordering is total and reproducible — never random."""
    return (_TYPE_RANK.get(t.endpoint_type, _DEFAULT_TYPE_RANK),
            -len(t.param_names), t.url)


def rank_injection_targets(targets) -> list[InjectionTarget]:
    """Injection targets sorted by _rank_key (see it for the documented order)."""
    return sorted(targets, key=_rank_key)


def select_injection_targets(endpoints, *, limit: int | None = None) -> list[InjectionTarget]:
    """Extract param-bearing injection targets from `endpoints`, rank them
    deterministically, and return at most `limit` of them (None = no cap).

    This is the single entry point the orchestrator uses: which endpoints get the
    (expensive, sandboxed) sqlmap/Dalfox treatment, and in what priority order when
    a scan mode caps the count.
    """
    ranked = rank_injection_targets(extract_injection_targets(endpoints))
    if limit is not None and limit >= 0:
        return ranked[:limit]
    return ranked


# ── Common-parameter seeding ─────────────────────────────────────────────────

def load_seed_params(limit: int | None = None) -> list[str]:
    """The curated common-parameter names (docker/sandbox/params.txt), highest-signal
    first (search/query, then ids, then generic). De-duplicated, blank/comment lines
    dropped, cached after first read. `limit` caps how many are returned (a scan
    mode's per-path budget); None = all. Empty list if the file is unreadable
    (seeding then simply produces nothing — never an error)."""
    global _seed_params_cache
    if _seed_params_cache is None:
        try:
            lines = _PARAM_WORDLIST_PATH.read_text(encoding="utf-8").splitlines()
        except OSError:
            lines = []
        seen: set = set()
        out: list[str] = []
        for ln in lines:
            w = ln.strip()
            if w and not w.startswith("#") and w not in seen:
                seen.add(w)
                out.append(w)
        _seed_params_cache = out
    params = _seed_params_cache
    if limit is not None and limit >= 0:
        return params[:limit]
    return list(params)


def is_seedable_api_path(endpoint) -> bool:
    """True if a PARAM-LESS endpoint looks like an API endpoint worth seeding: the
    crawler tagged it `api`, or its path carries an API marker (/api/, /rest/,
    /v1|v2/, /graphql). Purely static — no extra request. Gating on "looks like an
    API" (vs. seeding every param-less page) keeps the seeded surface small and
    high-signal: an HTML page with no params is usually genuinely param-less, while
    a JSON API path frequently hides its params from the crawler."""
    etype = _field(endpoint, "endpoint_type", "") or ""
    if etype == "api":
        return True
    url = _field(endpoint, "url", "") or ""
    try:
        path = urlsplit(url).path.lower()
    except (ValueError, AttributeError):
        return False
    probe = path if path.endswith("/") else path + "/"
    return any(marker in probe for marker in _API_PATH_MARKERS)


def _norm_path(url: str) -> str:
    """scheme://host/path with the query stripped — the identity used to dedupe a
    seeded path against an already-crawled (param-bearing) target on the same path."""
    try:
        p = urlsplit(url)
        return f"{p.scheme}://{p.netloc}{p.path}"
    except (ValueError, AttributeError):
        return url or ""


def _batches(seq: list, size: int):
    size = max(1, int(size))
    for i in range(0, len(seq), size):
        yield seq[i:i + size]


def _seed_injection_target(url: str, method: str, params: list, endpoint) -> InjectionTarget:
    """Build ONE seeded InjectionTarget: the path with `params` PACKED into its query
    string (each =1). Packing lets sqlmap/Dalfox test every seeded param in a SINGLE
    sandboxed run (they iterate all query params), instead of one run per param —
    the key to keeping seeding runtime-bounded. endpoint_type='seed' ranks it after
    every crawled target (crawled params are higher-confidence than a guess)."""
    parts = urlsplit(url)
    query = urlencode([(p, "1") for p in params])
    seeded_url = urlunsplit((parts.scheme, parts.netloc, parts.path, query, ""))
    cookies = _field(endpoint, "cookies_needed", []) or []
    return InjectionTarget(
        url=seeded_url, method=method, param_names=tuple(params),
        endpoint_type="seed", form_action=None, cookies_needed=tuple(cookies))


def _seed_path_rank(url: str) -> tuple:
    """Ranking key for a seedable path: a STRONG query-verb marker (search/query/
    find/lookup/filter) ranks first (tier 0), a WEAK collection-noun-only marker
    (products/users/orders/list/fetch/get) second (tier 1), anything else last
    (tier 2) — then by URL for a deterministic, total order. So a tight `max_paths`
    cap reaches /rest/products/search (strong) before /api/Products (weak-only)."""
    path = _norm_path(url).lower()
    if any(m in path for m in _QUERY_PATH_MARKERS_STRONG):
        tier = 0
    elif any(m in path for m in _QUERY_PATH_MARKERS_WEAK):
        tier = 1
    else:
        tier = 2
    return (tier, url)


def build_seed_targets(endpoints, *, param_names, max_paths: int | None = None,
                       batch_size: int = 20, crawled_target_urls=(),
                       isolate_top: int = 0) -> list[InjectionTarget]:
    """Seed common params onto param-LESS, API-looking endpoints -> candidate
    injection targets.

    An endpoint is seeded when it (a) has NO crawlable parameter, (b) looks like an
    API path (is_seedable_api_path), and (c) isn't already a crawled injection target.
    Eligible paths are RANKED (query/search-like first — see _seed_path_rank) then
    capped to `max_paths` (mode-aware, keeps total sandboxed runs bounded), so a small
    cap still reaches the high-value endpoints.

    For each kept path, the FIRST `isolate_top` params (highest-signal — `param_names`
    is already ordered that way) each get their OWN single-param target (a clean
    `?q=1` URL, nothing else in the query string) — packing many params into one URL
    can make it harder for sqlmap/Dalfox to cleanly attribute a signal to any ONE of
    them, especially error-based signals that are sensitive to unexpected extra
    params or a slow/degraded target. The REMAINING params (after `isolate_top`) are
    packed together, batched by `batch_size`, as a broader lower-confidence sweep.
    `isolate_top=0` (default) disables isolation — every param is packed/batched as
    before. Deterministic. Returns [] when param_names is empty (seeding disabled)."""
    params = [p for p in (param_names or []) if p]
    if not params:
        return []
    crawled_paths = {_norm_path(u) for u in crawled_target_urls}

    # 1. Collect eligible seedable endpoints, de-duped by normalized path.
    eligible: list = []
    seen_paths: set = set()
    for ep in endpoints or []:
        if extract_params(ep):                    # already has crawlable params -> tested already
            continue
        if not is_seedable_api_path(ep):
            continue
        url = _field(ep, "url", "") or ""
        npath = _norm_path(url)
        if not npath or npath in crawled_paths or npath in seen_paths:
            continue
        seen_paths.add(npath)
        eligible.append(ep)

    # 2. Rank (query-like first) and cap.
    eligible.sort(key=lambda e: _seed_path_rank(_field(e, "url", "") or ""))
    if max_paths is not None and max_paths >= 0:
        eligible = eligible[:max_paths]

    # 3. Isolated top params (one clean single-param URL each) + the rest packed,
    #    batched, for each kept path.
    top_n = max(0, int(isolate_top))
    isolated_params, batched_params = params[:top_n], params[top_n:]
    targets: list[InjectionTarget] = []
    for ep in eligible:
        url = _field(ep, "url", "") or ""
        method = (_field(ep, "method", "GET") or "GET").upper()
        for p in isolated_params:
            targets.append(_seed_injection_target(url, method, [p], ep))
        for batch in _batches(batched_params, batch_size):
            targets.append(_seed_injection_target(url, method, batch, ep))
    return targets
