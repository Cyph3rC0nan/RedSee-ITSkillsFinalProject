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
from urllib.parse import urlsplit, parse_qsl

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
