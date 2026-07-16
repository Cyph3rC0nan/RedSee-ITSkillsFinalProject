"""
Tests for common-parameter seeding (D-025) — engine/params.py helpers + the
evidence-gate on seeded candidates.

Fully offline. Seeding pairs a param-LESS API path with common param names to
produce candidate (url, param) injection targets; a finding STILL derives solely
from the tool confirming injection, so a seeded-but-not-injectable param must NOT
become a finding.

Run: PYTHONPATH=. python -m pytest tests/test_param_seeding.py -v
"""
import pytest

from schemas import Endpoint
from engine.params import (
    load_seed_params, is_seedable_api_path, build_seed_targets, InjectionTarget,
    extract_params,
)


def _ep(url, method="GET", inputs=(), etype="api"):
    return Endpoint(url=url, method=method, form_action=None, inputs=list(inputs),
                    cookies_needed=[], endpoint_type=etype)


# ── the wordlist ─────────────────────────────────────────────────────────────

def test_seed_wordlist_loads_high_signal_first():
    params = load_seed_params()
    assert params[0] == "q"                      # highest-signal search param first
    assert "id" in params and "search" in params
    # D-026: right-sized to a LEAN list (was 297) — memory pressure on an 8 GB host
    # comes from total sandboxed injection runs, not just list-file size; a real,
    # curated list (not a toy) but small enough that seeding stays cheap.
    assert 15 <= len(params) <= 40
    assert len(params) == len(set(params))        # de-duplicated


def test_seed_wordlist_limit_caps_and_preserves_order():
    assert load_seed_params(5) == load_seed_params()[:5]
    assert load_seed_params(0) == []


# ── is_seedable_api_path ─────────────────────────────────────────────────────

def test_api_type_endpoint_is_seedable():
    assert is_seedable_api_path(_ep("http://h/rest/products/search", etype="api"))


def test_api_path_marker_is_seedable_even_if_type_missing():
    assert is_seedable_api_path(_ep("http://h/rest/products/search", etype="link"))
    assert is_seedable_api_path(_ep("http://h/api/v2/thing", etype=""))
    assert is_seedable_api_path(_ep("http://h/graphql/query", etype=""))


def test_plain_page_is_not_seedable():
    assert not is_seedable_api_path(_ep("http://h/about", etype="page"))
    assert not is_seedable_api_path(_ep("http://h/contact.html", etype="link"))


# ── build_seed_targets ───────────────────────────────────────────────────────

def test_seeds_param_less_api_path_with_packed_params():
    eps = [_ep("http://h/rest/products/search", etype="api")]
    targets = build_seed_targets(eps, param_names=["q", "id", "search"], batch_size=10)
    assert len(targets) == 1
    t = targets[0]
    assert isinstance(t, InjectionTarget)
    assert t.endpoint_type == "seed"
    assert t.param_names == ("q", "id", "search")
    # params PACKED into the query string so one sandboxed run tests them all
    assert "q=1" in t.url and "id=1" in t.url and "search=1" in t.url
    assert t.url.split("?", 1)[0] == "http://h/rest/products/search"
    assert t.inputs == ["q", "id", "search"]      # duck-compat with the agents


def test_isolate_top_gives_top_params_their_own_clean_request():
    """D-026 follow-up: packing many params into one URL made sqlmap miss a
    hand-confirmed error-based SQLi on `q` (live-evidenced). isolate_top gives the
    top-ranked params EACH a clean single-param URL, packing only the rest."""
    eps = [_ep("http://h/rest/products/search", etype="api")]
    targets = build_seed_targets(eps, param_names=["q", "id", "search", "email"],
                                 batch_size=10, isolate_top=2)
    assert len(targets) == 3                       # 2 isolated + 1 batch of the rest
    isolated = [t for t in targets if len(t.param_names) == 1]
    batched = [t for t in targets if len(t.param_names) > 1]
    assert {t.param_names[0] for t in isolated} == {"q", "id"}
    assert all("id=1" not in t.url or t.param_names == ("id",) for t in isolated)
    assert batched[0].param_names == ("search", "email")


def test_isolate_top_zero_disables_isolation_all_packed():
    eps = [_ep("http://h/rest/products/search", etype="api")]
    targets = build_seed_targets(eps, param_names=["q", "id"], batch_size=10, isolate_top=0)
    assert len(targets) == 1
    assert targets[0].param_names == ("q", "id")


def test_isolate_top_covers_entire_list_no_batch_remains():
    eps = [_ep("http://h/rest/products/search", etype="api")]
    targets = build_seed_targets(eps, param_names=["q", "id"], batch_size=10, isolate_top=5)
    assert len(targets) == 2                        # both isolated, no batch target
    assert all(len(t.param_names) == 1 for t in targets)


def test_param_bearing_endpoint_is_not_seeded():
    eps = [_ep("http://h/rest/search?q=x", inputs=["q"], etype="api")]
    assert build_seed_targets(eps, param_names=["q", "id"], batch_size=10) == []


def test_page_endpoint_is_not_seeded():
    eps = [_ep("http://h/about", etype="page")]
    assert build_seed_targets(eps, param_names=["q", "id"], batch_size=10) == []


def test_seeding_dedupes_against_already_crawled_paths():
    eps = [_ep("http://h/rest/products/search", etype="api")]
    # the same path is already a crawled injection target -> do not seed it
    targets = build_seed_targets(
        eps, param_names=["q"], batch_size=10,
        crawled_target_urls=["http://h/rest/products/search?q=apple"])
    assert targets == []


def test_strong_query_verb_path_beats_weak_noun_only_path_under_tight_cap():
    """Live-evidenced bug: a standard-mode root scan against redsees.com capped
    seed_paths=1 and seeded /api/Products instead of the real SQLi target
    /rest/products/search. Both matched the OLD flat _QUERY_PATH_MARKERS set
    (via "products"), so the tie-break fell to alphabetical URL order ("api" <
    "rest") and picked the wrong one. /rest/products/search also matches a
    STRONG verb marker ("search"); /api/Products matches only the WEAK noun
    marker ("products") — the strong match must win regardless of URL string."""
    eps = [
        _ep("http://h/api/Products", etype="api"),
        _ep("http://h/rest/products/search", etype="api"),
    ]
    targets = build_seed_targets(eps, param_names=["q"], max_paths=1, batch_size=10)
    assert len(targets) == 1
    assert targets[0].url.split("?", 1)[0] == "http://h/rest/products/search"


def test_max_paths_cap_bounds_seeded_paths():
    eps = [_ep(f"http://h/rest/e{i}", etype="api") for i in range(6)]
    targets = build_seed_targets(eps, param_names=["q"], max_paths=2, batch_size=10)
    assert len({t.url.split("?", 1)[0] for t in targets}) == 2


def test_batching_splits_a_long_list_into_multiple_targets():
    eps = [_ep("http://h/rest/x", etype="api")]
    params = [f"p{i}" for i in range(45)]
    targets = build_seed_targets(eps, param_names=params, batch_size=20)
    assert len(targets) == 3                       # ceil(45/20)
    # every param is covered exactly once across the batches
    covered = [p for t in targets for p in t.param_names]
    assert sorted(covered) == sorted(params)


def test_empty_param_list_seeds_nothing():
    eps = [_ep("http://h/rest/x", etype="api")]
    assert build_seed_targets(eps, param_names=[], batch_size=10) == []


def test_seeded_target_extract_params_roundtrips():
    t = build_seed_targets([_ep("http://h/rest/x", etype="api")],
                           param_names=["q", "id"], batch_size=10)[0]
    # extract_params reads them back off the seeded URL's query string
    assert extract_params(t) == ("q", "id")


# ── evidence gate: a seeded candidate is only a finding if the tool confirms it ─

def test_seeded_not_injectable_candidate_is_not_a_finding(monkeypatch):
    import modules.scan as scan
    from modules.scan import _scan_sqli_targets, _PROFILES
    from engine.agent import SqliCandidate, SqliAgentResult
    from engine.llm import Usage

    seeded = build_seed_targets([_ep("http://h/rest/x", etype="api")],
                                param_names=["q"], batch_size=10)
    clean = SqliCandidate(endpoint_url="http://h/rest/x?q=1", parameter="q",
                          injectable=False, technique=None, dbms=None, evidence="",
                          sqlmap_argv=[], depth=0, status="clean")
    monkeypatch.setattr(scan, "run_sqli_agent",
                        lambda t, **k: SqliAgentResult([clean], Usage(0, 0, 0.0, 0), 1, [], "done"))
    findings, candidates = _scan_sqli_targets([], seeded, scope_config=None,
                                              profile=_PROFILES["standard"], scan_id="x")
    assert findings == []                          # not-injectable seed -> NO finding
    assert candidates and candidates[0]["status"] == "clean"  # but still visible for diagnosis


def test_seeded_injectable_candidate_becomes_a_finding(monkeypatch):
    import modules.scan as scan
    from modules.scan import _scan_sqli_targets, _PROFILES
    from engine.agent import SqliCandidate, SqliAgentResult
    from engine.llm import Usage

    seeded = build_seed_targets([_ep("http://h/rest/products/search", etype="api")],
                                param_names=["q"], batch_size=10)
    hit = SqliCandidate(endpoint_url="http://h/rest/products/search?q=1", parameter="q",
                        injectable=True, technique="error-based", dbms="SQLite",
                        evidence="Parameter: q (GET)\n  Type: error-based\n  Payload: q=1'",
                        sqlmap_argv=[], depth=0, status="injectable")
    monkeypatch.setattr(scan, "run_sqli_agent",
                        lambda t, **k: SqliAgentResult([hit], Usage(0, 0, 0.0, 0), 1, [], "done"))
    findings, candidates = _scan_sqli_targets([], seeded, scope_config=None,
                                              profile=_PROFILES["standard"], scan_id="x")
    assert len(findings) == 1
    assert candidates[0]["status"] == "injectable"
    assert findings[0].type == "SQLi" and findings[0].parameter == "q"


# ── standalone runner (repo convention) ──────────────────────────────────────

if __name__ == "__main__":
    class _MP:
        def __init__(self): self._undo = []
        def setattr(self, obj, name, value):
            self._undo.append((obj, name, getattr(obj, name))); setattr(obj, name, value)
        def undo(self):
            for obj, name, old in reversed(self._undo): setattr(obj, name, old)

    import inspect
    _tests = [v for k, v in sorted(globals().items())
              if k.startswith("test_") and callable(v)]
    print(f"Running {len(_tests)} param-seeding tests...")
    for _fn in _tests:
        mp = _MP() if "monkeypatch" in inspect.signature(_fn).parameters else None
        try:
            _fn(mp) if mp else _fn()
            print(f"  ok  {_fn.__name__}")
        finally:
            if mp:
                mp.undo()
    print("All param-seeding tests passed!")
