"""
Tests for the discovery->injection loop (D-025) in modules/scan.py.

Fully offline: crawl (per-URL fake sitemaps), run_ffuf (fake discovered paths),
recon runners, and the injection drivers are monkeypatched at the modules.scan
boundary; a guard on engine.recon_tools.run_in_sandbox fails loudly if anything
slips through.

Covers the whole loop against the CANONICAL shape of the real target: ffuf
discovers /market + /rest; re-crawling /market surfaces a param (q); /rest exposes
a param-LESS API path (/rest/products/search) that gets SEEDED with common params;
the injection set contains BOTH the crawled /market param AND seeded params for
/rest; caps + scope are enforced on discovered-path fetches; seeding is OFF in fast
mode; and the record reports discovered/re-crawled/seeded/tested counts.

Run: PYTHONPATH=. python -m pytest tests/test_discovery_loop.py -v
"""
import pytest

import modules.scan as scan
from modules.scan import run_scan
from schemas import Endpoint, Sitemap
from engine.params import InjectionTarget
from engine.scope import ScopeConfig, ScopeError
from engine.llm import Usage
from engine.nuclei_agent import NucleiAgentResult
from engine.recon_tools import ReconObservation

ROOT = "http://redsees.com:3000/"


def _scope():
    return ScopeConfig(target_url=ROOT, allowed_hosts=["redsees.com"], authorized=True)


def _ep(url, method="GET", inputs=(), etype="api"):
    return Endpoint(url=url, method=method, form_action=None, inputs=list(inputs),
                    cookies_needed=[], endpoint_type=etype)


def _sitemap(target, eps):
    return Sitemap(target_url=target, crawl_timestamp="2026-01-01T00:00:00Z",
                   endpoints=eps, total_pages=0, total_forms=0, total_api_endpoints=0)


def _ffuf_hit(path, base=ROOT):
    return ReconObservation(tool="ffuf", target=base, category="content-discovery",
                            title=f"200 {path}", severity="Low",
                            evidence=f"path={path} status=200 length=100",
                            status="observed", error=None, argv=[])


def _empty_nuclei():
    return NucleiAgentResult(candidates=[], usage=Usage(0, 0, 0.0, 0),
                             iterations=0, transcript=[], stopped_reason="done")


def _setup(monkeypatch, *, ffuf_paths=("/market", "/rest"), crawl_urls=None):
    """Install the discovery-flow doubles. Returns a recorder dict."""
    rec = {"crawled_urls": [], "sqli": None, "xss": None, "ffuf": 0, "httpx": 0}

    # Root crawl surfaces THREE param-LESS API paths (products/search ranks first —
    # it's query/search-like, see engine.params._seed_path_rank — so standard's
    # tight seed_paths=1 cap still seeds IT specifically); /market surfaces a
    # param-bearing link; anything else surfaces nothing new.
    def fake_crawl(url, **kwargs):
        rec["crawled_urls"].append(url)
        if "/market" in url:
            return _sitemap(url, [_ep("http://redsees.com:3000/market/search?q=1",
                                      inputs=["q"], etype="link")])
        if url.rstrip("/") == ROOT.rstrip("/"):
            return _sitemap(url, [
                _ep("http://redsees.com:3000/rest/products/search", inputs=[], etype="api"),
                _ep("http://redsees.com:3000/rest/admin", inputs=[], etype="api"),
                _ep("http://redsees.com:3000/rest/captcha", inputs=[], etype="api"),
            ])
        return _sitemap(url, [])

    monkeypatch.setattr(scan, "crawl", fake_crawl)
    monkeypatch.setattr(scan, "run_ffuf",
                        lambda t, **k: (rec.__setitem__("ffuf", rec["ffuf"] + 1),
                                        [_ffuf_hit(p) for p in ffuf_paths])[1])
    monkeypatch.setattr(scan, "run_httpx",
                        lambda t, **k: (rec.__setitem__("httpx", rec["httpx"] + 1),
                                        [ReconObservation(tool="httpx", target=ROOT,
                                            category="http-fingerprint", title="200",
                                            severity="Low", evidence="status=200",
                                            status="observed", error=None, argv=[])])[1])
    monkeypatch.setattr(scan, "run_tlsx", lambda t, **k: [])
    monkeypatch.setattr(scan, "run_nuclei_agent", lambda t, **k: _empty_nuclei())

    def fake_sqli(crawled, seeded=None, **k):
        rec["sqli"] = {"crawled": list(crawled), "seeded": list(seeded or [])}
        return []

    def fake_xss(crawled, seeded=None, **k):
        rec["xss"] = {"crawled": list(crawled), "seeded": list(seeded or [])}
        return []

    monkeypatch.setattr(scan, "_scan_sqli_targets", fake_sqli)
    monkeypatch.setattr(scan, "_scan_xss_targets", fake_xss)

    def _boom(*a, **k):
        raise AssertionError("run_in_sandbox must not be reached — tools are mocked")
    monkeypatch.setattr("engine.recon_tools.run_in_sandbox", _boom)
    return rec


# ── ffuf discovery -> re-crawl ───────────────────────────────────────────────

def test_ffuf_discovered_paths_are_recrawled(monkeypatch, tmp_path):
    rec = _setup(monkeypatch)
    run_scan(ROOT, scope_config=_scope(), out_dir=str(tmp_path), mode="standard")
    # root crawled once, PLUS each ffuf-discovered path re-crawled
    assert any("/market" in u for u in rec["crawled_urls"])
    assert any("/rest" in u for u in rec["crawled_urls"])


def test_discovered_urls_extracted_from_ffuf_observations():
    urls = scan._discovered_urls_from_ffuf([_ffuf_hit("/market"), _ffuf_hit("/rest")])
    assert urls == ["http://redsees.com:3000/market", "http://redsees.com:3000/rest"]


def test_discovery_rank_prefers_app_sections_over_static_leaf_files():
    """Live-evidenced (D-026 follow-up): a tight max_discovered_paths cap on ffuf's
    RAW hit order let static leaf files (.well-known/security.txt, favicon, a deep
    /ftp/*.md file) crowd out /market — the one path that actually needed a
    re-crawl. Ranking must put /market first regardless of ffuf's hit order."""
    urls = [
        "http://h/.well-known/security.txt",
        "http://h/Video",
        "http://h/assets",
        "http://h/ftp/announcement_encrypted.md",
        "http://h/market",
        "http://h/robots.txt",
    ]
    ranked = sorted(urls, key=scan._discovery_path_rank)
    assert ranked[0] == "http://h/market"
    # every static-leaf/extensioned path sorts AFTER the clean, shallow ones
    assert ranked.index("http://h/market") < ranked.index("http://h/.well-known/security.txt")
    assert ranked.index("http://h/market") < ranked.index("http://h/robots.txt")
    assert ranked.index("http://h/market") < ranked.index("http://h/ftp/announcement_encrypted.md")


def test_tight_discovery_cap_still_reaches_market_over_noise(monkeypatch, tmp_path):
    """The exact live failure mode: ffuf returns several static/noise paths BEFORE
    /market in raw order; a tight cap must still pick /market thanks to ranking."""
    noisy_order = ["/.well-known/security.txt", "/Video", "/assets", "/ftp", "/market"]
    rec = _setup(monkeypatch, ffuf_paths=noisy_order)
    run_scan(ROOT, scope_config=_scope(), out_dir=str(tmp_path), mode="standard")
    assert any("/market" in u for u in rec["crawled_urls"])


# ── the money test: crawled param + seeded param both queued ─────────────────

def test_injection_set_has_crawled_market_param_AND_seeded_rest_params(monkeypatch, tmp_path):
    rec = _setup(monkeypatch)
    run_scan(ROOT, scope_config=_scope(), out_dir=str(tmp_path), mode="standard")

    crawled = rec["sqli"]["crawled"]
    seeded = rec["sqli"]["seeded"]

    # /market/search?q= — surfaced by re-crawling the ffuf-discovered /market path
    assert any("market/search" in t.url and "q" in t.param_names for t in crawled)
    # /rest/products/search — param-less API path, SEEDED with common params (incl q)
    assert seeded, "expected seeded targets for the param-less /rest API path"
    assert all(isinstance(t, InjectionTarget) for t in seeded)
    assert any("rest/products/search" in t.url for t in seeded)
    assert any("q" in t.param_names for t in seeded)


# ── record transparency ──────────────────────────────────────────────────────

def test_record_reports_discovery_and_seeding_counts(monkeypatch, tmp_path):
    _setup(monkeypatch)
    record = run_scan(ROOT, scope_config=_scope(), out_dir=str(tmp_path), mode="standard")
    d = record["discovery"]
    assert d["paths_discovered"] == 2               # /market + /rest
    assert d["paths_recrawled"] == 2
    assert d["params_from_crawl"] >= 1              # the /market q
    assert d["seeded_api_paths"] >= 1               # /rest/products/search
    assert d["params_seeded"] >= 1
    assert d["injection_targets_tested"] == d["params_from_crawl"] + d["seed_targets"]
    # surfaced in summary too
    assert record["summary"]["paths_discovered"] == 2


# ── caps ─────────────────────────────────────────────────────────────────────

def test_max_discovered_paths_cap_bounds_recrawls(monkeypatch, tmp_path):
    rec = _setup(monkeypatch, ffuf_paths=[f"/p{i}" for i in range(20)])
    record = run_scan(ROOT, scope_config=_scope(), out_dir=str(tmp_path), mode="standard")
    # standard caps discovered-path re-crawls at 4 (D-026 follow-up: tightened from 8
    # after a live OOM during re-crawls against an already-stressed target)
    assert record["discovery"]["paths_recrawled"] <= 4
    recrawled = [u for u in rec["crawled_urls"] if u != ROOT and "/p" in u]
    assert len(recrawled) <= 4


# ── scope enforced on discovered-path fetches ────────────────────────────────

def test_scope_enforced_on_discovered_path_fetch(monkeypatch, tmp_path):
    rec = _setup(monkeypatch)
    real_assert = scan.assert_in_scope

    def picky(url, cfg):
        if "/rest" in url:                          # pretend /rest is out of scope
            raise ScopeError(f"out of scope: {url}")
        return real_assert(url, cfg)

    monkeypatch.setattr(scan, "assert_in_scope", picky)
    run_scan(ROOT, scope_config=_scope(), out_dir=str(tmp_path), mode="standard")
    # /rest was refused by the scope gate -> never crawled; /market still is
    assert not any(u.endswith("/rest") for u in rec["crawled_urls"])
    assert any("/market" in u for u in rec["crawled_urls"])


# ── fast mode: no discovery, no seeding ──────────────────────────────────────

def test_fast_mode_does_no_discovery_or_seeding(monkeypatch, tmp_path):
    rec = _setup(monkeypatch)
    record = run_scan(ROOT, scope_config=_scope(), out_dir=str(tmp_path), mode="fast")
    assert rec["ffuf"] == 0                          # fast has no ffuf -> no discovery
    assert rec["crawled_urls"] == [ROOT]            # only the root, no re-crawls
    assert record["discovery"]["paths_recrawled"] == 0
    assert record["discovery"]["seed_targets"] == 0
    # fast still injects whatever the root crawl itself found params on (none here)
    assert (rec["sqli"] is None) or (rec["sqli"]["seeded"] == [])


def test_deep_mode_seeds_more_paths_than_standard(monkeypatch, tmp_path):
    """D-026: both modes seed the SAME (lean, 25-name) full list per path — the
    breadth lever is now seed_paths (standard=1, deep=3), not params-per-path."""
    rec_std = _setup(monkeypatch)
    run_scan(ROOT, scope_config=_scope(), out_dir=str(tmp_path / "s"), mode="standard")
    std_paths = {t.url.split("?", 1)[0] for t in rec_std["sqli"]["seeded"]}
    assert std_paths == {"http://redsees.com:3000/rest/products/search"}  # the top-ranked one

    rec_deep = _setup(monkeypatch)
    run_scan(ROOT, scope_config=_scope(), out_dir=str(tmp_path / "d"), mode="deep")
    deep_paths = {t.url.split("?", 1)[0] for t in rec_deep["sqli"]["seeded"]}
    assert len(deep_paths) > len(std_paths)
    assert std_paths <= deep_paths                  # deep is a strict superset


# ── standalone runner (repo convention) ──────────────────────────────────────

if __name__ == "__main__":
    class _MP:
        def __init__(self): self._undo = []
        def setattr(self, obj, name, value=None):
            if isinstance(obj, str):
                import importlib
                mod, _, attr = obj.rpartition("."); obj, name = importlib.import_module(mod), attr
            self._undo.append((obj, name, getattr(obj, name))); setattr(obj, name, value)
        def undo(self):
            for obj, name, old in reversed(self._undo): setattr(obj, name, old)

    import inspect, tempfile
    from pathlib import Path
    _tests = [v for k, v in sorted(globals().items())
              if k.startswith("test_") and callable(v)]
    print(f"Running {len(_tests)} discovery-loop tests...")
    for _fn in _tests:
        needs_mp = "monkeypatch" in inspect.signature(_fn).parameters
        needs_tmp = "tmp_path" in inspect.signature(_fn).parameters
        mp = _MP() if needs_mp else None
        try:
            with tempfile.TemporaryDirectory() as d:
                kw = {}
                if needs_mp: kw["monkeypatch"] = mp
                if needs_tmp: kw["tmp_path"] = Path(d)
                _fn(**kw)
            print(f"  ok  {_fn.__name__}")
        finally:
            if mp:
                mp.undo()
    print("All discovery-loop tests passed!")
