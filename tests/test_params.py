"""
Tests for engine/params.py — injectable-parameter extraction from crawl output.

Fully offline (pure functions over schemas.Endpoint / dict). Covers: query-string
params, form/body fields, the skip-input filter, param-less endpoints being
EXCLUDED from injection targets, deterministic forms-first ranking, capping, and
that an InjectionTarget is duck-compatible with the agents (.url/.method/.inputs).

Run: PYTHONPATH=. python -m pytest tests/test_params.py -v
"""
from schemas import Endpoint
from engine.params import (
    InjectionTarget, extract_params, extract_injection_targets,
    rank_injection_targets, select_injection_targets,
)


def _ep(url, method="GET", inputs=(), etype="link"):
    return Endpoint(url=url, method=method, form_action=None, inputs=list(inputs),
                    cookies_needed=[], endpoint_type=etype)


# ── extract_params ───────────────────────────────────────────────────────────

def test_query_string_params_extracted():
    assert extract_params(_ep("http://h/s?id=1&q=x")) == ("id", "q")


def test_form_fields_extracted():
    ep = _ep("http://h/login", method="POST", inputs=["user", "pass"], etype="form")
    assert extract_params(ep) == ("user", "pass")


def test_query_and_form_merged_query_first_deduped():
    ep = _ep("http://h/s?q=1", method="GET", inputs=["q", "cat"], etype="form")
    # q from the query string comes first; the duplicate `q` in inputs is dropped.
    assert extract_params(ep) == ("q", "cat")


def test_skip_inputs_filtered_out():
    ep = _ep("http://h/f", method="POST",
             inputs=["Submit", "csrf_token", "user_token", "name"], etype="form")
    # submit/csrf/anti-forgery controls are not testable params — only `name` remains.
    assert extract_params(ep) == ("name",)


def test_form_with_only_control_inputs_has_no_params():
    ep = _ep("http://h/f", method="POST", inputs=["Submit", "csrf_token"], etype="form")
    assert extract_params(ep) == ()


def test_param_less_page_endpoint_has_no_params():
    assert extract_params(_ep("http://h/about", etype="page")) == ()


def test_path_only_api_endpoint_has_no_params():
    # e.g. /api/Users/1 — no query string, no inputs -> not injectable via a param.
    assert extract_params(_ep("http://h/api/Users/1", etype="api")) == ()


def test_extract_params_accepts_dict_endpoint():
    assert extract_params({"url": "http://h/s?a=1", "inputs": ["b"]}) == ("a", "b")


# ── extract_injection_targets: param-less excluded ───────────────────────────

def test_param_less_endpoints_excluded_from_injection_targets():
    eps = [
        _ep("http://h/s?q=1", inputs=["q"]),                 # param-bearing (link)
        _ep("http://h/about", etype="page"),                 # param-less  -> excluded
        _ep("http://h/api/Users/1", etype="api"),            # path-only   -> excluded
        _ep("http://h/f", method="POST", inputs=["name", "Submit"], etype="form"),
    ]
    targets = extract_injection_targets(eps)
    urls = {t.url for t in targets}
    assert urls == {"http://h/s?q=1", "http://h/f"}
    assert all(t.param_names for t in targets)               # never empty


def test_injection_targets_deduplicated():
    eps = [_ep("http://h/s?q=1", inputs=["q"]), _ep("http://h/s?q=1", inputs=["q"])]
    assert len(extract_injection_targets(eps)) == 1


def test_injection_target_is_duck_compatible_with_agents():
    t = extract_injection_targets([_ep("http://h/s?q=1", method="GET", inputs=["q"])])[0]
    assert isinstance(t, InjectionTarget)
    assert t.url == "http://h/s?q=1"
    assert t.method == "GET"
    assert t.inputs == ["q"]                                 # the alias the agents read
    assert t.param_names == ("q",)


# ── ranking + capping (deterministic) ────────────────────────────────────────

def test_ranking_puts_forms_first_then_links():
    link = _ep("http://h/a?x=1", inputs=["x"], etype="link")
    form = _ep("http://h/b", method="POST", inputs=["u"], etype="form")
    api = _ep("http://h/c?z=1", inputs=["z"], etype="api")
    ranked = rank_injection_targets(extract_injection_targets([link, api, form]))
    assert [t.endpoint_type for t in ranked] == ["form", "link", "api"]


def test_ranking_is_deterministic_and_more_params_first_within_type():
    two = _ep("http://h/two?a=1&b=2", inputs=["a", "b"], etype="link")
    one = _ep("http://h/one?a=1", inputs=["a"], etype="link")
    ranked = rank_injection_targets(extract_injection_targets([one, two]))
    # more params first within the same type
    assert ranked[0].url == "http://h/two?a=1&b=2"
    # stable across repeated runs (total order, url tie-break)
    again = rank_injection_targets(extract_injection_targets([one, two]))
    assert [t.url for t in ranked] == [t.url for t in again]


def test_select_caps_to_limit_after_ranking():
    eps = [_ep(f"http://h/p{i}?q=1", inputs=["q"], etype="link") for i in range(8)]
    assert len(select_injection_targets(eps, limit=3)) == 3
    assert len(select_injection_targets(eps, limit=None)) == 8   # None = no cap


# ── standalone runner (repo convention) ──────────────────────────────────────

if __name__ == "__main__":
    _tests = [v for k, v in sorted(globals().items())
              if k.startswith("test_") and callable(v)]
    print(f"Running {len(_tests)} param-extraction tests...")
    for _fn in _tests:
        _fn()
        print(f"  ok  {_fn.__name__}")
    print("All param-extraction tests passed!")
