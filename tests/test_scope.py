"""
Tests for engine/scope.py

Run: python -m pytest tests/test_scope.py -v
"""
import pytest
from engine.scope import ScopeConfig, ScopeError, is_in_scope, require_authorization, assert_in_scope


def _config(**overrides):
    defaults = dict(
        target_url="http://redsees.com",
        allowed_hosts=["redsees.com"],
        authorized=True,
        max_requests_per_min=60,
        allowed_url_prefixes=[],
    )
    defaults.update(overrides)
    return ScopeConfig(**defaults)


def test_spa_hash_fragment_url_matches_host():
    config = _config()
    assert is_in_scope("http://redsees.com:3000/#/", config) is True


def test_in_scope_host_returns_true():
    config = _config()
    assert is_in_scope("http://redsees.com/login", config) is True


def test_out_of_scope_host_returns_false():
    config = _config()
    assert is_in_scope("http://evil.com/login", config) is False


def test_subdomain_of_allowed_host_not_in_scope():
    config = _config()
    assert is_in_scope("http://admin.redsees.com/login", config) is False


def test_host_match_is_case_insensitive():
    config = _config()
    assert is_in_scope("http://REDSEES.COM/login", config) is True


def test_url_with_port_still_matches_host():
    config = _config()
    assert is_in_scope("http://redsees.com:8080/api/data", config) is True


def test_empty_allowed_hosts_out_of_scope_and_unauthorized():
    config = _config(allowed_hosts=[])
    assert is_in_scope("http://redsees.com/", config) is False
    with pytest.raises(ScopeError):
        require_authorization(config)


def test_unauthorized_raises_scope_error():
    config = _config(authorized=False)
    with pytest.raises(ScopeError):
        require_authorization(config)


def test_assert_in_scope_raises_for_out_of_scope_url():
    config = _config()
    with pytest.raises(ScopeError):
        assert_in_scope("http://evil.com/", config)


if __name__ == "__main__":
    test_spa_hash_fragment_url_matches_host()
    test_in_scope_host_returns_true()
    test_out_of_scope_host_returns_false()
    test_subdomain_of_allowed_host_not_in_scope()
    test_host_match_is_case_insensitive()
    test_url_with_port_still_matches_host()
    test_empty_allowed_hosts_out_of_scope_and_unauthorized()
    test_unauthorized_raises_scope_error()
    test_assert_in_scope_raises_for_out_of_scope_url()
    print("All scope tests passed!")
