"""
Tests for engine/sandbox.py

Offline unit tests mock the docker/iptables subprocess calls, so they run
without Docker. One integration test exercises a real container and is skipped
cleanly when Docker, the image, root, or a reachable target is unavailable.

Run: PYTHONPATH=. python -m pytest tests/test_sandbox.py -v
"""
import os
import shutil
import socket
import subprocess
import urllib.parse

import pytest

import engine.sandbox as sandbox
from engine.sandbox import SandboxResult, SandboxError, run_in_sandbox
from engine.scope import ScopeConfig, ScopeError


# ── Helpers ─────────────────────────────────────────────────────────────────

def _config(authorized=True, allowed_hosts=("redsees.com",),
            target_url="http://redsees.com:3000/"):
    return ScopeConfig(
        target_url=target_url,
        allowed_hosts=list(allowed_hosts),
        authorized=authorized,
    )


def _fake_run_factory(calls, *, scan="ok", selftest_ok=True):
    """Build a subprocess.run replacement that records calls and returns
    plausible results for docker/iptables invocations.

    scan: "ok" | "timeout" | "fail"
    """
    def fake_run(argv, capture_output=False, text=False, timeout=None, **kwargs):
        calls.append(list(argv))

        def cp(rc=0, out="", err=""):
            return subprocess.CompletedProcess(argv, rc, out, err)

        prog = argv[0]
        if prog == "iptables":
            return cp(0)

        if prog == "docker":
            sub = argv[1] if len(argv) > 1 else ""
            if sub == "network":
                action = argv[2] if len(argv) > 2 else ""
                if action == "create":
                    return cp(0, "networkidabc123\n")
                if action == "inspect":
                    # Distinguish the Gateway query from the Subnet query by the
                    # -f Go template, mirroring real `docker network inspect`.
                    fmt = " ".join(argv)
                    if "Gateway" in fmt:
                        return cp(0, "172.28.7.1\n")
                    return cp(0, "172.28.7.0/24\n")
                if action == "rm":
                    return cp(0)
                return cp(0)
            if sub == "run":
                joined = " ".join(argv)
                if "selftest" in joined:
                    if selftest_ok:
                        return cp(0, "REDSEE_SELFTEST target=0 public=28 ssh=28\nSELFTEST_OK\n")
                    return cp(11, "SELFTEST_FAIL public_reachable=0\n")
                # the real scan run
                if scan == "timeout":
                    raise subprocess.TimeoutExpired(
                        cmd=argv, timeout=timeout, output="partial-out", stderr="")
                if scan == "fail":
                    return cp(1, "", "boom")
                return cp(0, "scan-stdout", "scan-stderr")
            if sub == "rm":
                return cp(0)
            if sub in ("image", "inspect"):
                return cp(0)
            return cp(0)

        return cp(0)

    return fake_run


def _docker_calls(calls):
    return [c for c in calls if c and c[0] == "docker"]


def _scan_run_argv(calls):
    """The `docker run` argv for the real scan (name contains sandbox-run-)."""
    for c in calls:
        if len(c) > 1 and c[0] == "docker" and c[1] == "run" \
                and any("redsee-sandbox-run-" in tok for tok in c):
            return c
    return None


def _selftest_run_argv(calls):
    """The `docker run` argv for the isolation self-test container."""
    for c in calls:
        if len(c) > 1 and c[0] == "docker" and c[1] == "run" \
                and any("redsee-sandbox-selftest-" in tok for tok in c):
            return c
    return None


def _iptables_accept_target(calls):
    """The `-d <ip> ... --dport <port> ... ACCEPT` iptables insert rules (the
    single allowed target). Returns list of (ip, port) actually allowed."""
    allowed = []
    for c in calls:
        if c and c[0] == "iptables" and "-d" in c and "ACCEPT" in c and "--dport" in c:
            ip = c[c.index("-d") + 1]
            port = c[c.index("--dport") + 1]
            allowed.append((ip, port))
    return allowed


# ── Gate-first unit tests (no docker call must happen) ──────────────────────

def test_unauthorized_config_raises_before_any_docker_call(monkeypatch):
    calls = []
    monkeypatch.setattr(sandbox.subprocess, "run", _fake_run_factory(calls))
    monkeypatch.setattr(sandbox.socket, "gethostbyname", lambda h: "10.0.0.5")

    cfg = _config(authorized=False)
    with pytest.raises(ScopeError):
        run_in_sandbox(["sqlmap", "--version"],
                       target_url="http://redsees.com:3000/", config=cfg)

    assert _docker_calls(calls) == [], "no docker call may happen when unauthorized"


def test_out_of_scope_target_raises_before_any_docker_call(monkeypatch):
    calls = []
    monkeypatch.setattr(sandbox.subprocess, "run", _fake_run_factory(calls))
    monkeypatch.setattr(sandbox.socket, "gethostbyname", lambda h: "10.0.0.5")

    cfg = _config(authorized=True, allowed_hosts=("redsees.com",))
    with pytest.raises(ScopeError):
        run_in_sandbox(["sqlmap", "--version"],
                       target_url="http://evil.com/", config=cfg)

    assert _docker_calls(calls) == [], "no docker call may happen when out of scope"


# ── Hardened argv construction ──────────────────────────────────────────────

def test_scan_argv_is_hardened_and_never_privileged(monkeypatch):
    calls = []
    monkeypatch.setattr(sandbox.subprocess, "run", _fake_run_factory(calls))
    monkeypatch.setattr(sandbox.socket, "gethostbyname", lambda h: "10.1.2.3")
    # Remote target: not one of this host's own IPs -> public-IP path.
    monkeypatch.setattr(sandbox, "_host_ip_addresses", lambda: {"127.0.0.1"})

    cfg = _config()
    result = run_in_sandbox(
        ["sqlmap", "-u", "http://redsees.com:3000/rest/products/search?q=1"],
        target_url="http://redsees.com:3000/", config=cfg)

    assert isinstance(result, SandboxResult)
    assert result.target_ip == "10.1.2.3"
    assert result.exit_code == 0
    assert result.timed_out is False

    scan = _scan_run_argv(calls)
    assert scan is not None, "scan container was never launched"
    joined = " ".join(scan)

    # Required hardening flags.
    assert "--rm" in scan
    assert "--cap-drop=ALL" in scan
    assert "--security-opt=no-new-privileges" in scan
    assert "--add-host" in scan
    assert any(tok.startswith("--memory") for tok in scan)
    assert any(tok.startswith("--cpus") for tok in scan)
    assert any(tok.startswith("--pids-limit") for tok in scan)
    assert "--read-only" in scan

    # The restricted, dedicated network is used.
    assert any("redsee-sbx-net-" in tok for tok in scan)
    # The target host:ip is injected so no DNS is needed.
    assert "redsees.com:10.1.2.3" in scan

    # Must NEVER be privileged or granted NET_ADMIN.
    assert "--privileged" not in scan
    assert "NET_ADMIN" not in joined

    # Egress firewall was actually applied (default-deny DROP present).
    assert any(c[0] == "iptables" and "DROP" in c for c in calls)


def test_add_host_uses_host_resolved_ip(monkeypatch):
    calls = []
    monkeypatch.setattr(sandbox.subprocess, "run", _fake_run_factory(calls))
    monkeypatch.setattr(sandbox.socket, "gethostbyname", lambda h: "192.0.2.55")
    # Remote target (TEST-NET-1) -> unchanged public-IP path.
    monkeypatch.setattr(sandbox, "_host_ip_addresses", lambda: {"127.0.0.1"})

    run_in_sandbox(["sqlmap", "--version"],
                   target_url="http://redsees.com:3000/", config=_config())

    scan = _scan_run_argv(calls)
    assert "redsees.com:192.0.2.55" in scan
    # Remote egress rule targets the public IP:port, not a gateway.
    assert ("192.0.2.55", "3000") in _iptables_accept_target(calls)


# ── Host-local gateway routing (the hairpin-bug fix) ────────────────────────

def test_is_host_local_ip_detects_host_loopback_and_remote():
    # Loopback is always host-local.
    assert sandbox.is_host_local_ip("127.0.0.1") is True
    # One of the host's own interface IPs (incl. docker bridge gateways).
    assert sandbox.is_host_local_ip("10.9.9.9", host_ips={"10.9.9.9"}) is True
    assert sandbox.is_host_local_ip("172.28.7.1", host_ips={"172.28.7.1"}) is True
    # A clearly-remote address is NOT host-local.
    assert sandbox.is_host_local_ip("8.8.8.8", host_ips={"10.9.9.9"}) is False
    # Garbage is not an IP -> False (never crashes).
    assert sandbox.is_host_local_ip("not-an-ip") is False
    # The real host always has at least loopback in its own address set.
    assert "127.0.0.1" in sandbox._host_ip_addresses()


def test_host_local_target_routes_via_gateway_not_public_ip(monkeypatch):
    calls = []
    monkeypatch.setattr(sandbox.subprocess, "run", _fake_run_factory(calls))
    monkeypatch.setattr(sandbox.socket, "gethostbyname", lambda h: "13.140.164.230")
    # The target resolves to one of THIS host's OWN IPs -> host-local.
    monkeypatch.setattr(sandbox, "_host_ip_addresses",
                        lambda: {"13.140.164.230", "172.28.7.1", "127.0.0.1"})

    result = run_in_sandbox(["sqlmap", "--version"],
                            target_url="http://redsees.com:3000/", config=_config())

    scan = _scan_run_argv(calls)
    assert scan is not None
    # Hostname is mapped to the bridge GATEWAY, NEVER the public IP.
    assert "redsees.com:172.28.7.1" in scan
    assert "redsees.com:13.140.164.230" not in scan
    # Egress allows ONLY the gateway:port — never the public IP.
    allowed = _iptables_accept_target(calls)
    assert ("172.28.7.1", "3000") in allowed
    assert all(ip != "13.140.164.230" for ip, _ in allowed), \
        "public IP must never appear in an ACCEPT rule for a host-local target"
    # The self-test probes the SAME (gateway) address the scan will hit.
    st = _selftest_run_argv(calls)
    assert st is not None and "redsees.com:172.28.7.1" in st
    # Resolution is still reported (what the hostname resolved to).
    assert result.target_ip == "13.140.164.230"


def test_selftest_script_blocks_public_and_ssh_and_requires_target_success():
    script = sandbox._SELFTEST_SCRIPT
    # Public-internet block probe + host-SSH(22) block probe are present.
    assert "1.1.1.1" in script
    assert ":22/" in script
    # The TARGET probe must REQUIRE success (exit 0)...
    assert '[ "$t" = "0" ]' in script
    # ...while the BLOCK probes accept only timeout/refused (7 or 28).
    assert "7|28" in script
    # Fail-closed branches for a reachable non-target exist.
    assert "public_reachable" in script and "host_port_reachable" in script


def test_selftest_container_is_launched_and_hardened(monkeypatch):
    calls = []
    monkeypatch.setattr(sandbox.subprocess, "run", _fake_run_factory(calls))
    monkeypatch.setattr(sandbox.socket, "gethostbyname", lambda h: "192.0.2.55")
    monkeypatch.setattr(sandbox, "_host_ip_addresses", lambda: {"127.0.0.1"})

    run_in_sandbox(["sqlmap", "--version"],
                   target_url="http://redsees.com:3000/", config=_config())

    st = _selftest_run_argv(calls)
    assert st is not None, "isolation self-test container was never launched"
    joined = " ".join(st)
    # The self-test actually runs the probe script (public + ssh block probes).
    assert "1.1.1.1" in joined and ":22/" in joined
    # Same hardening as the scan run — self-test is never a weak point.
    assert "--cap-drop=ALL" in st
    assert "--security-opt=no-new-privileges" in st
    assert "--read-only" in st
    assert "--privileged" not in st
    assert "NET_ADMIN" not in joined
    # Probes the same address the scan uses (public IP for this remote target).
    assert "redsees.com:192.0.2.55" in st


# ── Timeout path ────────────────────────────────────────────────────────────

def test_timeout_sets_timed_out_flag(monkeypatch):
    calls = []
    monkeypatch.setattr(sandbox.subprocess, "run",
                        _fake_run_factory(calls, scan="timeout"))
    monkeypatch.setattr(sandbox.socket, "gethostbyname", lambda h: "10.1.2.3")

    result = run_in_sandbox(["sqlmap", "--crawl=3"],
                            target_url="http://redsees.com:3000/", config=_config())

    assert result.timed_out is True
    assert result.exit_code == 124
    # The timed-out container was force-removed.
    assert any(c[0] == "docker" and c[1] == "rm" and "-f" in c for c in calls)


# ── Fail-closed isolation self-test ─────────────────────────────────────────

def test_failed_isolation_selftest_aborts_before_scan(monkeypatch):
    calls = []
    monkeypatch.setattr(sandbox.subprocess, "run",
                        _fake_run_factory(calls, selftest_ok=False))
    monkeypatch.setattr(sandbox.socket, "gethostbyname", lambda h: "10.1.2.3")

    with pytest.raises(SandboxError):
        run_in_sandbox(["sqlmap", "--version"],
                       target_url="http://redsees.com:3000/", config=_config())

    # The real scan must never run if isolation was not confirmed.
    assert _scan_run_argv(calls) is None


def test_cleanup_runs_on_failure(monkeypatch):
    calls = []
    monkeypatch.setattr(sandbox.subprocess, "run",
                        _fake_run_factory(calls, selftest_ok=False))
    monkeypatch.setattr(sandbox.socket, "gethostbyname", lambda h: "10.1.2.3")

    with pytest.raises(SandboxError):
        run_in_sandbox(["sqlmap", "--version"],
                       target_url="http://redsees.com:3000/", config=_config())

    # Firewall rules removed and network removed even on the failure path.
    assert any(c[0] == "iptables" and c[1] == "-D" for c in calls)
    assert any(c[0] == "docker" and c[1] == "network" and c[2] == "rm" for c in calls)


# ── Docker-gated integration test (skips cleanly without Docker) ────────────

def _docker_image_ready(image="redsee-sandbox:latest"):
    if shutil.which("docker") is None:
        return False
    r = subprocess.run(["docker", "image", "inspect", image],
                       capture_output=True, text=True)
    return r.returncode == 0


def _target_reachable(host, port, timeout=2.0):
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True
    except OSError:
        return False


@pytest.mark.skipif(not _docker_image_ready(),
                    reason="redsee-sandbox:latest not built (run docker/sandbox/build.sh)")
@pytest.mark.skipif(hasattr(os, "geteuid") and os.geteuid() != 0,
                    reason="host firewall management (iptables) requires root")
def test_real_sandbox_isolation():
    """With the image built + root + a reachable in-scope target, a real
    container reaches the target but is blocked from non-targets. A successful
    return implies the fail-closed isolation self-test passed."""
    target_url = os.environ.get("REDSEE_TARGET_URL", "http://redsees.com:3000/")
    parsed = urllib.parse.urlparse(target_url)
    host = parsed.hostname
    port = parsed.port or 80
    if not host or not _target_reachable(host, port):
        pytest.skip(f"target {target_url} not reachable from host")

    cfg = ScopeConfig(target_url=target_url, allowed_hosts=[host], authorized=True)
    result = run_in_sandbox(
        ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
         f"http://{host}:{port}/"],
        target_url=target_url, config=cfg)

    assert result.target_ip
    # curl to the in-scope target succeeded inside the isolated sandbox.
    assert result.exit_code == 0, f"target curl failed: {result.stderr}"


if __name__ == "__main__":
    import types

    class _MP:
        """Minimal monkeypatch stand-in for __main__ runs."""
        def __init__(self):
            self._undo = []

        def setattr(self, obj, name, value):
            self._undo.append((obj, name, getattr(obj, name)))
            setattr(obj, name, value)

        def undo(self):
            for obj, name, old in reversed(self._undo):
                setattr(obj, name, old)

    def _run(fn):
        needs_mp = fn.__code__.co_argcount == 1
        mp = _MP()
        try:
            fn(mp) if needs_mp else fn()
            print(f"  ok  {fn.__name__}")
        finally:
            mp.undo()

    for _fn in (test_unauthorized_config_raises_before_any_docker_call,
                test_out_of_scope_target_raises_before_any_docker_call,
                test_scan_argv_is_hardened_and_never_privileged,
                test_add_host_uses_host_resolved_ip,
                test_is_host_local_ip_detects_host_loopback_and_remote,
                test_host_local_target_routes_via_gateway_not_public_ip,
                test_selftest_script_blocks_public_and_ssh_and_requires_target_success,
                test_selftest_container_is_launched_and_hardened,
                test_timeout_sets_timed_out_flag,
                test_failed_isolation_selftest_aborts_before_scan,
                test_cleanup_runs_on_failure):
        _run(_fn)
    print("All sandbox unit tests passed!")
