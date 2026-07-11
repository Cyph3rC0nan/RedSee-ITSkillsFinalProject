# engine/sandbox.py
"""
Sandbox runner — Layer 2 of the RedSee agent engine (the isolation boundary).

Every active test (sqlmap and, later, other tools) runs INSIDE a throwaway
Docker container that can reach ONLY the resolved target IP:port. Nothing
active ever runs on the host.

Design principles:
  * Gate first. Layer 1 (engine.scope) authorizes and scope-checks the target
    BEFORE any container is created. If the gate refuses, no docker call is made.
  * Default-deny egress. A dedicated bridge network plus host-managed iptables
    rules (DOCKER-USER + INPUT) allow only the SINGLE address:port the scan will
    actually contact. DNS, every other host port (SSH/22, the Flask app, ...),
    every other private range, and the public internet are dropped.
  * Host-local targets go via the bridge gateway, never the public IP. When the
    target hostname resolves to one of THIS host's own IPs (e.g. redsees.com ->
    the host public IP, with DVWA/Juice Shop published on this host), the
    container cannot hairpin/NAT back to that public IP from the restricted
    bridge. Instead we map the hostname to the bridge GATEWAY address (the host's
    own IP on the sandbox bridge, reached as the container's default gateway —
    on-bridge, traffic never leaves the host) and allow ONLY <gateway_ip>:<port>.
    Genuinely-remote targets keep the direct <public_ip>:<port> path unchanged.
  * Least privilege. The scanning container runs non-root with --cap-drop=ALL,
    no-new-privileges, a read-only rootfs, resource caps, and NO host bind
    mounts. It is NEVER --privileged and NEVER granted NET_ADMIN — the firewall
    is managed by the host, not the container.
  * Fail closed. Before trusting any result, an isolation self-test proves from
    inside the sandbox that the target is reachable AND known non-targets are
    not. If that cannot be confirmed, we abort and never return scan output.
  * Always tear down. try/finally removes the container(s), firewall rules, and
    network on every path — success, error, or timeout.

Requires root on the host to manage iptables rules. Standard library only;
shells out to the `docker` and `iptables` CLIs.
"""

import ipaddress
import socket
import subprocess
import urllib.parse
import uuid
from dataclasses import dataclass

from engine.scope import ScopeConfig, assert_in_scope, require_authorization

# Resource caps for the scanning container.
_MEM_LIMIT = "256m"
_CPU_LIMIT = "1.0"
_PIDS_LIMIT = "128"

_DEFAULT_IMAGE = "redsee-sandbox:latest"

# Inline POSIX-sh isolation probe run inside the sandbox (with curl).
# $1 = target host (mapped via --add-host), $2 = target port.
# curl exit codes: 0 = HTTP transaction ok (connected), 7 = connection refused,
# 28 = timeout (a DROP rule). A blocked destination must yield 7 or 28 — any
# other code (0, 52, 56, ...) means TCP actually connected, i.e. NOT isolated.
_SELFTEST_SCRIPT = r'''
set -u
HOST="$1"; PORT="$2"
probe() { curl -s -o /dev/null --connect-timeout 5 --max-time 8 "$1" >/dev/null 2>&1; echo $?; }
t=$(probe "http://$HOST:$PORT/")
p=$(probe "http://1.1.1.1:80/")
s=$(probe "http://$HOST:22/")
echo "REDSEE_SELFTEST target=$t public=$p ssh=$s"
[ "$t" = "0" ] || { echo "SELFTEST_FAIL target_unreachable=$t"; exit 10; }
case "$p" in 7|28) ;; *) echo "SELFTEST_FAIL public_reachable=$p"; exit 11 ;; esac
case "$s" in 7|28) ;; *) echo "SELFTEST_FAIL host_port_reachable=$s"; exit 12 ;; esac
echo "SELFTEST_OK"
'''


@dataclass
class SandboxResult:
    """Outcome of a single sandboxed command run."""
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool
    target_ip: str


class SandboxError(Exception):
    """Raised when the sandbox cannot be set up, isolated, or trusted."""
    pass


# ── Docker run argv construction ────────────────────────────────────────────

def _build_hardening_argv(name: str, network: str, host: str, connect_ip: str,
                          *, entrypoint: str = None) -> list[str]:
    """Common hardened `docker run` prefix (everything up to, but not including,
    the image name). Applied identically to the self-test and the scan run.

    `connect_ip` is the address the container should reach the target at — the
    resolved public IP for a remote target, or the sandbox bridge gateway IP for
    a host-local target (see run_in_sandbox). The hostname is statically mapped to
    it so no DNS is needed AND so the scan and self-test hit the same address."""
    argv = [
        "docker", "run", "--rm",
        "--name", name,
        "--network", network,
        # Container needs no DNS: the single target host is injected statically,
        # mapped to the exact IP the egress firewall allows.
        "--add-host", f"{host}:{connect_ip}",
        # Least privilege — never privileged, never NET_ADMIN.
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        # Immutable rootfs; writable scratch only on a tmpfs, HOME points at it.
        "--read-only",
        "--tmpfs", "/tmp",
        "--env=HOME=/tmp",
        # Resource caps.
        "--memory=" + _MEM_LIMIT,
        "--cpus=" + _CPU_LIMIT,
        "--pids-limit=" + _PIDS_LIMIT,
    ]
    if entrypoint:
        argv += ["--entrypoint", entrypoint]
    return argv


# ── Host helpers (docker / iptables) ────────────────────────────────────────

def _host_cmd(argv: list[str], what: str) -> subprocess.CompletedProcess:
    """Run a host command, raising SandboxError on failure."""
    cp = subprocess.run(argv, capture_output=True, text=True)
    if cp.returncode != 0:
        raise SandboxError(f"failed to {what}: {(cp.stderr or cp.stdout).strip()}")
    return cp


def _network_subnet(network: str) -> str:
    """Read the CIDR subnet Docker assigned to a bridge network."""
    cp = _host_cmd(
        ["docker", "network", "inspect", "-f",
         "{{range .IPAM.Config}}{{.Subnet}}{{end}}", network],
        "inspect sandbox network",
    )
    subnet = cp.stdout.strip()
    if not subnet:
        raise SandboxError(f"could not determine subnet for network {network!r}")
    return subnet


def _network_gateway(network: str, subnet: str = None) -> str:
    """The bridge GATEWAY IP for `network` — the host's own address on that
    bridge, which a container reaches as its default gateway (on-bridge, never
    leaving the host). Falls back to the first host address of the subnet when
    Docker does not populate the Gateway field explicitly."""
    cp = _host_cmd(
        ["docker", "network", "inspect", "-f",
         "{{range .IPAM.Config}}{{.Gateway}}{{end}}", network],
        "inspect sandbox network gateway",
    )
    gateway = cp.stdout.strip()
    if gateway:
        return gateway
    # Derive .1 of the subnet as the conventional Docker bridge gateway.
    if subnet is None:
        subnet = _network_subnet(network)
    try:
        net = ipaddress.ip_network(subnet, strict=False)
        return str(next(net.hosts()))
    except (ValueError, StopIteration):
        raise SandboxError(f"could not determine gateway for network {network!r}")


def _host_ip_addresses() -> set:
    """Best-effort set of THIS host's own IPv4 addresses — including every
    interface (docker bridge gateways like 172.17.0.1, the LAN/public IP, etc.)
    plus loopback. Used to decide whether a resolved target is host-local."""
    ips = {"127.0.0.1"}
    try:
        cp = subprocess.run(["hostname", "-I"], capture_output=True, text=True, timeout=5)
        if cp.returncode == 0:
            ips.update(tok for tok in cp.stdout.split() if tok and ":" not in tok)
    except (OSError, subprocess.SubprocessError):
        pass
    try:
        ips.add(socket.gethostbyname(socket.gethostname()))
    except OSError:
        pass
    return ips


def is_host_local_ip(ip: str, host_ips: set = None) -> bool:
    """True if `ip` is served by THIS host: a loopback address, or one of the
    host's own interface IPs (which includes the docker bridge gateways). Such a
    target must be reached via the bridge gateway, not hairpinned via its public
    IP. A clearly-remote address (e.g. 8.8.8.8) returns False."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if addr.is_loopback:
        return True
    if host_ips is None:
        host_ips = _host_ip_addresses()
    return ip in host_ips


def _apply_egress_firewall(subnet: str, allow_ip: str, port: int) -> list[list[str]]:
    """Install default-deny egress rules for `subnet`, allowing ONLY
    allow_ip:port (the single address the scan will contact — the remote target's
    public IP, or the bridge gateway for a host-local target). Rules are added to
    both DOCKER-USER (forwarded egress: other hosts, internet, external DNS) and
    INPUT (host-local delivery, e.g. reaching a service via the bridge gateway).
    Returns the applied rule specs (chain + match) so they can be removed exactly.
    Fails closed: on any error the partial rules are rolled back before raising.
    """
    port = str(port)
    applied: list[list[str]] = []
    try:
        for chain in ("DOCKER-USER", "INPUT"):
            # Inserted at position 1 each time, so the LAST inserted ends up on
            # top. Insert DROP, then ESTABLISHED, then the target ACCEPT, giving
            # final order: ACCEPT target -> ACCEPT established -> DROP rest.
            specs = [
                [chain, "-s", subnet, "-j", "DROP"],
                [chain, "-s", subnet, "-m", "conntrack",
                 "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
                [chain, "-s", subnet, "-d", allow_ip, "-p", "tcp",
                 "--dport", port, "-j", "ACCEPT"],
            ]
            for spec in specs:
                cp = subprocess.run(
                    ["iptables", "-I", spec[0], "1"] + spec[1:],
                    capture_output=True, text=True,
                )
                if cp.returncode != 0:
                    raise SandboxError(
                        f"failed to apply egress firewall rule {spec}: "
                        f"{cp.stderr.strip()}"
                    )
                applied.append(spec)
        return applied
    except Exception:
        _remove_egress_firewall(applied)
        raise


def _remove_egress_firewall(rules: list[list[str]]) -> None:
    """Remove previously applied firewall rules. Best effort — never raises."""
    for spec in reversed(rules):
        subprocess.run(
            ["iptables", "-D", spec[0]] + spec[1:],
            capture_output=True, text=True,
        )


def _apply_prerouting_bypass(subnet: str, gateway_ip: str, port: int) -> list[str]:
    """For a host-local target reached via the bridge gateway, skip Docker's
    published-port DNAT for our subnet's traffic to <gateway_ip>:<port>.

    Docker DNATs a published port for every non-docker0 input interface, so from
    our dedicated bridge the destination would be rewritten to the target
    CONTAINER's private IP BEFORE our filter ACCEPT can match — and the catch-all
    DROP then kills it. Skipping DNAT here delivers the packet to the host's local
    listener instead (the docker-proxy for a published port, or a host-bound
    service), which our INPUT ACCEPT already permits. This does NOT broaden egress:
    the filter table still allows ONLY <gateway_ip>:<port> and drops everything
    else; this rule only affects that exact same subnet -> gateway:port flow.

    Returns the applied nat rule match (for exact removal), or [] on failure
    (best-effort: a host-bound target needs no DNAT bypass anyway).
    """
    match = ["-s", subnet, "-d", gateway_ip, "-p", "tcp",
             "--dport", str(port), "-j", "ACCEPT"]
    cp = subprocess.run(
        ["iptables", "-t", "nat", "-I", "PREROUTING", "1"] + match,
        capture_output=True, text=True,
    )
    if cp.returncode != 0:
        return []
    return match


def _remove_prerouting_bypass(match: list[str]) -> None:
    """Remove the PREROUTING DNAT-bypass rule. Best effort — never raises."""
    if match:
        subprocess.run(
            ["iptables", "-t", "nat", "-D", "PREROUTING"] + match,
            capture_output=True, text=True,
        )


def _force_remove_container(name: str) -> None:
    """Best-effort `docker rm -f` — never raises."""
    subprocess.run(["docker", "rm", "-f", name], capture_output=True, text=True)


def _run_isolation_selftest(name: str, network: str, host: str,
                            connect_ip: str, port: int, image: str) -> None:
    """Fail-closed isolation proof. Runs the probe container and requires that it
    confirms BOTH target reachability and non-target unreachability. Raises
    SandboxError otherwise — the scan must not run on a sandbox we cannot trust.

    The probe hits `host` (statically mapped to `connect_ip` — the SAME address
    the scan will use), so a passing self-test proves the exact path the scan
    takes. The target probe must succeed (exit 0); the public-internet and host
    SSH(22) probes must stay blocked (timeout/refused).
    """
    argv = _build_hardening_argv(name, network, host, connect_ip,
                                 entrypoint="/bin/sh") + \
        [image, "-c", _SELFTEST_SCRIPT, "redsee", host, str(port)]
    try:
        cp = subprocess.run(argv, capture_output=True, text=True, timeout=90)
    except subprocess.TimeoutExpired:
        _force_remove_container(name)
        raise SandboxError(
            "isolation self-test timed out — refusing to run scan (fail-closed)"
        )
    if cp.returncode != 0 or "SELFTEST_OK" not in (cp.stdout or ""):
        raise SandboxError(
            "isolation self-test FAILED — sandbox is not properly isolated; "
            f"aborting before scan. stdout={cp.stdout!r} stderr={cp.stderr!r}"
        )


# ── Public entry point ──────────────────────────────────────────────────────

def run_in_sandbox(argv: list[str], *, target_url: str, config: ScopeConfig,
                   timeout_sec: int = 300,
                   image: str = _DEFAULT_IMAGE) -> SandboxResult:
    """Run `argv` inside a hardened, egress-restricted throwaway container.

    Args:
        argv: The command to run inside the container (e.g. ["sqlmap", "-u", ...]).
              This runner is generic — it adds no tool-specific flags.
        target_url: The URL being tested. Its host is resolved on the host and is
              the ONLY destination the container may reach.
        config: Layer-1 ScopeConfig. Authorization and scope are enforced first.
        timeout_sec: Kill/remove the container if the scan exceeds this.
        image: Sandbox image tag (default redsee-sandbox:latest).

    Returns:
        SandboxResult with captured stdout/stderr, exit code, timeout flag, and
        the resolved target IP.

    Raises:
        ScopeError: if the config is unauthorized or the target is out of scope
            (raised BEFORE any docker call).
        SandboxError: on setup failure or if the isolation self-test fails.
    """
    # 1. GATE FIRST — Layer 1 wired into Layer 2. No docker call happens if this
    #    refuses.
    require_authorization(config)
    assert_in_scope(target_url, config)

    if not argv:
        raise SandboxError("argv must be a non-empty command list")

    # 2. Parse + resolve the single allowed destination on the HOST.
    parsed = urllib.parse.urlparse(target_url.strip().split("#", 1)[0])
    host = parsed.hostname
    if not host:
        raise SandboxError(f"could not parse host from target_url: {target_url!r}")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        target_ip = socket.gethostbyname(host)
    except OSError as exc:
        raise SandboxError(f"could not resolve target host {host!r}: {exc}")

    token = uuid.uuid4().hex[:8]
    network = f"redsee-sbx-net-{token}"
    selftest_name = f"redsee-sandbox-selftest-{token}"
    run_name = f"redsee-sandbox-run-{token}"

    applied_rules: list[list[str]] = []
    applied_nat: list[str] = []
    network_created = False
    try:
        # 3. Dedicated bridge network.
        _host_cmd(["docker", "network", "create", "--driver", "bridge", network],
                  "create sandbox network")
        network_created = True
        subnet = _network_subnet(network)

        # 4. Decide the address the container will ACTUALLY contact. A host-local
        #    target (hostname resolves to one of THIS host's own IPs) cannot be
        #    hairpinned back to that public IP from the restricted bridge, so route
        #    it via the bridge GATEWAY — on-bridge, traffic never leaves the host.
        #    A genuinely-remote target keeps its resolved public IP. The firewall,
        #    the --add-host mapping, and the self-test all use this one address.
        host_local = is_host_local_ip(target_ip)
        connect_ip = _network_gateway(network, subnet) if host_local else target_ip

        # 5. Default-deny egress firewall — allow ONLY connect_ip:port (nothing
        #    broader). Fail-closed if it cannot be applied.
        applied_rules = _apply_egress_firewall(subnet, connect_ip, port)

        # 5b. Host-local only: skip Docker's published-port DNAT for this exact
        #     subnet -> gateway:port flow so it reaches the host's local listener
        #     instead of being NAT-rewritten to the target container (which the
        #     filter DROP would then kill). Does NOT widen egress.
        if host_local:
            applied_nat = _apply_prerouting_bypass(subnet, connect_ip, port)

        # 6. Prove isolation BEFORE running the scan — probing connect_ip:port.
        _run_isolation_selftest(selftest_name, network, host, connect_ip, port, image)

        # 7. Run the actual command under a timeout.
        run_argv = _build_hardening_argv(run_name, network, host, connect_ip) \
            + [image] + list(argv)
        try:
            cp = subprocess.run(run_argv, capture_output=True, text=True,
                                timeout=timeout_sec)
            return SandboxResult(
                exit_code=cp.returncode,
                stdout=cp.stdout or "",
                stderr=cp.stderr or "",
                timed_out=False,
                target_ip=target_ip,
            )
        except subprocess.TimeoutExpired as exc:
            _force_remove_container(run_name)
            out = exc.stdout.decode() if isinstance(exc.stdout, bytes) else (exc.stdout or "")
            err = exc.stderr.decode() if isinstance(exc.stderr, bytes) else (exc.stderr or "")
            return SandboxResult(
                exit_code=124,
                stdout=out,
                stderr=(err + f"\n[sandbox] killed after {timeout_sec}s timeout").strip(),
                timed_out=True,
                target_ip=target_ip,
            )
    finally:
        # 8. Always tear everything down.
        _force_remove_container(run_name)
        _force_remove_container(selftest_name)
        _remove_prerouting_bypass(applied_nat)
        _remove_egress_firewall(applied_rules)
        if network_created:
            subprocess.run(["docker", "network", "rm", network],
                           capture_output=True, text=True)
