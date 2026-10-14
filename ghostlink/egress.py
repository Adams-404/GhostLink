"""Pre-auth egress probing: which traffic still leaves the network before
you have paid (i.e. what the captive-portal firewall lets through)."""

from __future__ import annotations

import concurrent.futures
import socket
import subprocess

from .config import Target
from .dnswire import build_query, parse_header

# Ports worth probing pre-auth: DNS, VPNs, and classic tunnel ports.
TCP_PORTS = [53, 80, 123, 443, 500, 1194, 4500, 8443]
PUBLIC_IPS = ["1.1.1.1", "8.8.8.8"]


def tcp_probe(ip: str, port: int, timeout: float = 3.0) -> str:
    """Classify a TCP port on a public host: open / closed (refused) / filtered."""
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return "open"
    except ConnectionRefusedError:
        return "closed"
    except (socket.timeout, OSError) as exc:
        if isinstance(exc, TimeoutError):
            return "filtered"
        return f"error:{type(exc).__name__}"


def tcp_matrix(concurrency: int = 32, timeout: float = 3.0) -> dict[str, dict[int, str]]:
    jobs = [(ip, port) for ip in PUBLIC_IPS for port in TCP_PORTS]
    results: dict[str, dict[int, str]] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = {pool.submit(tcp_probe, ip, port, timeout): (ip, port) for ip, port in jobs}
        for fut in concurrent.futures.as_completed(futures):
            ip, port = futures[fut]
            results.setdefault(ip, {})[port] = fut.result()
    return results


def udp_dns_probe(server: str, qname: str = "example.com", timeout: float = 3.0) -> dict:
    """Send one UDP/DNS query to `server` and see if a reply comes back.

    A reply from an off-LAN resolver pre-auth means UDP/53 egress is unfiltered —
    the classic dnscat2/iodine tunnel path through a portal's walled garden.
    """
    qid = 0x4242
    query = build_query(qname, qid=qid)
    result = {"server": server, "qname": qname, "reply": False, "rcode": None, "error": None}
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(query, (server, 53))
            data, _ = sock.recvfrom(1024)
        header = parse_header(data)
        result["reply"] = header["id"] == qid
        result["rcode"] = header["rcode"]
        result["ancount"] = header["ancount"]
    except (socket.timeout, OSError) as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    return result


def dns_leak_test(gateway: str | None, timeout: float = 3.0) -> dict:
    """Is DNS usable pre-auth, and against which servers?

    - gateway answering direct queries  -> local recursion available (tunnel host)
    - off-LAN resolver replying over UDP -> unfiltered UDP/53 egress (dnscat2 path)
    """
    result = {"gateway": None, "upstream": []}
    if gateway:
        result["gateway"] = udp_dns_probe(gateway, timeout=timeout)
    for server in ("1.1.1.1", "8.8.8.8"):
        result["upstream"].append(udp_dns_probe(server, timeout=timeout))
    return result


def icmp_probe(host: str = "1.1.1.1", count: int = 1, timeout: float = 3.0) -> dict:
    """ICMP reachability via ping(1) — the raw-socket path needs privileges,
    so we detect capability rather than assume it."""
    result = {"host": host, "reachable": False, "error": None, "output": ""}
    try:
        proc = subprocess.run(
            ["ping", "-c", str(count), "-W", str(int(timeout)), host],
            capture_output=True,
            text=True,
            timeout=timeout + count + 5,
        )
        result["output"] = proc.stdout.strip().splitlines()[-1] if proc.stdout.strip() else ""
        result["reachable"] = proc.returncode == 0
        if proc.returncode == 2:
            result["error"] = "ping reported failure (privileges? firewall?)"
    except FileNotFoundError:
        result["error"] = "ping binary not found"
    except subprocess.TimeoutExpired:
        result["error"] = "ping timed out"
    return result


def run(target: Target, concurrency: int = 32, timeout: float = 3.0) -> dict:
    return {
        "tcp": tcp_matrix(concurrency=concurrency, timeout=timeout),
        "udp_upstream": udp_dns_probe("1.1.1.1", timeout=timeout),
        "dns_leak": dns_leak_test(target.gateway, timeout=timeout),
        "icmp": icmp_probe(timeout=timeout),
    }


def render(target: Target, data: dict, console: Console) -> None:
    console.section("Pre-auth TCP egress (public IPs)")
    for ip, ports in sorted(data["tcp"].items()):
        open_ports = sorted(p for p, st in ports.items() if st == "open")
        filtered = sorted(p for p, st in ports.items() if st == "filtered")
        console.kv(f"{ip} open", ", ".join(map(str, open_ports)) or "none")
        console.kv(f"{ip} filtered", ", ".join(map(str, filtered)) or "none")

    console.section("Pre-auth UDP/53 egress")
    for entry in data["dns_leak"]["upstream"]:
        if entry["reply"]:
            console.fail(f"UDP/53 to {entry['server']} replies pre-auth -> DNS-tunnel egress possible")
        else:
            console.ok(f"UDP/53 to {entry['server']} blocked ({entry['error'] or 'no reply'})")
    gw = data["dns_leak"]["gateway"]
    if gw:
        state = "answers recursively" if gw.get("reply") else f"no direct reply ({gw.get('error')})"
        console.kv(f"Gateway {target.gateway} DNS", state)

    console.section("ICMP")
    icmp = data["icmp"]
    if icmp["error"]:
        console.warn(f"ping: {icmp['error']}")
    else:
        console.info(f"{icmp['host']} -> {'reachable' if icmp['reachable'] else 'unreachable'}")
