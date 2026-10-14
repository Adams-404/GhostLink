"""Extra probes: IPv6 leakage, MTU/TTL fingerprint, egress-path divergence,
and DHCP hostname disclosure."""

from __future__ import annotations

import re
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor

from .config import Target, ip_json


def ipv6_addresses() -> list[dict]:
    """Global (non-link-local) IPv6 addresses per interface."""
    out: list[dict] = []
    for entry in ip_json(["addr", "show"]) or []:
        ifname = entry.get("ifname", "?")
        for addr in entry.get("addr_info", []):
            if addr.get("family") == "inet6" and addr.get("scope") == "global":
                out.append({"iface": ifname, "address": addr.get("local"), "prefixlen": addr.get("prefixlen")})
    return out


def ipv6_egress(host: str = "2606:4700:4700::1111", port: int = 443, timeout: float = 3.0) -> str:
    """Can we egress over IPv6 directly? Returns open/closed/filtered/error."""
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((host, port))
        return "open"
    except ConnectionRefusedError:
        return "closed"
    except socket.timeout:
        return "filtered"
    except OSError as exc:
        return f"error:{type(exc).__name__}"


def route_metrics(dest: str = "1.1.1.1") -> dict:
    """MTU/hoplimit of the current path to `dest` (text mode; JSON omits these)."""
    metrics: dict = {"dest": dest, "via": None, "iface": None, "mtu": None, "hoplimit": None}
    try:
        proc = subprocess.run(["ip", "route", "get", dest], capture_output=True, text=True, timeout=10)
        if proc.returncode != 0:
            metrics["error"] = proc.stderr.strip()
            return metrics
        fields = proc.stdout.split()
        if "via" in fields:
            metrics["via"] = fields[fields.index("via") + 1]
        if "dev" in fields:
            metrics["iface"] = fields[fields.index("dev") + 1]
        for key, target in (("mtu", "mtu"), ("hoplimit", "hoplimit")):
            if target in fields:
                metrics[key] = fields[fields.index(target) + 1]
    except (OSError, subprocess.TimeoutExpired) as exc:
        metrics["error"] = str(exc)
    return metrics


def traceroute(dest: str = "1.1.1.1", max_hops: int = 12, timeout: float = 3.0) -> list[str]:
    """Hop list toward `dest` ('*' for unreplied hops)."""
    try:
        proc = subprocess.run(
            ["traceroute", "-n", "-w", str(int(timeout)), "-q", "1", "-m", str(max_hops), dest],
            capture_output=True,
            text=True,
            timeout=max_hops * timeout + 10,
        )
    except FileNotFoundError:
        return []
    except subprocess.TimeoutExpired:
        return []
    hops: list[str] = []
    for line in proc.stdout.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 2 and parts[0].isdigit():
            hops.append(parts[1] if parts[1] != "*" else "*")
    return hops


def path_divergence(target: Target, hops: list[str]) -> dict:
    """Compare the first egress hop to the expected gateway.

    On a captive-portal network you often see the portal/AP itself as hop 1
    (traffic is being intercepted in-path) or extra hops inside your own /24
    (transparent bridge). Either is a strong interception tell.
    """
    result = {"expected_gateway": target.gateway, "first_hop": hops[0] if hops else None, "matches_gateway": None, "in_subnet_hops": []}
    if not hops:
        result["note"] = "no traceroute data"
        return result
    result["matches_gateway"] = hops[0] == target.gateway
    subnet = ".".join(target.address.split(".")[:3])
    result["in_subnet_hops"] = [h for h in hops if h != "*" and h.startswith(f"{subnet}.")]
    return result


def dhcp_hostname(iface: str) -> dict:
    """Hostname/lease disclosure: what the DHCP layer leaks about this client."""
    result: dict = {"iface": iface, "local_hostname": socket.gethostname(), "dhcp_hostname": None, "nmcli": None}
    try:
        proc = subprocess.run(
            ["nmcli", "-t", "-f", "DHCP4.OPTION", "device", "show", iface],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if proc.returncode == 0:
            for line in proc.stdout.splitlines():
                if "host_name" in line:
                    result["nmcli"] = line
                    result["dhcp_hostname"] = line.rsplit("=", 1)[-1]
                    break
    except (FileNotFoundError, subprocess.TimeoutExpired):
        result["nmcli"] = "unavailable"
    return result


def run(target: Target, timeout: float = 3.0) -> dict:
    v6 = ipv6_addresses()
    hops = traceroute(timeout=timeout)
    return {
        "ipv6_addresses": v6,
        "ipv6_egress": ipv6_egress(timeout=timeout) if v6 else "no-global-v6",
        "route_metrics": route_metrics(),
        "path": path_divergence(target, hops),
        "dhcp": dhcp_hostname(target.iface),
    }


def render(target: Target, data: dict, console) -> None:
    console.section("IPv6")
    if data["ipv6_addresses"]:
        console.warn("global IPv6 addresses present — potential egress path that may bypass portal:")
        for entry in data["ipv6_addresses"]:
            console.info(f"  {entry['iface']}: {entry['address']}/{entry['prefixlen']}")
    else:
        console.ok("no global IPv6 addresses — IPv6 egress not applicable")

    console.section("Path")
    path = data["path"]
    console.kv("Expected gateway", path.get("expected_gateway"))
    console.kv("First hop", path.get("first_hop"))
    if path.get("matches_gateway"):
        console.ok("first hop matches gateway — no obvious in-path interception from this host")
    elif path.get("first_hop"):
        console.warn("first hop differs from gateway — possible transparent interception/bridge")
    if path.get("in_subnet_hops"):
        console.info(f"hops inside local subnet: {path['in_subnet_hops']}")

    console.section("DHCP disclosure")
    dhcp = data["dhcp"]
    console.kv("Local hostname", dhcp["local_hostname"])
    if dhcp["dhcp_hostname"]:
        console.info(f"DHCP sends host_name={dhcp['dhcp_hostname'].strip()!r} (usable for client fingerprinting)")
    else:
        console.ok("no DHCP hostname disclosed")
