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
