"""Target discovery and link configuration data model.

Wraps `ip -j` (iproute2 JSON mode) so callers get typed objects instead of
having to shell out and parse text.
"""

from __future__ import annotations

import ipaddress
import json
import os
import subprocess
from dataclasses import dataclass, field


class IpError(RuntimeError):
    """Raised when an `ip` call fails or the environment is unusable."""


@dataclass
class Target:
    """Everything GhostLink needs to know about the link under analysis."""

    iface: str
    address: str
    prefix: int
    gateway: str | None
    resolvers: list[str] = field(default_factory=list)
    network: str = ""
    wireless: bool = False
    mac: str = ""

    @property
    def cidr(self) -> str:
        return f"{self.address}/{self.prefix}"


def ip_json(args: list[str]) -> object:
    """Run `ip -j <args>` and return parsed JSON output."""
    proc = subprocess.run(
        ["ip", "-j", *args],
        capture_output=True,
        text=True,
        timeout=10,
    )
    if proc.returncode != 0:
        raise IpError(f"`ip {' '.join(args)}` failed: {proc.stderr.strip()}")
    return json.loads(proc.stdout or "null")


def list_interfaces() -> list[dict]:
    data = ip_json(["link", "show"])
    return data if isinstance(data, list) else []


def interface_mac(iface: str) -> str:
    data = ip_json(["link", "show", "dev", iface])
    if not data or not isinstance(data, list):
        raise IpError(f"interface {iface!r} not found")
    return str(data[0].get("address", ""))


def is_wireless(iface: str) -> bool:
    """True when the interface is backed by a WiFi PHY (sysfs probe)."""
    if os.path.exists(f"/sys/class/net/{iface}/wireless"):
        return True
    return os.path.islink(f"/sys/class/net/{iface}/phy80211")


def default_route() -> dict:
    routes = ip_json(["route", "show", "default"])
    if not routes or not isinstance(routes, list):
        raise IpError("no default route found — are you connected to a network?")
    return routes[0]


def read_resolvers() -> list[str]:
    resolvers: list[str] = []
    try:
        with open("/etc/resolv.conf", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line.startswith("nameserver"):
                    entry = line.split()[1:2]
                    if entry and entry[0] not in resolvers:
                        resolvers.append(entry[0])
    except OSError:
        pass
    return resolvers


def detect_target(iface: str | None = None) -> Target:
    """Build a Target from the live link state (default-route iface by default)."""
    route = default_route()
    iface = iface or route.get("dev")
    if not iface:
        raise IpError("could not determine active interface")

    addrs = ip_json(["addr", "show", "dev", iface])
    inet = None
    for entry in addrs or []:
        inet = next(
            (a for a in entry.get("addr_info", []) if a.get("family") == "inet"),
            None,
        )
        if inet:
            break
    if inet is None:
        raise IpError(f"no IPv4 address on {iface!r}")

    address = inet["local"]
    prefix = int(inet["prefixlen"])
    network = str(ipaddress.ip_network(f"{address}/{prefix}", strict=False))

    return Target(
        iface=iface,
        address=address,
        prefix=prefix,
        gateway=route.get("gateway"),
        resolvers=read_resolvers(),
        network=network,
        wireless=is_wireless(iface),
        mac=interface_mac(iface),
    )
