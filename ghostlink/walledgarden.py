"""Walled-garden dissection: figure out what a portal page reveals and which
of those hosts are actually reachable pre-auth."""

from __future__ import annotations

import re
from urllib.parse import urlsplit

_URL_RE = re.compile(r"""https?://([a-zA-Z0-9][a-zA-Z0-9.\-]*[a-zA-Z0-9])""")
_SKIP_HOSTS = {"localhost"}
_MAX_CANDIDATES = 40


def _host_is_ip(host: str) -> bool:
    import ipaddress

    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def extract_candidate_hosts(html: str, portal_host: str | None = None, limit: int = _MAX_CANDIDATES) -> list[str]:
    """Pull external hostnames referenced by a portal splash page.

    The portal page itself must reach the payment processor / CDNs / connectivity
    checks — every one of those hosts is a walled-garden member and a potential
    relay for a tunnel.
    """
    portal_host = (portal_host or "").lower()
    hosts: set[str] = set()
    for match in _URL_RE.finditer(html or ""):
        host = match.group(1).lower().rstrip(".")
        if not host or host in _SKIP_HOSTS or host == portal_host:
            continue
        if _host_is_ip(host) and host.startswith(("0.", "127.", "10.", "169.254.")):
            continue
        hosts.add(host)
    return sorted(hosts)[:limit]


# Seeded candidates used when no portal page is available yet (or in addition to
# the ones parsed from it): OS connectivity probes, public DNS, and the payment
# / portal-vendor hosts that portals typically must whitelist.
DEFAULT_CANDIDATES = [
    "captive.apple.com",
    "detectportal.firefox.com",
    "connectivitycheck.gstatic.com",
    "www.msftconnecttest.com",
    "1.1.1.1",
    "8.8.8.8",
    "dns.google",
    "js.stripe.com",
    "api.stripe.com",
    "q.stripe.com",
    "api.paypal.com",
    "www.paypal.com",
    "spotipo.com",
    "coova.org",
]


def probe_host(host: str, ports: tuple[int, ...] = (443, 80), timeout: float = 3.0) -> list[int]:
    """Return which of `ports` accept TCP connections pre-auth."""
    import socket

    reachable = []
    for port in ports:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                reachable.append(port)
        except OSError:
            continue
    return reachable


def probe_candidates(hosts: list[str], ports: tuple[int, ...] = (443, 80), concurrency: int = 24, timeout: float = 3.0) -> dict[str, list[int]]:
    """Concurrently probe a host list; only reachable hosts are returned."""
    import concurrent.futures

    result: dict[str, list[int]] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = {pool.submit(probe_host, h, ports, timeout): h for h in hosts}
        for fut in concurrent.futures.as_completed(futures):
            host = futures[fut]
            hit = fut.result()
            if hit:
                result[host] = hit
    return dict(sorted(result.items()))
