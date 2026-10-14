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


def fetch_portal_page(url: str, timeout: float = 5.0) -> tuple[str | None, str | None]:
    """Fetch the portal splash page (HTTPS capable). Returns (html, error)."""
    import urllib.request

    if url.startswith("http://"):
        url = "http://" + urlsplit(url).netloc + (urlsplit(url).path or "/")
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (ghostlink)"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read(1_000_000).decode("utf-8", errors="replace"), None
    except Exception as exc:  # noqa: BLE001 - report any fetch failure verbatim
        return None, f"{type(exc).__name__}: {exc}"


def run(portal_url: str | None = None, concurrency: int = 24, timeout: float = 3.0, candidate_limit: int = _MAX_CANDIDATES) -> dict:
    """Dissect the portal page (if any) and probe the walled garden."""
    data: dict = {"portal_url": portal_url, "page_hosts": [], "fetch_error": None, "reachable": {}}
    if portal_url:
        html, err = fetch_portal_page(portal_url, timeout=timeout + 2)
        if html is None:
            data["fetch_error"] = err
        else:
            portal_host = urlsplit(portal_url).hostname
            data["page_hosts"] = extract_candidate_hosts(html, portal_host, limit=candidate_limit)
    if data["page_hosts"]:
        data["reachable"] = probe_candidates(data["page_hosts"], concurrency=concurrency, timeout=timeout)
    else:
        data["reachable"] = probe_candidates(DEFAULT_CANDIDATES, concurrency=concurrency, timeout=timeout)
    return data


def render(data: dict, console) -> None:
    console.section("Walled garden")
    if data["portal_url"]:
        console.kv("Portal page", data["portal_url"])
        if data["fetch_error"]:
            console.warn(f"could not fetch portal page: {data['fetch_error']}")
        elif data["page_hosts"]:
            console.ok(f"{len(data['page_hosts'])} host(s) referenced by portal page")
        else:
            console.info("portal page referenced no external hosts")
    else:
        console.info("no portal page — probing seeded candidates (connectivity/DNS/payment hosts)")

    if data["reachable"]:
        console.fail(f"{len(data['reachable'])} host(s) reachable pre-auth:")
        for host, ports in data["reachable"].items():
            console.info(f"  {host:<40} ports {ports}")
    else:
        console.ok("no candidate hosts reachable pre-auth")
