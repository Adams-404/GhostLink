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
