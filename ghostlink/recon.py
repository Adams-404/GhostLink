"""Link discovery and captive-portal detection."""

from __future__ import annotations

import http.client
import socket
from urllib.parse import urlsplit

from .config import Target
from .output import Console

# OS captive-portal probe endpoints: OSes hit these expecting a well-known
# success body. Anything else (redirect / changed body) = portal interception.
PROBES: list[tuple[str, str, bytes | None]] = [
    ("apple", "http://captive.apple.com/hotspot-detect.html", b"Success"),
    ("firefox", "http://detectportal.firefox.com/success.txt", b"success"),
    ("google", "http://connectivitycheck.gstatic.com/generate_204", None),
    ("msft", "http://www.msftconnecttest.com/connecttest.txt", b"Microsoft Connect Test"),
]


def http_get_no_redirect(url: str, timeout: float = 4.0) -> tuple[int, dict[str, str], bytes]:
    """GET a URL without following redirects. Returns (status, headers, body)."""
    parts = urlsplit(url)
    conn = http.client.HTTPConnection(parts.hostname or "", parts.port or 80, timeout=timeout)
    path = parts.path or "/"
    if parts.query:
        path += f"?{parts.query}"
    conn.request("GET", path, headers={"Host": parts.netloc, "User-Agent": "Mozilla/5.0 (ghostlink)", "Connection": "close"})
    resp = conn.getresponse()
    body = resp.read(4096)
    headers = {k.lower(): v for k, v in resp.getheaders()}
    conn.close()
    return resp.status, headers, body


def detect_portal(timeout: float = 4.0) -> dict:
    """Probe OS connectivity-check endpoints and classify portal interception."""
    result: dict = {"portal": False, "portal_url": None, "unexpected": [], "probes": []}
    for name, url, expect in PROBES:
        entry: dict = {"probe": name, "url": url}
        try:
            status, headers, body = http_get_no_redirect(url, timeout)
            entry["status"] = status
            location = headers.get("location")
            if 300 <= status < 400 and location:
                entry["result"] = "redirect"
                entry["location"] = location
                if not result["portal"]:
                    result["portal"] = True
                    result["portal_url"] = location
            elif status == 200 and (expect is None or expect in body):
                entry["result"] = "direct"
            elif status == 200:
                entry["result"] = "unexpected-body"
                result["unexpected"].append(name)
            else:
                entry["result"] = f"http-{status}"
        except (http.client.HTTPException, socket.error, OSError) as exc:
            entry["result"] = f"error: {type(exc).__name__}: {exc}"
        result["probes"].append(entry)
    return result


def run(target: Target, timeout: float = 4.0) -> dict:
    portal = detect_portal(timeout)
    return {
        "target": {
            "iface": target.iface,
            "address": target.address,
            "prefix": target.prefix,
            "gateway": target.gateway,
            "network": target.network,
            "resolvers": target.resolvers,
            "wireless": target.wireless,
            "mac": target.mac,
        },
        "portal": portal,
    }


def render(target: Target, data: dict, console: Console) -> None:
    console.section("Link")
    console.kv("Interface", f"{target.iface} ({'wifi' if target.wireless else 'ethernet'})")
    console.kv("MAC", target.mac)
    console.kv("Address", target.cidr)
    console.kv("Gateway", target.gateway or "unknown")
    console.kv("Network", target.network)
    console.kv("Resolvers", ", ".join(target.resolvers) or "none found")
    if any(r.startswith("127.0.0.53") for r in target.resolvers):
        console.info("systemd-resolved stub detected — local DNS views may be cached/rewritten")

    portal = data["portal"]
    console.section("Portal")
    if portal["portal"]:
        console.fail(f"captive portal detected -> {portal['portal_url']}")
    else:
        console.ok("no captive portal on this link (all probes returned expected bodies)")
    for entry in portal["probes"]:
        detail = entry.get("location") or entry.get("result", "")
        console.info(f"{entry['probe']:<8} {entry['url']}  -> {detail}")
