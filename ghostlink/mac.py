"""MAC identity tooling: inventory, neighbor discovery, MAC generation.

The spoof engine (backup/apply/restore) is layered on top in a later stage.
"""

from __future__ import annotations

import re
import secrets

from .config import ip_json, is_wireless

_MAC_RE = re.compile(
    r"^([0-9a-fA-F]{2})[:-]([0-9a-fA-F]{2})[:-]([0-9a-fA-F]{2})[:-]"
    r"([0-9a-fA-F]{2})[:-]([0-9a-fA-F]{2})[:-]([0-9a-fA-F]{2})$"
)

# Common consumer OUIs — for realistic impersonation of a paying device.
# Replace with the OUIs actually seen on the target network at the venue.
VENDOR_OUI: dict[str, list[str]] = {
    "apple": ["f0:18:98", "dc:a6:32", "a4:83:e7"],
    "samsung": ["34:23:87", "8c:77:12", "5c:0a:5b"],
    "xiaomi": ["64:09:80", "28:6c:07", "9c:5a:44"],
    "intel": ["8c:70:5a", "3c:58:c2", "94:65:9c"],
    "google": ["3c:5a:b4", "f4:f5:d8", "1c:f2:9a"],
}


class MacError(ValueError):
    """Raised for malformed MAC strings or invalid spoof requests."""


def normalize_mac(mac: str) -> str:
    """Validate and normalize a MAC to lowercase colon-separated form."""
    match = _MAC_RE.match(mac.strip())
    if not match:
        raise MacError(f"invalid MAC address: {mac!r}")
    return ":".join(group.lower() for group in match.groups())


def is_locally_administered(mac: str) -> bool:
    """True when the locally-administered bit (U/L) is set."""
    return bool(int(normalize_mac(mac).split(":")[0], 16) & 0b10)


def random_mac(local: bool = True, vendor: str | None = None) -> str:
    """Generate a spoofable MAC — locally administered by default, optionally
    prefixed with a well-known consumer OUI for realism."""
    octets: list[int]
    if vendor is not None:
        if vendor not in VENDOR_OUI:
            raise MacError(f"unknown vendor {vendor!r}; choices: {sorted(VENDOR_OUI)}")
        oui = secrets.choice(VENDOR_OUI[vendor])
        octets = [int(p, 16) for p in oui.split(":")] + list(secrets.token_bytes(3))
    else:
        octets = list(secrets.token_bytes(6))
    octets[0] = (octets[0] & ~0b11) | (0b10 if local else 0b00)
    return ":".join(f"{o:02x}" for o in octets)


def list_interfaces() -> list[dict]:
    """Interfaces with name, MAC, type and wireless-ness."""
    out = []
    for entry in ip_json(["link", "show"]):
        name = entry.get("ifname", "?")
        out.append(
            {
                "name": name,
                "mac": entry.get("address", ""),
                "state": entry.get("operstate", "unknown"),
                "wireless": is_wireless(name),
            }
        )
    return out


def neighbors() -> list[dict]:
    """Neighbor (ARP/ND) table entries — who has been talkative on this link."""
    entries = ip_json(["neigh", "show"])
    return [
        {
            "ip": entry.get("dst", "?"),
            "mac": entry.get("lladdr", "incomplete"),
            "state": ",".join(entry["state"]) if isinstance(entry.get("state"), list) else entry.get("state", "?"),
            "dev": entry.get("dev", "?"),
        }
        for entry in entries
    ]


def neighbor_counts() -> dict[str, int]:
    counts: dict[str, int] = {}
    for entry in neighbors():
        counts[entry["state"]] = counts.get(entry["state"], 0) + 1
    return counts
