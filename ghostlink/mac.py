"""MAC identity tooling: inventory, neighbor discovery, MAC generation,
and the spoof engine (dry-run / sudo apply / backup / restore)."""

from __future__ import annotations

import os
import re
import secrets
import subprocess
from pathlib import Path

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


# ---------------------------------------------------------------------------
# Spoof engine
# ---------------------------------------------------------------------------


def _cache_dir() -> Path:
    path = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "ghostlink"
    path.mkdir(parents=True, exist_ok=True)
    return path


def backup_mac(iface: str, mac: str) -> None:
    """Persist the pre-spoof MAC so `restore` can always undo a spoof."""
    (_cache_dir() / f"{iface}.orig.mac").write_text(mac, encoding="utf-8")


def read_backup(iface: str) -> str | None:
    path = _cache_dir() / f"{iface}.orig.mac"
    if not path.exists():
        return None
    mac = path.read_text(encoding="utf-8").strip()
    return normalize_mac(mac) if mac else None


def clear_backup(iface: str) -> None:
    (_cache_dir() / f"{iface}.orig.mac").unlink(missing_ok=True)


def default_route_iface() -> str | None:
    from .config import default_route

    try:
        return default_route().get("dev")
    except Exception:  # noqa: BLE001 - no route is a valid answer, not an error
        return None


def current_mac(iface: str) -> str:
    from .config import interface_mac

    return interface_mac(iface).lower()


def apply_mac(iface: str, mac: str, timeout: float = 10.0) -> None:
    """Apply a MAC via `sudo -n ip link set` (non-interactive; fails loudly
    if the user has no passwordless sudo, rather than hanging on a prompt)."""
    proc = subprocess.run(
        ["sudo", "-n", "ip", "link", "set", "dev", iface, "address", mac],
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if proc.returncode != 0:
        raise MacError(
            f"`sudo -n ip link set` failed (rc={proc.returncode}): "
            f"{(proc.stderr or proc.stdout).strip() or 'no output'}"
        )


def spoof(iface: str, mac: str | None, apply: bool = False, force: bool = False) -> dict:
    """Prepare (and optionally apply) a MAC change on `iface`.

    Returns a plan dict; by default nothing is changed (dry-run) so the
    operator can review the exact commands first.
    """
    mac = normalize_mac(mac)
    original = current_mac(iface)
    plan = {
        "iface": iface,
        "original": original,
        "target": mac,
        "applied": False,
        "warnings": [],
        "commands": [f"sudo -n ip link set dev {iface} address {mac}"],
    }

    if mac == original:
        raise MacError(f"{iface} already has MAC {mac}")
    if not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", mac):
        raise MacError(f"will not apply malformed MAC {mac!r}")

    if not is_wireless(iface):
        plan["warnings"].append(f"{iface} does not look wireless (MAC changes still work, but check)")
    if iface == default_route_iface() and not force:
        raise MacError(
            f"{iface} carries your current connection — changing its MAC will drop you offline. "
            "Re-run with --force when connected via another path (management port, second link, console)."
        )

    if apply:
        apply_mac(iface, mac)
        if current_mac(iface) != mac:
            raise MacError("MAC write did not stick (interface may reject it)")
        backup_mac(iface, original)
        plan["applied"] = True
    return plan


def restore(iface: str) -> dict:
    """Restore the backed-up original MAC for `iface`."""
    original = read_backup(iface)
    if not original:
        raise MacError(f"no backup found for {iface} — nothing to restore")
    apply_mac(iface, original)
    ok = current_mac(iface) == original
    clear_backup(iface)
    return {"iface": iface, "restored_to": original, "verified": ok}


def watch(target_mac: str, interval: float = 2.0, duration: float = 60.0) -> dict:
    """Poll the neighbor table for a target MAC (paid-device hunt).

    A cloned MAC only inherits a paid session if the *real* device keeps the
    session alive (or expires gracefully) — watching ARP behaviour tells you
    whether the target is present, how long its entries live, and when the
    session binding might be stealable.
    """
    import time

    target = normalize_mac(target_mac)
    events: list[dict] = []
    states_seen: set[str] = set()
    last_state: str | None = None
    started = time.monotonic()
    polls = 0
    while time.monotonic() - started < duration:
        polls += 1
        hits = [n for n in neighbors() if n["mac"] == target]
        if hits:
            hit = hits[0]
            state = hit["state"]
            if state != last_state:
                events.append(
                    {
                        "event": "seen" if last_state is None else "state-change",
                        "state": state,
                        "ip": hit["ip"],
                        "at_round": polls,
                        "elapsed": round(time.monotonic() - started, 2),
                    }
                )
                last_state = state
            states_seen.add(state)
        elif last_state is not None:
            events.append(
                {
                    "event": "disappeared",
                    "at_round": polls,
                    "elapsed": round(time.monotonic() - started, 2),
                }
            )
            last_state = None
        time.sleep(max(0.2, interval))
    return {
        "target": target,
        "polls": polls,
        "seen": last_state is not None,
        "states": sorted(states_seen),
        "events": events,
    }
