"""Identity enrichment: friendly names, device types, OUI vendor hints,
randomized-MAC detection, and best-effort hostname resolution.

Every probe here degrades silently to None — enrichment must never break the
core sweeps. Vendor attribution is a *hint*, not ground truth: modern phones
and laptops randomize their MACs (the tool flags those explicitly, since a
randomized MAC is also a much weaker session-identity to inherit).
"""

from __future__ import annotations

import ipaddress
import os
import re
import socket
import struct
import time
from concurrent.futures import ThreadPoolExecutor

from .dnswire import build_query

QTYPE_PTR = 12
QTYPE_A = 1

_MAC_RE = re.compile(
    r"^([0-9a-fA-F]{2})[:-]([0-9a-fA-F]{2})[:-]([0-9a-fA-F]{2})[:-]"
    r"([0-9a-fA-F]{2})[:-]([0-9a-fA-F]{2})[:-]([0-9a-fA-F]{2})$"
)

# Heuristic table of common consumer OUIs — extend as observations pile up.
# Keys are lowercase 3-octet prefixes.
OUI_TABLE: dict[str, str] = {
    # Apple
    "f0:18:98": "Apple", "dc:a6:32": "Apple", "a4:83:e7": "Apple",
    "3c:2e:f5": "Apple", "88:66:39": "Apple", "8c:85:90": "Apple",
    # Samsung
    "34:23:87": "Samsung", "8c:77:12": "Samsung", "5c:0a:5b": "Samsung",
    "78:47:3d": "Samsung", "c8:19:f7": "Samsung",
    # Xiaomi / Redmi / POCO
    "64:09:80": "Xiaomi", "28:6c:07": "Xiaomi", "9c:5a:44": "Xiaomi",
    "f8:a2:d6": "Xiaomi", "50:8f:4c": "Xiaomi",
    # Huawei / Honor
    "48:46:fb": "Huawei", "00:e0:fc": "Huawei", "4c:50:f9": "Huawei",
    "ac:e2:15": "Huawei",
    # Google / Nest
    "3c:5a:b4": "Google", "f4:f5:d8": "Google", "1c:f2:9a": "Google",
    # Intel
    "8c:70:5a": "Intel", "3c:58:c2": "Intel", "94:65:9c": "Intel",
    "7c:b2:7b": "Intel",
    # ESPRESSIF IoT (ESP8266/ESP32) — the classic cloned-device class
    "24:0a:c4": "Espressif", "30:ae:a4": "Espressif", "a4:cf:12": "Espressif",
    "8c:aa:b5": "Espressif",
    # Raspberry Pi
    "b8:27:eb": "Raspberry Pi", "dc:a6:32": "Raspberry Pi", "e4:5f:01": "Raspberry Pi",
    # Network gear
    "50:c7:bf": "TP-Link", "14:cc:20": "TP-Link", "a4:2b:b0": "TP-Link",
    "9c:8e:cd": "Netgear", "f0:9f:c2": "Ubiquiti", "78:8a:20": "Ubiquiti",
}

IFACE_TYPES = [
    (re.compile(r"^lo$"), "loopback"),
    (re.compile(r"^(wl[a-z]|wifi)"), "wifi"),
    (re.compile(r"^(br-|docker|virbr)"), "bridge"),
    (re.compile(r"^(veth|tap|tun|vpn)"), "virtual"),
    (re.compile(r"^en[a-z]"), "ethernet"),
    (re.compile(r"^(wwan|usb)"), "cellular"),
]


class IdentityError(ValueError):
    pass


def normalize_mac(mac: str) -> str:
    match = _MAC_RE.match(mac.strip())
    if not match:
        raise IdentityError(f"invalid MAC: {mac!r}")
    return ":".join(g.lower() for g in match.groups())


def is_randomized(mac: str) -> bool:
    """True when the locally-administered (U/L) bit is set — typical of MAC
    randomization, and a strong hint the identity is NOT a stable session key."""
    return bool(int(normalize_mac(mac).split(":")[0], 16) & 0b10)


def lookup_vendor(mac: str) -> str:
    try:
        return OUI_TABLE.get(normalize_mac(mac)[:8], "")
    except IdentityError:
        return ""


def friendly_iface_type(name: str, wireless: bool = False) -> str:
    if wireless:
        return "wifi"
    for pattern, label in IFACE_TYPES:
        if pattern.match(name):
            return label
    return "other"


def iface_driver(name: str) -> str | None:
    """Kernel driver name from sysfs, when the interface has one."""
    link = f"/sys/class/net/{name}/device/driver"
    try:
        return os.path.basename(os.readlink(link))
    except OSError:
        return None


# ---------------------------------------------------------------------------
# Hostname resolution: reverse PTR, mDNS (Apple/Linux/Android), NetBIOS (Windows)
# ---------------------------------------------------------------------------


def reverse_ptr(ip: str, timeout: float = 2.0) -> str | None:
    try:
        socket.setdefaulttimeout(timeout)
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return None


def decode_name(data: bytes, offset: int) -> tuple[str | None, int]:
    """Decode a DNS label sequence, following compression pointers."""
    labels: list[bytes] = []
    pos = offset
    next_offset = offset
    jumped = False
    seen: set[int] = set()
    while pos < len(data):
        length = data[pos]
        if length == 0:
            pos += 1
            if not jumped:
                next_offset = pos
            break
        if length & 0xC0 == 0xC0:
            pointer = struct.unpack(">H", data[pos : pos + 2])[0] & 0x3FFF
            if not jumped:
                next_offset = pos + 2
                jumped = True
            if pointer in seen or pointer >= len(data):
                break
            seen.add(pointer)
            pos = pointer
            continue
        pos += 1
        labels.append(data[pos : pos + length])
        pos += length
    name = ".".join(part.decode("ascii", errors="replace") for part in labels)
    return (name or None), next_offset


def extract_ptr_from_mdns(data: bytes) -> str | None:
    """Pull the first PTR answer out of an mDNS response packet."""
    try:
        if len(data) < 12:
            return None
        qdcount, ancount = struct.unpack(">HH", data[4:8])
        offset = 12
        for _ in range(qdcount):
            _, offset = decode_name(data, offset)
            offset += 4  # qtype + qclass
        for _ in range(ancount):
            if offset >= len(data):
                return None
            _, offset = decode_name(data, offset)
            rtype, _rclass, _ttl, rdlen = struct.unpack(">HHIH", data[offset : offset + 10])
            rdata_start = offset + 10
            rdata = data[rdata_start : rdata_start + rdlen]
            offset = rdata_start + rdlen
            if rtype == QTYPE_PTR and rdata:
                name, _ = decode_name(data, rdata_start)
                return name
    except (struct.error, IndexError):
        return None
    return None


def mdns_ptr(ip: str, timeout: float = 1.5) -> str | None:
    """Query the mDNS multicast group for this IP's PTR (Apple/Linux/Android)."""
    name = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
    query = build_query(name, qid=0x6D64, rd=False, qtype=QTYPE_PTR)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
            except OSError:
                pass
            sock.sendto(query, ("224.0.0.251", 5353))
            deadline = time.monotonic() + timeout
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return None
                sock.settimeout(remaining)
                try:
                    data, _addr = sock.recvfrom(2048)
                except socket.timeout:
                    return None
                name_found = extract_ptr_from_mdns(data)
                if name_found:
                    return name_found
    except OSError:
        return None


def _encode_nbname(name: str) -> bytes:
    padded = name.ljust(15)[:15].encode("ascii", errors="replace") + b"\x00"
    encoded = bytearray()
    for byte in padded:
        encoded.append((byte >> 4) + ord("A"))
        encoded.append((byte & 0x0F) + ord("A"))
    return bytes([len(encoded)]) + bytes(encoded)


def parse_nbstat_response(data: bytes) -> list[str]:
    """Parse NetBIOS NBSTAT reply into ['NAME (nb:type)', ...]."""
    try:
        if len(data) < 12:
            return []
        qdcount, ancount = struct.unpack(">HH", data[4:8])
        offset = 12
        if qdcount:
            offset += 33 + 4  # encoded '*'-name + qtype/qclass
        if ancount < 1 or offset + 10 > len(data):
            return []
        if data[offset] & 0xC0 == 0xC0:
            offset += 2
        else:
            offset += 33
        rtype, _rclass, _ttl, rdlen = struct.unpack(">HHIH", data[offset : offset + 10])
        rdata_start = offset + 10
        rdata = data[rdata_start : rdata_start + rdlen]
        if rtype != 0x21 or not rdata:
            return []
        count = rdata[0]
        names = []
        pos = 1
        for _ in range(count):
            chunk = rdata[pos : pos + 18]
            if len(chunk) < 18:
                break
            raw = chunk[:15].decode("ascii", errors="replace").strip()
            nbtype = chunk[15]
            if raw:
                names.append(f"{raw} (nb:{nbtype:#04x})")
            pos += 18
        return names
    except (struct.error, IndexError):
        return []


def netbios_name(ip: str, timeout: float = 1.0) -> list[str]:
    """NetBIOS name query (Windows hosts) — returns registered names."""
    query = struct.pack(">HHHHHH", 0x1337, 0x0000, 1, 0, 0, 0) + _encode_nbname("*") + struct.pack(">HH", 0x21, 1)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(query, (ip, 137))
            data, _addr = sock.recvfrom(2048)
        return parse_nbstat_response(data)
    except (OSError, socket.timeout):
        return []


def hostname_for(ip: str, timeout: float = 2.0) -> dict:
    """Best-effort naming for an IP: {'name': str|None, 'source': str, 'ptr':..., 'mdns':..., 'netbios':[...]}"""
    result: dict = {"name": None, "source": None, "ptr": None, "mdns": None, "netbios": []}
    mdns = mdns_ptr(ip, timeout=min(timeout, 1.5))
    if mdns:
        result["mdns"] = mdns
    ptr = reverse_ptr(ip, timeout=timeout)
    if ptr:
        result["ptr"] = ptr
    names = netbios_name(ip, timeout=min(timeout, 1.0))
    result["netbios"] = names
    if mdns:
        result.update(name=mdns, source="mDNS")
    elif ptr and not ptr.startswith(ip):
        result.update(name=ptr, source="PTR")
    elif names:
        result.update(name=names[0], source="NetBIOS")
    return result


def enrich_neighbors(entries: list[dict], concurrency: int = 16, timeout: float = 2.0) -> list[dict]:
    """Add vendor / randomized / name fields to neighbor-table entries."""
    enriched = []
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        name_futures = {
            entry["ip"]: pool.submit(hostname_for, entry["ip"], timeout) for entry in entries
        }
        for entry in entries:
            item = dict(entry)
            mac = entry.get("mac", "")
            item["vendor"] = lookup_vendor(mac) if mac and mac != "incomplete" else ""
            try:
                item["randomized"] = is_randomized(mac) if mac and mac != "incomplete" else False
            except IdentityError:
                item["randomized"] = False
            naming = name_futures[entry["ip"]].result()
            item["name"] = naming["name"]
            item["name_source"] = naming["source"]
            item["naming"] = naming
            enriched.append(item)
    return enriched


def enrich_interfaces(entries: list[dict]) -> list[dict]:
    """Add type / driver / vendor fields to interface entries."""
    for entry in entries:
        entry["type"] = friendly_iface_type(entry.get("name", ""), bool(entry.get("wireless")))
        entry["driver"] = iface_driver(entry.get("name", ""))
        entry["vendor"] = lookup_vendor(entry.get("mac", ""))
        try:
            entry["randomized"] = is_randomized(entry.get("mac", ""))
        except IdentityError:
            entry["randomized"] = False
    return entries


def sweep_hosts(network: str, ports: tuple[int, ...] = (80, 443, 22, 445), concurrency: int = 64, timeout: float = 0.7) -> dict:
    """Touch every host in a /24-on-smaller subnet to populate the ARP cache;
    returns live hosts. No root needed — plain TCP connects make the kernel
    resolve ARP for us."""
    from .egress import tcp_probe

    net = ipaddress.ip_network(network, strict=False)
    hosts = [str(host) for host in net.hosts()]
    if len(hosts) > 1022:
        hosts = hosts[:1022]

    def probe_ip(ip: str) -> tuple[str, list[int]]:
        open_ports = []
        for port in ports:
            try:
                if tcp_probe(ip, port, timeout) == "open":
                    open_ports.append(port)
            except Exception:  # noqa: BLE001 - per-probe failures are noise
                continue
        return ip, open_ports

    live: dict[str, list[int]] = {}
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        for ip, open_ports in pool.map(probe_ip, hosts):
            if open_ports:
                live[ip] = open_ports
    return {"network": str(net), "probed": len(hosts), "live": dict(sorted(live.items()))}
