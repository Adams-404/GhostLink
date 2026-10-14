"""Minimal DNS wire-format helpers: build a query, parse a response header.

Deliberately tiny — enough to fingerprint whether DNS egress works, without
pulling in a full resolver library. Pure functions, unit-tested.
"""

from __future__ import annotations

import struct

QTYPE_A = 1
QCLASS_IN = 1


def build_query(qname: str, qid: int = 0x1234, rd: bool = True) -> bytes:
    """Build a DNS query for `qname` (type A, class IN)."""
    header = struct.pack(">HHHHHH", qid, 0x0100 if rd else 0x0000, 1, 0, 0, 0)
    question = b"".join(
        bytes([len(label)]) + label.encode("ascii", errors="strict")
        for label in qname.strip(".").split(".")
    )
    question += b"\x00" + struct.pack(">HH", QTYPE_A, QCLASS_IN)
    return header + question


def parse_header(resp: bytes) -> dict:
    """Parse the first 12 bytes of a DNS message into its fields."""
    if len(resp) < 12:
        raise ValueError(f"DNS response too short: {len(resp)} bytes")
    qid, flags, qdcount, ancount, nscount, arcount = struct.unpack(">HHHHHH", resp[:12])
    return {
        "id": qid,
        "flags": flags,
        "rd": bool(flags & 0x0100),
        "ra": bool(flags & 0x0080),
        "rcode": flags & 0x000F,
        "qdcount": qdcount,
        "ancount": ancount,
        "nscount": nscount,
        "arcount": arcount,
    }
