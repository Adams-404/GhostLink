"""Pre-auth egress probing: which traffic still leaves the network before
you have paid (i.e. what the captive-portal firewall lets through)."""

from __future__ import annotations

import concurrent.futures
import socket
import subprocess

from .config import Target
from .dnswire import build_query, parse_header

# Ports worth probing pre-auth: DNS, VPNs, and classic tunnel ports.
TCP_PORTS = [53, 80, 123, 443, 500, 1194, 4500, 8443]
PUBLIC_IPS = ["1.1.1.1", "8.8.8.8"]


def tcp_probe(ip: str, port: int, timeout: float = 3.0) -> str:
    """Classify a TCP port on a public host: open / closed (refused) / filtered."""
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return "open"
    except ConnectionRefusedError:
        return "closed"
    except (socket.timeout, OSError) as exc:
        if isinstance(exc, TimeoutError):
            return "filtered"
        return f"error:{type(exc).__name__}"


def tcp_matrix(concurrency: int = 32, timeout: float = 3.0) -> dict[str, dict[int, str]]:
    jobs = [(ip, port) for ip in PUBLIC_IPS for port in TCP_PORTS]
    results: dict[str, dict[int, str]] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = {pool.submit(tcp_probe, ip, port, timeout): (ip, port) for ip, port in jobs}
        for fut in concurrent.futures.as_completed(futures):
            ip, port = futures[fut]
            results.setdefault(ip, {})[port] = fut.result()
    return results
