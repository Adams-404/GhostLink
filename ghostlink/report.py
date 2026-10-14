"""Findings report generation: heuristic analysis + Markdown/JSON output.

Reports are the artifacts that land in docs/findings/ — every run of
`ghostlink all` writes one so there is a durable record for the writeup.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from .config import Target


def generate_findings(results: dict) -> list[dict]:
    """Turn raw sweep results into prioritized findings.

    Severity is only escalated when a portal is actually present — on an open
    network the same observations are informational, not vulnerabilities.
    """
    portal = results.get("recon", {}).get("portal", {})
    portal_present = bool(portal.get("portal"))
    findings: list[dict] = []

    if portal_present:
        findings.append(
            {
                "severity": "info",
                "title": "Captive portal present",
                "detail": f"Splash page at {portal.get('portal_url')}",
            }
        )

    egress = results.get("egress", {})
    for entry in egress.get("dns_leak", {}).get("upstream", []):
        if entry.get("reply"):
            sev = "high" if portal_present else "info"
            findings.append(
                {
                    "severity": sev,
                    "title": f"UDP/53 egress to {entry['server']} before authentication",
                    "detail": "External resolver replied pre-auth — DNS-tunnel (dnscat2/iodine) path available",
                }
            )
        break
    open_ports = egress.get("tcp", {})
    if open_ports:
        summary = {ip: sorted(int(p) for p, st in ports.items() if st == "open") for ip, ports in open_ports.items()}
        summary = {ip: ports for ip, ports in summary.items() if ports}
        if summary:
            sev = "medium" if portal_present else "info"
            findings.append(
                {
                    "severity": sev,
                    "title": "TCP egress reachable before authentication",
                    "detail": f"open ports: {summary}",
                }
            )

    walled = results.get("walled", {})
    reachable = walled.get("reachable", {})
    if portal_present and reachable:
        findings.append(
            {
                "severity": "info",
                "title": f"{len(reachable)} walled-garden host(s) identified",
                "detail": ", ".join(f"{h} (tcp {p})" for h, p in reachable.items()),
            }
        )

    extras = results.get("extras", {})
    if extras.get("ipv6_addresses") and extras.get("ipv6_egress") == "open":
        findings.append(
            {
                "severity": "high",
                "title": "Global IPv6 egress available",
                "detail": "IPv6 path may bypass IPv4-only portal enforcement",
            }
        )
    elif extras.get("ipv6_addresses"):
        findings.append(
            {
                "severity": "info",
                "title": "Global IPv6 addresses assigned",
                "detail": "Check whether the portal enforces policy on the IPv6 path",
            }
        )
    path = extras.get("path", {})
    if path.get("first_hop") and path.get("matches_gateway") is False:
        findings.append(
            {
                "severity": "medium",
                "title": "First egress hop differs from gateway",
                "detail": f"expected {path.get('expected_gateway')}, got {path.get('first_hop')} — likely transparent interception",
            }
        )
    dhcp = extras.get("dhcp", {})
    if dhcp.get("dhcp_hostname"):
        findings.append(
            {
                "severity": "low",
                "title": "DHCP discloses client hostname",
                "detail": f"host_name={dhcp['dhcp_hostname'].strip()!r} — usable for client fingerprinting",
            }
        )

    severity_order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    findings.sort(key=lambda f: severity_order.get(f["severity"], 9))
    return findings


def _portal_section(portal: dict) -> str:
    lines = ["## Portal", ""]
    if portal.get("portal"):
        lines.append(f"- **Captive portal detected:** `{portal.get('portal_url')}`")
    else:
        lines.append("- No captive portal detected (all OS probe endpoints returned expected responses)")
    lines += ["", "| Probe | Result |", "| --- | --- |"]
    for entry in portal.get("probes", []):
        detail = entry.get("location") or entry.get("result", "")
        lines.append(f"| {entry['probe']} | {detail} |")
    return "\n".join(lines)


def _egress_section(egress: dict) -> str:
    lines = ["## Pre-auth egress", ""]
    if egress.get("tcp"):
        ports = sorted({int(p) for ports in egress["tcp"].values() for p in ports})
        lines += ["| Public IP | " + " | ".join(str(p) for p in ports) + " |", "| --- |" + " --- |" * len(ports)]
        for ip, results in sorted(egress["tcp"].items()):
            lines.append(f"| {ip} | " + " | ".join(results.get(str(p), results.get(p, "?")) for p in ports) + " |")
        lines.append("")
    leak = egress.get("dns_leak", {})
    if leak:
        lines += ["### DNS leak test", "", "| Server | Reply pre-auth |", "| --- | --- |"]
        for entry in leak.get("upstream", []):
            lines.append(f"| {entry['server']} | {'YES' if entry.get('reply') else 'no'} |")
        gateway = leak.get("gateway")
        if gateway:
            lines.append(f"| {gateway['server']} (gateway) | {'YES' if gateway.get('reply') else 'no'} |")
    return "\n".join(lines)


def _walled_section(walled: dict) -> str:
    lines = ["## Walled garden", ""]
    if walled.get("portal_url"):
        lines.append(f"- Portal page: `{walled['portal_url']}`")
    for host, ports in walled.get("reachable", {}).items():
        lines.append(f"- `{host}` — tcp {', '.join(map(str, ports))}")
    if not walled.get("reachable"):
        lines.append("- No candidate hosts reachable pre-auth.")
    return "\n".join(lines)


def _extras_section(extras: dict) -> str:
    lines = ["## Other observations", ""]
    v6 = extras.get("ipv6_addresses") or []
    lines.append(f"- Global IPv6 addresses: {len(v6)} (egress: {extras.get('ipv6_egress', 'n/a')})")
    path = extras.get("path", {})
    if path.get("first_hop"):
        lines.append(f"- First hop {path['first_hop']} vs gateway {path.get('expected_gateway')}")
    dhcp = extras.get("dhcp", {})
    if dhcp.get("dhcp_hostname"):
        lines.append(f"- DHCP hostname disclosed: `{dhcp['dhcp_hostname'].strip()}`")
    return "\n".join(lines)


def render_markdown(target: Target, results: dict) -> str:
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    findings = generate_findings(results)
    lines = [
        f"# GhostLink report — {generated}",
        "",
        f"- Target link: `{target.iface}` ({target.cidr}), gateway `{target.gateway}`, resolvers {', '.join(target.resolvers) or 'none'}",
        f"- MAC under test: `{target.mac}`",
        "",
        _portal_section(results.get("recon", {}).get("portal", {})),
        "",
        _egress_section(results.get("egress", {})),
        "",
        _walled_section(results.get("walled", {})),
        "",
        _extras_section(results.get("extras", {})),
        "",
        "## Findings",
        "",
        "| Severity | Finding | Detail |",
        "| --- | --- | --- |",
    ]
    for finding in findings:
        detail = str(finding["detail"]).replace("|", "\\|")
        lines.append(f"| {finding['severity'].upper()} | {finding['title']} | {detail} |")
    lines += ["", f"_Generated by GhostLink._", ""]
    return "\n".join(lines)


def write(out_base: str, target: Target, results: dict) -> tuple[str, str]:
    """Write `<out_base>.md` and `<out_base>.json`; returns both paths."""
    md_path = str(Path(out_base).with_suffix(".md"))
    json_path = str(Path(out_base).with_suffix(".json"))
    Path(md_path).write_text(render_markdown(target, results), encoding="utf-8")
    Path(json_path).write_text(json.dumps({"results": results, "findings": generate_findings(results)}, indent=2), encoding="utf-8")
    return md_path, json_path


def render_from_json(json_path: str, out_md: str) -> str:
    data = json.loads(Path(json_path).read_text(encoding="utf-8"))
    results = data["results"]

    class _StubTarget:
        pass

    target = _StubTarget()
    for key, value in results.get("recon", {}).get("target", {}).items():
        setattr(target, key, value)
    for prop in ("iface", "address", "prefix", "gateway", "resolvers", "mac", "network"):
        if not hasattr(target, prop):
            setattr(target, prop, "?")
    markdown = render_markdown(target, results)
    Path(out_md).write_text(markdown, encoding="utf-8")
    return out_md
