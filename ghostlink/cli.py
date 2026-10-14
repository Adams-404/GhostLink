"""GhostLink command-line interface.

Usage: ghostlink <command> [options]
Shared options (--iface, --no-color, --json) go after the subcommand:
    ghostlink recon --iface wlp0s20f3 --no-color --json
"""

from __future__ import annotations

import argparse
import json
import sys

from . import __version__, egress, extras, mac as macmod, recon, report, walledgarden
from .config import detect_target
from .output import Console


def _target(args) -> object:
    return detect_target(args.iface)


def cmd_recon(args, console: Console) -> int:
    target = _target(args)
    data = recon.run(target, timeout=args.timeout)
    if args.json:
        print(json.dumps(data, indent=2))
        return 0
    recon.render(target, data, console)
    return 0


def cmd_egress(args, console: Console) -> int:
    target = _target(args)
    data = egress.run(target, concurrency=args.concurrency, timeout=args.timeout)
    if args.json:
        print(json.dumps(data, indent=2))
        return 0
    egress.render(target, data, console)
    return 0


def cmd_walled(args, console: Console) -> int:
    data = walledgarden.run(
        portal_url=args.portal_url,
        concurrency=args.concurrency,
        timeout=args.timeout,
        candidate_limit=args.candidates,
    )
    if args.json:
        print(json.dumps(data, indent=2))
        return 0
    walledgarden.render(data, console)
    return 0


def cmd_extras(args, console: Console) -> int:
    target = _target(args)
    data = extras.run(target, timeout=args.timeout)
    if args.json:
        print(json.dumps(data, indent=2))
        return 0
    extras.render(target, data, console)
    return 0


def cmd_report(args, console: Console) -> int:
    out = report.render_from_json(args.input, args.out)
    console.ok(f"report written from {args.input} -> {out}")
    return 0


def cmd_mac_list(args, console: Console) -> int:
    interfaces = macmod.list_interfaces()
    if args.json:
        print(json.dumps(interfaces, indent=2))
        return 0
    console.section("Interfaces")
    console.table(
        [[i["name"], i["mac"], i["state"], "yes" if i["wireless"] else "no"] for i in interfaces],
        ["Interface", "MAC", "State", "WiFi"],
    )
    return 0


def cmd_mac_neighbors(args, console: Console) -> int:
    entries = macmod.neighbors()
    if args.json:
        print(json.dumps(entries, indent=2))
        return 0
    console.section("Neighbor table")
    console.table(
        [[e["ip"], e["mac"], e["state"], e["dev"]] for e in entries],
        ["IP", "MAC", "State", "Iface"],
    )
    counts = macmod.neighbor_counts()
    console.info(f"states: {counts}")
    return 0


def cmd_mac_gen(args, console: Console) -> int:
    macs = [macmod.random_mac(local=not args.universal, vendor=args.vendor) for _ in range(args.count)]
    if args.json:
        print(json.dumps(macs, indent=2))
        return 0
    console.section(f"Generated {len(macs)} MAC(s)")
    for mac in macs:
        locale = "local" if macmod.is_locally_administered(mac) else "universal"
        console.info(f"{mac}  ({locale})")
    return 0


def cmd_mac_spoof(args, console: Console) -> int:
    target = _target(args)
    iface = args.iface or target.iface
    mac = args.mac if args.mac and args.mac != "random" else macmod.random_mac(vendor=args.vendor)
    if not args.apply:
        console.info("dry-run — pass --apply to execute (uses sudo -n, non-interactive)")
    try:
        plan = macmod.spoof(iface, mac, apply=args.apply, force=args.force)
    except Exception as exc:  # noqa: BLE001 - surface refusal cleanly
        console.fail(f"spoof refused: {exc}")
        return 2
    console.kv("Interface", plan["iface"])
    console.kv("Original MAC", plan["original"])
    console.kv("Target MAC", plan["target"])
    console.kv("Applied", "yes" if plan["applied"] else "no (dry-run)")
    for warning in plan["warnings"]:
        console.warn(warning)
    for command in plan["commands"]:
        console.info(f"command: {command}")
    return 0


def cmd_mac_restore(args, console: Console) -> int:
    target = _target(args)
    iface = args.iface or target.iface
    result = macmod.restore(iface)
    console.ok(f"restored {result['iface']} to {result['restored_to']} (verified={result['verified']})")
    return 0


def cmd_mac_watch(args, console: Console) -> int:
    console.section(f"Watching for {args.mac} ({args.duration}s @ {args.interval}s)")
    result = macmod.watch(args.mac, interval=args.interval, duration=args.duration)
    if args.json:
        print(json.dumps(result, indent=2))
        return 0
    if result["seen"]:
        console.fail(f"target MAC seen — states observed: {result['states']}")
    else:
        console.ok("target MAC never appeared in the neighbor table")
    for event in result["events"]:
        console.info(f"  {event}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    # Shared flags live on a parent parser so they can appear after any
    # subcommand (ghostlink recon --json) — the least surprising placement.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--iface", help="interface to analyse (default: default-route interface)")
    common.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    common.add_argument("--json", action="store_true", help="emit machine-readable JSON")

    parser = argparse.ArgumentParser(
        prog="ghostlink",
        description="Captive-portal paywall analysis toolkit — for authorized security research only.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("recon", parents=[common], help="link/gateway/resolver discovery + captive-portal detection")
    p.add_argument("--timeout", type=float, default=4.0)
    p.set_defaults(func=cmd_recon)

    p = sub.add_parser("egress", parents=[common], help="pre-auth TCP/UDP/ICMP egress matrix + DNS leak test")
    p.add_argument("--timeout", type=float, default=3.0)
    p.add_argument("--concurrency", type=int, default=32)
    p.set_defaults(func=cmd_egress)

    p = sub.add_parser("walled", parents=[common], help="portal page dissection + walled-garden reachability")
    p.add_argument("--portal-url", default=None, help="portal splash page URL (auto-detected if omitted)")
    p.add_argument("--timeout", type=float, default=3.0)
    p.add_argument("--concurrency", type=int, default=24)
    p.add_argument("--candidates", type=int, default=walledgarden._MAX_CANDIDATES, help="max hosts parsed from the portal page")
    p.set_defaults(func=cmd_walled)

    p = sub.add_parser("extras", parents=[common], help="IPv6 leak, path divergence, DHCP disclosure")
    p.add_argument("--timeout", type=float, default=3.0)
    p.set_defaults(func=cmd_extras)

    p = sub.add_parser("report", parents=[common], help="render markdown from a saved run JSON")
    p.add_argument("--input", default="ghostlink-report.json")
    p.add_argument("--out", default="ghostlink-report.md")
    p.set_defaults(func=cmd_report)

    m = sub.add_parser("mac", help="MAC inventory, generation, spoofing, neighbor watch")
    msub = m.add_subparsers(dest="mac_command", required=True)

    p = msub.add_parser("list", parents=[common], help="interfaces and current MACs")
    p.set_defaults(func=cmd_mac_list)

    p = msub.add_parser("neighbors", parents=[common], help="ARP/neighbor table (paid-device candidates)")
    p.set_defaults(func=cmd_mac_neighbors)

    p = msub.add_parser("gen", parents=[common], help="generate spoofable MACs")
    p.add_argument("--vendor", choices=sorted(macmod.VENDOR_OUI), help="prefix a consumer OUI (realistic impersonation)")
    p.add_argument("--universal", action="store_true", help="generate universally-administered instead of locally-administered")
    p.add_argument("--count", type=int, default=5)
    p.set_defaults(func=cmd_mac_gen)

    p = msub.add_parser("spoof", parents=[common], help="change this interface's MAC (dry-run by default)")
    p.add_argument("mac", nargs="?", help="MAC to apply, or 'random'")
    p.add_argument("--vendor", choices=sorted(macmod.VENDOR_OUI), help="when generating: prefix a consumer OUI")
    p.add_argument("--apply", action="store_true", help="execute via sudo -n (default: dry-run)")
    p.add_argument("--force", action="store_true", help="allow spoofing the interface carrying your current connection")
    p.set_defaults(func=cmd_mac_spoof)

    p = msub.add_parser("restore", parents=[common], help="restore the backed-up original MAC")
    p.set_defaults(func=cmd_mac_restore)

    p = msub.add_parser("watch", parents=[common], help="poll the neighbor table for a target MAC")
    p.add_argument("mac", help="MAC to look for (e.g. a paying device you want to clone)")
    p.add_argument("--interval", type=float, default=2.0)
    p.add_argument("--duration", type=float, default=60.0)
    p.set_defaults(func=cmd_mac_watch)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    console = Console(color=not args.no_color)
    try:
        return int(args.func(args, console))
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130
    except Exception as exc:  # noqa: BLE001 - CLI boundary: print, don't traceback
        console.fail(f"{type(exc).__name__}: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
