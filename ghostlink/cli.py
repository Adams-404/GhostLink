"""GhostLink command-line interface.

Usage: ghostlink [--iface IFACE] [--no-color] [--json] <command> [options]
Run `ghostlink <command> -h` for per-command options.
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
    args_json_target = _target(args)
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
    del args_json_target
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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ghostlink",
        description="Captive-portal paywall analysis toolkit — for authorized security research only.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--iface", help="interface to analyse (default: default-route interface)")
    parser.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")

    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("recon", help="link/gateway/resolver discovery + captive-portal detection")
    p.add_argument("--timeout", type=float, default=4.0)
    p.set_defaults(func=cmd_recon)

    p = sub.add_parser("egress", help="pre-auth TCP/UDP/ICMP egress matrix + DNS leak test")
    p.add_argument("--timeout", type=float, default=3.0)
    p.add_argument("--concurrency", type=int, default=32)
    p.set_defaults(func=cmd_egress)

    p = sub.add_parser("walled", help="portal page dissection + walled-garden reachability")
    p.add_argument("--portal-url", default=None, help="portal splash page URL (auto-detected if omitted)")
    p.add_argument("--timeout", type=float, default=3.0)
    p.add_argument("--concurrency", type=int, default=24)
    p.add_argument("--candidates", type=int, default=wallgarden_default_candidates(), help="max hosts parsed from the portal page")
    p.set_defaults(func=cmd_walled)

    p = sub.add_parser("extras", help="IPv6 leak, path divergence, DHCP disclosure")
    p.add_argument("--timeout", type=float, default=3.0)
    p.set_defaults(func=cmd_extras)

    p = sub.add_parser("report", help="render markdown from a saved run JSON")
    p.add_argument("--input", default="ghostlink-report.json")
    p.add_argument("--out", default="ghostlink-report.md")
    p.set_defaults(func=cmd_report)

    return parser


def wallgarden_default_candidates() -> int:
    return walledgarden._MAX_CANDIDATES


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
