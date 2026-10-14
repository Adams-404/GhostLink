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
