# GhostLink

**CLI toolkit for captive-portal paywall analysis** — MAC/session binding,
walled-garden leakage, pre-auth egress, and DNS tunneling — built for
**authorized security research** (vendor-hosted hackathons, lab replicas,
networks you own).

> **Scope & ethics.** GhostLink is a research instrument. Use it only on
> networks you own or are explicitly authorized to test (e.g. a hackathon's
> designated test SSID). See [docs/venue-runbook.md](docs/venue-runbook.md)
> for the operating procedure and guardrails.

## Install

### npm (wrapper, Linux)

```bash
npm install -g ghostlink
ghostlink recon --no-color
```

This ships the same stdlib-only Python CLI in a Node wrapper — at runtime it
needs **Python 3.10+** and **iproute2** (`ip -j`) on the box. The wrapper
locates `python3` (override with `GHOSTLINK_PYTHON`), checks the version, and
execs `python -m ghostlink`.

### from source

```bash
git clone https://github.com/Adams-404/GhostLink.git && cd GhostLink
python -m unittest discover -s tests     # 27 tests, no network needed
python -m venv .venv && . .venv/bin/activate && pip install -e .
ghostlink --help
```

Requires Python ≥ 3.10 and iproute2 (`ip`). Everything else is stdlib.
Actual MAC changes need `sudo -n` (non-interactive) — nothing is ever changed
without `--apply`.

## Quickstart

```bash
# 1. who am I on, and is there a portal?
python -m ghostlink recon --no-color

# 2. everything at once + a findings report (ghostlink-report.md/.json)
python -m ghostlink all --no-color --timeout 2.0

# 3. the MAC toolkit
python -m ghostlink mac neighbors          # ARP table — paid-device candidates
python -m ghostlink mac watch aa:bb:cc:dd:ee:ff --duration 300
python -m ghostlink mac gen --vendor apple --count 5
python -m ghostlink mac spoof f0:18:98:2a:07:06            # dry-run
python -m ghostlink mac spoof f0:18:98:2a:07:06 --apply --force
python -m ghostlink mac restore

# 4. the wall
python -m ghostlink egress --no-color
python -m ghostlink walled --portal-url http://portal/login --no-color

# 5. extras: IPv6 leak, path divergence, DHCP fingerprint
python -m ghostlink extras --no-color
```

All commands accept `--json` for machine-readable output and `--iface` to
override the auto-detected interface.

## Commands

| Command | Purpose |
| --- | --- |
| `recon` | iface/gateway/resolver discovery + captive-portal detection via OS probe URLs |
| `egress` | pre-auth TCP/UDP/ICMP egress matrix + DNS leak test (gateway vs. upstream) |
| `walled` | portal splash-page dissection + walled-garden reachability matrix |
| `extras` | IPv6 leak, traceroute/gateway divergence, DHCP hostname disclosure |
| `mac` | `list` / `neighbors` / `gen` / `spoof` / `restore` / `watch` |
| `report` | render markdown from a saved run's JSON |
| `all` | full sweep + findings report with severity heuristics |

## How the analysis maps to the target architecture

Paid-WiFi gateways enforce the paywall with three components: a **redirect
splash page**, a **firewall rule set** (walled garden), and a **session state
machine** keyed to the client (usually MAC). GhostLink maps one module onto
each:

- `recon` → detects the splash-page interception
- `egress` + `walled` → characterizes the firewall and its leaks
- `mac` + `extras` → probes the session/identity layer
- `report` + `docs/findings/` → durable evidence for the vendor writeup

See [docs/README.md](docs/README.md) for per-technique deep dives and the
venue runbook.

## Layout

```
ghostlink/          CLI + modules (config, recon, egress, walledgarden, mac, extras, report, dnswire)
tests/              stdlib unittest suite (27 tests, offline)
docs/               index, techniques/, findings/, venue-runbook.md
npm/                npm wrapper (bin shim + package.json; sync-python.sh bundles the Python code at pack time)
```

## Tech notes

- Pure stdlib; iproute2 JSON (`ip -j`) for link/neighbor/recon facts.
- `sudo -n` for privileged MAC changes — fails loudly instead of hanging.
- Every `all` run emits a markdown + JSON findings report.
- Severity escalation in `report.py` only fires when a portal is actually
  present, so open-network runs stay informational.
