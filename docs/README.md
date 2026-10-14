# GhostLink documentation

- [Techniques](#techniques) — how each bypass class works and what to look for
- [Findings](#findings) — durable records from real runs (one file per run)
- [Venue runbook](#venue-runbook) — operating procedure at the event

## Techniques

| Doc | Vector class |
| --- | --- |
| [mac-spoofing.md](techniques/mac-spoofing.md) | Clone a paying device's MAC to inherit its session |
| [walled-garden.md](techniques/walled-garden.md) | Escape via hosts the portal must whitelist pre-auth |
| [dns-and-egress.md](techniques/dns-and-egress.md) | UDP/53 egress, DNS tunneling, TCP egress matrix |
| [other-vectors.md](techniques/other-vectors.md) | IPv6 leak, DHCP fingerprinting, session/token abuse, path divergence |

## Findings

Every `ghostlink all` run writes `ghostlink-report.md` + `.json` at the project
root. Anything worth keeping gets copied into `findings/` with a dated name:

| Finding | Network | Summary |
| --- | --- | --- |
| [2026-10-14-baseline-open-network.md](findings/2026-10-14-baseline-open-network.md) | `wlp0s20f3` (192.168.42.0/24, no portal) | Toolchain validation run: open network, all modules verified |
| [2026-10-14-npm-wrapper-pipeline.md](findings/2026-10-14-npm-wrapper-pipeline.md) | npm publishing | Postmortem: broken PYTHONPATH, name collision, help UX — plus the registry verification protocol |

## Venue runbook

[venue-runbook.md](venue-runbook.md) — the ordered procedure to follow once
connected to the hackathon SSID.
