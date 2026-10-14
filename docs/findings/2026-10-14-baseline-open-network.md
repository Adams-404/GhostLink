# Finding 2026-10-14 — baseline run on open network (no portal)

- **Date:** 2026-10-14
- **Operator:** GhostLink CLI v0.1.0 (`python -m ghostlink all`)
- **Link under test:** `wlp0s20f3` — `192.168.42.28/24`, gateway `192.168.42.1`,
  resolvers `127.0.0.53` (systemd-resolved stub)
- **MAC under test:** `62:0e:4b:81:a9:e8`
- **Purpose:** validate the whole GhostLink pipeline end-to-end on an open
  network before the venue run, and record the "normal internet" baseline that
  the venue results get diffed against.

## Portal detection

All four OS probe endpoints returned their expected bodies (apple `Success`,
firefox `success`, google `204`, msft `Microsoft Connect Test`) →
**no captive portal on this link.**

| Probe | Result |
| --- | --- |
| apple | direct |
| firefox | direct |
| google | direct (204) |
| msft | direct |

## Pre-auth egress matrix

| Public IP | 53 | 80 | 123 | 443 | 500 | 1194 | 4500 | 8443 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1.1.1.1 | open | open | filtered | open | filtered | filtered | filtered | open |
| 8.8.8.8 | open | filtered | filtered | open | filtered | filtered | filtered | filtered |

DNS leak test: gateway `192.168.42.1`, `1.1.1.1`, and `8.8.8.8` all answered
UDP/53 queries. ICMP to 1.1.1.1 reachable.

## Walled-garden probes (seeded candidates)

All 14 seeded candidates reachable on TCP/80 and/or TCP/443 — payment vendors,
portal software, connectivity probes, and public DNS. On an open network this
is expected; the value of the run is that the probe machinery and the
reporting path are proven.

## Other observations

- Global IPv6: none (no egress path to test).
- First hop `192.168.42.1` = configured gateway → no transparent interception
  from this host.
- DHCP discloses hostname `fedora`.

## GhostLink findings (severity is informational without a portal)

| Severity | Finding | Detail |
| --- | --- | --- |
| LOW | DHCP discloses client hostname | `host_name='fedora'` — client fingerprinting potential |
| INFO | UDP/53 egress to 1.1.1.1 pre-auth | DNS-tunnel path (irrelevant on an open LAN, expected) |
| INFO | TCP egress pre-auth | 53/80/443/8443 open to 1.1.1.1 |

## Takeaways for the venue run

1. Every module ran green — the tool can be used as-is at the hackathon.
2. This file is the **diff baseline**: at the venue, anything that changes
   (a portal appearing, UDP/53 going dark, extra in-subnet hops) is signal
   about how the paywall implements its wall.
3. Next finding file to create at the venue:
   `docs/findings/2026-10-XX-venue-<ssid>.md` (template in the runbook).
