# Technique: walled-garden escape

## Why it works

A paywall cannot block *everything* before payment: the client must at minimum
reach

- the **splash page** itself (and its CDN/API),
- the **payment processor** (Stripe/PayPal domains — on the reference
  implementation of portals like SpotPass's you typically see `js.stripe.com`,
  `api.stripe.com`, `q.stripe.com`),
- the OS **connectivity probes** that keep captive-portal popups honest.

Every one of those whitelisted hosts is inside the "walled garden", and any of
them can become a relay: most CDNs and payment frontends proxy arbitrary
traffic under a whitelisted hostname, and several walled-garden members speak
non-HTTP protocols (NTP, STUN, DNS, CDN mirrors) that nobody deep-inspects.

## Procedure

```bash
# 1. detect the portal and (if needed) feed the splash page explicitly
ghostlink recon --json          # portal + portal_url land here

# 2. dissect the splash page: every external host it references
ghostlink walled --portal-url "<portal_url_from_recon>" --no-color

# 3. compare against the seeded baseline set
#    (connectivity probes, DNS, payment vendors, portal software)
ghostlink walled --no-color
```

Typical output at the venue (hypothetical):

```
[*] 6 host(s) referenced by portal page
[x] 6 host(s) reachable pre-auth:
[*]   portal.spotpass.local                    ports [80]
[*]   js.stripe.com                            ports [443]
[*]   api.stripe.com                           ports [443]
[*]   q.stripe.com                             ports [443]
[*]   cdn.portalvendor.net                     ports [443, 80]
[*]   connectivitycheck.gstatic.com            ports [443, 80]
```

## What each member buys you

| Member | Escape potential |
| --- | --- |
| Stripe / PayPal hosts | Weak directly, but their inclusion proves the firewall is hostname-keyed; some CDNs in front of them host user content that can be abused as a proxy |
| OS probe hosts | Low — but they reveal that plain TCP/80 egress to those IPs is open pre-auth |
| Portal CDN (`cdn.portalvendor.net`) | **High** — general-purpose CDNs proxying arbitrary paths/config files can relay traffic; large CDNs also host Angry IP Scanner–style tunnelling services |
| Internal portal IPs (`10.x`/`192.168.x`) | **High** — management/API ports, admin panels, and sometimes the RADIUS/voucher backend itself |

## Procedure when a CDN member shows up

1. Resolve it pre-auth; note which IP range it is on.
2. Test whether non-HTTP protocols to it pass (`nc -vz <ip> <port>` for a few).
3. Test whether it will serve *arbitrary* content (path traversal/config files),
   then whether it will act as a forward proxy for tunnel traffic
   (CONNECT vs GET rewriting).
4. Document it as a finding with evidence; do **not** pivot through it beyond
   proving reachability unless the venue rules allow it.

## Vendor remediation notes

- Key the wall on **IP ranges**, not hostnames, and only on the exact IPs the
  payment flow needs.
- Restrict walled hosts to TCP/80+443 and block CONNECT/absolute-URI proxy
  requests to them.
- Don't put internal portal IPs in the wall on the same rule as public hosts.
