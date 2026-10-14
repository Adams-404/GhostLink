# Technique: other vectors

## 1. IPv6 leak

If the venue's WLAN hands out global IPv6 addresses while the portal only
enforces policy on the IPv4 path, IPv6 is a clean bypass (no NAT, no
interception). GhostLink checks it with `ghostlink extras`:

- global IPv6 addressing present → risk,
- TCP connect to `2606:4700:4700::1111:443` replying pre-auth → confirmed egress.

Vendor remediation: apply the same wall on ip6tables/nftables and consider
RA-guard / no-IPv6 on the guest SSID.

## 2. DHCP/fingerprint disclosure

`ghostlink extras` reports the DHCP `host_name` option the OS sends
(hostname like `fedora`, `Adams-MacBook-Pro`, etc.). On its own it's
information leakage; combined with a walled-garden member list it fingerprints
the client class, and some portals use it for session analytics. It also
confirms which OS/device you are emulating when you clone a MAC.

## 3. Path divergence (transparent bridge)

`ip route get` says hop 1 is the gateway, but `traceroute` may show the
portal/AP IP as hop 1 instead — meaning traffic is intercepted in-path by a
transparent bridge that your OS doesn't know about. GhostLink flags:

- first hop ≠ configured gateway → likely transparent interception,
- extra hops inside your own /24 → portal bridge/relay in the path.

## 4. ICMP

If ping survives pre-auth, check for ICMP tunneling carriers (rare in modern
portals, cheap to rule out).

## 5. Session and token abuse (web layer)

The highest-value bug class on these portals is usually **not** RF or L2 at all —
it's the web/API layer that issues the session after payment. Observe with
browser devtools while walking the *pay* flow yourself (one legitimate
purchase is in every hackathon budget):

- **Redirect parameters.** Portal redirect URLs commonly carry client identity:
  `http://portal.../login?ip=10.0.0.5&mac=AA:BB:...&dest=...`. Check whether
  the gateway trusts these parameters to *open* the wall; try replaying the
  post-payment callback URL with a different IP/mac (payment-callback replay).
- **Voucher redemption API.** Look for an unauthenticated `redeem` endpoint;
  test for IDOR (redeem someone else's code), code re-use across multiple MACs,
  and absence of rate-limiting (guessable/short codes).
- **Client-side enforcement.** Trial/speed limits enforced in the splash-page
  JS rather than the firewall — always spoofable.
- **Admin/management.** Default credentials on the gateway's own web UI, or an
  unauthenticated `/api/v1/...` on the portal software; both are common on
  small vendor gateways and are show-stoppers for the whole fleet.

## 6. Shared NAT (social, not technical)

A paid client acting as a router for unpaid ones defeats the paywall without
breaking anything cryptographic. Portals that bind per-MAC but never
meter/bind egress allow chains of NATs — worth demonstrating (and cheap to
fix via per-device quotas).
