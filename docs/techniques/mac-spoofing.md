# Technique: MAC spoofing (session inheritance)

## Why it works

Most paid-WiFi gateways key the "who has paid" session to the **layer-2
identity of the client** — its MAC — because that's what the gateway's DHCP
and firewall layer sees. The chain looks like:

1. Client connects, DHCP assigns IP for MAC `AA`.
2. Client pays; backend marks MAC `AA` as authorized (time and/or bytes).
3. Gateway opens its firewall for MAC `AA` until the quota expires.

If any of that binding is weak, a second device claiming MAC `AA` inherits the
authorized state. In real deployments you see three binding strengths:

| Binding | Bypass difficulty | Notes |
| --- | --- | --- |
| MAC only | **trivial** | clone, inherit, done |
| MAC + IP | easy | clone MAC, force same DHCP lease (release/renew or static) |
| MAC + voucher re-auth | hard | session requires interactive re-proof |

## Reconnaissance order

```bash
# 1. who is on the link right now
ghostlink mac neighbors

# 2. find a device that is likely paying — look for the phone/laptop class OUIs
#    (Apple/Samsung/Xiaomi/Intel) and, importantly, high-traffic ARP states
ghostlink mac watch <candidate-mac> --duration 300
```

`watch` tells you whether the target device is **present** (REACHABLE/STALE
entries keep refreshing) or **absent**. A paid device that leaves creates a
window: gateways often keep the session open until the timer expires, so during
that window a cloned MAC inherits the session cleanly.

## Execution

```bash
# generate a fresh locally-administered MAC, or impersonate a consumer OUI
ghostlink mac gen --vendor apple --count 3

# dry-run first (default) — prints the exact command and refuses if the
# interface carries your own connection
ghostlink mac spoof f0:18:98:2a:07:06

# apply for real (non-interactive sudo; nothing is changed without this)
ghostlink mac spoof f0:18:98:2a:07:06 --apply --force

# undo — the original MAC is backed up on first apply
ghostlink mac restore
```

## Pitfalls

- **Your own connectivity.** Changing the MAC of the interface carrying your
  SSH/management link drops you. Use a second interface, or the console. The
  tool refuses this unless `--force`.
- **DHCP IP.** If the portal binds MAC+IP, after cloning you must land the same
  IP: `sudo dhclient -r <iface> && sudo dhclient <iface>` and hope the lease
  map re-assigns it; some gateways pin the IP in the app database, which makes
  this a lot weaker as an attack.
- **ARP cache.** Stale ARP entries on the gateway may delay the clone taking
  effect; wait a lease cycle.
- **Operating-system randomization.** macOS/iOS/Android rotate MACs per SSID by
  default (private Wi-Fi address) — the gateway's view of "the" device MAC is
  then unstable, which changes the economics of this attack entirely.
- **Anti-clone detection.** Gateways that log MAC changes, watch for two IPs
  on one MAC, or re-MFA on MAC flap will see you immediately — this is the
  weakness the hackathon wants documented.

## What to report to the vendor

- Whether the session survives: clone → browse → screenshot, and whether the
  *original* device gets disconnected (indicates MAC conflict detection).
- Whether IP is pinned (release/renew test).
- Whether MAC changes are logged/alerted anywhere.
