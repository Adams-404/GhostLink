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
# 1. sweep the subnet — fills the ARP table and names everyone
ghostlink mac discover --no-color

# 2. or read the existing table
ghostlink mac neighbors --no-color        # --fast to skip mDNS/PTR/NetBIOS
ghostlink mac list --no-color             # interface type/driver/vendor

# 3. find a device that is likely paying — phones publish names over mDNS
#    (e.g. "omarchy.local", "fedora-linux.local", "DESKTOP-AB12"), flagship
#    phones and IoT devices keep stable MACs; look for those
ghostlink mac watch <mac> --duration 300
```

Two signals the enriched table gives you for free:

- **`randomized`** means the locally-administered (U/L) bit is set — the OS
  rotates its MAC per SSID, so a cloned MAC buys you nothing against a
  gateway that binds sessions to that identity. A *non*-randomized MAC
  (stable, vendor-prefixed) is the inherit-capable class.
- **Vendor hints** come from a built-in OUI table (Apple/Samsung/Xiaomi/Huawei/
  Google/Espressif/Raspberry Pi/...). IoT devices with stable MACs (ESP32,
  Raspberry Pi) are the classic "printer that always pays" pattern.

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
