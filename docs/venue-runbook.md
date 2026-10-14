# Venue runbook — operating GhostLink at the hackathon

**Pre-flight.** Clone the repo, verify tooling: `python -m unittest discover -s tests`.
Connect to the venue SSID. Confirm scope with the organizers before touching
anything that isn't the hackathon-provided network (no attacking the payment
processor, other attendees' sessions, or venue production SSIDs).

## Step 1 — connect & triage (5 min)

```bash
ghostlink recon --no-color
```

Record: interface, gateway, resolver, **and whether a portal was detected**.
Create the run's finding file:

```bash
cp docs/findings/2026-10-14-baseline-open-network.md docs/findings/$(date +%F)-venue-<ssid>.md
```

## Step 2 — full sweep (5 min)

```bash
ghostlink all --no-color --timeout 2.0
```

This writes `ghostlink-report.md` + `.json` in the project root. Copy both into
`docs/findings/$(date +%F)-venue-<ssid>.md` as the raw evidence attachment, and
annotate every GhostLink severity judgement in prose.

## Step 3 — enumerate the victims (10 min)

```bash
ghostlink mac neighbors --no-color
ghostlink mac list --no-color
```

Pick candidate paying devices (consumer OUIs, REACHABLE/STALE + high traffic).
Watch them:

```bash
ghostlink mac watch <mac> --interval 2 --duration 300
```

Map each result into these classes:

- target **present** → wait for absence window, or test MAC+IP binding live
- target **absent** → session likely still open (timeout window); clone now

## Step 4 — attempt the inherit (MAC vector)

```bash
ghostlink mac spoof <target-mac-or-fresh> --no-color     # dry-run, review
ghostlink mac spoof <mac> --apply --force
# verify internet, then:
ghostlink mac restore
```

Record: does the clone inherit the session? Does the original lose it (clone
detection)? Does IP pinning block the inherit?

## Step 5 — attempt the wall (walled-garden vector)

```bash
ghostlink walled --portal-url "<url from step 1>" --no-color
```

Then follow `docs/techniques/walled-garden.md` per member: non-HTTP protocols,
proxy behaviour, internal IPs.

## Step 6 — DNS vector

```bash
ghostlink egress --no-color          # UDP/53 + TCP matrix pre-payment
```

If UDP/53 answers pre-auth, follow `docs/techniques/dns-and-egress.md` (lab
server only).

## Step 7 — web/API layer

Buy one real pass (budget line). With devtools open, capture the whole pay
flow. Feed redirect URLs, callbacks, voucher redemption, and any management
API into the writeup; see `docs/techniques/other-vectors.md` §5.

## Step 8 — write it up

Fill in `docs/findings/<date>-venue-<ssid>.md` with:

1. **Summary** — what was found, in one paragraph.
2. **Evidence** — commands + outputs + timestamps (paste report tables).
3. **Impact** — revenue bypass severity (free internet vs. fleet-wide).
4. **Remediation** — concrete fix the vendor can implement (per-technique
   notes in the docs above).

Commit: `git add docs/findings && git commit -m "docs(findings): venue run 2026-10-XX <ssid>"`.

## Ethics guardrails

- Stay inside the SSID(s) the organizers designate. Get the exclusion list in
  writing at kickoff.
- No persistence, no data exfiltration beyond proving connectivity, no touching
  other attendees' devices.
- Every PoC must be reproducible from this repo by the organizers.
