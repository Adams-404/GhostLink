# Finding 2026-10-14 — npm wrapper release pipeline (postmortem)

- **Date:** 2026-10-14
- **Scope:** publishing GhostLink as `@adams-404/ghostlink` on npm
- **Outcome:** three real defects found and fixed across releases 0.1.0 → 0.1.3

## Defects found during registry verification

### 1. Broken `PYTHONPATH` in the bin shim (0.1.0) — HIGH

The Node shim pointed `PYTHONPATH` at the bundled package **directory**
(`<install>/ghostlink`) instead of its **parent**. Python searches each
`sys.path` entry for a `ghostlink/` subdirectory, so every invocation that did
not run from the source tree failed with:

```
/usr/bin/python3: No module named ghostlink
```

**Why initial verification missed it:** the test cwd was the project directory,
and `python -m` puts `''` (cwd) on `sys.path` before `PYTHONPATH` — the local
package masked the broken env. Only running from `~`/`/tmp` exposed it.

**Fix:** `PYTHONPATH` now points at `pkgRoot` (`<install>`), the parent of the
package dir. Released in 0.1.1; 0.1.0 deprecated.

### 2. Unscoped name collision — packaging decision

`ghostlink` was rejected with `E403: Package name too similar to existing
package ghost-link` (npm's anti-typosquatting rule). Resolved by publishing
under the account scope, `@adams-404/ghostlink`, which is reserved per-account
and never collides.

### 3. Bare invocation printed an argparse error (0.1.3) — LOW

`ghostlink` and `ghostlink mac` with no subcommand raised
`error: the following arguments are required: command`. Subparsers are now
optional and the CLI prints help with exit code 1.

### 4. Placeholder version noise

npm auto-created a `0.0.0-stage` placeholder when the scoped package was first
claimed; registry views during propagation lag made it briefly look like the
publish had failed. Non-issue — documented here so it isn't misread later.

## Verification protocol adopted

1. Install the published tarball into a **clean prefix**.
2. Run **from a neutral cwd** (`~` or `/tmp`) — never from the project dir.
3. Exercise at least one live command, not just `--version`.
4. Confirm `npm view <pkg> dist-tags` shows `latest` on the new version.

## Releases

| Version | Contents |
| --- | --- |
| 0.1.0 | initial publish — broken PYTHONPATH (deprecated) |
| 0.1.1 | shim PYTHONPATH fix |
| 0.1.2 | identity enrichment (mDNS/PTR/NetBIOS names, OUI vendors, randomized-MAC flag) + `mac discover` |
| 0.1.3 | bare invocation prints help |
