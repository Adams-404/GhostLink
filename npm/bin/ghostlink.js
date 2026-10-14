#!/usr/bin/env node
'use strict';

/**
 * ghostlink — npm bin shim.
 *
 * GhostLink itself is a stdlib-only Python 3.10+ CLI (it needs iproute2 and
 * sudo -n for the MAC tooling), so this wrapper does no business logic: it
 * locates a suitable interpreter, points PYTHONPATH at the bundled Python
 * package, and execs `python -m ghostlink` with the inherited argv/stdio.
 */

const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

function die(message, hint) {
  console.error(`ghostlink: ${message}`);
  if (hint) console.error(`hint: ${hint}`);
  process.exit(1);
}

const pkgRoot = path.resolve(__dirname, '..');
const pythonPkg = path.join(pkgRoot, 'ghostlink');

// 1. Find a Python interpreter (override with GHOSTLINK_PYTHON).
let python = process.env.GHOSTLINK_PYTHON;
if (!python) {
  for (const candidate of ['python3', 'python']) {
    const probe = spawnSync(candidate, ['--version'], { encoding: 'utf8' });
    if (!probe.error && probe.status === 0) {
      python = candidate;
      break;
    }
  }
}
if (!python) {
  die('no Python interpreter found on PATH', 'install Python 3.10+ (python3 --version)');
}

// 2. Enforce the 3.10+ floor with the human-readable version.
const versionProbe = spawnSync(python, ['-c', 'import sys; print("%d.%d" % sys.version_info[:2])'], {
  encoding: 'utf8',
});
if (!versionProbe.error) {
  const [major, minor] = versionProbe.stdout.trim().split('.').map(Number);
  if (major < 3 || (major === 3 && minor < 10)) {
    die(`${python} is ${major}.${minor} — GhostLink requires Python 3.10+`);
  }
}

// 3. The bundled Python package must be inside this install.
if (!fs.existsSync(path.join(pythonPkg, 'cli.py'))) {
  die('bundled Python package is missing', 'reinstall with: npm install -g @adams-404/ghostlink');
}

// 4. Warn (don't fail) when iproute2's JSON mode is unavailable.
if (process.argv[2] !== '--version' && !process.env.GHOSTLINK_NO_IP_CHECK) {
  const ipProbe = spawnSync('ip', ['-j', 'link', 'show'], { stdio: 'ignore', encoding: 'utf8' });
  if (ipProbe.error || ipProbe.status !== 0) {
    console.error('ghostlink: warning: `ip -j` (iproute2) not available — most commands require it');
  }
}

// PYTHONPATH must be the PARENT of the package directory — python searches
// each sys.path entry for a `ghostlink/` subdir, so pointing it *at* the
// package dir leaves the module unimportable.
const env = {
  ...process.env,
  PYTHONPATH: pkgRoot + (process.env.PYTHONPATH ? `${path.delimiter}${process.env.PYTHONPATH}` : ''),
};

const child = spawnSync(python, ['-m', 'ghostlink', ...process.argv.slice(2)], {
  stdio: 'inherit',
  env,
});

process.exit(child.status === null ? 1 : child.status);
