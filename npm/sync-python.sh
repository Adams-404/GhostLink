#!/usr/bin/env bash
# Sync the Python package + README into the npm wrapper right before packing,
# so the tarball can never ship a stale copy of the Python sources.
set -euo pipefail
cd "$(dirname "$0")"

SRC="$(cd .. && pwd)"

if ! command -v rsync >/dev/null 2>&1; then
  rm -rf ghostlink
  cp -r "$SRC/ghostlink" ./ghostlink
else
  rsync -a --delete --exclude '__pycache__' --exclude '*.pyc' "$SRC/ghostlink/" ./ghostlink/
fi
find ./ghostlink -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true

cp "$SRC/README.md" ./README.md

echo "synced $(find ./ghostlink -name '*.py' | wc -l) Python files into npm wrapper"
