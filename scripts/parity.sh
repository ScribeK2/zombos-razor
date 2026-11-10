#!/usr/bin/env bash
# Regenerates the Finding-code tables in docs/parity.md, then verifies the audit:
# every cited test exists, the Go reference tables exist in Rust, and the generated block
# is current. Go is read from git (commit b8fc3d5, the last Go commit), never the working tree.
# Usage: scripts/parity.sh [--check]   (--check changes nothing and fails on a stale block)
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
DOC=docs/parity.md

if [ "${1:-}" != "--check" ]; then
  python3 scripts/parity_findings.py --write "$DOC"
fi
python3 scripts/parity_findings.py --stale "$DOC" || { echo "generated block is stale: run scripts/parity.sh"; exit 1; }
python3 scripts/parity_findings.py --check "$DOC"
python3 scripts/parity_lists.py
sed -n '/<!-- COUNTS -->/,/<!-- \/COUNTS -->/p' "$DOC" | grep '^| [a-zA-Z]'

