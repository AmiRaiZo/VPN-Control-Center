#!/bin/bash
# Build and verify a publishable release ZIP from the current project tree.
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
VERSION="$(tr -d '[:space:]' < "$PROJECT_ROOT/VERSION")"
OUTPUT="${1:-$PROJECT_ROOT/../vpn-panel-fixed-${VERSION}.zip}"
OUTPUT_DIR="$(dirname "$OUTPUT")"
OUTPUT_NAME="$(basename "$OUTPUT")"

mkdir -p "$OUTPUT_DIR"
OUTPUT="$(cd "$OUTPUT_DIR" && pwd)/$OUTPUT_NAME"

STAGE="$(mktemp -d)"
cleanup() { rm -rf "$STAGE"; }
trap cleanup EXIT

# The leading slash is intentional: only the root checksum is regenerated.
# frontend/dist.sha256 and backend/dist.sha256 are release inputs and must be
# copied into the archive.
rsync -a \
  --exclude='/.git/' \
  --exclude='.git/' \
  --exclude='.pytest_cache/' \
  --exclude='.ruff_cache/' \
  --exclude='.tools/' \
  --exclude='.venv/' \
  --exclude='venv/' \
  --exclude='node_modules/' \
  --exclude='backups/' \
  --exclude='var/' \
  --exclude='logs/' \
  --exclude='.env' \
  --exclude='.env.local' \
  --exclude='.env.production' \
  --exclude='*.db' \
  --exclude='*.db-wal' \
  --exclude='*.db-shm' \
  --exclude='*.sqlite' \
  --exclude='*.sqlite3' \
  --exclude='*.log' \
  --exclude='*.pem' \
  --exclude='*.key' \
  --exclude='*.p12' \
  --exclude='*.pfx' \
  --exclude='/dist.sha256' \
  --exclude='/frontend/node_modules/' \
  --exclude='/frontend/dist-next/' \
  --exclude='/backend/venv/' \
  --exclude='__pycache__/' \
  --exclude='*.pyc' \
  --exclude='.DS_Store' \
  "$PROJECT_ROOT/" "$STAGE/project/"

(cd "$STAGE/project" && \
  find . -type f ! -path './dist.sha256' -print0 \
    | LC_ALL=C sort -z \
    | xargs -0 sha256sum > dist.sha256)

rm -f "$OUTPUT"
(cd "$STAGE/project" && zip -q -r "$OUTPUT" .)

"$SCRIPT_DIR/verify_release_archive.sh" "$OUTPUT"
sha256sum "$OUTPUT"
