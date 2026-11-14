#!/bin/bash
# Verify the exact ZIP that will be published, not only the source worktree.
set -Eeuo pipefail

if [ "$#" -ne 1 ]; then
  echo "Usage: $0 /path/to/vpn-panel-release.zip" >&2
  exit 2
fi

ARCHIVE="$(readlink -f "$1")"
[ -f "$ARCHIVE" ] || { echo "ERROR: release archive not found: $ARCHIVE" >&2; exit 1; }

WORKDIR="$(mktemp -d)"
cleanup() { rm -rf "$WORKDIR"; }
trap cleanup EXIT

unzip -tq "$ARCHIVE" >/dev/null
unzip -q "$ARCHIVE" -d "$WORKDIR/extracted"

PROJECT_ROOT="$WORKDIR/extracted"
if [ ! -f "$PROJECT_ROOT/install/update.sh" ]; then
  mapfile -t CANDIDATES < <(find "$PROJECT_ROOT" -mindepth 2 -maxdepth 2 -type f -path '*/install/update.sh' -printf '%h\n')
  [ "${#CANDIDATES[@]}" -eq 1 ] || {
    echo "ERROR: archive must contain exactly one panel project root" >&2
    exit 1
  }
  PROJECT_ROOT="$(dirname "${CANDIDATES[0]}")"
fi

[ -s "$PROJECT_ROOT/dist.sha256" ] || { echo "ERROR: root dist.sha256 is missing" >&2; exit 1; }
[ -s "$PROJECT_ROOT/frontend/dist.sha256" ] || {
  echo "ERROR: frontend/dist.sha256 is missing from the final archive" >&2
  exit 1
}
WHEELHOUSE_AVAILABLE=0
if [ -d "$PROJECT_ROOT/vendor/wheels" ] && [ -s "$PROJECT_ROOT/vendor/wheels.sha256" ]; then
  WHEELHOUSE_AVAILABLE=1
fi
[ -s "$PROJECT_ROOT/install/npm_safe.sh" ] || { echo "ERROR: install/npm_safe.sh is missing" >&2; exit 1; }
[ -s "$PROJECT_ROOT/bot/pyproject.toml" ] || { echo "ERROR: integrated bot source is missing" >&2; exit 1; }
[ -s "$PROJECT_ROOT/bot/.env.example" ] || { echo "ERROR: bot/.env.example is missing" >&2; exit 1; }
[ -s "$PROJECT_ROOT/bot/systemd/vpn-manager-bot.service.in" ] || { echo "ERROR: bot systemd unit template is missing" >&2; exit 1; }

source "$PROJECT_ROOT/install/npm_safe.sh"
FRONTEND_LOG="$WORKDIR/frontend-preflight.log"
if ! vpn_panel_verify_bundled_frontend "$PROJECT_ROOT/frontend" >"$FRONTEND_LOG" 2>&1; then
  cat "$FRONTEND_LOG" >&2
  exit 1
fi

(cd "$PROJECT_ROOT" && sha256sum -c dist.sha256 >/dev/null)
if [ "$WHEELHOUSE_AVAILABLE" -eq 1 ]; then
  (cd "$PROJECT_ROOT/vendor" && sha256sum -c wheels.sha256 >/dev/null)
fi

python3 - "$PROJECT_ROOT" <<'PYVERIFYCOVERAGE'
from pathlib import Path
import sys

root = Path(sys.argv[1])
actual = {
    path.relative_to(root).as_posix()
    for path in root.rglob("*")
    if path.is_file() and path != root / "dist.sha256"
}
listed = set()
for raw in (root / "dist.sha256").read_text(encoding="utf-8").splitlines():
    if not raw.strip():
        continue
    parts = raw.split(maxsplit=1)
    if len(parts) != 2:
        raise SystemExit("ERROR: malformed root checksum line: " + raw)
    name = parts[1].lstrip("*").strip()
    while name.startswith("./"):
        name = name[2:]
    listed.add(name)

missing = sorted(actual - listed)
stale = sorted(listed - actual)
if missing or stale:
    if missing:
        print("ERROR: files missing from root dist.sha256:", *missing[:20], sep="\n  ", file=sys.stderr)
    if stale:
        print("ERROR: stale paths in root dist.sha256:", *stale[:20], sep="\n  ", file=sys.stderr)
    raise SystemExit(1)
PYVERIFYCOVERAGE

python3 - "$PROJECT_ROOT" <<'PYVERIFYSECRETS'
from pathlib import Path
import sys

root = Path(sys.argv[1])
forbidden_dirs = {".git", ".venv", "venv", "node_modules", ".tools", "backups", "var", "logs", "__pycache__"}
forbidden_suffixes = {".db", ".sqlite", ".sqlite3", ".log", ".pem", ".key", ".p12", ".pfx"}
bad = []
for path in root.rglob("*"):
    relative = path.relative_to(root)
    if path.is_dir() and path.name in forbidden_dirs:
        bad.append(relative.as_posix() + "/")
        continue
    if not path.is_file():
        continue
    name = path.name.lower()
    if name == ".env" or (name.startswith(".env.") and name != ".env.example"):
        bad.append(relative.as_posix())
    elif path.suffix.lower() in forbidden_suffixes or name.endswith((".db-wal", ".db-shm")):
        bad.append(relative.as_posix())
if bad:
    print("ERROR: release archive contains runtime data or sensitive artifacts:", *sorted(bad[:30]), sep="\n  ", file=sys.stderr)
    raise SystemExit(1)
PYVERIFYSECRETS

echo "[release-verify] ZIP structure: OK"
echo "[release-verify] frontend checksum manifest: OK"
echo "[release-verify] frontend active asset graph: OK"
echo "[release-verify] integrated bot source and secret exclusions: OK"
if [ "$WHEELHOUSE_AVAILABLE" -eq 1 ]; then
  echo "[release-verify] offline Python wheelhouse: OK"
else
  echo "[release-verify] compact online package: bundled Python wheelhouse intentionally omitted"
fi
echo "[release-verify] root checksum manifest and coverage: OK"
