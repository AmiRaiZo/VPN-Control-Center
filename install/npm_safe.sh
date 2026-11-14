#!/bin/bash
# Safe frontend deployment helper.
# Release ZIPs contain a production Vite build plus SHA-256 manifest. Servers
# deploy that verified artifact directly, so npm bugs or registry failures do
# not block installation. Local npm build remains an explicit fallback.

vpn_panel_latest_npm_log() {
  find /root/.npm/_logs /var/cache/vpn-panel/npm/_logs -maxdepth 1 -type f -name '*-debug-0.log' -printf '%T@ %p\n' 2>/dev/null \
    | sort -nr | head -n1 | cut -d' ' -f2-
}

vpn_panel_verify_bundled_frontend() {
  local frontend_dir="$1"
  local manifest="$frontend_dir/dist.sha256"
  local first_path="" manifest_base=""

  [ -s "$frontend_dir/dist/index.html" ] || {
    echo "[frontend-verify] missing: $frontend_dir/dist/index.html" >&2
    return 1
  }
  [ -s "$manifest" ] || {
    echo "[frontend-verify] missing: $manifest" >&2
    return 1
  }

  # Select one checksum base from the manifest itself. Current manifests list
  # dist/... paths and are checked from frontend/. Legacy manifests list
  # index.html/assets/... and are checked from frontend/dist/. Do not retry a
  # failed current manifest from the legacy directory: that only creates a
  # misleading wall of "No such file" messages and hides the real mismatch.
  first_path="$(awk 'NF >= 2 && $1 !~ /^#/ {print $2; exit}' "$manifest")"
  case "$first_path" in
    dist/*) manifest_base="$frontend_dir" ;;
    index.html|assets/*|favicon.svg|*.css|*.js|*.json) manifest_base="$frontend_dir/dist" ;;
    *)
      echo "[frontend-verify] unsupported checksum path in manifest: ${first_path:-<empty>}" >&2
      return 1
      ;;
  esac

  if ! (cd "$manifest_base" && sha256sum -c "$manifest"); then
    echo "[frontend-verify] checksum mismatch; manifest base: $manifest_base" >&2
    echo "[frontend-verify] failed entries above are the release files that must be regenerated." >&2
    return 1
  fi

  python3 - "$frontend_dir/dist/index.html" "$frontend_dir/dist" <<'PYFRONTENDENTRY'
from pathlib import Path
import re
import sys

index = Path(sys.argv[1]).read_text(encoding="utf-8")
dist = Path(sys.argv[2])
module = re.search(r'<script[^>]+type=["\']module["\'][^>]+src=["\']([^"\']+)["\']', index)
if not module:
    raise SystemExit("[frontend-verify] module entry is missing from index.html")
src = module.group(1)
if "?" in src or "#" in src:
    raise SystemExit(
        "[frontend-verify] module entry must not contain a query/hash; "
        "Vite chunks import the same entry without it and duplicate React: " + src
    )
asset = dist / src.lstrip("/")
if not asset.is_file():
    raise SystemExit("[frontend-verify] referenced module entry is missing: " + str(asset))
for ref in re.findall(r'(?:src|href)=["\'](/assets/[^"\']+)["\']', index):
    clean = ref.split("?", 1)[0].split("#", 1)[0]
    target = dist / clean.lstrip("/")
    if not target.is_file():
        raise SystemExit("[frontend-verify] referenced frontend asset is missing: " + str(target))

assets_dir = dist / "assets"
for script in assets_dir.glob("*.js"):
    text = script.read_text(encoding="utf-8")
    refs = re.findall(r'(?:from\s*|import\s*\()["\']\./([^"\']+\.js)["\']', text)
    for ref in refs:
        target = assets_dir / ref
        if not target.is_file():
            raise SystemExit(
                "[frontend-verify] missing JS chunk " + ref + " imported by " + script.name
            )

entry_name = Path(src.split("?", 1)[0].split("#", 1)[0]).name
asset_ref_re = re.compile(r'(?:\./|assets/)([^"\'`?]+?\.(?:js|css))')
queue = [entry_name]
visited = set()
while queue:
    current = queue.pop(0)
    if current in visited:
        continue
    visited.add(current)
    current_path = assets_dir / current
    if not current_path.is_file():
        raise SystemExit("[frontend-verify] active graph asset is missing: " + str(current_path))
    text = current_path.read_text(encoding="utf-8")
    for ref in asset_ref_re.findall(text):
        ref_name = Path(ref).name
        ref_path = assets_dir / ref_name
        if not ref_path.is_file():
            raise SystemExit(
                "[frontend-verify] active graph references missing asset "
                + ref_name + " from " + current
            )
        if ref_name.endswith(".css"):
            continue
        if re.fullmatch(r'index-v\d+\.js', ref_name) and ref_name != entry_name:
            raise SystemExit(
                "[frontend-verify] mixed React runtimes detected: "
                + current + " imports " + ref_name + " while entry is " + entry_name
            )
        if ref_name not in visited:
            queue.append(ref_name)
PYFRONTENDENTRY
}

vpn_panel_deploy_bundled_frontend() {
  local frontend_dir="$1" web_dir="$2"
  local nonce="$$.$RANDOM"
  local staged_index="$web_dir/.index.html.new.$nonce"
  vpn_panel_verify_bundled_frontend "$frontend_dir" || {
    echo "[!] Bundled frontend verification failed." >&2
    return 1
  }
  mkdir -p "$web_dir" "$web_dir/assets"

  # Deployment order is intentionally assets-first and index-last. Publishing
  # index.html before its hashed files creates a real race: a browser can fetch
  # the new HTML during the copy and receive 404 for the referenced entry/chunk.
  # Old hashed assets remain for already-open tabs, while the final mv is atomic
  # because the temporary index lives on the same filesystem as WEB_DIR.
  cp -a "$frontend_dir/dist/assets/." "$web_dir/assets/"

  # Refresh all non-asset top-level files except index.html without deleting the
  # currently served entry. Stale harmless top-level files are cleaned after the
  # new entry is published, never before it.
  find "$frontend_dir/dist" -mindepth 1 -maxdepth 1 ! -name assets ! -name index.html -print0 \
    | while IFS= read -r -d '' item; do cp -a "$item" "$web_dir/"; done

  cp -a "$frontend_dir/dist/index.html" "$staged_index"
  test -s "$staged_index" || { rm -f "$staged_index"; return 1; }
  mv -f "$staged_index" "$web_dir/index.html"

  # Keep previous immutable assets for fourteen days so tabs opened before the
  # update can finish normally. Remove abandoned temporary entries immediately.
  find "$web_dir" -maxdepth 1 -type f -name '.index.html.new.*' -delete 2>/dev/null || true
  find "$web_dir/assets" -type f -mtime +14 -delete 2>/dev/null || true
  test -s "$web_dir/index.html"
}

vpn_panel_npm_install_frontend() {
  local frontend_dir="$1"
  local cache_dir="/var/cache/vpn-panel/npm"
  local npm_log="/tmp/vpn-panel-npm-install.log"
  mkdir -p "$cache_dir"
  : > "$npm_log"
  cd "$frontend_dir"

  export NODE_ENV=development
  export NPM_CONFIG_PRODUCTION=false
  export npm_config_production=false
  export NPM_CONFIG_OMIT=""
  export npm_config_omit=""
  export NPM_CONFIG_INCLUDE=dev
  export npm_config_include=dev

  local cmd=(npm install --include=dev --omit=optional --no-audit --no-fund --cache "$cache_dir")
  if [ -f package-lock.json ]; then
    cmd=(npm ci --include=dev --omit=optional --no-audit --no-fund --cache "$cache_dir")
  fi

  rm -rf node_modules
  set +e
  env -u NODE_ENV -u NPM_CONFIG_PRODUCTION -u npm_config_production \
    NPM_CONFIG_OMIT='' npm_config_omit='' NPM_CONFIG_INCLUDE=dev npm_config_include=dev \
    "${cmd[@]}" >"$npm_log" 2>&1
  local rc=$?
  set -e

  if [ "$rc" -ne 0 ] || [ ! -x node_modules/.bin/vite ]; then
    echo "[!] npm dependency installation failed; retrying once with a clean cache..." >&2
    rm -rf node_modules "$cache_dir/_cacache/tmp" /root/.npm/_cacache/tmp 2>/dev/null || true
    npm cache clean --force >>"$npm_log" 2>&1 || true
    set +e
    env -u NODE_ENV -u NPM_CONFIG_PRODUCTION -u npm_config_production \
      NPM_CONFIG_OMIT='' npm_config_omit='' NPM_CONFIG_INCLUDE=dev npm_config_include=dev \
      "${cmd[@]}" --foreground-scripts >>"$npm_log" 2>&1
    rc=$?
    set -e
  fi

  if [ "$rc" -ne 0 ] || [ ! -x node_modules/.bin/vite ]; then
    echo "[!] Frontend dependencies were not installed correctly; Vite is missing." >&2
    tail -n 80 "$npm_log" >&2 || true
    local latest
    latest=$(vpn_panel_latest_npm_log || true)
    if [ -n "$latest" ] && [ -f "$latest" ]; then
      echo "[!] Latest npm debug log: $latest" >&2
      tail -n 60 "$latest" >&2 || true
    fi
    return 1
  fi

  ./node_modules/.bin/vite --version >>"$npm_log" 2>&1
}

vpn_panel_npm_build_frontend() {
  local frontend_dir="$1"
  cd "$frontend_dir"
  [ -x node_modules/.bin/vite ] || {
    echo "[!] Cannot build frontend: node_modules/.bin/vite is missing." >&2
    return 1
  }
  rm -rf dist
  ./node_modules/.bin/vite build
  test -s dist/index.html
}
