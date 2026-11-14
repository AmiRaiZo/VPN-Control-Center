#!/bin/bash
# Add an API-independent, read-only fallback for the update status endpoint.
# The normal authenticated API is always tried first. Only 502/503/504 errors
# produced while vpn-panel-api is intentionally restarting are served from the
# sanitized progress file written by the detached updater.
set -Eeuo pipefail

SITE="${1:-/etc/nginx/sites-available/vpn-panel}"
MARKER="# VPN Panel API-independent update progress fallback v2.3.245"

[ -f "$SITE" ] || {
  echo "ERROR: panel Nginx site not found: $SITE" >&2
  exit 1
}

python3 - "$SITE" "$MARKER" <<'PY'
from pathlib import Path
import os
import re
import sys

path = Path(sys.argv[1])
marker = sys.argv[2]
text = path.read_text(encoding="utf-8")

if marker in text:
    raise SystemExit(0)

server_start_re = re.compile(r"(?m)^[ \t]*server[ \t]*\{")
api_location_re = re.compile(r"(?m)^[ \t]*location[ \t]+/api/[ \t]*\{")
api_proxy_re = re.compile(
    r"proxy_pass[ \t]+http://127\.0\.0\.1:(?P<port>[0-9]+)/api/;"
)


def matching_brace(source: str, opening: int) -> int:
    depth = 0
    quote = None
    escaped = False
    comment = False
    for index in range(opening, len(source)):
        char = source[index]
        if comment:
            if char == "\n":
                comment = False
            continue
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if quote:
            if char == quote:
                quote = None
            continue
        if char in {"'", '"'}:
            quote = char
            continue
        if char == "#":
            comment = True
            continue
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return index
    raise ValueError("unbalanced Nginx server block")


insertions = []
for match in server_start_re.finditer(text):
    opening = text.find("{", match.start(), match.end())
    closing = matching_brace(text, opening)
    block = text[match.start():closing + 1]
    if not api_location_re.search(block):
        continue
    proxy = api_proxy_re.search(block)
    if not proxy:
        continue
    indent_match = re.match(r"[ \t]*", text[text.rfind("\n", 0, match.start()) + 1:match.start()])
    base_indent = indent_match.group(0) if indent_match else ""
    inner = base_indent + "    "
    port = proxy.group("port")
    snippet = f"""

{inner}{marker}
{inner}location = /api/backup/update/status {{
{inner}    proxy_pass http://127.0.0.1:{port}/api/backup/update/status;
{inner}    proxy_set_header Host $http_host;
{inner}    proxy_set_header X-Forwarded-Host $http_host;
{inner}    proxy_set_header X-Forwarded-Port $server_port;
{inner}    proxy_set_header X-Real-IP $remote_addr;
{inner}    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
{inner}    proxy_set_header X-Forwarded-Proto $scheme;
{inner}    proxy_connect_timeout 2s;
{inner}    proxy_send_timeout 5s;
{inner}    proxy_read_timeout 5s;
{inner}    proxy_intercept_errors on;
{inner}    error_page 502 503 504 = /__vpnpanel_update_status_fallback;
{inner}    add_header Cache-Control "no-store, no-cache, must-revalidate, max-age=0" always;
{inner}}}

{inner}location = /__vpnpanel_update_status_fallback {{
{inner}    internal;
{inner}    alias /opt/vpn-panel/update-progress-public.json;
{inner}    default_type application/json;
{inner}    add_header Cache-Control "no-store, no-cache, must-revalidate, max-age=0" always;
{inner}}}
"""
    insertions.append((closing, snippet))

if not insertions:
    raise SystemExit("ERROR: no panel server block with /api/ proxy was found")

for offset, snippet in reversed(insertions):
    text = text[:offset] + snippet + "\n" + text[offset:]

temporary = path.with_name(f"{path.name}.update-progress.{os.getpid()}")
temporary.write_text(text, encoding="utf-8")
os.chmod(temporary, path.stat().st_mode & 0o777)
os.replace(temporary, path)
PY
