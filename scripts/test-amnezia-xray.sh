#!/bin/bash
# Smoke Amnezia Xray status API (full enable needs amnezia-xray image + port free).
# Requires: stack up (./deploy.sh), admin credentials.
set -euo pipefail
cd "$(dirname "$0")/.."

PANEL_URL="${PANEL_URL:-https://127.0.0.1}"
ADMIN_USER="${ADMIN_USERNAME:-admin}"
ADMIN_PWD="${ADMIN_PASSWORD:-admin}"
COOKIE="${TMPDIR:-/tmp}/awg-xray-smoke.cj"

rm -f "$COOKIE"
echo "=== Login ==="
curl -sk -c "$COOKIE" -b "$COOKIE" -X POST "$PANEL_URL/api/session" \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"${ADMIN_USER}\",\"password\":\"${ADMIN_PWD}\"}" | head -c 200
echo

echo "=== Xray status ==="
curl -sk -b "$COOKIE" "$PANEL_URL/api/amnezia-xray" | tee /tmp/awg-xray-status.json
grep -q '"phase"' /tmp/awg-xray-status.json
grep -q '"port"' /tmp/awg-xray-status.json

echo "=== Moderator must be forbidden (if mod credentials set) ==="
if [ -n "${MOD_USERNAME:-}" ] && [ -n "${MOD_PASSWORD:-}" ]; then
  MOD_COOKIE="${TMPDIR:-/tmp}/awg-xray-mod.cj"
  rm -f "$MOD_COOKIE"
  curl -sk -c "$MOD_COOKIE" -b "$MOD_COOKIE" -X POST "$PANEL_URL/api/session" \
    -H 'Content-Type: application/json' \
    -d "{\"username\":\"${MOD_USERNAME}\",\"password\":\"${MOD_PASSWORD}\"}" >/dev/null
  code=$(curl -sk -b "$MOD_COOKIE" -o /dev/null -w '%{http_code}' "$PANEL_URL/api/amnezia-xray")
  test "$code" = "403"
  echo "moderator HTTP $code OK"
fi

echo "=== Public /sub unknown (no cookie) ==="
code=$(curl -sk -o /dev/null -w '%{http_code}' "$PANEL_URL/sub/__no_such_client__")
# 503 if xray off, 404 if running but name missing
test "$code" = "404" -o "$code" = "503"
echo "HTTP $code OK"

echo "=== Done ==="
