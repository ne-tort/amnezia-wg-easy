#!/bin/bash
# Smoke Amnezia DNS lifecycle via panel API (enable → resolve → disable).
# Requires: stack up (./deploy.sh), amnezia-dns image built, admin/admin or env overrides.
set -euo pipefail
cd "$(dirname "$0")/.."

PANEL_URL="${PANEL_URL:-https://127.0.0.1}"
ADMIN_USER="${ADMIN_USERNAME:-admin}"
ADMIN_PWD="${ADMIN_PASSWORD:-admin}"
COOKIE="${TMPDIR:-/tmp}/awg-dns-smoke.cj"
TEST_DOMAIN="${AMNEZIA_DNS_TEST_DOMAIN:-cloudflare.com}"
WG="${AMNEZIA_DNS_WG_CONTAINER:-amnezia-awg}"

rm -f "$COOKIE"
echo "=== Login ==="
curl -sk -c "$COOKIE" -b "$COOKIE" -X POST "$PANEL_URL/api/session" \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"${ADMIN_USER}\",\"password\":\"${ADMIN_PWD}\"}" | head -c 200
echo

echo "=== Profiles ==="
curl -sk -b "$COOKIE" "$PANEL_URL/api/amnezia-dns/profiles" | tee /tmp/awg-dns-profiles.json
grep -q '"profiles"' /tmp/awg-dns-profiles.json
PROFILE_ID="${AMNEZIA_DNS_PROFILE_ID:-4}"

echo "=== Enable Amnezia DNS (profile ${PROFILE_ID}) ==="
curl -sk -b "$COOKIE" -X POST "$PANEL_URL/api/amnezia-dns/enable" \
  -H 'Content-Type: application/json' \
  -d "{\"profileId\":\"${PROFILE_ID}\"}" \
  -w "\nHTTP:%{http_code}\n" | tee /tmp/awg-dns-enable.json
grep -q '"phase":"running"' /tmp/awg-dns-enable.json || grep -q '"available":true' /tmp/awg-dns-enable.json
grep -q "\"profileId\":\"${PROFILE_ID}\"" /tmp/awg-dns-enable.json

echo "=== Status ==="
curl -sk -b "$COOKIE" "$PANEL_URL/api/amnezia-dns" | tee /tmp/awg-dns-status.json
grep -q '"available":true' /tmp/awg-dns-status.json
grep -q "\"profileId\":\"${PROFILE_ID}\"" /tmp/awg-dns-status.json

echo "=== forward-records applied ==="
docker exec "$WG" grep -E 'forward-addr:|forward-tls' /opt/amnezia/awg/amnezia-dns/forward-records.conf | head -n 10

echo "=== Resolve via Unbound from panel container ==="
docker exec "$WG" dig @"172.29.172.254" "$TEST_DOMAIN" +short +time=3 +tries=2 | head -n1 | grep -E '^[0-9.]+$'

echo "=== Resolve via dnsmasq 127.0.0.1 ==="
docker exec "$WG" dig @127.0.0.1 "$TEST_DOMAIN" +short +time=3 +tries=2 | head -n1 | grep -E '^[0-9.]+$'

echo "=== Client capabilities ==="
curl -sk -b "$COOKIE" "$PANEL_URL/api/wireguard/client" | grep -q '"amneziaDnsAvailable":true'

echo "=== Disable Amnezia DNS ==="
curl -sk -b "$COOKIE" -X POST "$PANEL_URL/api/amnezia-dns/disable" | tee /tmp/awg-dns-disable.json
grep -q '"available":false' /tmp/awg-dns-disable.json || grep -q '"phase":"off"' /tmp/awg-dns-disable.json

echo "=== Container removed ==="
if docker inspect amnezia-dns >/dev/null 2>&1; then
  echo "FAIL: amnezia-dns still present" >&2
  exit 1
fi
echo "OK: amnezia-dns removed"

echo "=== Capabilities after disable ==="
curl -sk -b "$COOKIE" "$PANEL_URL/api/wireguard/client" | grep -q '"amneziaDnsAvailable":false'

echo "All Amnezia DNS API smoke checks passed."
