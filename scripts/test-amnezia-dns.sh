#!/bin/bash
# Test Amnezia DNS chain: dnsmasq in wg-easy -> amnezia-dns (Unbound) -> DoT upstream.
# Requires: WG_DEFAULT_DNS=10.8.0.1 in .env and stack running (docker compose up -d).

set -e
CONTAINER_WG="${AMNEZIA_WG_CONTAINER:-amnezia-wg-easy}"
CONTAINER_DNS="${AMNEZIA_DNS_CONTAINER:-amnezia-dns}"
TEST_DOMAIN="${1:-google.com}"

echo "=== Test 1: dnsmasq running in $CONTAINER_WG when WG_DEFAULT_DNS=10.8.0.1 ==="
if docker exec "$CONTAINER_WG" ps aux 2>/dev/null | grep -q "dnsmasq.*dnsmasq-amnezia"; then
  echo "OK: dnsmasq is running."
else
  echo "FAIL: dnsmasq not found. Set WG_DEFAULT_DNS=10.8.0.1 in .env and restart: docker compose up -d amnezia-wg-easy"
  exit 1
fi

echo ""
echo "=== Test 2: resolve $TEST_DOMAIN via 127.0.0.1 (dnsmasq -> amnezia-dns) ==="
if docker exec "$CONTAINER_WG" nslookup "$TEST_DOMAIN" 127.0.0.1 2>&1 | grep -q "Address:"; then
  echo "OK: resolution via 127.0.0.1 succeeded."
  docker exec "$CONTAINER_WG" nslookup "$TEST_DOMAIN" 127.0.0.1 2>&1 | grep -A 20 "Name:"
else
  echo "FAIL: nslookup $TEST_DOMAIN 127.0.0.1 failed."
  exit 1
fi

echo ""
echo "=== Test 3: resolve $TEST_DOMAIN via 10.8.0.1 (as VPN client would use) ==="
if docker exec "$CONTAINER_WG" nslookup "$TEST_DOMAIN" 10.8.0.1 2>&1 | grep -q "Address:"; then
  echo "OK: resolution via 10.8.0.1 succeeded."
else
  echo "FAIL: nslookup $TEST_DOMAIN 10.8.0.1 failed."
  exit 1
fi

echo ""
echo "=== Test 4: amnezia-dns container reachable from wg-easy ==="
if docker exec "$CONTAINER_WG" nc -z -u 172.29.172.254 53 2>/dev/null || docker exec "$CONTAINER_WG" sh -c "echo '' | timeout 2 nc -u 172.29.172.254 53" 2>/dev/null; then
  echo "OK: amnezia-dns:53 reachable from wg-easy."
else
  echo "WARN: could not probe amnezia-dns:53 (UDP); resolution above may still work."
fi

echo ""
echo "All checks passed. Amnezia DNS chain is working."
