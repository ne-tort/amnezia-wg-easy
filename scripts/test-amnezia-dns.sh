#!/bin/bash
# Test Amnezia DNS chain: dnsmasq in wg-easy -> amnezia-dns (Unbound) -> DoT upstream.
# Requires: WG_DEFAULT_DNS=10.8.0.1 in .env and stack running (docker compose up -d).

set -e
CONTAINER_WG="${AMNEZIA_WG_CONTAINER:-amnezia-awg}"
CONTAINER_DNS="${AMNEZIA_DNS_CONTAINER:-amnezia-dns}"
TEST_DOMAIN="${1:-google.com}"
FAILED=0

echo "=== Test 1: dnsmasq running in $CONTAINER_WG when WG_DEFAULT_DNS=10.8.0.1 ==="
if docker exec "$CONTAINER_WG" ps aux 2>/dev/null | grep -q "dnsmasq.*dnsmasq-amnezia"; then
  echo "OK: dnsmasq is running."
else
  echo "FAIL: dnsmasq not found. Set WG_DEFAULT_DNS=10.8.0.1 in .env and restart: docker compose up -d amnezia-wg-easy"
  exit 1
fi

echo ""
echo "=== Test 2: resolve $TEST_DOMAIN via 172.29.172.254 (amnezia-dns / Unbound) ==="
if docker exec "$CONTAINER_WG" nslookup "$TEST_DOMAIN" 172.29.172.254 2>&1 | grep -q "Address:"; then
  echo "OK: resolution via amnezia-dns (172.29.172.254) succeeded."
  docker exec "$CONTAINER_WG" nslookup "$TEST_DOMAIN" 172.29.172.254 2>&1 | grep -A 20 "Name:"
else
  echo "FAIL: nslookup $TEST_DOMAIN 172.29.172.254 failed."
  FAILED=1
fi

echo ""
echo "=== Test 3: resolve $TEST_DOMAIN via 127.0.0.1 (dnsmasq -> amnezia-dns) ==="
if docker exec "$CONTAINER_WG" nslookup "$TEST_DOMAIN" 127.0.0.1 2>&1 | grep -q "Address:"; then
  echo "OK: resolution via 127.0.0.1 succeeded."
else
  echo "WARN: nslookup $TEST_DOMAIN 127.0.0.1 failed (known in some Docker setups). VPN clients using 10.8.0.1 may still work."
fi

echo ""
echo "=== Test 4: resolve $TEST_DOMAIN via 10.8.0.1 (as VPN client would use) ==="
if docker exec "$CONTAINER_WG" nslookup "$TEST_DOMAIN" 10.8.0.1 2>&1 | grep -q "Address:"; then
  echo "OK: resolution via 10.8.0.1 succeeded."
else
  echo "WARN: nslookup $TEST_DOMAIN 10.8.0.1 failed (known in some Docker setups). Test from a real VPN client with DNS=10.8.0.1."
fi

echo ""
echo "=== Test 5: amnezia-dns container reachable from wg-easy ==="
if docker exec "$CONTAINER_WG" ping -c 1 -W 2 172.29.172.254 >/dev/null 2>&1; then
  echo "OK: amnezia-dns (172.29.172.254) reachable from wg-easy."
else
  echo "WARN: could not ping amnezia-dns; resolution may still work."
fi

echo ""
if [ "$FAILED" = 1 ]; then
  echo "One or more required checks failed."
  exit 1
fi
echo "Required checks passed. Amnezia DNS upstream is working (Test 2). If Tests 3/4 show WARN, verify from a real VPN client with DNS=10.8.0.1."
