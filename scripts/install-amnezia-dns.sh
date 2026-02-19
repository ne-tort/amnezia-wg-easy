#!/bin/bash
# Install Amnezia DNS directly (without Amnezia client).
# For the full stack (WG + panel + DNS), prefer: docker compose up -d (from repo root).
# This script is for standalone DNS (e.g. on another host). Same container as in amnezia-vpn/amnezia-client (server_scripts/dns).
# Requires: Docker. Run from repo root or set AMNEZIA_WG_FRESH_ROOT.

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${AMNEZIA_WG_FRESH_ROOT:-$(cd "$SCRIPT_DIR/.." && pwd)}"
DNS_DIR="$REPO_ROOT/amnezia-dns"
CONTAINER_NAME="amnezia-dns"
NETWORK_NAME="amnezia-dns-net"
DNS_IP="172.29.172.254"

if [ ! -f "$DNS_DIR/Dockerfile" ]; then
  echo "Error: $DNS_DIR/Dockerfile not found. Run from repo root or set AMNEZIA_WG_FRESH_ROOT."
  exit 1
fi

echo "[1/3] Creating Docker network $NETWORK_NAME if missing..."
if ! docker network ls --format '{{.Name}}' | grep -q "^${NETWORK_NAME}$"; then
  docker network create \
    --driver bridge \
    --subnet=172.29.172.0/24 \
    --opt "com.docker.network.bridge.name=amn0" \
    "$NETWORK_NAME"
  echo "Created $NETWORK_NAME."
else
  echo "Network $NETWORK_NAME already exists."
fi

echo "[2/3] Building Amnezia DNS image..."
docker build --no-cache --pull -t "$CONTAINER_NAME" "$DNS_DIR"

echo "[3/3] Running container $CONTAINER_NAME at $DNS_IP..."
docker rm -f "$CONTAINER_NAME" 2>/dev/null || true
docker run -d \
  --log-driver none \
  --restart always \
  --network "$NETWORK_NAME" \
  --ip "$DNS_IP" \
  --name "$CONTAINER_NAME" \
  "$CONTAINER_NAME"

echo "Done. Amnezia DNS is running at $DNS_IP (internal)."
echo "To use with amnezia-wg-easy: connect the WG container to this network and forward DNS to $DNS_IP (see project README)."
