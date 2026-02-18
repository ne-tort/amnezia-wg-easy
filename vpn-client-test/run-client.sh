#!/bin/bash
# Run AmneziaWG client in Docker with host network.
# Expects wg0.conf in the same directory. Uses amneziavpn/amneziawg-go and resolvconf stub.

set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
CONFIG_DIR="$DIR"
BIN_DIR="$DIR/bin"
mkdir -p "$BIN_DIR"
if [ ! -x "$BIN_DIR/resolvconf" ]; then
  echo '#!/bin/sh' > "$BIN_DIR/resolvconf"
  echo 'exit 0' >> "$BIN_DIR/resolvconf"
  chmod +x "$BIN_DIR/resolvconf"
fi

if [ ! -f "$CONFIG_DIR/wg0.conf" ]; then
  echo "Error: wg0.conf not found in $CONFIG_DIR"
  exit 1
fi

docker rm -f amneziawg-client 2>/dev/null || true

docker run -dit \
  --name=amneziawg-client \
  -v "$CONFIG_DIR:/config" \
  -v "$BIN_DIR:/usr/local/bin:ro" \
  --network=host \
  --device=/dev/net/tun:/dev/net/tun \
  --cap-add=NET_ADMIN \
  --cap-add=SYS_MODULE \
  --restart=unless-stopped \
  --entrypoint= \
  amneziavpn/amneziawg-go:latest \
  /bin/sh -c "export PATH=/usr/local/bin:\$PATH; awg-quick up /config/wg0.conf; sleep infinity"

echo "Container amneziawg-client started. Check: ip a | grep 10.8 or wg show"
