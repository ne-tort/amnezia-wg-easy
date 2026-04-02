#!/bin/bash
# Linux / WSL с Docker: --network host → Endpoint должен быть 127.0.0.1:51820
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

RUN_CONF="$CONFIG_DIR/wg0.conf.run"
sed 's/^Endpoint = .*/Endpoint = 127.0.0.1:51820/' "$CONFIG_DIR/wg0.conf" > "$RUN_CONF"

docker rm -f amneziawg-client 2>/dev/null || true

docker run -dit \
  --name=amneziawg-client \
  -v "$RUN_CONF:/config/wg0.conf:ro" \
  -v "$BIN_DIR:/usr/local/bin:ro" \
  --network=host \
  --device=/dev/net/tun:/dev/net/tun \
  --cap-add=NET_ADMIN \
  --cap-add=SYS_MODULE \
  --privileged \
  --restart=unless-stopped \
  --entrypoint= \
  amneziavpn/amneziawg-go:latest \
  /bin/sh -c 'export PATH=/usr/local/bin:$PATH; awg-quick up /config/wg0.conf; sleep infinity'

echo "amneziawg-client (host network). Try: docker exec amneziawg-client ping -c 2 10.8.0.1"
