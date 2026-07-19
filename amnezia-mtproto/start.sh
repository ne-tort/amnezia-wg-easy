#!/bin/bash
set -e
echo "amnezia-mtproto (telemt) container startup"
CFG=""
if [ -f /opt/amnezia/awg/mtproto/config.toml ]; then
  CFG=/opt/amnezia/awg/mtproto/config.toml
fi
if [ -z "$CFG" ] && [ -f /opt/amnezia/mtproto/config.toml ]; then
  CFG=/opt/amnezia/mtproto/config.toml
fi
if [ -n "$CFG" ]; then
  cd "$(dirname "$CFG")"
  exec telemt "$(basename "$CFG")"
fi
echo "No config.toml yet; waiting"
exec tail -f /dev/null
