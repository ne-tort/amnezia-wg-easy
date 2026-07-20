#!/bin/bash
# Reference entrypoint (also embedded in Dockerfile for stdin docker build).
set -e
echo "amnezia-mieru container startup"
PORT="${MIERU_SERVER_PORT:-3080}"
CFG=""
if [ -f /opt/amnezia/awg/mieru/server.json ]; then CFG=/opt/amnezia/awg/mieru/server.json; fi
if [ -z "$CFG" ] && [ -f /opt/amnezia/mieru/server.json ]; then CFG=/opt/amnezia/mieru/server.json; fi

mita run &
sleep 2

if [ -n "$CFG" ]; then
  APPLY="$CFG"
  if jq -e '.port and (.portBindings|not)' "$CFG" >/dev/null 2>&1; then
    APPLY="/tmp/mita-apply.json"
    jq --argjson p "$(jq -r .port "$CFG")" --arg pr "$(jq -r .protocol "$CFG")" \
      '. + {portBindings:[{port:$p,protocol:$pr}]} | del(.port,.protocol)' "$CFG" > "$APPLY"
  fi
  mita apply config "$APPLY"
  mita start
fi

wait -n
