FROM rwecho/caddy-forwardproxy:latest
LABEL maintainer="AmneziaVPN / amnezia-wg-easy"

RUN mkdir -p /opt/amnezia/naive /opt/amnezia/awg/naive /var/www/html

# Entrypoint: prefer volume-backed config under panel data mount (/opt/amnezia/awg/naive).
RUN printf '%s\n' \
  '#!/bin/sh' \
  'set -e' \
  'echo "amnezia-naive container startup"' \
  'CFG=""' \
  'if [ -f /opt/amnezia/awg/naive/Caddyfile ]; then CFG=/opt/amnezia/awg/naive/Caddyfile; fi' \
  'if [ -z "$CFG" ] && [ -f /opt/amnezia/naive/Caddyfile ]; then CFG=/opt/amnezia/naive/Caddyfile; fi' \
  'if [ -n "$CFG" ]; then' \
  '  exec caddy run --config "$CFG" --adapter caddyfile' \
  'fi' \
  'echo "No Caddyfile yet; waiting"' \
  'exec tail -f /dev/null' \
  > /opt/amnezia/start.sh \
  && chmod a+x /opt/amnezia/start.sh

ENTRYPOINT ["/opt/amnezia/start.sh"]
