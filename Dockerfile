# Amnezia WG-Easy panel image

FROM docker.io/library/node:20-alpine AS build_node_modules

# Keep the image npm (Node 20 ships npm 10). Do not bump to npm@latest — it may require Node 22+.

RUN for i in 1 2 3 4 5; do \
  apk add --no-cache --virtual .gyp-deps python3 make g++ && break; \
  echo "[build_node_modules] apk add build deps failed, retry $i/5..." >&2; \
  sleep 2; \
done

COPY src /app
WORKDIR /app
ENV npm_config_disturl=https://nodejs.org/dist
RUN npm ci --omit=dev && \
    mv node_modules /node_modules

FROM amneziavpn/amneziawg-go:latest

HEALTHCHECK CMD /usr/bin/timeout 5s /bin/sh -c "/usr/bin/wg show awg0 >/dev/null 2>&1 || exit 1" --interval=1m --timeout=5s --retries=3

RUN mkdir -p /app /opt/amnezia/awg

RUN for i in 1 2 3 4 5; do \
    apk add --no-cache nodejs npm && break; \
    echo "[panel] apk add nodejs/npm failed, retry $i/5..." >&2; \
    sleep 2; \
done

RUN for i in 1 2 3 4 5; do \
    apk add --no-cache \
      bind-tools \
      dpkg \
      dumb-init \
      dnsmasq \
      docker-cli \
      iptables \
      nftables \
      curl \
      openssl && break; \
    echo "[panel] apk add runtime tools failed, retry $i/5..." >&2; \
    sleep 2; \
done
# Compose plugin for portPlan recreate (community repo; optional if mirror lacks it).
RUN apk add --no-cache docker-cli-compose 2>/dev/null \
  || echo "[panel] docker-cli-compose unavailable — portPlan will use docker-run fallback"

ENV DEBUG=Server,WireGuard

RUN mkdir -p /var/run/amneziawg && \
    sed -i '/cmd.*amneziawg-go.*INTERFACE/a\
		sleep 2;\
		i=0; while [ \$i -lt 120 ]; do [ -S /var/run/amneziawg/\$INTERFACE.sock ] \&\& break; sleep 0.5; i=\$((i+1)); done' /usr/bin/awg-quick

COPY config/dnsmasq-amnezia.conf /etc/dnsmasq-amnezia.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

COPY migrations /migrations

COPY --from=build_node_modules /app /app
COPY --from=build_node_modules /node_modules /app/node_modules
# Seed after app copy so it is never wiped by the build stage overlay.
COPY config/signatures.seed.json /app/config/signatures.seed.json
COPY config/dns-profiles.seed.json /app/config/dns-profiles.seed.json
COPY config/junk-ranges.seed.json /app/config/junk-ranges.seed.json
COPY config/mtu-profiles.seed.json /app/config/mtu-profiles.seed.json
COPY config/roles.labels.json /app/config/roles.labels.json
COPY config/sni-bank.seed.json /app/config/sni-bank.seed.json
COPY config/sni-blocked.seed.json /app/config/sni-blocked.seed.json
COPY config/mirror-bank.seed.json /app/config/mirror-bank.seed.json

COPY scripts/cascade-in-container-postup.sh scripts/cascade-in-container-predown.sh /app/scripts/
RUN chmod +x /app/scripts/cascade-in-container-postup.sh /app/scripts/cascade-in-container-predown.sh

# Same path as Amnezia client (/opt/amnezia/amnezia-dns) for on-demand docker build from the panel.
COPY amnezia-dns/Dockerfile /opt/amnezia/amnezia-dns/Dockerfile
# Xray VLESS Reality image sources (stdin docker build from panel; deploy.sh also pre-builds).
COPY amnezia-xray/Dockerfile amnezia-xray/start.sh /opt/amnezia/xray/

WORKDIR /app
CMD ["/entrypoint.sh"]
