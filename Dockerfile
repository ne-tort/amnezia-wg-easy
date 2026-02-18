# Amnezia WG-Easy — custom build with DPI patches and UI modifications
# Based on https://github.com/imbtqd/amnezia-wg-easy

FROM docker.io/library/node:20-alpine AS build_node_modules

RUN npm install -g npm@latest

COPY src /app
WORKDIR /app
RUN npm ci --omit=dev && \
    mv node_modules /node_modules

FROM amneziavpn/amneziawg-go:latest

HEALTHCHECK CMD /usr/bin/timeout 5s /bin/sh -c "/usr/bin/wg show | /bin/grep -q interface || exit 1" --interval=1m --timeout=5s --retries=3
COPY --from=build_node_modules /app /app

RUN apk add --no-cache \
    nodejs \
    npm

COPY --from=build_node_modules /node_modules /node_modules

RUN apk add --no-cache \
    dpkg \
    dumb-init \
    dnsmasq \
    iptables

ENV DEBUG=Server,WireGuard

RUN mkdir -p /etc/amnezia/amneziawg

COPY config/dnsmasq-amnezia.conf /etc/dnsmasq-amnezia.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

WORKDIR /app
CMD ["/entrypoint.sh"]
