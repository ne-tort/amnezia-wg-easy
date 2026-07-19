FROM debian:12-slim
LABEL maintainer="AmneziaVPN / amnezia-wg-easy"
LABEL amnezia.service=mtproto

ARG TARGETARCH=amd64
ARG TELEMT_VERSION=latest

RUN set -eux; \
  apt-get update; \
  apt-get install -y --no-install-recommends ca-certificates curl tar netcat-openbsd; \
  rm -rf /var/lib/apt/lists/*

RUN set -eux; \
  case "${TARGETARCH}" in \
    amd64|x86_64) ASSET="telemt-x86_64-linux-musl.tar.gz" ;; \
    arm64|aarch64) ASSET="telemt-aarch64-linux-musl.tar.gz" ;; \
    *) echo "Unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1 ;; \
  esac; \
  if [ "${TELEMT_VERSION}" = "latest" ]; then \
    BASE_URL="https://github.com/telemt/telemt/releases/latest/download"; \
  else \
    BASE_URL="https://github.com/telemt/telemt/releases/download/${TELEMT_VERSION}"; \
  fi; \
  curl -fL --retry 5 --retry-delay 3 --connect-timeout 10 --max-time 180 \
    -o "/tmp/${ASSET}" "${BASE_URL}/${ASSET}"; \
  tar -xzf "/tmp/${ASSET}" -C /tmp; \
  install -m 0755 /tmp/telemt /usr/local/bin/telemt; \
  rm -rf /tmp/*

RUN mkdir -p /opt/amnezia/awg/mtproto

COPY start.sh /opt/amnezia/start.sh
RUN sed -i 's/\r$//' /opt/amnezia/start.sh && chmod a+x /opt/amnezia/start.sh

ENTRYPOINT ["/opt/amnezia/start.sh"]
