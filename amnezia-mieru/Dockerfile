FROM ghcr.io/enfein/mita:v3.34.0
LABEL maintainer="AmneziaVPN / amnezia-wg-easy"

RUN apk add --no-cache dumb-init bash netcat-openbsd jq \
  && apk --update upgrade --no-cache

RUN mkdir -p /opt/amnezia/mieru /opt/amnezia/awg/mieru

COPY start.sh /opt/amnezia/start.sh
RUN chmod a+x /opt/amnezia/start.sh

ENTRYPOINT [ "dumb-init", "/opt/amnezia/start.sh" ]
