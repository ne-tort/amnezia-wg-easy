# Amnezia WG-Easy — custom build with DPI patches and UI modifications
# Based on https://github.com/imbtqd/amnezia-wg-easy
#
# * Node deps: npm ci requires src/package-lock.json to be in sync with src/package.json.
#   After changing src/package.json run: docker run --rm -v "$(pwd)/src:/app" -w /app node:20-alpine npm install
#   then commit the updated src/package-lock.json (so the image build stays reproducible).

FROM docker.io/library/node:20-alpine AS build_node_modules

RUN npm install -g npm@latest

# better-sqlite3 при отсутствии prebuild падает в сборку через node-gyp,
# которому нужен Python и toolchain.
RUN for i in 1 2 3 4 5; do \
  apk add --no-cache --virtual .gyp-deps python3 make g++ && break; \
  echo "[build_node_modules] apk add build deps failed, retry $i/5..." >&2; \
  sleep 2; \
done

COPY src /app
WORKDIR /app
RUN npm ci --omit=dev && \
    mv node_modules /node_modules

# * Python deps: Poetry builds requirements.txt; final image uses pip only (no Poetry at runtime).
# * pybuilder uses 3.11-slim (aligned with pyproject.toml python >=3.10).
FROM docker.io/library/python:3.11-slim AS pybuilder
RUN pip install --no-cache-dir poetry poetry-plugin-export
WORKDIR /build
COPY pyproject.toml poetry.lock* ./
COPY python_signatures ./python_signatures
RUN poetry config virtualenvs.create false && \
    poetry export -f requirements.txt --without-hashes --only main -o requirements.txt

FROM amneziavpn/amneziawg-go:latest

HEALTHCHECK CMD /usr/bin/timeout 5s /bin/sh -c "/usr/bin/wg show awg0 >/dev/null 2>&1 || exit 1" --interval=1m --timeout=5s --retries=3

# * Layer order for cache: heavy installs (apk, pip) before any COPY that changes with app code.
#   Changing src/ or python_signatures then only re-copies artifacts, not re-downloads packages.
RUN mkdir -p /app /opt/amnezia/awg

# Alpine apk иногда падает из-за временных проблем с загрузкой индексов.
# Добавляем небольшой retry, чтобы сборка была стабильнее.
RUN for i in 1 2 3 4 5; do \
    apk add --no-cache nodejs npm && break; \
    echo "[panel] apk add nodejs/npm failed, retry $i/5..." >&2; \
    sleep 2; \
done

# * Runtime Python and DNS/tooling; nftables for firewall backend (FIREWALL_BACKEND=nftables).
RUN for i in 1 2 3 4 5; do \
    apk add --no-cache \
      bind-tools \
      dpkg \
      dumb-init \
      dnsmasq \
      iptables \
      nftables \
      python3 \
      py3-pip \
      tcpdump \
      curl \
      openssl && break; \
    echo "[panel] apk add runtime tools failed, retry $i/5..." >&2; \
    sleep 2; \
done

COPY --from=pybuilder /build/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --break-system-packages -r /app/requirements.txt

COPY python_signatures /app/python_signatures
ENV PYTHONPATH=/app
ENV DEBUG=Server,WireGuard

# * After amneziawg-go daemonizes, wait for UAPI socket before awg setconf (fixes "Unable to modify interface: Invalid argument").
RUN mkdir -p /var/run/amneziawg && \
    sed -i '/cmd.*amneziawg-go.*INTERFACE/a\
		sleep 2;\
		i=0; while [ \$i -lt 120 ]; do [ -S /var/run/amneziawg/\$INTERFACE.sock ] \&\& break; sleep 0.5; i=\$((i+1)); done' /usr/bin/awg-quick

COPY config/dnsmasq-amnezia.conf /etc/dnsmasq-amnezia.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

COPY scripts/cascade-in-container-postup.sh scripts/cascade-in-container-predown.sh /app/scripts/
RUN chmod +x /app/scripts/cascade-in-container-postup.sh /app/scripts/cascade-in-container-predown.sh

# * Migrations path in runtime: path.join(__dirname, '..','..','migrations') from /app/lib => /migrations
COPY migrations /migrations

# * App code and node_modules last so cache is invalidated only when src/ or lockfile changes.
COPY --from=build_node_modules /app /app
COPY --from=build_node_modules /node_modules /app/node_modules

WORKDIR /app
CMD ["/entrypoint.sh"]
