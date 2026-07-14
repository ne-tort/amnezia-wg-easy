# Amnezia DNS — Unbound (+ Emercoin stubs). Upstream forwarders come from a profile
# written by the panel to /opt/amnezia/awg/amnezia-dns/forward-records.conf at enable time.
FROM mvance/unbound:latest

LABEL maintainer="AmneziaVPN"

# Fallback forwarders (Cloudflare DoT) if no profile file is mounted.
RUN echo " \n\
domain-insecure: \"coin.\"\n\
domain-insecure: \"emc.\"\n\
domain-insecure: \"lib.\"\n\
domain-insecure: \"bazar.\"\n\
domain-insecure: \"enum.\"\n\
\n\
stub-zone:\n\
 name: coin.\n\
 stub-host: seed1.emercoin.com\n\
 stub-host: seed2.emercoin.com\n\
 stub-first: yes\n\
\n\
stub-zone:\n\
 name: emc.\n\
 stub-host: seed1.emercoin.com\n\
 stub-host: seed2.emercoin.com\n\
 stub-first: yes\n\
\n\
stub-zone:\n\
 name: lib.\n\
 stub-host: seed1.emercoin.com\n\
 stub-host: seed2.emercoin.com\n\
 stub-first: yes\n\
\n\
stub-zone:\n\
 name: bazar.\n\
 stub-host: seed1.emercoin.com\n\
 stub-host: seed2.emercoin.com\n\
 stub-first: yes\n\
\n\
stub-zone:\n\
 name: enum.\n\
 stub-host: seed1.emercoin.com\n\
 stub-host: seed2.emercoin.com\n\
 stub-first: yes\n\
\n\
forward-zone:\n\
 name: .\n\
 forward-tls-upstream: yes\n\
 forward-addr: 1.1.1.1@853#cloudflare-dns.com\n\
 forward-addr: 1.0.0.1@853#cloudflare-dns.com\n\
" | tee /opt/unbound/etc/unbound/forward-records.conf

# Entrypoint (inline so `docker build -` from panel still works without build context).
RUN printf '%s\n' \
  '#!/bin/sh' \
  'SRC=/opt/amnezia/awg/amnezia-dns/forward-records.conf' \
  'DST=/opt/unbound/etc/unbound/forward-records.conf' \
  'if [ -f "$SRC" ]; then cp "$SRC" "$DST" || true; fi' \
  'exec /unbound.sh' \
  > /entrypoint-dns.sh && chmod +x /entrypoint-dns.sh

ENTRYPOINT ["/entrypoint-dns.sh"]
