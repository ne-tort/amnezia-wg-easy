#!/bin/sh
# Amnezia DNS (dnsmasq): start only when not disabled and WG_DEFAULT_DNS equals VPN gateway.
# Gateway is derived from WG_DEFAULT_ADDRESS (e.g. 10.8.0.x -> 10.8.0.1). Set AMNEZIA_DNS_ENABLE=0 to disable.
set -e
case "${AMNEZIA_DNS_ENABLE}" in
  0|[Ff][Aa][Ll][Ss][Ee]|[Nn][Oo]|[Oo][Ff][Ff]|[Dd][Ii][Ss][Aa][Bb][Ll][Ee][Dd]) ;;
  *)
    WG_GW="${WG_DEFAULT_ADDRESS:-10.8.0.x}"
    WG_GW="${WG_GW%x}1"
    if [ -n "$WG_DEFAULT_DNS" ] && [ "$WG_DEFAULT_DNS" = "$WG_GW" ]; then
      dnsmasq -C /etc/dnsmasq-amnezia.conf -k &
    fi
    ;;
esac
exec /usr/bin/dumb-init node server.js
