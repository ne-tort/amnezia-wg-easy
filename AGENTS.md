# Agent notes — Amnezia WG-Easy

## Epic: Xray VLESS Reality in panel

Integrate Docker `amnezia-xray` (VLESS + REALITY) similar to Amnezia DNS: UI install toggle, per-client UUID synced with AWG clients, public `{SUB_PUBLIC_PREFIX}/{name}` (default `/sub`), `vless://`, QR, and Amnezia `.vpn` export.

Defaults (FQDN): `PANEL_HTTPS_PORT` = `XRAY_PUBLIC_PORT` = `MTPROTO_PUBLIC_PORT` = **443** → nginx SNI demux; unknown SNI → panel TLS; UI at `/panel/`, root `/` = reverse-proxy mirror. Bare IP: panel soft-forced off shared 443 (default 10123). Internal listen 20000–50000 (exclude-list, not host-scan). `WG_PORT` random free UDP in 20000–50000 unless set.

**Persistence (source of truth):** `app_settings` + `clients.xray_uuid` + `{WG_PATH}/xray/server.json` on volume `amnezia-wg-data`. Disable/redeploy panel must **not** wipe Reality keys or client UUIDs. `WireGuard.__saveConfig` / `clients.replaceAll` must round-trip `xray_uuid`. Deploy only builds sidecar images; panel starts/stops containers by `desired`.

**Connect vs camouflage:** `amnezia_xray_address` = TCP host in `vless://`; `amnezia_xray_sni` = Reality site. Client-facing port = **publicPort**. `spiderX` empty.

**SNI Finder:** `src/lib/sniFinder.js` — public-IP guard, TLS+HTTP/2, cache TTL 24h + bank `config/sni-bank.seed.json`.

## Epic: Unified Port Plan + paths + mirror

`src/lib/portPlan.js` — group by public TCP: shared → stream SNI demux; exclusive → direct `-p`. Panel joins demux only with **FQDN** SNI; bare IP → conflict + no panel route; demux `default` → panel when panel in map, else `:9`.

Nginx: `WEBUI_PUBLIC_PREFIX=/panel` (UI+API), `SUB_PUBLIC_PREFIX=/sub`, `NGINX_ROOT_BEHAVIOR=mirror` + `NGINX_MIRROR_HOST`. DNS VPN-only (no host 53/853).

### Checklist

- [x] Xray/MTProto + portPlan demux/direct + publicPort
- [x] Panel FQDN catch-all default; bare-IP excluded
- [x] `/panel` + `/panel/api` + configurable `/sub`
- [x] install paths + mirror host from sni-bank
- [x] SNI Finder; persist keys/UUID; Amnezia export

### Reference

- DNS: `src/lib/amneziaDns.js`
- Export: `src/lib/amneziaClientQr.js`
- Port plan: `src/lib/portPlan.js`
- Nginx: `nginx/entrypoint.sh`, `nginx/panel-subpath.conf.template`
