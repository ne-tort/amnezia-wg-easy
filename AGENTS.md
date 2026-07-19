# Agent notes — Amnezia WG-Easy

## Workflow

После завершения задачи с изменениями в репо — **сразу commit + push** на origin, без вопроса «закоммитить?». Не коммитить `scripts/_remote_*`, секреты, `.env`.

## Epic: Xray VLESS Reality in panel

Integrate Docker `amnezia-xray` (VLESS + REALITY) similar to Amnezia DNS: UI install toggle, per-client UUID synced with AWG clients, public `{SUB_PUBLIC_PREFIX}/{name}` (default `/sub`), `vless://`, QR, and Amnezia `.vpn` export.

Defaults: `PANEL_HTTPS_PORT` = `XRAY_PUBLIC_PORT` = **443** → nginx SNI demux. Known SNI → Xray (and panel FQDN); unknown/missing SNI → panel TLS only for **bare IP** (mirror + `/panel/`); with panel FQDN stub/UI only via panel SNI (`default` → `:9`). Internal listen 20000–50000 (exclude-list, not host-scan). `WG_PORT` random free UDP in 20000–50000 unless set.

**Persistence (source of truth):** `app_settings` + `clients.xray_uuid` + `{WG_PATH}/xray/server.json` on volume `amnezia-wg-data`. Disable/redeploy panel must **not** wipe Reality keys or client UUIDs. `WireGuard.__saveConfig` / `clients.replaceAll` must round-trip `xray_uuid`. Deploy only builds sidecar images; panel starts/stops containers by `desired`.

**Connect vs camouflage:** `amnezia_xray_address` = TCP host in `vless://`; `amnezia_xray_sni` = Reality site. Client-facing port = **publicPort**. `spiderX` empty.

**SNI bank (Reality):** `config/sni-bank.seed.json` → volume override `{WG_PATH}/xray/sni-bank.json`. Used by `sniFinder` (UI Finder for Xray install modal), `amneziaXray.getSni` / `pickDefaultSni`, and `install.sh` enable fallbacks. Mirror root uses separate `config/mirror-bank.seed.json`.

## Epic: Unified Port Plan + paths + mirror

`src/lib/portPlan.js` — group by public TCP: shared → stream SNI demux; exclusive → direct `-p`. Named SNI routes: Xray + panel **FQDN** only. Bare IP panel: no named route; demux `default` → panel TLS. FQDN panel: `default` → `:9` (stub/UI on panel SNI).

Nginx: `WEBUI_PUBLIC_PREFIX=/panel` (UI+API), `SUB_PUBLIC_PREFIX=/sub`, `NGINX_ROOT_BEHAVIOR=mirror` + `NGINX_MIRROR_HOST`. DNS VPN-only (no host 53/853).

### Checklist

- [x] Xray + portPlan demux/direct + publicPort
- [x] Panel FQDN via named SNI; bare-IP via catch-all default
- [x] `/panel` + `/panel/api` + configurable `/sub`
- [x] install paths + mirror host from sni-bank
- [x] SNI Finder; persist keys/UUID; Amnezia export

### Reference

- DNS: `src/lib/amneziaDns.js`
- Export: `src/lib/amneziaClientQr.js`
- Port plan: `src/lib/portPlan.js`
- Nginx: `nginx/entrypoint.sh`, `nginx/panel-subpath.conf.template`
