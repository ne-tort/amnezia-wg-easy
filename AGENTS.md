# Agent notes — Amnezia WG-Easy

## Epic: Xray VLESS Reality in panel

Integrate Docker `amnezia-xray` (VLESS + REALITY) similar to Amnezia DNS: UI install toggle, per-client UUID synced with AWG clients, public `/sub/{name}`, `vless://`, QR, and Amnezia `.vpn` export.

Defaults: `XRAY_PORT=8443` (nginx already uses host 443). SNI/fp/flow/address/port configurable from UI.

**Persistence (source of truth):** `app_settings` + `clients.xray_uuid` + `{WG_PATH}/xray/server.json` on volume `amnezia-wg-data`. Disable/redeploy panel must **not** wipe Reality keys or client UUIDs. `WireGuard.__saveConfig` / `clients.replaceAll` must round-trip `xray_uuid` (otherwise every Xray toggle regen’d UUIDs). Deploy only builds the `amnezia-xray` image; the panel starts/stops the container by `desired`.

**Connect vs camouflage:** `amnezia_xray_address` = TCP host in `vless://`; `amnezia_xray_sni` = Reality site. `spiderX` stays empty (Amnezia/Xray default `/`; omit from URL).

**SNI Finder:** panel-native scan (`src/lib/sniFinder.js`) — public-IP guard, default VPS `/24`, TLS+HTTP/2 probe, merge-cache `{WG_PATH}/xray/sni-cache.json` TTL 24h + bank `config/sni-bank.seed.json` (override `{WG_PATH}/xray/sni-bank.json`). Scan=green, bank=yellow, dead=red. Background ensure on boot / `?ensureBg=1`. No masscan; no GPL vendoring.

### Checklist

- [x] Scaffold `amneziaXray.js` + keys/settings + Dockerfile/scripts under `amnezia-xray/`
- [x] Docker enable/disable/smoke/boot/reconcile
- [x] DB: `xray_uuid` + migration; sync clients → `server.json`
- [x] API + ACL (`system.xray`, admin) + `serverCapabilities`
- [x] Public `GET /sub/:name` + vless builder
- [x] Amnezia `.vpn` / QR export includes `amnezia-xray` when running
- [x] UI header toggle + install modal (SNI, fingerprint, flow, port, address)
- [x] UI Preview Xray JSON + tab **xRay** (QR → sub URL, copy sub + vless)
- [x] compose/env/deploy docs (`XRAY_PORT`)
- [x] Contract + HTTP tests + smoke script
- [x] Persist keys/UUID across disable; boot teardown orphans when desired=0
- [x] `amnezia_xray_address` (default panel hostname, override IP/domain)
- [x] Reset API/UI (new Reality keys + all client UUIDs) — reset as title icon
- [x] spiderX empty; QR copy fields width-locked to QR
- [x] SNI Finder UI + cache TTL 24h + public IP guard

### Reference

- Amnezia client scripts: `amnezia-client/client/server_scripts/xray/`
- Panel DNS orchestration pattern: `src/lib/amneziaDns.js`
- Export: `src/lib/amneziaClientQr.js`
- SNI discovery inspiration: Reality-SNI-Finder, RealiTLScanner (not vendored)
