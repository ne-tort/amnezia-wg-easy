'use strict';

const path = require('node:path');
const { release } = require('./package.json');

module.exports.CHECK_UPDATE = process.env.CHECK_UPDATE ? process.env.CHECK_UPDATE.toLowerCase() === 'true' : false;
module.exports.RELEASE = release;
module.exports.PORT = process.env.PORT || '51821';
module.exports.WEBUI_HOST = process.env.WEBUI_HOST || '0.0.0.0';
module.exports.WG_PATH = process.env.WG_PATH || '/opt/amnezia/awg/';
module.exports.DB_PATH = process.env.DB_PATH || path.join(module.exports.WG_PATH, 'panel.db');
// * Set SESSION_SECRET in production so sessions survive restarts.
module.exports.SESSION_SECRET = process.env.SESSION_SECRET || 'change-me-in-production';
module.exports.ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin';
module.exports.ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
module.exports.WG_DEVICE = process.env.WG_DEVICE || 'eth0';
module.exports.WG_HOST = process.env.WG_HOST;
module.exports.WG_PORT = process.env.WG_PORT || '51820';
// * MTU 1280 avoids fragmentation on mobile (large response packets often dropped otherwise). Set WG_MTU=none or empty to omit from client config.
const _mtu = process.env.WG_MTU;
module.exports.WG_MTU = (_mtu === '' || _mtu === 'none') ? null : (_mtu || '1280');
// * PersistentKeepalive: 0 can break connectivity behind mobile NAT; 25 keeps tunnel alive. Override via WG_PERSISTENT_KEEPALIVE.
module.exports.WG_PERSISTENT_KEEPALIVE = process.env.WG_PERSISTENT_KEEPALIVE !== undefined && process.env.WG_PERSISTENT_KEEPALIVE !== ''
  ? process.env.WG_PERSISTENT_KEEPALIVE
  : '25';
module.exports.WG_DEFAULT_ADDRESS = process.env.WG_DEFAULT_ADDRESS || '10.8.0.x';
// * Default DNS for client configs (comma-separated for multiple). 8.8.8.8, 8.8.4.4 = Google Public DNS. Override via WG_DEFAULT_DNS.
module.exports.WG_DEFAULT_DNS = typeof process.env.WG_DEFAULT_DNS === 'string'
  ? process.env.WG_DEFAULT_DNS
  : '8.8.8.8, 8.8.4.4';
// * DNS used in client config when "direct DNS" is selected (not server/Amnezia DNS). Override via WG_DIRECT_DNS.
module.exports.WG_DIRECT_DNS = typeof process.env.WG_DIRECT_DNS === 'string' && process.env.WG_DIRECT_DNS.trim()
  ? process.env.WG_DIRECT_DNS.trim()
  : '8.8.8.8, 8.8.4.4';
// * DEPRECATED: AllowedIPs in client config now come from firewall allow rules (global + profile + client). Left for env compatibility.
module.exports.WG_ALLOWED_IPS = process.env.WG_ALLOWED_IPS || '0.0.0.0/0';

module.exports.WG_PRE_UP = process.env.WG_PRE_UP || '';
// * Subnet for NAT/forward (e.g. 10.8.0.0/24). eth1 = amnezia-dns-net.
const WG_SUBNET = module.exports.WG_DEFAULT_ADDRESS.replace('x', '0') + '/24';
const WG_DEV = module.exports.WG_DEVICE;
const FIREWALL_BACKEND = (process.env.FIREWALL_BACKEND || 'nftables').toLowerCase();

function getDefaultPostUp() {
  if (FIREWALL_BACKEND === 'firewalld') {
    return [
      `firewall-cmd -q --permanent --add-masquerade 2>/dev/null || true`,
      `firewall-cmd -q --reload 2>/dev/null || true`,
    ].join(' ; ');
  }
  // * Use single quotes around nft chain blocks so shell (wg-quick) does not interpret ; and }
  return [
    `nft delete table ip amnezia_nat 2>/dev/null || true`,
    `nft add table ip amnezia_nat`,
    `nft add chain ip amnezia_nat postrouting '{ type nat hook postrouting priority 100; }'`,
    `nft add rule ip amnezia_nat postrouting ip saddr ${WG_SUBNET} oifname "${WG_DEV}" masquerade`,
    `nft add rule ip amnezia_nat postrouting ip saddr ${WG_SUBNET} oifname "eth1" masquerade`,
    `nft delete table inet amnezia_wg_base 2>/dev/null || true`,
    `nft add table inet amnezia_wg_base`,
    `nft add chain inet amnezia_wg_base input_awg0 '{ type filter hook input priority -100; policy accept; }'`,
    `nft add rule inet amnezia_wg_base input_awg0 udp dport ${module.exports.WG_PORT} accept`,
    `nft add chain inet amnezia_wg_base forward_awg0_base '{ type filter hook forward priority 0; policy accept; }'`,
    `nft add rule inet amnezia_wg_base forward_awg0_base iifname "awg0" accept`,
    `nft add rule inet amnezia_wg_base forward_awg0_base oifname "awg0" accept`,
    `nft add rule inet amnezia_wg_base forward_awg0_base iifname "awg0" oifname "eth1" ip saddr ${WG_SUBNET} accept`,
  ].join(' ; ');
}

function getDefaultPostDown() {
  if (FIREWALL_BACKEND === 'firewalld') {
    return 'true';
  }
  return [
    `nft delete table ip amnezia_nat 2>/dev/null || true`,
    `nft delete table inet amnezia_wg_base 2>/dev/null || true`,
  ].join(' ; ');
}

module.exports.WG_POST_UP = process.env.WG_POST_UP || getDefaultPostUp();
module.exports.WG_POST_DOWN = process.env.WG_POST_DOWN || getDefaultPostDown();
module.exports.FIREWALL_BACKEND = FIREWALL_BACKEND;
// * Default UI language. No auto-detection; user selects manually in the UI.
module.exports.LANG = process.env.LANGUAGE || 'ru';
module.exports.UI_TRAFFIC_STATS = process.env.UI_TRAFFIC_STATS || 'false';
module.exports.UI_CHART_TYPE = process.env.UI_CHART_TYPE || 0;

// * Traffic recorder: sample interval (seconds), flush interval (seconds), max buffer size before flush.
module.exports.TRAFFIC_SAMPLE_INTERVAL_SEC = Math.max(30, parseInt(process.env.TRAFFIC_SAMPLE_INTERVAL_SEC || '60', 10));
module.exports.TRAFFIC_FLUSH_INTERVAL_SEC = Math.max(60, parseInt(process.env.TRAFFIC_FLUSH_INTERVAL_SEC || '120', 10));
module.exports.TRAFFIC_BUFFER_MAX = Math.max(100, parseInt(process.env.TRAFFIC_BUFFER_MAX || '500', 10));

const getRandomInt = (min, max) => min + Math.floor(Math.random() * (max - min));
const getRandomJunkSize = () => getRandomInt(15, 150);

// H1–H4: AmneziaWG accepts single value ("1234") or range ("x-y"). Wide range = high entropy but
// not QUIC-realistic (QUIC headers have structure, not random int32). For "QUIC-realistic" profile
// set via env: H1=1-4096 H2=1-4096 H3=1-4096 H4=1-4096 (per Amnezia protocol).
const WG_HEADER_RANGE_DEFAULT = '1-2147483647';

// Jc: amneziawg-go README recommends 4–12. Jmin/Jmax: docs.amnezia suggest 64–1024 bytes for junk.
module.exports.JC = process.env.JC || getRandomInt(4, 12);
module.exports.JMIN = process.env.JMIN || 64;
module.exports.JMAX = process.env.JMAX || 1000;
module.exports.S1 = process.env.S1 || getRandomJunkSize();
module.exports.S2 = process.env.S2 || getRandomJunkSize();
module.exports.S3 = process.env.S3 || getRandomJunkSize();
module.exports.S4 = process.env.S4 || getRandomJunkSize();
module.exports.H1 = process.env.H1 || WG_HEADER_RANGE_DEFAULT;
module.exports.H2 = process.env.H2 || WG_HEADER_RANGE_DEFAULT;
module.exports.H3 = process.env.H3 || WG_HEADER_RANGE_DEFAULT;
module.exports.H4 = process.env.H4 || WG_HEADER_RANGE_DEFAULT;

// * Size in bytes for <r N> in level-based chain (I4, I5). Levels I2–I5 use I2=<c>, I3=<t>, I4/I5=<r N>.
module.exports.OBFS_R_BYTES = parseInt(process.env.OBFS_R_BYTES || '48', 10);

// I2–I5: when level is not used, optional server-stored values (legacy). Empty = skip.
module.exports.I2 = process.env.I2 || '';
module.exports.I3 = process.env.I3 || '';
module.exports.I4 = process.env.I4 || '';
module.exports.I5 = process.env.I5 || '';

// WG_QR_COMPACT: when true, QR encodes config without I1 (smaller, easier to scan).
// AmneziaWG works without I1 (AmneziaWG 1.0 mode). Use file download for full DPI config.
module.exports.WG_QR_COMPACT = process.env.WG_QR_COMPACT
  ? process.env.WG_QR_COMPACT.toLowerCase() === 'true'
  : false;
