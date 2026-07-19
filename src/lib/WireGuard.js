'use strict';

const fs = require('node:fs/promises');
const path = require('path');
const dns = require('node:dns').promises;
const debug = require('debug')('WireGuard');
const crypto = require('node:crypto');
const QRCode = require('qrcode');

const Util = require('./Util');
const ServerError = require('./ServerError');
const db = require('./db');
const { migrateAwgToDb } = require('./migrateAwgToDb');
const {
  loadBank,
  ensureBinding,
  assignNewClientBinding,
  pickRandomVariant,
  listVariants,
  BankError,
} = require('./signaturesBank');
const { isKnownProfile } = require('./obfuscationProfiles');
const { isAmneziaDnsAvailable, getStatus: getAmneziaDnsStatus } = require('./amneziaDns');
const {
  isAmneziaXrayAvailable,
  getStatus: getAmneziaXrayStatus,
  syncClientsFromDb: syncAmneziaXrayClients,
  ensureClientUuids: ensureAmneziaXrayClientUuids,
} = require('./amneziaXray');
const { computeClientPresence } = require('./clientPresence');
const { CLIENT_ONLINE_WINDOW_MS } = require('../config');

function scheduleAmneziaXraySync() {
  try {
    const st = getAmneziaXrayStatus();
    if (st.desired !== true && st.phase !== 'running' && st.phase !== 'degraded') return;
    syncAmneziaXrayClients().catch((err) => {
      // eslint-disable-next-line no-console
      console.error('Amnezia Xray sync:', err && err.message ? err.message : err);
    });
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Amnezia Xray sync schedule:', err && err.message ? err.message : err);
  }
}
const {
  generateAmneziaClientQrSvgs,
  buildAmneziaVpnExport,
  countAmneziaQrChunks,
  MAX_AMNEZIA_QR_CHUNKS,
  parseEndpoint,
} = require('./amneziaClientQr');
const junkParams = require('./junkParams');
const mtuProfiles = require('./mtuProfiles');

const {
  WG_PATH,
  WG_HOST,
  WG_PORT,
  WG_MTU,
  WG_DEFAULT_DNS,
  WG_DIRECT_DNS,
  WG_DEFAULT_ADDRESS,
  WG_PERSISTENT_KEEPALIVE,
  WG_PRE_UP,
  WG_POST_UP,
  WG_POST_UP_OVERRIDE,
  WG_PRE_DOWN,
  WG_POST_DOWN,
  buildNatPostUp,
  JC,
  JMIN,
  JMAX,
  S1,
  S2,
  S3,
  S4,
  H1,
  H2,
  H3,
  H4,
  WG_QR_COMPACT,
  WG_CASCADE_ENABLED,
  WG_CASCADE_CONF_FILE,
  WG_CASCADE_ADDRESS,
  WG_CASCADE_EXIT_TUNNEL_IP,
  WG_CASCADE_EXIT_PUBLIC_KEY,
  WG_CASCADE_EXIT_ENDPOINT,
  resolveCascadeClientSubnet,
} = require('../config');
const vpnAddress = require('./vpnAddress');

// * Official Amnezia client pattern: awg0.conf and interface awg0 in /opt/amnezia/awg/
const AWG_JSON = 'awg0.json';
const AWG_CONF = 'awg0.conf';
const AWG_IFACE = 'awg0';

const AWG_CASCADE_CONF = WG_CASCADE_CONF_FILE || 'awg-cascade.conf';
const AWG_CASCADE_IFACE = String(AWG_CASCADE_CONF).replace(/\.conf$/i, '') || 'awg-cascade';
const CASCADE_LINK_KEY = 'cascade_link.private';
const CASCADE_LINK_PUB = 'cascade_link.public';
const CASCADE_EXIT_PUB_FILE = 'cascade_exit.public';
const CASCADE_EXIT_ENDPOINT_FILE = 'cascade_exit.endpoint';

/**
 * Parses IPv4 CIDR string (a.b.c.d/len) into numeric prefix and prefix length.
 * @param {string} cidr - e.g. "10.8.0.0/24"
 * @returns {{ prefix: number, prefixLen: number } | null} 32-bit prefix and 0–32 length, or null if invalid
 */
function parseIPv4Cidr(cidr) {
  if (typeof cidr !== 'string') return null;
  const s = cidr.trim();
  const slash = s.indexOf('/');
  if (slash < 0) return null;
  const addr = s.slice(0, slash).trim();
  const lenStr = s.slice(slash + 1).trim();
  const len = parseInt(lenStr, 10);
  if (!Number.isInteger(len) || len < 0 || len > 32) return null;
  const parts = addr.split('.');
  if (parts.length !== 4) return null;
  let prefix = 0;
  for (let i = 0; i < 4; i++) {
    const n = parseInt(parts[i], 10);
    if (!Number.isInteger(n) || n < 0 || n > 255) return null;
    prefix = (prefix << 8) | n;
  }
  prefix >>>= 0;
  return { prefix, prefixLen: len };
}

/**
 * Returns true iff outer IPv4 CIDR fully contains inner (every IP in inner is in outer).
 * @param {string} outerCidr - broader CIDR
 * @param {string} innerCidr - narrower or equal CIDR
 * @returns {boolean}
 */
function cidrContains(outerCidr, innerCidr) {
  const outer = parseIPv4Cidr(outerCidr);
  const inner = parseIPv4Cidr(innerCidr);
  if (!outer || !inner) return false;
  if (outer.prefixLen > inner.prefixLen) return false;
  const maskLen = outer.prefixLen;
  const mask = maskLen === 0 ? 0 : (0xffffffff << (32 - maskLen)) >>> 0;
  return (outer.prefix & mask) === (inner.prefix & mask);
}

/**
 * Host part of cascade Endpoint (IPv4:port or [IPv6]:port) for policy routing — must not be routed via awg-cascade.
 * @param {string} endpointLine
 * @returns {string}
 */
function cascadeExitPublicHostFromEndpoint(endpointLine) {
  const s = String(endpointLine || '').trim().split('\n')[0];
  if (!s) return '';
  if (s.startsWith('[')) {
    const j = s.indexOf(']');
    return j > 1 ? s.slice(1, j).trim() : '';
  }
  const c = s.indexOf(':');
  if (c < 0) return s;
  return s.slice(0, c).trim();
}

/**
 * Resolve panel endpoint hostname to an IP for client exports (.conf, Amnezia). Literals unchanged.
 * @param {string} host - from parseEndpoint hostName
 * @returns {Promise<string>}
 */
async function resolveEndpointHostToIp(host) {
  const h = String(host || '').trim();
  if (!h) return '';
  if (Util.isValidIPv4(h)) return h;
  if (h.includes(':') && !h.includes('.')) return h;
  /* lookup uses getaddrinfo (same as ping/curl in container); resolve4/6 query DNS directly */
  try {
    const r = await dns.lookup(h, { family: 4 });
    if (r?.address) return r.address;
  } catch {
    /* */
  }
  try {
    const r = await dns.lookup(h, { family: 0, verbatim: true });
    if (r?.address) return r.address;
  } catch {
    /* */
  }
  try {
    const v4 = await dns.resolve4(h);
    if (v4 && v4.length) return v4[0];
  } catch {
    /* */
  }
  try {
    const v6 = await dns.resolve6(h);
    if (v6 && v6.length) return v6[0];
  } catch {
    /* */
  }
  return h;
}

/**
 * @param {string} ip
 * @param {number} port
 * @returns {string}
 */
function formatWireGuardEndpoint(ip, port) {
  const p = Number(port);
  if (ip.includes(':') && !Util.isValidIPv4(ip)) {
    return `[${ip}]:${p}`;
  }
  return `${ip}:${p}`;
}

/**
 * Rewrites `Endpoint =` in client ini (.conf) so hostname becomes IPv4/IPv6 literal when resolvable.
 * Used for live exports, Amnezia build from stored text, and config version downloads.
 * @param {string} iniText
 * @returns {Promise<string>}
 */
async function rewriteIniEndpointHostToIp(iniText) {
  if (typeof iniText !== 'string' || !iniText.trim()) return iniText || '';
  const hadCrLf = iniText.includes('\r\n');
  const nl = hadCrLf ? '\r\n' : '\n';
  const lines = iniText.replace(/\r\n/g, '\n').split('\n');
  const out = [];
  for (const line of lines) {
    const m = line.match(/^(\s*Endpoint\s*=\s*)(.+)$/i);
    if (!m) {
      out.push(line);
      continue;
    }
    const prefix = m[1];
    const rawEp = m[2].trim();
    try {
      const { hostName, port } = parseEndpoint(rawEp);
      if (Util.isValidIPv4(hostName) || (hostName.includes(':') && !hostName.includes('.'))) {
        out.push(line);
        continue;
      }
      const ip = await resolveEndpointHostToIp(hostName);
      const newEp = formatWireGuardEndpoint(ip, port);
      out.push(newEp === rawEp ? line : `${prefix}${newEp}`);
    } catch {
      out.push(line);
    }
  }
  return out.join(nl);
}

/**
 * Builds AllowedIPs string for client config from allow rules (client → profile → global).
 * Cascading collapse: a CIDR fully contained in an earlier one is skipped; a new CIDR
 * removes from the result any that it fully contains. Invalid CIDRs are kept as-is.
 * @param {{ id: string, ruleProfileId?: number|null, rule_profile_id?: number|null }} client - client id and profile
 * @returns {string} comma-separated destination_cidr or empty string
 */
function getAllowedIPsForClient(client) {
  const raw = client.ruleProfileId ?? client.rule_profile_id ?? null;
  const profileId = raw != null ? raw : 1;

  const ordered = [];
  const push = (r) => {
    const s = (r.destination_cidr || '').trim();
    if (s && r.action === 'allow') ordered.push(s);
  };
  for (const r of db.clientFirewallRules.getByClientId(client.id)) push(r);
  if (profileId != null) {
    for (const r of db.ipRules.getByProfileId(profileId)) push(r);
  }
  for (const r of db.globalFirewallRules.getAll()) push(r);

  const result = [];
  for (const cidr of ordered) {
    const containedInResult = result.some((existing) => cidrContains(existing, cidr));
    if (containedInResult) continue;
    for (let i = result.length - 1; i >= 0; i--) {
      if (cidrContains(cidr, result[i])) result.splice(i, 1);
    }
    result.push(cidr);
  }
  return result.join(', ') || '';
}

const WireGuard = class {
  __buildConfigFromDb() {
    const row = db.serverConfig.get();
    if (!row) return null;
    const server = {
      privateKey: row.private_key,
      publicKey: row.public_key,
      address: row.address,
      jc: row.jc,
      jmin: row.jmin,
      jmax: row.jmax,
      s1: row.s1,
      s2: row.s2,
      s3: row.s3,
      s4: row.s4,
      h1: row.h1,
      h2: row.h2,
      h3: row.h3,
      h4: row.h4,
      i2: row.i2 || '',
      i3: row.i3 || '',
      i4: row.i4 || '',
      i5: row.i5 || '',
    };
    const clients = {};
    for (const c of db.clients.getAll()) {
      clients[c.id] = {
        id: c.id,
        name: c.name,
        address: c.address,
        publicKey: c.public_key,
        privateKey: c.private_key,
        preSharedKey: c.pre_shared_key || undefined,
        enabled: c.enabled === 1,
        note: c.note || undefined,
        createdAt: new Date(c.created_at * 1000),
        updatedAt: new Date(c.updated_at * 1000),
        expiresAt: c.expires_at ? new Date(c.expires_at * 1000) : null,
        ruleProfileId: c.rule_profile_id ?? undefined,
        defaultProfile: c.default_profile || undefined,
        defaultSignature: c.default_signature || undefined,
        defaultLevel: c.default_level ?? undefined,
        useServerDns: c.use_server_dns !== 0,
        junkPins: junkParams.parseJunkPins(c.junk_pins),
        mtuProfile: c.mtu_profile || undefined,
        createdBy: c.created_by || null,
        xrayUuid: c.xray_uuid || null,
      };
    }
    return { server, clients };
  }

  async __ensureServerConfig() {
    if (db.serverConfig.get()) return;
    const migrated = await migrateAwgToDb();
    if (migrated) return;
    const privateKey = await Util.exec('wg genkey');
    const publicKey = await Util.exec(`echo ${privateKey} | wg pubkey`, {
      log: 'echo ***hidden*** | wg pubkey',
    });
    const primary = db.vpnPools.getPrimary();
    const address = (primary && primary.gateway) || WG_DEFAULT_ADDRESS.replace('x', '1');
    const now = Math.floor(Date.now() / 1000);
    db.serverConfig.upsert({
      private_key: privateKey,
      public_key: publicKey,
      address,
      jc: JC,
      jmin: JMIN,
      jmax: JMAX,
      s1: String(S1),
      s2: String(S2),
      s3: String(S3),
      s4: String(S4),
      h1: String(H1),
      h2: String(H2),
      h3: String(H3),
      h4: String(H4),
      i2: null,
      i3: null,
      i4: null,
      i5: null,
      updated_at: now,
    });
    debug('Server config generated and saved to DB.');
  }

  /**
   * Serializes getConfig (wg-quick / awg-cascade). Concurrent saves caused races:
   * second wg-quick up awg-cascade while the first amneziawg-go was not ready → "Protocol not supported", link deleted, no internet.
   */
  async __withConfigLock(fn) {
    const prev = this.__configLockPromise ?? Promise.resolve();
    let release;
    this.__configLockPromise = new Promise((res) => {
      release = res;
    });
    await prev.catch(() => {});
    try {
      return await fn();
    } finally {
      release();
    }
  }

  async getConfig() {
    if (!WG_HOST) {
      throw new Error('WG_HOST Environment Variable Not Set!');
    }
    return this.__withConfigLock(async () => {
      if (this.__config) return this.__config;
      await this.__ensureServerConfig();
      const config = this.__buildConfigFromDb();
      if (!config) throw new Error('Failed to build config from DB');
      await this.__saveConfig(config);
      const awgConfPath = path.join(WG_PATH, AWG_CONF);
      await Util.exec(`wg-quick down ${awgConfPath}`).catch(() => {});
      const upErr = await Util.exec(`wg-quick up ${awgConfPath}`).catch((e) => e);
      if (upErr && upErr.message && upErr.message.includes(`Cannot find device "${AWG_IFACE}"`)) {
        throw new Error(`WireGuard exited with the error: Cannot find device "${AWG_IFACE}"\nThis usually means that your host's kernel does not support WireGuard!`);
      }
      // * If interface already exists (e.g. userspace amneziawg-go left it), apply config via syncconf only.
      if (upErr && !(upErr.message || '').includes('already exists')) {
        throw upErr;
      }
      await this.__syncConfig();
      await this.__syncCascadeInterface();
      this.__config = config;
      return config;
    });
  }

  async saveConfig() {
    this.__config = null;
    // getConfig() already runs __saveConfig, __syncConfig, __syncCascadeInterface; duplicating
    // them here raced two concurrent wg-quick up awg-cascade (Address already assigned / link deleted).
    await this.getConfig();
  }

  // * Converts H1–H4 range (e.g. "1-2147483647") to single int for server config; userspace amneziawg-go may not accept ranges.
  __hToSingle(v) {
    if (typeof v !== 'string' || !v.includes('-')) return v;
    const parts = v.split('-').map((x) => parseInt(x.trim(), 10));
    if (parts.length !== 2 || parts.some(Number.isNaN)) return v;
    return Math.floor(Math.random() * (parts[1] - parts[0] + 1)) + parts[0];
  }

  async __readCascadeExitPublicKey() {
    const fromEnv = (WG_CASCADE_EXIT_PUBLIC_KEY || '').trim();
    if (fromEnv) return fromEnv;
    try {
      return (await fs.readFile(path.join(WG_PATH, CASCADE_EXIT_PUB_FILE), 'utf8')).trim();
    } catch {
      return '';
    }
  }

  async __readCascadeExitEndpoint() {
    const fromEnv = (WG_CASCADE_EXIT_ENDPOINT || '').trim();
    if (fromEnv) return fromEnv;
    try {
      const line = (await fs.readFile(path.join(WG_PATH, CASCADE_EXIT_ENDPOINT_FILE), 'utf8')).trim();
      return line.split('\n')[0].trim();
    } catch {
      return '';
    }
  }

  async __ensureCascadeLinkPrivateKey() {
    const keyPath = path.join(WG_PATH, CASCADE_LINK_KEY);
    try {
      const existing = (await fs.readFile(keyPath, 'utf8')).trim();
      if (existing) return existing;
    } catch { /* create */ }
    const privateKey = (await Util.exec('wg genkey')).trim();
    await fs.writeFile(keyPath, `${privateKey}\n`, { mode: 0o600 });
    const publicKey = (await Util.exec(`echo ${privateKey} | wg pubkey`, {
      log: 'echo ***hidden*** | wg pubkey',
    })).trim();
    await fs.writeFile(path.join(WG_PATH, CASCADE_LINK_PUB), `${publicKey}\n`, { mode: 0o644 });
    return privateKey;
  }

  /**
   * Second AmneziaWG iface (cascade S1→S2): same Jc/H as awg0; keys in WG_PATH.
   */
  async __writeCascadeConf(config, h1, h2, h3, h4) {
    const cascadePath = path.join(WG_PATH, AWG_CASCADE_CONF);
    if (!WG_CASCADE_ENABLED) {
      await Util.exec(`wg-quick down "${cascadePath}"`).catch(() => {});
      await fs.unlink(cascadePath).catch(() => {});
      return;
    }
    await this.__ensureCascadeLinkPrivateKey();
    const exitPub = await this.__readCascadeExitPublicKey();
    const endpoint = await this.__readCascadeExitEndpoint();
    if (!exitPub || !endpoint) {
      debug('Cascade uplink: missing exit public key or endpoint; remove stale conf');
      await Util.exec(`wg-quick down "${cascadePath}"`).catch(() => {});
      await fs.unlink(cascadePath).catch(() => {});
      return;
    }
    const priv = await this.__ensureCascadeLinkPrivateKey();
    const mtuLine = this.__serverMtuConfLine();
    const cidrEsc = resolveCascadeClientSubnet().replace(/"/g, '\\"');
    const exitHost = cascadeExitPublicHostFromEndpoint(endpoint);
    const exitArg = exitHost ? ` "${exitHost}"` : '';
    const postUp = `/bin/sh -c '/app/scripts/cascade-in-container-postup.sh ${WG_CASCADE_EXIT_TUNNEL_IP} "${cidrEsc}"${exitArg}'`;
    const preDown = `/bin/sh -c '/app/scripts/cascade-in-container-predown.sh "${cidrEsc}"${exitArg}'`;
    const body = `# Note: Do not edit this file directly (cascade uplink).
# Your changes will be overwritten!

[Interface]
PrivateKey = ${priv}
Address = ${WG_CASCADE_ADDRESS}
PostUp = ${postUp}
PreDown = ${preDown}
${mtuLine}Jc = ${config.server.jc}
Jmin = ${config.server.jmin}
Jmax = ${config.server.jmax}
S1 = ${config.server.s1}
S2 = ${config.server.s2}
S3 = ${config.server.s3}
S4 = ${config.server.s4}
H1 = ${h1}
H2 = ${h2}
H3 = ${h3}
H4 = ${h4}

[Peer]
PublicKey = ${exitPub}
AllowedIPs = 0.0.0.0/0
Endpoint = ${endpoint}
PersistentKeepalive = ${WG_PERSISTENT_KEEPALIVE}
`;
    await fs.writeFile(cascadePath, body, { mode: 0o600 });
    debug('Cascade conf saved.');
  }

  /**
   * Policy routing + table 166 for cascade. Must run after awg-cascade exists (wg-quick or syncconf).
   * When wg-quick up fails (e.g. "Address already assigned" then link deleted), PostUp from wg-quick
   * never runs — syncconf restores the tunnel but leaves table 166 empty and no internet for clients.
   */
  async __applyCascadePostUp() {
    if (!WG_CASCADE_ENABLED) return;
    const cidrEsc = String(resolveCascadeClientSubnet()).replace(/"/g, '\\"');
    const ep = await this.__readCascadeExitEndpoint();
    const exitHost = cascadeExitPublicHostFromEndpoint(ep);
    const exitArg = exitHost ? ` "${exitHost}"` : '';
    await Util.exec(
      `/bin/sh -c '/app/scripts/cascade-in-container-postup.sh ${WG_CASCADE_EXIT_TUNNEL_IP} "${cidrEsc}"${exitArg}'`,
    ).catch((e) => debug('Cascade postup script:', e.message));
  }

  async __syncCascadeInterface() {
    if (!WG_CASCADE_ENABLED) return;
    const cascadePath = path.join(WG_PATH, AWG_CASCADE_CONF);
    try {
      await fs.access(cascadePath);
    } catch {
      return;
    }
    const exitPub = await this.__readCascadeExitPublicKey();
    if (!exitPub) return;

    const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
    const maxAttempts = 5;

    for (let attempt = 0; attempt < maxAttempts; attempt++) {
      if (attempt > 0) {
        debug(`Cascade wg-quick up retry ${attempt + 1}/${maxAttempts}`);
        await sleep(900);
      }
      await Util.exec(`wg-quick down "${cascadePath}"`).catch(() => {});
      await Util.exec(
        `/bin/sh -c 'ip link set dev ${AWG_CASCADE_IFACE} down 2>/dev/null; ip link del dev ${AWG_CASCADE_IFACE} 2>/dev/null; true'`,
      ).catch(() => {});
      await sleep(250);
      const upErr = await Util.exec(`wg-quick up "${cascadePath}"`).catch((e) => e);
      if (upErr && upErr.message && !String(upErr.message).includes('already exists')) {
        debug('Cascade wg-quick up:', upErr.message);
      }
      await Util.exec(`wg syncconf ${AWG_CASCADE_IFACE} <(wg-quick strip "${cascadePath}")`).catch(() => {});
      const ifaceOk = await Util.exec(`ip link show dev ${AWG_CASCADE_IFACE}`).catch(() => '');
      if (ifaceOk && String(ifaceOk).includes(AWG_CASCADE_IFACE)) {
        break;
      }
      if (attempt === maxAttempts - 1) {
        debug('Cascade: awg-cascade interface still missing after retries');
      }
    }

    await this.__applyCascadePostUp();
  }

  async __saveConfig(config) {
    const h1 = this.__hToSingle(config.server.h1);
    const h2 = this.__hToSingle(config.server.h2);
    const h3 = this.__hToSingle(config.server.h3);
    const h4 = this.__hToSingle(config.server.h4);
    const now = Math.floor(Date.now() / 1000);

    const pools = db.vpnPools.list();
    if (pools[0] && pools[0].gateway) {
      config.server.address = pools[0].gateway;
    }

    db.serverConfig.upsert({
      private_key: config.server.privateKey,
      public_key: config.server.publicKey,
      address: config.server.address,
      jc: config.server.jc,
      jmin: config.server.jmin,
      jmax: config.server.jmax,
      s1: String(config.server.s1),
      s2: String(config.server.s2),
      s3: String(config.server.s3),
      s4: String(config.server.s4),
      h1: String(h1),
      h2: String(h2),
      h3: String(h3),
      h4: String(h4),
      i2: config.server.i2 || null,
      i3: config.server.i3 || null,
      i4: config.server.i4 || null,
      i5: config.server.i5 || null,
      updated_at: now,
    });

    const clientRows = Object.entries(config.clients).map(([id, c]) => ({
      id,
      name: c.name,
      address: c.address,
      public_key: c.publicKey,
      private_key: c.privateKey,
      pre_shared_key: c.preSharedKey ?? null,
      enabled: c.enabled !== false ? 1 : 0,
      note: c.note ?? null,
      created_at: Math.floor(new Date(c.createdAt).getTime() / 1000),
      updated_at: c.updatedAt ? Math.floor(new Date(c.updatedAt).getTime() / 1000) : now,
      expires_at: c.expiresAt ? Math.floor(new Date(c.expiresAt).getTime() / 1000) : null,
      rule_profile_id: c.ruleProfileId ?? null,
      default_profile: c.defaultProfile || null,
      default_signature: c.defaultSignature || null,
      default_level: c.defaultLevel ?? null,
      use_server_dns: c.useServerDns !== false ? 1 : 0,
      junk_pins: junkParams.stringifyJunkPins(c.junkPins),
      mtu_profile: c.mtuProfile || null,
      created_by: c.createdBy || null,
      xray_uuid: c.xrayUuid || null,
    }));
    db.clients.replaceAll(clientRows);

    const addressLines = pools.length
      ? pools.map((p) => {
        const parsed = vpnAddress.parseCidr(p.cidr);
        const pfx = parsed ? parsed.prefixLen : 24;
        return `Address = ${p.gateway}/${pfx}`;
      }).join('\n')
      : `Address = ${config.server.address}/24`;
    const postUp = WG_POST_UP_OVERRIDE
      ? WG_POST_UP
      : buildNatPostUp(pools.map((p) => p.cidr));
    const postDown = WG_POST_DOWN;

    const serverMtuLine = this.__serverMtuConfLine();
    let result = `
# Note: Do not edit this file directly.
# Your changes will be overwritten!

# Server
[Interface]
PrivateKey = ${config.server.privateKey}
${addressLines}
ListenPort = ${WG_PORT}
${serverMtuLine}PreUp = ${WG_PRE_UP}
PostUp = ${postUp}
PreDown = ${WG_PRE_DOWN}
PostDown = ${postDown}
Jc = ${config.server.jc}
Jmin = ${config.server.jmin}
Jmax = ${config.server.jmax}
S1 = ${config.server.s1}
S2 = ${config.server.s2}
S3 = ${config.server.s3}
S4 = ${config.server.s4}
H1 = ${h1}
H2 = ${h2}
H3 = ${h3}
H4 = ${h4}
`;

    const cutoffDate = new Date();
    for (const [clientId, client] of Object.entries(config.clients)) {
      if (!client.enabled) continue;
      if (client.expiresAt != null && new Date(client.expiresAt) <= cutoffDate) continue;
      result += `

# Client: ${client.name} (${clientId})
[Peer]
PublicKey = ${client.publicKey}
${client.preSharedKey ? `PresharedKey = ${client.preSharedKey}\n` : ''}AllowedIPs = ${client.address}/32`;
    }

    debug('Config saving...');
    await fs.writeFile(path.join(WG_PATH, AWG_CONF), result, {
      mode: 0o600,
    });
    await this.__writeCascadeConf(config, h1, h2, h3, h4);
    debug('Config saved.');
  }

  async __syncConfig() {
    debug('Config syncing...');
    const awgConfPath = path.join(WG_PATH, AWG_CONF);
    await Util.exec(`wg syncconf ${AWG_IFACE} <(wg-quick strip "${awgConfPath}")`);
    debug('Config synced.');
  }

  async getClients() {
    if (db.clients.disableExpired()) {
      this.__config = null;
      await this.saveConfig();
      const { applyFirewall } = require('./firewall');
      applyFirewall();
    }
    const config = await this.getConfig();
    const amneziaDnsStatus = getAmneziaDnsStatus();
    const amneziaDnsAvailable = amneziaDnsStatus.available === true;
    const amneziaXrayStatus = getAmneziaXrayStatus();
    const amneziaXrayAvailable = amneziaXrayStatus.available === true;
    const poolCidrs = db.vpnPools.list().map((p) => p.cidr);
    const clients = Object.entries(config.clients).map(([clientId, client]) => ({
      id: clientId,
      name: client.name,
      enabled: client.enabled,
      address: client.address,
      addressInPool: !!(client.address && vpnAddress.ipInAnyPool(client.address, poolCidrs)),
      publicKey: client.publicKey,
      createdAt: new Date(client.createdAt),
      updatedAt: new Date(client.updatedAt),
      expiresAt: client.expiresAt ?? null,
      createdBy: client.createdBy || null,
      ruleProfileId: client.ruleProfileId ?? null,
      allowedIPs: getAllowedIPsForClient(client),
      defaultProfile: client.defaultProfile || undefined,
      defaultSignature: client.defaultSignature || undefined,
      defaultLevel: client.defaultLevel ?? undefined,
      junkPins: client.junkPins || {},
      mtuProfile: client.mtuProfile || undefined,
      useServerDns: client.useServerDns !== false,
      downloadableConfig: 'privateKey' in client,
      persistentKeepalive: null,
      latestHandshakeAt: null,
      latestXrayActivityAt: null,
      latestActivityAt: null,
      isOnline: false,
      onlineSources: [],
      transferRx: null,
      transferTx: null,
      xrayUuid: client.xrayUuid || null,
    }));

    // Loop WireGuard status
    const dump = await Util.exec(`wg show ${AWG_IFACE} dump`, {
      log: false,
    });
    dump
      .trim()
      .split('\n')
      .slice(1)
      .forEach((line) => {
        const [
          publicKey,
          preSharedKey, // eslint-disable-line no-unused-vars
          endpoint, // eslint-disable-line no-unused-vars
          allowedIps, // eslint-disable-line no-unused-vars
          latestHandshakeAt,
          transferRx,
          transferTx,
          persistentKeepalive,
        ] = line.split('\t');

        const client = clients.find((client) => client.publicKey === publicKey);
        if (!client) return;

        client.latestHandshakeAt = latestHandshakeAt === '0'
          ? null
          : new Date(Number(`${latestHandshakeAt}000`));
        client.transferRx = Number(transferRx);
        client.transferTx = Number(transferTx);
        client.persistentKeepalive = persistentKeepalive;
      });

    // Merge Xray presence (traffic / online stats via trafficRecorder) into online indicator.
    // Lazy require: avoid WireGuard ↔ trafficRecorder cycle at module load.
    // eslint-disable-next-line global-require
    const { getXrayLastActivityMap } = require('./trafficRecorder');
    const xrayActivity = getXrayLastActivityMap();
    const now = Date.now();
    for (const client of clients) {
      const ts = xrayActivity.get(client.id);
      client.latestXrayActivityAt = (ts != null && Number.isFinite(ts))
        ? new Date(ts * 1000)
        : null;
      const presence = computeClientPresence({
        latestHandshakeAt: client.latestHandshakeAt,
        latestXrayActivityAt: client.latestXrayActivityAt,
      }, { now, windowMs: CLIENT_ONLINE_WINDOW_MS });
      client.latestActivityAt = presence.latestActivityAt;
      client.isOnline = presence.isOnline;
      client.onlineSources = presence.onlineSources;
    }

    const creatorMap = db.clients.mapCreatedByUsernames(clients.map((c) => c.id));
    for (const c of clients) {
      c.createdByUsername = creatorMap[c.id] || null;
    }

    const serverJunk = junkParams.readServerJunk(config.server);

    return {
      clients,
      serverCapabilities: {
        amneziaDnsAvailable,
        amneziaDns: {
          phase: amneziaDnsStatus.phase,
          desired: amneziaDnsStatus.desired,
          lastError: amneziaDnsStatus.lastError,
          busy: amneziaDnsStatus.busy,
          updatedAt: amneziaDnsStatus.updatedAt,
          profileId: amneziaDnsStatus.profileId,
          profile: amneziaDnsStatus.profile,
        },
        xrayAvailable: amneziaXrayAvailable,
        xray: {
          phase: amneziaXrayStatus.phase,
          desired: amneziaXrayStatus.desired,
          lastError: amneziaXrayStatus.lastError,
          busy: amneziaXrayStatus.busy,
          updatedAt: amneziaXrayStatus.updatedAt,
          address: amneziaXrayStatus.address,
          addressStored: amneziaXrayStatus.addressStored,
          sni: amneziaXrayStatus.sni,
          sniStored: amneziaXrayStatus.sniStored,
          fingerprint: amneziaXrayStatus.fingerprint,
          flow: amneziaXrayStatus.flow,
          port: amneziaXrayStatus.port,
          publicPort: amneziaXrayStatus.publicPort,
          mode: amneziaXrayStatus.mode,
          demuxPeers: amneziaXrayStatus.demuxPeers,
          healthy: amneziaXrayStatus.healthy === true,
          smoke: amneziaXrayStatus.smoke || null,
        },
      },
      serverJunk,
    };
  }

  async getClient({ clientId }) {
    const config = await this.getConfig();
    const client = config.clients[clientId];
    if (!client) {
      throw new ServerError(`Client Not Found: ${clientId}`, 404);
    }

    return client;
  }

  async getClientConfiguration({ clientId, forQR = false, forceOmitI1ForCapacity = false, level, profile, signature }) {
    const bank = await loadBank();
    const config = await this.getConfig();
    const client = await this.getClient({ clientId });

    const preferredProfile = (profile != null && typeof profile === 'string' && profile.trim())
      ? profile.trim()
      : (client.defaultProfile || null);
    const preferredSignature = (signature != null && String(signature).trim())
      ? String(signature).trim()
      : (client.defaultSignature || null);

    // Do not silently persist binding healing — only apply() may write clients.
    const binding = ensureBinding(preferredProfile, preferredSignature, bank);

    const prof = binding.slots;
    if (!prof || !prof.i1) {
      throw new BankError(`signature not found: ${binding.profile}#${binding.signature}`, { status: 400 });
    }

    const omitI1 = (forQR && WG_QR_COMPACT) || forceOmitI1ForCapacity;

    let iLines = [];
    const pushSlot = (slot, label) => {
      if (prof[slot]) iLines.push(`${label} = ${prof[slot]}`);
    };
    if (level !== undefined && level !== null) {
      const l = Number(level);
      if (l === 0) {
        iLines = [];
      } else if (l === 1) {
        if (!omitI1) pushSlot('i1', 'I1');
      } else if (l >= 2 && l <= 5) {
        if (!omitI1) pushSlot('i1', 'I1');
        if (l >= 2) pushSlot('i2', 'I2');
        if (l >= 3) pushSlot('i3', 'I3');
        if (l >= 4) pushSlot('i4', 'I4');
        if (l >= 5) pushSlot('i5', 'I5');
      } else {
        if (!omitI1) pushSlot('i1', 'I1');
        pushSlot('i2', 'I2');
        pushSlot('i3', 'I3');
        pushSlot('i4', 'I4');
        pushSlot('i5', 'I5');
      }
    } else {
      if (!omitI1) pushSlot('i1', 'I1');
      pushSlot('i2', 'I2');
      pushSlot('i3', 'I3');
      pushSlot('i4', 'I4');
      pushSlot('i5', 'I5');
    }
    const iBlock = iLines.length ? iLines.join('\n') + '\n\n' : '';

    const dnsAvailable = isAmneziaDnsAvailable();
    const useServerDns = dnsAvailable && (client.useServerDns !== false);
    const dnsValue = useServerDns ? WG_DEFAULT_DNS : WG_DIRECT_DNS;

    let clientMtu = null;
    try {
      mtuProfiles.ensureSeedBank();
      clientMtu = mtuProfiles.resolveMtuValue(client.mtuProfile);
    } catch {
      clientMtu = WG_MTU != null ? Number(WG_MTU) : null;
      if (!Number.isFinite(clientMtu)) clientMtu = null;
    }
    const mtuLine = clientMtu != null ? `MTU = ${clientMtu}\n` : '';

    return `[Interface]
PrivateKey = ${client.privateKey ? `${client.privateKey}` : 'REPLACE_ME'}
Address = ${client.address}
${dnsValue ? `DNS = ${dnsValue}\n` : ''}\
${mtuLine}\
Jc = ${config.server.jc}
Jmin = ${config.server.jmin}
Jmax = ${config.server.jmax}
S1 = ${config.server.s1}
S2 = ${config.server.s2}
S3 = ${config.server.s3}
S4 = ${config.server.s4}
H1 = ${config.server.h1}
H2 = ${config.server.h2}
H3 = ${config.server.h3}
H4 = ${config.server.h4}
${iBlock}[Peer]
PublicKey = ${config.server.publicKey}
${client.preSharedKey ? `PresharedKey = ${client.preSharedKey}\n` : ''
}AllowedIPs = ${getAllowedIPsForClient(client)}
PersistentKeepalive = ${WG_PERSISTENT_KEEPALIVE}
Endpoint = ${await this.__getClientEndpointLine()}`;
  }

  /**
   * Raw endpoint host:port from settings / env (may be a domain for TLS/panel).
   */
  __getEndpoint() {
    const stored = db.appSettings.get('endpoint');
    if (stored && stored.trim()) return stored.trim();
    const fromEnv = WG_HOST && WG_PORT ? `${WG_HOST}:${WG_PORT}` : '';
    if (fromEnv) db.appSettings.set('endpoint', fromEnv);
    return fromEnv;
  }

  /**
   * Endpoint for client .conf / Amnezia export: host resolved to IPv4/IPv6 literal when possible.
   */
  async __getClientEndpointLine() {
    const raw = this.__getEndpoint();
    if (!raw || !String(raw).trim()) return '';
    try {
      const { hostName, port } = parseEndpoint(raw.trim());
      const ip = await resolveEndpointHostToIp(hostName);
      return formatWireGuardEndpoint(ip, port);
    } catch (e) {
      debug('__getClientEndpointLine: parse failed, using raw endpoint:', e.message);
      return String(raw).trim();
    }
  }

  /** Resolved Endpoint line for DB audit / API (same as in exported .conf). */
  async getResolvedClientEndpointLine() {
    return this.__getClientEndpointLine();
  }

  /** Normalize stored or live ini before .conf download / Amnezia payload. */
  async rewriteIniEndpointForClientExport(iniText) {
    return rewriteIniEndpointHostToIp(iniText);
  }

  async __configToQrSvg(config) {
    return QRCode.toString(config, {
      type: 'svg',
      width: 512,
      errorCorrectionLevel: 'L',
    });
  }

  /** Highest I{n} line present in ini (0 = none). */
  __maxILevelInConfig(configText) {
    const text = String(configText || '');
    let max = 0;
    for (let i = 1; i <= 5; i += 1) {
      if (new RegExp(`^I${i}\\s*=`, 'm').test(text)) max = i;
    }
    return max;
  }

  /**
   * @param {number|null|undefined} requestedLevel - UI level (undefined ≈ full I1–I5)
   * @param {string} configText - payload actually encoded in QR
   * @param {{ forceOmitI1?: boolean, attemptLevel?: number|null }} [opts]
   */
  __buildILimitMeta(requestedLevel, configText, opts = {}) {
    const requested = requestedLevel != null && Number.isFinite(Number(requestedLevel))
      ? Number(requestedLevel)
      : 5;
    const text = String(configText || '');
    const effective = this.__maxILevelInConfig(text);
    const hasI1 = /^I1\s*=/m.test(text);
    const forceOmitI1 = !!opts.forceOmitI1;
    const attemptLevel = opts.attemptLevel != null && Number.isFinite(Number(opts.attemptLevel))
      ? Number(opts.attemptLevel)
      : null;

    // Notice when capacity forced a cut: lower level, or drop I1 while user wanted I≥1.
    let limited = false;
    if (requested > 0) {
      if (effective < requested) limited = true;
      else if (forceOmitI1 && !hasI1) limited = true;
      else if (attemptLevel != null && attemptLevel < requested) limited = true;
    }
    const excluded = limited && effective === 0;
    return { requested, effective, limited, excluded };
  }

  /**
   * Reject QR versions that technically encode but are too dense for reliable phone scanning.
   * Version 18 ≈ 1.9KB binary @ ECC L — still practical at ~560px display size.
   */
  __assertTextQrScannable(config) {
    const qr = QRCode.create(config, { errorCorrectionLevel: 'L' });
    const version = Math.floor((qr.modules.size - 21) / 4) + 1;
    const maxVersion = 18;
    if (version > maxVersion) {
      const err = new Error(`QR Code version ${version} exceeds scannable limit ${maxVersion}`);
      err.code = 'QR_TOO_DENSE';
      throw err;
    }
  }

  __isTextQrCapacityError(err) {
    const msg = String((err && err.message) || err || '');
    return err && err.code === 'QR_TOO_DENSE'
      || /too big to be stored in a QR Code/i.test(msg)
      || /exceeds scannable limit/i.test(msg);
  }

  __buildQrCapacityAttempts(level) {
    const attempts = [];
    const requested = level === undefined || level === null ? null : Number(level);
    if (requested != null && Number.isFinite(requested)) {
      attempts.push({ level: requested, forceOmitI1ForCapacity: false });
      attempts.push({ level: requested, forceOmitI1ForCapacity: true });
      for (let l = requested - 1; l >= 0; l -= 1) {
        attempts.push({ level: l, forceOmitI1ForCapacity: true });
      }
    } else {
      attempts.push({ level: undefined, forceOmitI1ForCapacity: false });
      attempts.push({ level: undefined, forceOmitI1ForCapacity: true });
      for (let l = 5; l >= 0; l -= 1) {
        attempts.push({ level: l, forceOmitI1ForCapacity: true });
      }
    }
    return { requested: requested != null && Number.isFinite(requested) ? requested : null, attempts };
  }

  /**
   * Single text QR. Prefer limiting I params over packing an unscannable dense QR.
   */
  async getClientQRCodeSVG({ clientId, level, profile, signature }) {
    const { requested, attempts } = this.__buildQrCapacityAttempts(level);

    for (const attempt of attempts) {
      try {
        // eslint-disable-next-line no-await-in-loop
        const config = await this.getClientConfiguration({
          clientId,
          forQR: true,
          forceOmitI1ForCapacity: attempt.forceOmitI1ForCapacity,
          level: attempt.level,
          profile,
          signature,
        });
        this.__assertTextQrScannable(config);
        // eslint-disable-next-line no-await-in-loop
        const svg = await this.__configToQrSvg(config);
        return {
          svg,
          payload: config,
          iLimit: this.__buildILimitMeta(requested, config, {
            forceOmitI1: attempt.forceOmitI1ForCapacity,
            attemptLevel: attempt.level,
          }),
        };
      } catch (err) {
        if (!this.__isTextQrCapacityError(err)) throw err;
      }
    }
    throw new ServerError(
      'Config too large for a single text QR. Use AmneziaClient tab or Preview/Download.',
      413,
    );
  }

  /** MTU line for awg0 / cascade Interface (app_settings → profile bank → WG_MTU). */
  __serverMtuConfLine() {
    try {
      mtuProfiles.ensureSeedBank();
      const stored = db.appSettings.get('mtu_profile');
      const pid = stored && mtuProfiles.isKnownProfile(stored)
        ? String(stored).trim()
        : mtuProfiles.getDefaultProfileId();
      const mtu = mtuProfiles.resolveMtuValue(pid);
      return mtu != null ? `MTU = ${mtu}\n` : '';
    } catch {
      return WG_MTU ? `MTU = ${WG_MTU}\n` : '';
    }
  }

  __persistServerMtuProfile(profileId) {
    mtuProfiles.ensureSeedBank();
    const pid = profileId != null ? String(profileId).trim() : '';
    if (!mtuProfiles.isKnownProfile(pid)) {
      throw new ServerError(`Unknown MTU profile: ${profileId}`, 400);
    }
    db.appSettings.set('mtu_profile', pid);
    return pid;
  }

  /**
   * AmneziaVPN app: chunked Base64URL QR payloads (see amneziaClientQr.js).
   * Caps at MAX_AMNEZIA_QR_CHUNKS (1×3 UI) by omitting I1 / lowering level when needed.
   * @returns {Promise<{ svgs: string[], payloads: string[], iLimit: object }>}
   */
  async getClientAmneziaQRCodeSvgs({ clientId, level, profile, signature }) {
    const client = await this.getClient({ clientId });
    const description = client.name && String(client.name).trim() ? client.name : 'AmneziaWG';
    const dnsAvailable = isAmneziaDnsAvailable();
    const useServerDns = dnsAvailable && client.useServerDns !== false;
    const qrOpts = {
      includeAmneziaDns: dnsAvailable && useServerDns,
      includeAmneziaXray: isAmneziaXrayAvailable(),
      xrayClient: db.clients.getById(clientId) || null,
    };

    const { requested, attempts } = this.__buildQrCapacityAttempts(level);

    let lastConfig = null;
    let lastAttempt = null;
    for (const attempt of attempts) {
      // eslint-disable-next-line no-await-in-loop
      const config = await this.getClientConfiguration({
        clientId,
        forQR: true,
        forceOmitI1ForCapacity: attempt.forceOmitI1ForCapacity,
        level: attempt.level,
        profile,
        signature,
      });
      lastConfig = config;
      lastAttempt = attempt;
      const chunks = countAmneziaQrChunks(config, description, qrOpts);
      if (chunks <= MAX_AMNEZIA_QR_CHUNKS) {
        // eslint-disable-next-line no-await-in-loop
        const out = await generateAmneziaClientQrSvgs(config, description, qrOpts);
        return {
          ...out,
          iLimit: this.__buildILimitMeta(requested, config, {
            forceOmitI1: attempt.forceOmitI1ForCapacity,
            attemptLevel: attempt.level,
          }),
        };
      }
    }
    // Extreme case: still over cap after level 0 — emit anyway (UI grid still wraps).
    const out = await generateAmneziaClientQrSvgs(lastConfig, description, qrOpts);
    return {
      ...out,
      iLimit: this.__buildILimitMeta(requested, lastConfig, {
        forceOmitI1: lastAttempt && lastAttempt.forceOmitI1ForCapacity,
        attemptLevel: lastAttempt && lastAttempt.level,
      }),
    };
  }

  /**
   * Builds vpn:// import string from any AmneziaWG .ini text (live config, history row, etc.).
   * @param {string} iniText
   * @param {string} clientId
   * @returns {Promise<string>}
   */
  async buildAmneziaVpnFromIni(iniText, clientId) {
    if (typeof iniText !== 'string' || !iniText.trim()) {
      throw new ServerError('Config text is empty', 400);
    }
    const normalized = await rewriteIniEndpointHostToIp(iniText.trim());
    const client = await this.getClient({ clientId });
    const description = client.name && String(client.name).trim() ? client.name : 'AmneziaWG';
    const dnsAvailable = isAmneziaDnsAvailable();
    const useServerDns = dnsAvailable && client.useServerDns !== false;
    return buildAmneziaVpnExport(normalized, description, {
      includeAmneziaDns: dnsAvailable && useServerDns,
      includeAmneziaXray: isAmneziaXrayAvailable(),
      xrayClient: db.clients.getById(clientId) || null,
    });
  }

  /**
   * AmneziaVPN import string (vpn:// + Base64URL(qCompress(JSON))), same as official ExportController.
   * @returns {Promise<string>}
   */
  async getClientAmneziaVpnExport({ clientId, level, profile, signature }) {
    const config = await this.getClientConfiguration({
      clientId,
      forQR: level === undefined || level === null,
      forceOmitI1ForCapacity: level === undefined || level === null,
      level,
      profile,
      signature,
    });
    return this.buildAmneziaVpnFromIni(config, clientId);
  }

  async createClient({ name, createdBy, addressRanges }) {
    if (!name) {
      throw new Error('Missing: Name');
    }
    const trimmedName = String(name).trim();
    if (!trimmedName) {
      throw new Error('Missing: Name');
    }
    const nameTaken = db.clients.getAll().some((c) => c.name === trimmedName);
    if (nameTaken) {
      throw new ServerError('Client name already exists', 409);
    }

    const bank = await loadBank();
    const binding = assignNewClientBinding(bank);

    const privateKey = await Util.exec('wg genkey');
    const publicKey = await Util.exec(`echo ${privateKey} | wg pubkey`);
    const preSharedKey = await Util.exec('wg genpsk');

    const pools = db.vpnPools.list();
    const ranges = Array.isArray(addressRanges) ? addressRanges.filter(Boolean) : [];
    if (!ranges.length) {
      throw new ServerError('No VPN CIDRs assigned to this user', 400);
    }
    const usedSet = db.clients.usedAddresses();
    const reservedGateways = pools.map((p) => p.gateway).filter(Boolean);
    const address = vpnAddress.allocateAddress({ ranges, usedSet, reservedGateways });
    if (!address) throw new Error('Maximum number of clients reached.');

    const id = crypto.randomUUID();
    const now = Math.floor(Date.now() / 1000);
    await this.__ensureServerConfig();
    let pinJunk = junkParams.readServerJunk(this.__buildConfigFromDb().server);
    if (!pinJunk) {
      try {
        pinJunk = junkParams.generateJunk(binding.profile);
      } catch {
        pinJunk = null;
      }
    }
    const junkPins = pinJunk ? { [binding.profile]: pinJunk } : {};
    let mtuProfileId = null;
    try {
      mtuProfiles.ensureSeedBank();
      mtuProfileId = mtuProfiles.getDefaultProfileId();
    } catch {
      mtuProfileId = '1280';
    }
    db.clients.create({
      id,
      name: trimmedName,
      address,
      public_key: publicKey,
      private_key: privateKey,
      pre_shared_key: preSharedKey,
      enabled: 1,
      note: null,
      created_at: now,
      updated_at: now,
      expires_at: null,
      rule_profile_id: 1,
      default_profile: binding.profile,
      default_signature: binding.signature,
      default_level: 1,
      use_server_dns: 1,
      junk_pins: junkParams.stringifyJunkPins(junkPins),
      mtu_profile: mtuProfileId,
      created_by: createdBy || null,
    });
    try {
      ensureAmneziaXrayClientUuids();
    } catch {
      /* xray optional */
    }

    this.__config = null;
    await this.saveConfig();
    const { applyFirewall } = require('./firewall');
    applyFirewall();
    scheduleAmneziaXraySync();

    return {
      id,
      name: trimmedName,
      address,
      privateKey,
      publicKey,
      preSharedKey,
      createdAt: new Date(now * 1000),
      updatedAt: new Date(now * 1000),
      enabled: true,
      defaultProfile: binding.profile,
      defaultSignature: binding.signature,
      defaultLevel: 1,
    };
  }

  async deleteClient({ clientId }) {
    if (!db.clients.getById(clientId)) {
      throw new ServerError(`Client Not Found: ${clientId}`, 404);
    }
    db.clients.delete(clientId);
    this.__config = null;
    await this.saveConfig();
    const { applyFirewall } = require('./firewall');
    applyFirewall();
    scheduleAmneziaXraySync();
  }

  async enableClient({ clientId }) {
    const client = db.clients.getById(clientId);
    if (!client) throw new ServerError(`Client Not Found: ${clientId}`, 404);
    const pools = db.vpnPools.list();
    const poolCidrs = pools.map((p) => p.cidr);
    if (!client.address || !vpnAddress.ipInAnyPool(client.address, poolCidrs)) {
      throw new ServerError('Client address is outside configured VPN pools; assign a valid IP first', 400);
    }
    const now = Math.floor(Date.now() / 1000);
    if (client.expires_at != null && client.expires_at < now) {
      client.expires_at = null;
    }
    client.enabled = 1;
    client.updated_at = now;
    db.clients.update(client);
    this.__config = null;
    await this.saveConfig();
    const { applyFirewall } = require('./firewall');
    applyFirewall();
    scheduleAmneziaXraySync();
  }

  async disableClient({ clientId }) {
    const client = db.clients.getById(clientId);
    if (!client) throw new ServerError(`Client Not Found: ${clientId}`, 404);
    client.enabled = 0;
    client.updated_at = Math.floor(Date.now() / 1000);
    db.clients.update(client);
    this.__config = null;
    await this.saveConfig();
    const { applyFirewall } = require('./firewall');
    applyFirewall();
    scheduleAmneziaXraySync();
  }

  async updateClientName({ clientId, name }) {
    const trimmedName = typeof name === 'string' ? name.trim() : '';
    if (!trimmedName) {
      throw new ServerError('Missing: Name', 400);
    }
    const client = db.clients.getById(clientId);
    if (!client) throw new ServerError(`Client Not Found: ${clientId}`, 404);
    const nameTaken = db.clients.getAll().some((c) => c.id !== clientId && c.name === trimmedName);
    if (nameTaken) {
      throw new ServerError('Client name already exists', 409);
    }
    client.name = trimmedName;
    client.updated_at = Math.floor(Date.now() / 1000);
    db.clients.update(client);
    this.__config = null;
    await this.saveConfig();
    scheduleAmneziaXraySync();
  }

  async updateClientAddress({ clientId, address, allowedRanges }) {
    if (!Util.isValidIPv4(address)) {
      throw new ServerError(`Invalid Address: ${address}`, 400);
    }
    const client = db.clients.getById(clientId);
    if (!client) throw new ServerError(`Client Not Found: ${clientId}`, 404);
    const pools = db.vpnPools.list();
    const poolCidrs = pools.map((p) => p.cidr);
    if (!vpnAddress.ipInAnyPool(address, poolCidrs)) {
      throw new ServerError('Address is outside configured VPN pools', 400);
    }
    const gateways = new Set(pools.map((p) => p.gateway).filter(Boolean));
    if (gateways.has(address)) {
      throw new ServerError('Address is reserved as a pool gateway', 400);
    }
    if (Array.isArray(allowedRanges)) {
      if (!allowedRanges.length) {
        throw new ServerError('No VPN address ranges available for this user', 403);
      }
      const inRange = allowedRanges.some((cidr) => vpnAddress.ipInCidr(address, cidr));
      if (!inRange) {
        throw new ServerError('Address is outside your assigned CIDRs', 403);
      }
    }
    const used = db.clients.usedAddresses(clientId);
    if (used.has(address)) {
      throw new ServerError('Address already in use', 409);
    }
    client.address = address;
    client.updated_at = Math.floor(Date.now() / 1000);
    db.clients.update(client);
    this.__config = null;
    await this.saveConfig();
    const { applyFirewall } = require('./firewall');
    applyFirewall();
  }

  /**
   * Legacy immediate persist (scripts). UI must use preview + apply instead.
   */
  async updateClientObfuscation({ clientId, profile, signature, level }) {
    const client = db.clients.getById(clientId);
    if (!client) throw new ServerError(`Client Not Found: ${clientId}`, 404);

    const bank = await loadBank();

    if (profile !== undefined) {
      const pid = typeof profile === 'string' ? profile.trim() : '';
      if (!pid || !isKnownProfile(pid)) {
        throw new ServerError(`Unknown protocol: ${profile}`, 400);
      }
      client.default_profile = pid;
      if (signature === undefined) {
        const next = pickRandomVariant(pid, bank);
        if (!next) throw new ServerError(`No signature variants for ${pid}`, 400);
        client.default_signature = next;
      }
    }

    if (signature !== undefined) {
      const pid = client.default_profile;
      const variants = listVariants(pid, bank);
      const vk = String(signature).trim();
      if (!variants.includes(vk)) {
        throw new ServerError(`Unknown signature variant ${vk} for ${pid}`, 400);
      }
      client.default_signature = vk;
    }

    if (level !== undefined) client.default_level = level;
    client.updated_at = Math.floor(Date.now() / 1000);
    db.clients.update(client);
    this.__config = null;
    await this.saveConfig();
    return {
      profile: client.default_profile,
      signature: client.default_signature,
      level: client.default_level,
    };
  }

  /**
   * Legacy immediate persist. Prefer previewClientObfuscation (no write).
   */
  async refreshClientSignature({ clientId }) {
    const client = db.clients.getById(clientId);
    if (!client) throw new ServerError(`Client Not Found: ${clientId}`, 404);
    const bank = await loadBank();
    const binding = ensureBinding(client.default_profile, client.default_signature, bank);
    const alternatives = listVariants(binding.profile, bank)
      .filter((v) => v !== String(binding.signature));
    if (!alternatives.length) {
      throw new ServerError('No alternative signatures for this protocol', 400);
    }
    const next = alternatives[crypto.randomInt(0, alternatives.length)];
    if (binding.changed) {
      client.default_profile = binding.profile;
    }
    client.default_signature = next;
    client.updated_at = Math.floor(Date.now() / 1000);
    db.clients.update(client);
    this.__config = null;
    await this.saveConfig();
    return {
      profile: client.default_profile,
      signature: client.default_signature,
      level: client.default_level,
    };
  }

  async getClientObfuscation({ clientId }) {
    const client = db.clients.getById(clientId);
    if (!client) throw new ServerError(`Client Not Found: ${clientId}`, 404);
    junkParams.ensureSeedBank();
    const config = await this.getConfig();
    return {
      level: client.default_level ?? 1,
      profile: client.default_profile || null,
      signature: client.default_signature != null ? String(client.default_signature) : null,
      junkPins: junkParams.parseJunkPins(client.junk_pins),
      serverJunk: junkParams.readServerJunk(config.server),
    };
  }

  /**
   * Build draft values without writing DB / awg.
   * @param {{ clientId: string, profile?: string, level?: number, signature?: string,
   *           refreshSignature?: boolean, regenerateJunk?: boolean }} opts
   */
  async previewClientObfuscation(opts = {}) {
    const { clientId } = opts;
    const client = db.clients.getById(clientId);
    if (!client) throw new ServerError(`Client Not Found: ${clientId}`, 404);

    junkParams.ensureSeedBank();
    const bank = await loadBank();
    const pins = junkParams.parseJunkPins(client.junk_pins);

    let profile = opts.profile != null
      ? String(opts.profile).trim()
      : (client.default_profile || null);
    if (!profile || !isKnownProfile(profile)) {
      throw new ServerError(`Unknown protocol: ${profile}`, 400);
    }

    let level = opts.level !== undefined
      ? Number(opts.level)
      : (client.default_level ?? 1);
    if (!Number.isInteger(level) || level < 0 || level > 5) {
      throw new ServerError('level must be 0..5', 400);
    }

    let signature = opts.signature != null
      ? String(opts.signature).trim()
      : (client.default_signature != null ? String(client.default_signature) : null);

    const refreshSignature = opts.refreshSignature === true;
    // New junk only when explicit regenerate/refresh; protocol switch reuses junk_pins when present.
    const forceNewJunk = opts.regenerateJunk === true || refreshSignature;

    if (refreshSignature) {
      const binding = ensureBinding(profile, signature, bank);
      profile = binding.profile;
      const alternatives = listVariants(profile, bank)
        .filter((v) => v !== String(binding.signature));
      if (!alternatives.length) {
        throw new ServerError('No alternative signatures for this protocol', 400);
      }
      signature = alternatives[crypto.randomInt(0, alternatives.length)];
    } else {
      const variants = listVariants(profile, bank);
      if (!variants.length) {
        throw new ServerError(`No signature variants for ${profile}`, 400);
      }
      if (!signature || !variants.includes(signature)) {
        signature = pickRandomVariant(profile, bank);
      }
    }

    let junk;
    if (!forceNewJunk && pins[profile] && typeof pins[profile] === 'object') {
      try {
        junk = junkParams.validateJunk(pins[profile]);
      } catch {
        junk = null;
      }
    }
    if (!junk) {
      junk = junkParams.generateJunk(profile);
    }

    return {
      level,
      profile,
      signature,
      junk,
      junkPinned: Boolean(pins[profile]),
      persisted: false,
    };
  }

  async applyClientObfuscation({ clientId, level, profile, signature, junk, mtuProfile }) {
    return this.__withConfigLock(async () => {
      const client = db.clients.getById(clientId);
      if (!client) throw new ServerError(`Client Not Found: ${clientId}`, 404);

      junkParams.ensureSeedBank();
      const bank = await loadBank();

      const pid = typeof profile === 'string' ? profile.trim() : '';
      if (!pid || !isKnownProfile(pid)) {
        throw new ServerError(`Unknown protocol: ${profile}`, 400);
      }
      const lvl = Number(level);
      if (!Number.isInteger(lvl) || lvl < 0 || lvl > 5) {
        throw new ServerError('level must be 0..5', 400);
      }
      const vk = signature != null ? String(signature).trim() : '';
      const variants = listVariants(pid, bank);
      if (!vk || !variants.includes(vk)) {
        throw new ServerError(`Unknown signature variant ${vk} for ${pid}`, 400);
      }

      let validatedJunk;
      try {
        validatedJunk = junkParams.validateJunk(junk);
      } catch (err) {
        if (err instanceof junkParams.JunkParamsError) {
          throw new ServerError(err.message, err.status || 400);
        }
        throw err;
      }

      let mtuProfileId = null;
      if (mtuProfile != null && String(mtuProfile).trim() !== '') {
        mtuProfileId = this.__persistServerMtuProfile(mtuProfile);
        client.mtu_profile = mtuProfileId;
      }

      const pins = junkParams.parseJunkPins(client.junk_pins);
      pins[pid] = validatedJunk;

      client.default_profile = pid;
      client.default_signature = vk;
      client.default_level = lvl;
      client.junk_pins = junkParams.stringifyJunkPins(pins);
      client.updated_at = Math.floor(Date.now() / 1000);
      db.clients.update(client);

      // Avoid getConfig() here — it also takes __withConfigLock (would deadlock).
      await this.__ensureServerConfig();
      const config = this.__buildConfigFromDb();
      if (!config) throw new ServerError('Failed to build config from DB', 500);
      junkParams.applyJunkToServer(config.server, validatedJunk);

      try {
        await this.__saveConfig(config);
        await this.__syncConfig();
        await this.__syncCascadeInterface();
        this.__config = config;
      } catch (err) {
        this.__config = null;
        throw new ServerError(
          `Obfuscation saved but WireGuard sync failed: ${err.message || err}`,
          503,
        );
      }

      return {
        level: lvl,
        profile: pid,
        signature: vk,
        junk: validatedJunk,
        junkPins: pins,
        serverJunk: validatedJunk,
        mtuProfile: mtuProfileId || client.mtu_profile || null,
        mtu: mtuProfileId ? mtuProfiles.resolveMtuValue(mtuProfileId) : null,
        persisted: true,
      };
    });
  }

  async updateClientDns({ clientId, useServerDns }) {
    const client = db.clients.getById(clientId);
    if (!client) throw new ServerError(`Client Not Found: ${clientId}`, 404);
    client.use_server_dns = useServerDns === true ? 1 : 0;
    client.updated_at = Math.floor(Date.now() / 1000);
    db.clients.update(client);
    this.__config = null;
    await this.saveConfig();
  }

  async updateClientMtu({ clientId, profileId }) {
    const client = db.clients.getById(clientId);
    if (!client) throw new ServerError(`Client Not Found: ${clientId}`, 404);
    const pid = this.__persistServerMtuProfile(profileId);
    client.mtu_profile = pid;
    client.updated_at = Math.floor(Date.now() / 1000);
    db.clients.update(client);
    this.__config = null;
    await this.saveConfig();
    return {
      mtuProfile: pid,
      mtu: mtuProfiles.resolveMtuValue(pid),
    };
  }

  async updateClientRuleProfile({ clientId, ruleProfileId }) {
    const client = db.clients.getById(clientId);
    if (!client) throw new ServerError(`Client Not Found: ${clientId}`, 404);
    client.rule_profile_id = ruleProfileId != null ? ruleProfileId : null;
    client.updated_at = Math.floor(Date.now() / 1000);
    db.clients.update(client);
    this.__config = null;
    await this.saveConfig();
    const { applyFirewall } = require('./firewall');
    applyFirewall();
  }

  async updateClientExpires({ clientId, expiresAt }) {
    const client = db.clients.getById(clientId);
    if (!client) throw new ServerError(`Client Not Found: ${clientId}`, 404);
    const unix = expiresAt == null ? null : (typeof expiresAt === 'number' ? expiresAt : Math.floor(new Date(expiresAt).getTime() / 1000));
    client.expires_at = unix;
    client.updated_at = Math.floor(Date.now() / 1000);
    db.clients.update(client);
    this.__config = null;
    await this.saveConfig();
    const { applyFirewall } = require('./firewall');
    applyFirewall();
  }

  // Shutdown wireguard
  async Shutdown() {
    const cascadePath = path.join(WG_PATH, AWG_CASCADE_CONF);
    await Util.exec(`wg-quick down "${cascadePath}"`).catch(() => {});
    const awgConfPath = path.join(WG_PATH, AWG_CONF);
    await Util.exec(`wg-quick down ${awgConfPath}`).catch(() => { });
  }
};

const wg = new WireGuard();
wg.getAllowedIPsForClient = getAllowedIPsForClient;
module.exports = wg;
