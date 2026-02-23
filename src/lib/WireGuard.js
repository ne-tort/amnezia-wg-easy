'use strict';

const fs = require('node:fs/promises');
const path = require('path');
const debug = require('debug')('WireGuard');
const crypto = require('node:crypto');
const QRCode = require('qrcode');

const Util = require('./Util');
const ServerError = require('./ServerError');
const db = require('./db');
const { migrateAwgToDb } = require('./migrateAwgToDb');
const { getProfileI1, isKnownProfile, DEFAULT_PROFILE_ID } = require('./obfuscationProfiles');
const { loadSignatures, runSignatureGeneration } = require('./signatures');
const { isAmneziaDnsAvailable } = require('./amneziaDns');

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
  WG_PRE_DOWN,
  WG_POST_DOWN,
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
  I2,
  I3,
  I4,
  I5,
  WG_QR_COMPACT,
  OBFS_R_BYTES,
} = require('../config');

// * Official Amnezia client pattern: awg0.conf and interface awg0 in /opt/amnezia/awg/
const AWG_JSON = 'awg0.json';
const AWG_CONF = 'awg0.conf';
const AWG_IFACE = 'awg0';

/**
 * Builds AllowedIPs string for client config from allow rules (global + profile + client).
 * Uses Set to deduplicate; trims whitespace from destination_cidr.
 * @param {{ id: string, ruleProfileId?: number|null, rule_profile_id?: number|null }} client - client id and profile
 * @returns {string} comma-separated destination_cidr or empty string
 */
function getAllowedIPsForClient(client) {
  const cidrs = new Set();
  const add = (v) => { const s = (v || '').trim(); if (s) cidrs.add(s); };
  for (const r of db.globalFirewallRules.getAll()) {
    if (r.action === 'allow') add(r.destination_cidr);
  }
  const raw = client.ruleProfileId ?? client.rule_profile_id ?? null;
  const profileId = raw != null ? raw : 1;
  if (profileId != null) {
    for (const r of db.ipRules.getByProfileId(profileId)) {
      if (r.action === 'allow') add(r.destination_cidr);
    }
  }
  const clientRules = db.clientFirewallRules.getByClientId(client.id);
  for (const r of clientRules) {
    if (r.action === 'allow') add(r.destination_cidr);
  }
  return [...cidrs].join(', ') || '';
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
        defaultLevel: c.default_level ?? undefined,
        useServerDns: c.use_server_dns !== 0,
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
    const address = WG_DEFAULT_ADDRESS.replace('x', '1');
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
      i2: I2 || null,
      i3: I3 || null,
      i4: I4 || null,
      i5: I5 || null,
      updated_at: now,
    });
    debug('Server config generated and saved to DB.');
  }

  async getConfig() {
    if (!WG_HOST) {
      throw new Error('WG_HOST Environment Variable Not Set!');
    }
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
    this.__config = config;
    return config;
  }

  async saveConfig() {
    this.__config = null;
    const config = await this.getConfig();
    await this.__saveConfig(config);
    await this.__syncConfig();
  }

  // * Converts H1–H4 range (e.g. "1-2147483647") to single int for server config; userspace amneziawg-go may not accept ranges.
  __hToSingle(v) {
    if (typeof v !== 'string' || !v.includes('-')) return v;
    const parts = v.split('-').map((x) => parseInt(x.trim(), 10));
    if (parts.length !== 2 || parts.some(Number.isNaN)) return v;
    return Math.floor(Math.random() * (parts[1] - parts[0] + 1)) + parts[0];
  }

  async __saveConfig(config) {
    const h1 = this.__hToSingle(config.server.h1);
    const h2 = this.__hToSingle(config.server.h2);
    const h3 = this.__hToSingle(config.server.h3);
    const h4 = this.__hToSingle(config.server.h4);
    const now = Math.floor(Date.now() / 1000);

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
      default_level: c.defaultLevel ?? null,
      use_server_dns: c.useServerDns !== false ? 1 : 0,
    }));
    db.clients.replaceAll(clientRows);

    let result = `
# Note: Do not edit this file directly.
# Your changes will be overwritten!

# Server
[Interface]
PrivateKey = ${config.server.privateKey}
Address = ${config.server.address}/24
ListenPort = ${WG_PORT}
PreUp = ${WG_PRE_UP}
PostUp = ${WG_POST_UP}
PreDown = ${WG_PRE_DOWN}
PostDown = ${WG_POST_DOWN}
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
    const amneziaDnsAvailable = isAmneziaDnsAvailable();
    const clients = Object.entries(config.clients).map(([clientId, client]) => ({
      id: clientId,
      name: client.name,
      enabled: client.enabled,
      address: client.address,
      publicKey: client.publicKey,
      createdAt: new Date(client.createdAt),
      updatedAt: new Date(client.updatedAt),
      expiresAt: client.expiresAt ?? null,
      ruleProfileId: client.ruleProfileId ?? null,
      allowedIPs: getAllowedIPsForClient(client),
      defaultProfile: client.defaultProfile || undefined,
      defaultLevel: client.defaultLevel ?? undefined,
      useServerDns: client.useServerDns !== false,
      downloadableConfig: 'privateKey' in client,
      persistentKeepalive: null,
      latestHandshakeAt: null,
      transferRx: null,
      transferTx: null,
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

    return { clients, serverCapabilities: { amneziaDnsAvailable } };
  }

  async getClient({ clientId }) {
    const config = await this.getConfig();
    const client = config.clients[clientId];
    if (!client) {
      throw new ServerError(`Client Not Found: ${clientId}`, 404);
    }

    return client;
  }

  async getClientConfiguration({ clientId, forQR = false, forceOmitI1ForCapacity = false, level, profile }) {
    await loadSignatures();
    const config = await this.getConfig();
    const client = await this.getClient({ clientId });

    const profileId = (profile != null && isKnownProfile(profile)) ? profile : DEFAULT_PROFILE_ID;
    const i1 = getProfileI1(profileId);

    let iLines = [];
    if (level !== undefined && level !== null) {
      // * Level-based obfuscation (QUIC-realistic): I0 = none, I1 = I1 only,
      // I2 = <c>, I3 = <t>, I4 = <r N>, I5 = <r N> — dynamic chain per protocol recommendations.
      const l = Number(level);
      if (l === 0) {
        iLines = [];
      } else if (l === 1) {
        if (i1) iLines.push(`I1 = ${i1}`);
      } else if (l >= 2 && l <= 5) {
        if (i1) iLines.push(`I1 = ${i1}`);
        if (l >= 2) iLines.push('I2 = <c>');
        if (l >= 3) iLines.push('I3 = <t>');
        if (l >= 4) iLines.push(`I4 = <r ${OBFS_R_BYTES}>`);
        if (l >= 5) iLines.push(`I5 = <r ${OBFS_R_BYTES}>`);
      } else {
        // Invalid level: fall back to legacy behavior.
        const omitI1 = (forQR && WG_QR_COMPACT) || forceOmitI1ForCapacity;
        if (!omitI1 && i1) iLines.push(`I1 = ${i1}`);
        if (config.server.i2) iLines.push(`I2 = ${config.server.i2}`);
        if (config.server.i3) iLines.push(`I3 = ${config.server.i3}`);
        if (config.server.i4) iLines.push(`I4 = ${config.server.i4}`);
        if (config.server.i5) iLines.push(`I5 = ${config.server.i5}`);
      }
    } else {
      // Legacy: no level — use omitI1 and server i2–i5.
      const omitI1 = (forQR && WG_QR_COMPACT) || forceOmitI1ForCapacity;
      if (!omitI1 && i1) iLines.push(`I1 = ${i1}`);
      if (config.server.i2) iLines.push(`I2 = ${config.server.i2}`);
      if (config.server.i3) iLines.push(`I3 = ${config.server.i3}`);
      if (config.server.i4) iLines.push(`I4 = ${config.server.i4}`);
      if (config.server.i5) iLines.push(`I5 = ${config.server.i5}`);
    }
    const iBlock = iLines.length ? iLines.join('\n') + '\n\n' : '';

    const dnsAvailable = isAmneziaDnsAvailable();
    const useServerDns = dnsAvailable && (client.useServerDns !== false);
    const dnsValue = useServerDns ? WG_DEFAULT_DNS : WG_DIRECT_DNS;

    return `[Interface]
PrivateKey = ${client.privateKey ? `${client.privateKey}` : 'REPLACE_ME'}
Address = ${client.address}
${dnsValue ? `DNS = ${dnsValue}\n` : ''}\
${WG_MTU ? `MTU = ${WG_MTU}\n` : ''}\
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
Endpoint = ${this.__getEndpoint()}`;
  }

  __getEndpoint() {
    const stored = db.appSettings.get('endpoint');
    if (stored && stored.trim()) return stored.trim();
    const fromEnv = WG_HOST && WG_PORT ? `${WG_HOST}:${WG_PORT}` : '';
    if (fromEnv) db.appSettings.set('endpoint', fromEnv);
    return fromEnv;
  }

  async getClientQRCodeSVG({ clientId, level, profile, encoding }) {
    // When level is provided, build config by level (may be large for L5). Otherwise compact (no I1).
    let config = await this.getClientConfiguration({
      clientId,
      forQR: level === undefined || level === null,
      forceOmitI1ForCapacity: level === undefined || level === null,
      level,
      profile,
    });
    const payload = encoding === 'base64' ? Buffer.from(config, 'utf8').toString('base64') : config;
    return QRCode.toString(payload, {
      type: 'svg',
      width: 512,
      errorCorrectionLevel: 'L',
    });
  }

  async createClient({ name }) {
    if (!name) {
      throw new Error('Missing: Name');
    }

    runSignatureGeneration();

    const privateKey = await Util.exec('wg genkey');
    const publicKey = await Util.exec(`echo ${privateKey} | wg pubkey`);
    const preSharedKey = await Util.exec('wg genpsk');

    const allClients = db.clients.getAll();
    let address;
    for (let i = 2; i < 255; i++) {
      const candidate = WG_DEFAULT_ADDRESS.replace('x', i);
      if (!allClients.some((c) => c.address === candidate)) {
        address = candidate;
        break;
      }
    }
    if (!address) throw new Error('Maximum number of clients reached.');

    const id = crypto.randomUUID();
    const now = Math.floor(Date.now() / 1000);
    db.clients.create({
      id,
      name,
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
      default_profile: null,
      default_level: null,
      use_server_dns: 1,
    });

    this.__config = null;
    await this.saveConfig();
    const { applyFirewall } = require('./firewall');
    applyFirewall();

    return {
      id,
      name,
      address,
      privateKey,
      publicKey,
      preSharedKey,
      createdAt: new Date(now * 1000),
      updatedAt: new Date(now * 1000),
      enabled: true,
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
  }

  async enableClient({ clientId }) {
    const client = db.clients.getById(clientId);
    if (!client) throw new ServerError(`Client Not Found: ${clientId}`, 404);
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
  }

  async updateClientName({ clientId, name }) {
    const client = db.clients.getById(clientId);
    if (!client) throw new ServerError(`Client Not Found: ${clientId}`, 404);
    client.name = name;
    client.updated_at = Math.floor(Date.now() / 1000);
    db.clients.update(client);
    this.__config = null;
    await this.saveConfig();
  }

  async updateClientAddress({ clientId, address }) {
    if (!Util.isValidIPv4(address)) {
      throw new ServerError(`Invalid Address: ${address}`, 400);
    }
    const client = db.clients.getById(clientId);
    if (!client) throw new ServerError(`Client Not Found: ${clientId}`, 404);
    const allClients = db.clients.getAll();
    const alreadyUsed = allClients.some((c) => c.id !== clientId && c.address === address);
    if (alreadyUsed) {
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

  async updateClientObfuscation({ clientId, profile, level }) {
    const client = db.clients.getById(clientId);
    if (!client) throw new ServerError(`Client Not Found: ${clientId}`, 404);
    if (profile !== undefined) client.default_profile = profile;
    if (level !== undefined) client.default_level = level;
    client.updated_at = Math.floor(Date.now() / 1000);
    db.clients.update(client);
    this.__config = null;
    await this.saveConfig();
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
    const awgConfPath = path.join(WG_PATH, AWG_CONF);
    await Util.exec(`wg-quick down ${awgConfPath}`).catch(() => { });
  }
};

const wg = new WireGuard();
wg.getAllowedIPsForClient = getAllowedIPsForClient;
module.exports = wg;
