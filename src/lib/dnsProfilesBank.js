'use strict';

/**
 * Amnezia DNS upstream profiles bank: WG_PATH/dns-profiles.json
 *
 * Shape:
 *   {
 *     version, defaultProfile,
 *     profiles: {
 *       "1": { name, description?, forwardTls, servers: [{ address, port?, tlsName? }] }
 *     }
 *   }
 */

const fs = require('node:fs');
const path = require('node:path');
const { WG_PATH } = require('../config');

const BANK_PATH = path.join(WG_PATH, 'dns-profiles.json');
const SEED_CANDIDATES = [
  path.join(__dirname, '..', 'config', 'dns-profiles.seed.json'),
  path.join(__dirname, '..', '..', 'config', 'dns-profiles.seed.json'),
];

const IPV4_RE = /^(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)$/;

class DnsProfileError extends Error {
  constructor(message, { status = 400, code = 'DNS_PROFILE_ERROR' } = {}) {
    super(message);
    this.name = 'DnsProfileError';
    this.status = status;
    this.code = code;
  }
}

function resolveSeedPath() {
  for (const p of SEED_CANDIDATES) {
    try {
      if (fs.existsSync(p) && fs.statSync(p).size > 0) return p;
    } catch {
      // continue
    }
  }
  return null;
}

function bankVersion(data) {
  const n = Number(data && data.version);
  return Number.isFinite(n) ? n : 0;
}

/** @type {{ mtimeMs: number, bank: object } | null} */
let cache = null;

function invalidateCache() {
  cache = null;
}

function normalizeServer(raw, index, profileId) {
  if (!raw || typeof raw !== 'object') {
    throw new DnsProfileError(`profile ${profileId}: server #${index + 1} invalid`, {
      code: 'DNS_PROFILE_BAD_SERVER',
    });
  }
  const address = String(raw.address || '').trim();
  if (!IPV4_RE.test(address)) {
    throw new DnsProfileError(`profile ${profileId}: server #${index + 1} address must be IPv4`, {
      code: 'DNS_PROFILE_BAD_SERVER',
    });
  }
  const port = raw.port == null || raw.port === '' ? null : Number(raw.port);
  if (port != null && (!Number.isInteger(port) || port < 1 || port > 65535)) {
    throw new DnsProfileError(`profile ${profileId}: server #${index + 1} port invalid`, {
      code: 'DNS_PROFILE_BAD_SERVER',
    });
  }
  const tlsName = raw.tlsName != null ? String(raw.tlsName).trim() : '';
  return {
    address,
    port: port == null ? undefined : port,
    tlsName: tlsName || undefined,
  };
}

function normalizeProfile(id, raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new DnsProfileError(`profile ${id}: invalid object`, { code: 'DNS_PROFILE_INVALID' });
  }
  const name = String(raw.name || '').trim() || `Profile ${id}`;
  const description = raw.description != null ? String(raw.description).trim() : '';
  const forwardTls = raw.forwardTls !== false && raw.forwardTls !== 0 && raw.forwardTls !== '0';
  if (!Array.isArray(raw.servers) || raw.servers.length === 0) {
    throw new DnsProfileError(`profile ${id}: servers[] required`, {
      status: 400,
      code: 'DNS_PROFILE_NO_SERVERS',
    });
  }
  const servers = raw.servers.map((s, i) => normalizeServer(s, i, id));
  return {
    id: String(id),
    name,
    description,
    forwardTls,
    servers,
  };
}

function parseBankObject(data) {
  if (!data || typeof data !== 'object' || Array.isArray(data)) {
    throw new DnsProfileError('invalid dns-profiles.json: root must be an object', {
      status: 503,
      code: 'DNS_PROFILES_INVALID',
    });
  }
  if (!data.profiles || typeof data.profiles !== 'object' || Array.isArray(data.profiles)) {
    throw new DnsProfileError('invalid dns-profiles.json: missing profiles object', {
      status: 503,
      code: 'DNS_PROFILES_INVALID',
    });
  }
  /** @type {Record<string, ReturnType<typeof normalizeProfile>>} */
  const profiles = {};
  for (const [id, raw] of Object.entries(data.profiles)) {
    const key = String(id).trim();
    if (!key) continue;
    try {
      profiles[key] = normalizeProfile(key, raw);
    } catch (err) {
      if (err instanceof DnsProfileError) throw err;
      throw new DnsProfileError(`profile ${key}: ${err.message}`, { status: 503 });
    }
  }
  if (Object.keys(profiles).length === 0) {
    throw new DnsProfileError('invalid dns-profiles.json: no usable profiles', {
      status: 503,
      code: 'DNS_PROFILES_EMPTY',
    });
  }
  let defaultProfile = data.defaultProfile != null ? String(data.defaultProfile) : '';
  if (!defaultProfile || !profiles[defaultProfile]) {
    defaultProfile = Object.keys(profiles).sort((a, b) => Number(a) - Number(b) || a.localeCompare(b))[0];
  }
  return {
    version: bankVersion(data),
    defaultProfile,
    profiles,
  };
}

function ensureSeedBank() {
  const seedPath = resolveSeedPath();
  if (!seedPath) {
    if (!fs.existsSync(BANK_PATH)) {
      throw new DnsProfileError('dns-profiles.json missing and no packaged seed available', {
        status: 503,
        code: 'DNS_PROFILES_MISSING',
      });
    }
    return false;
  }

  let seed;
  try {
    seed = parseBankObject(JSON.parse(fs.readFileSync(seedPath, 'utf8')));
  } catch (err) {
    throw new DnsProfileError(`packaged dns-profiles seed invalid: ${err.message}`, {
      status: 503,
      code: 'DNS_PROFILES_SEED_INVALID',
    });
  }

  let needsSeed = false;
  try {
    if (!fs.existsSync(BANK_PATH) || fs.statSync(BANK_PATH).size === 0) {
      needsSeed = true;
    } else {
      try {
        const current = parseBankObject(JSON.parse(fs.readFileSync(BANK_PATH, 'utf8')));
        if (bankVersion(current) < bankVersion(seed)) needsSeed = true;
      } catch {
        needsSeed = true;
      }
    }
  } catch {
    needsSeed = true;
  }

  if (!needsSeed) return false;

  fs.mkdirSync(path.dirname(BANK_PATH), { recursive: true });
  fs.copyFileSync(seedPath, BANK_PATH);
  invalidateCache();
  // eslint-disable-next-line no-console
  console.log(`[dnsProfilesBank] seeded ${BANK_PATH} from ${seedPath} (version ${seed.version})`);
  return true;
}

function loadBankSync() {
  ensureSeedBank();
  let st;
  try {
    st = fs.statSync(BANK_PATH);
  } catch (err) {
    if (err.code === 'ENOENT') {
      throw new DnsProfileError('dns-profiles.json missing', {
        status: 503,
        code: 'DNS_PROFILES_MISSING',
      });
    }
    throw new DnsProfileError(`Failed to read dns-profiles.json: ${err.message}`, { status: 503 });
  }
  if (cache && cache.mtimeMs === st.mtimeMs) return cache.bank;
  let raw;
  try {
    raw = fs.readFileSync(BANK_PATH, 'utf8');
  } catch (err) {
    throw new DnsProfileError(`Failed to read dns-profiles.json: ${err.message}`, { status: 503 });
  }
  let parsed;
  try {
    parsed = parseBankObject(JSON.parse(raw));
  } catch (err) {
    if (err instanceof DnsProfileError) throw err;
    throw new DnsProfileError(`invalid dns-profiles.json: ${err.message}`, {
      status: 503,
      code: 'DNS_PROFILES_INVALID',
    });
  }
  cache = { mtimeMs: st.mtimeMs, bank: parsed };
  return parsed;
}

function listProfiles(bank = loadBankSync()) {
  return Object.keys(bank.profiles)
    .sort((a, b) => Number(a) - Number(b) || a.localeCompare(b))
    .map((id) => {
      const p = bank.profiles[id];
      return {
        id: p.id,
        name: p.name,
        description: p.description,
        forwardTls: p.forwardTls,
        servers: p.servers.map((s) => ({
          address: s.address,
          port: s.port != null ? s.port : (p.forwardTls ? 853 : 53),
          tlsName: s.tlsName,
        })),
        isDefault: id === bank.defaultProfile,
      };
    });
}

function getProfilesCatalog() {
  try {
    const bank = loadBankSync();
    return {
      version: bank.version,
      defaultProfile: bank.defaultProfile,
      profiles: listProfiles(bank),
    };
  } catch (err) {
    return {
      version: 0,
      defaultProfile: null,
      profiles: [],
      error: err.message,
      code: err.code || 'DNS_PROFILES_ERROR',
    };
  }
}

function resolveProfile(profileId) {
  const bank = loadBankSync();
  const id = profileId == null || profileId === ''
    ? bank.defaultProfile
    : String(profileId).trim();
  if (!id) {
    throw new DnsProfileError('DNS profile id required', { code: 'DNS_PROFILE_REQUIRED' });
  }
  const profile = bank.profiles[id];
  if (!profile) {
    throw new DnsProfileError(`DNS profile not found: ${id}`, {
      status: 404,
      code: 'DNS_PROFILE_NOT_FOUND',
    });
  }
  return profile;
}

const EMERCOIN_STUBS = `domain-insecure: "coin."
domain-insecure: "emc."
domain-insecure: "lib."
domain-insecure: "bazar."
domain-insecure: "enum."

stub-zone:
 name: coin.
 stub-host: seed1.emercoin.com
 stub-host: seed2.emercoin.com
 stub-first: yes

stub-zone:
 name: emc.
 stub-host: seed1.emercoin.com
 stub-host: seed2.emercoin.com
 stub-first: yes

stub-zone:
 name: lib.
 stub-host: seed1.emercoin.com
 stub-host: seed2.emercoin.com
 stub-first: yes

stub-zone:
 name: bazar.
 stub-host: seed1.emercoin.com
 stub-host: seed2.emercoin.com
 stub-first: yes

stub-zone:
 name: enum.
 stub-host: seed1.emercoin.com
 stub-host: seed2.emercoin.com
 stub-first: yes
`;

/**
 * Build Unbound forward-records.conf for a profile (Emercoin stubs + forward-zone).
 */
function renderForwardRecords(profile) {
  const p = typeof profile === 'string' ? resolveProfile(profile) : profile;
  const lines = [
    `# Amnezia DNS profile ${p.id}: ${p.name}`,
    EMERCOIN_STUBS.trimEnd(),
    '',
    'forward-zone:',
    ' name: .',
  ];
  if (p.forwardTls) {
    lines.push(' forward-tls-upstream: yes');
  } else {
    lines.push(' forward-tls-upstream: no');
  }
  for (const s of p.servers) {
    const port = s.port != null ? s.port : (p.forwardTls ? 853 : 53);
    let addr = `${s.address}@${port}`;
    if (p.forwardTls && s.tlsName) {
      addr += `#${s.tlsName}`;
    }
    lines.push(` forward-addr: ${addr}`);
  }
  lines.push('');
  return `${lines.join('\n')}\n`;
}

function writeForwardRecordsFile(profile, destPath) {
  const conf = renderForwardRecords(profile);
  fs.mkdirSync(path.dirname(destPath), { recursive: true });
  fs.writeFileSync(destPath, conf, 'utf8');
  return destPath;
}

module.exports = {
  BANK_PATH,
  DnsProfileError,
  ensureSeedBank,
  loadBankSync,
  listProfiles,
  getProfilesCatalog,
  resolveProfile,
  renderForwardRecords,
  writeForwardRecordsFile,
  invalidateCache,
};
