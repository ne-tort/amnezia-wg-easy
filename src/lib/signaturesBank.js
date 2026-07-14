'use strict';

/**
 * Static signature bank: WG_PATH/signatures.json
 *
 * Shape:
 *   { version, target?, profiles: { <protocol>: { "1": { i1..i5 }, ... } } }
 */

const fs = require('node:fs');
const fsp = require('node:fs/promises');
const path = require('node:path');
const crypto = require('node:crypto');

const { WG_PATH } = require('../config');

const SIGNATURES_PATH = path.join(WG_PATH, 'signatures.json');
const SEED_CANDIDATES = [
  path.join(__dirname, '..', 'config', 'signatures.seed.json'), // Docker: /app/config/...
  path.join(__dirname, '..', '..', 'config', 'signatures.seed.json'), // local: repo/config/...
];
const SLOT_KEYS = ['i1', 'i2', 'i3', 'i4', 'i5'];

class BankError extends Error {
  constructor(message, { status = 503 } = {}) {
    super(message);
    this.name = 'BankError';
    this.status = status;
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

/**
 * Copy packaged seed into WG_PATH when signatures.json is missing, unusable,
 * or older than the packaged seed (version bump).
 * Returns true if a seed was written.
 */
function ensureSeedBank() {
  const seedPath = resolveSeedPath();
  if (!seedPath) {
    if (!fs.existsSync(SIGNATURES_PATH)) {
      throw new BankError('signatures.json missing and no packaged seed available');
    }
    return false;
  }

  let seed;
  try {
    seed = parseBankObject(JSON.parse(fs.readFileSync(seedPath, 'utf8')));
  } catch (err) {
    throw new BankError(`packaged seed invalid: ${err.message}`);
  }

  let needsSeed = false;
  try {
    if (!fs.existsSync(SIGNATURES_PATH) || fs.statSync(SIGNATURES_PATH).size === 0) {
      needsSeed = true;
    } else {
      try {
        const current = parseBankObject(JSON.parse(fs.readFileSync(SIGNATURES_PATH, 'utf8')));
        if (bankVersion(current) < bankVersion(seed)) needsSeed = true;
      } catch {
        needsSeed = true;
      }
    }
  } catch {
    needsSeed = true;
  }

  if (!needsSeed) return false;

  fs.mkdirSync(path.dirname(SIGNATURES_PATH), { recursive: true });
  fs.copyFileSync(seedPath, SIGNATURES_PATH);
  invalidateCache();
  // eslint-disable-next-line no-console
  console.log(`[signaturesBank] seeded ${SIGNATURES_PATH} from ${seedPath} (version ${bankVersion(seed)})`);
  return true;
}

/** @type {{ mtimeMs: number, bank: object } | null} */
let cache = null;

function normalizeSlots(raw) {
  if (raw == null || typeof raw !== 'object' || Array.isArray(raw)) return {};
  const out = {};
  for (const k of SLOT_KEYS) {
    if (typeof raw[k] === 'string' && raw[k].trim()) out[k] = raw[k].trim();
  }
  return out;
}

function hasI1(slots) {
  return Boolean(slots?.i1);
}

function normalizeVariantKey(key) {
  const n = parseInt(String(key), 10);
  if (!Number.isFinite(n) || n < 1) return null;
  return String(n);
}

function invalidateCache() {
  cache = null;
}

function parseBankObject(data) {
  if (!data || typeof data !== 'object' || Array.isArray(data)) {
    throw new BankError('invalid signatures.json: root must be an object');
  }
  if (!data.profiles || typeof data.profiles !== 'object' || Array.isArray(data.profiles)) {
    throw new BankError('invalid signatures.json: missing profiles object');
  }
  return data;
}

async function loadBank() {
  let st;
  try {
    st = await fsp.stat(SIGNATURES_PATH);
  } catch (err) {
    if (err.code === 'ENOENT') throw new BankError('signatures.json missing');
    throw new BankError(`Failed to read signatures.json: ${err.message}`);
  }

  if (cache && cache.mtimeMs === st.mtimeMs) return cache.bank;

  let raw;
  try {
    raw = await fsp.readFile(SIGNATURES_PATH, 'utf8');
  } catch (err) {
    throw new BankError(`Failed to read signatures.json: ${err.message}`);
  }

  let data;
  try {
    data = JSON.parse(raw);
  } catch (err) {
    throw new BankError(`invalid signatures.json: ${err.message}`);
  }

  data = parseBankObject(data);
  cache = { mtimeMs: st.mtimeMs, bank: data };
  return data;
}

function loadBankSync() {
  let st;
  try {
    st = fs.statSync(SIGNATURES_PATH);
  } catch (err) {
    if (err.code === 'ENOENT') throw new BankError('signatures.json missing');
    throw new BankError(`Failed to read signatures.json: ${err.message}`);
  }

  if (cache && cache.mtimeMs === st.mtimeMs) return cache.bank;

  let raw;
  try {
    raw = fs.readFileSync(SIGNATURES_PATH, 'utf8');
  } catch (err) {
    throw new BankError(`Failed to read signatures.json: ${err.message}`);
  }

  let data;
  try {
    data = JSON.parse(raw);
  } catch (err) {
    throw new BankError(`invalid signatures.json: ${err.message}`);
  }

  data = parseBankObject(data);
  cache = { mtimeMs: st.mtimeMs, bank: data };
  return data;
}

function listVariants(protocol, bank) {
  const pid = String(protocol || '').trim();
  const raw = bank?.profiles?.[pid];
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return [];

  const nums = [];
  for (const key of Object.keys(raw)) {
    const vk = normalizeVariantKey(key);
    if (!vk) continue;
    if (hasI1(normalizeSlots(raw[key]))) nums.push(Number(vk));
  }
  nums.sort((a, b) => a - b);
  return nums.map(String);
}

function listProtocols(bank) {
  const ids = [];
  for (const pid of Object.keys(bank.profiles || {})) {
    if (listVariants(pid, bank).length > 0) ids.push(pid);
  }
  ids.sort((a, b) => {
    if (a === 'dns') return -1;
    if (b === 'dns') return 1;
    return a.localeCompare(b);
  });
  return ids;
}

function getDefaultProtocol(bank) {
  const ids = listProtocols(bank);
  if (ids.includes('dns')) return 'dns';
  return ids[0] || null;
}

function pickRandomVariant(protocol, bank, { exclude } = {}) {
  let variants = listVariants(protocol, bank);
  if (exclude != null) {
    const filtered = variants.filter((v) => v !== String(exclude));
    if (filtered.length) variants = filtered;
  }
  if (!variants.length) return null;
  return variants[crypto.randomInt(0, variants.length)];
}

function getEntry(protocol, variant, bank) {
  const pid = String(protocol || '').trim();
  const vk = normalizeVariantKey(variant);
  if (!pid || !vk) return null;
  const raw = bank?.profiles?.[pid]?.[vk];
  const slots = normalizeSlots(raw);
  return hasI1(slots) ? slots : null;
}

/**
 * Resolve protocol+variant; re-pick if stale. Does not persist.
 */
function ensureBinding(profile, signature, bank) {
  const protocols = listProtocols(bank);
  if (!protocols.length) {
    throw new BankError('invalid signatures.json: no usable profiles');
  }

  let pid = typeof profile === 'string' && profile.trim() ? profile.trim() : null;
  let sig = signature != null && String(signature).trim()
    ? normalizeVariantKey(signature)
    : null;

  const stale = !pid || !protocols.includes(pid)
    || !sig
    || !listVariants(pid, bank).includes(sig);

  if (!stale) {
    return {
      profile: pid,
      signature: sig,
      changed: false,
      slots: getEntry(pid, sig, bank),
    };
  }

  if (!pid || !protocols.includes(pid) || !listVariants(pid, bank).length) {
    pid = getDefaultProtocol(bank);
  }
  sig = pickRandomVariant(pid, bank);
  if (!sig) throw new BankError(`no signature variants for protocol: ${pid}`);

  return {
    profile: pid,
    signature: sig,
    changed: true,
    slots: getEntry(pid, sig, bank),
  };
}

function assignNewClientBinding(bank) {
  const profile = getDefaultProtocol(bank);
  if (!profile) throw new BankError('invalid signatures.json: no usable profiles');
  const signature = pickRandomVariant(profile, bank);
  if (!signature) throw new BankError(`no signature variants for protocol: ${profile}`);
  return { profile, signature };
}

function getProfilesCatalog(bank) {
  const protocols = listProtocols(bank).map((id) => {
    const variants = listVariants(id, bank);
    return { id, label: id, variants, count: variants.length };
  });
  const defaultProtocol = getDefaultProtocol(bank);
  return {
    ok: true,
    protocols,
    profileIds: protocols.map((p) => p.id),
    defaultProtocol,
    defaultProfile: defaultProtocol,
  };
}

module.exports = {
  SIGNATURES_PATH,
  SEED_CANDIDATES,
  SLOT_KEYS,
  BankError,
  ensureSeedBank,
  invalidateCache,
  loadBank,
  loadBankSync,
  listProtocols,
  listVariants,
  getDefaultProtocol,
  pickRandomVariant,
  getEntry,
  ensureBinding,
  assignNewClientBinding,
  getProfilesCatalog,
  normalizeSlots,
  hasI1,
  normalizeVariantKey,
};
