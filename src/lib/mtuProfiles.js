'use strict';

/**
 * MTU profiles bank: WG_PATH/mtu-profiles.json
 * profiles.<id> = { mtu: number|null, label?: string }
 */

const fs = require('node:fs');
const path = require('node:path');
const { WG_PATH } = require('../config');

const BANK_PATH = path.join(WG_PATH, 'mtu-profiles.json');
const SEED_CANDIDATES = [
  path.join(__dirname, '..', 'config', 'mtu-profiles.seed.json'),
  path.join(__dirname, '..', '..', 'config', 'mtu-profiles.seed.json'),
];

class MtuProfileError extends Error {
  constructor(message, { status = 400, code = 'MTU_PROFILE_ERROR' } = {}) {
    super(message);
    this.name = 'MtuProfileError';
    this.status = status;
    this.code = code;
  }
}

/** @type {{ mtimeMs: number, bank: object } | null} */
let cache = null;

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

function ensureSeedBank() {
  const seedPath = resolveSeedPath();
  if (!seedPath) {
    throw new MtuProfileError('mtu-profiles seed missing', {
      status: 500,
      code: 'MTU_SEED_MISSING',
    });
  }
  let need = false;
  if (!fs.existsSync(BANK_PATH) || !fs.statSync(BANK_PATH).size) {
    need = true;
  } else {
    try {
      const dest = JSON.parse(fs.readFileSync(BANK_PATH, 'utf8'));
      const seed = JSON.parse(fs.readFileSync(seedPath, 'utf8'));
      if (bankVersion(dest) < bankVersion(seed)) need = true;
    } catch {
      need = true;
    }
  }
  if (need) {
    fs.mkdirSync(path.dirname(BANK_PATH), { recursive: true });
    fs.copyFileSync(seedPath, BANK_PATH);
  }
}

function loadBankSync() {
  ensureSeedBank();
  const st = fs.statSync(BANK_PATH);
  if (cache && cache.mtimeMs === st.mtimeMs) return cache.bank;
  let data;
  try {
    data = JSON.parse(fs.readFileSync(BANK_PATH, 'utf8'));
  } catch (err) {
    throw new MtuProfileError(`mtu-profiles invalid JSON: ${err.message}`, {
      status: 500,
      code: 'MTU_JSON',
    });
  }
  if (!data || typeof data.profiles !== 'object' || !data.profiles) {
    throw new MtuProfileError('mtu-profiles missing profiles', {
      status: 500,
      code: 'MTU_SHAPE',
    });
  }
  cache = { mtimeMs: st.mtimeMs, bank: data };
  return data;
}

function invalidateCache() {
  cache = null;
}

function listProfiles(bank = loadBankSync()) {
  return Object.keys(bank.profiles).map((id) => {
    const p = bank.profiles[id] || {};
    const mtu = p.mtu == null || p.mtu === '' ? null : Number(p.mtu);
    return {
      id,
      mtu: mtu == null || !Number.isFinite(mtu) ? null : mtu,
      label: p.label != null ? String(p.label) : (mtu == null ? '—' : String(mtu)),
    };
  });
}

function getDefaultProfileId(bank = loadBankSync()) {
  const d = bank.defaultProfile != null ? String(bank.defaultProfile) : '';
  if (d && bank.profiles[d]) return d;
  const ids = Object.keys(bank.profiles);
  return ids[0] || '1280';
}

function isKnownProfile(id, bank = loadBankSync()) {
  return Boolean(id && bank.profiles && bank.profiles[String(id)]);
}

/** @returns {number|null} null = omit MTU from client conf */
function resolveMtuValue(profileId, bank = loadBankSync()) {
  const id = profileId && isKnownProfile(profileId, bank)
    ? String(profileId)
    : getDefaultProfileId(bank);
  const p = bank.profiles[id] || {};
  if (p.mtu == null || p.mtu === '' || p.mtu === 'none') return null;
  const n = Number(p.mtu);
  if (!Number.isFinite(n) || n < 576 || n > 9000) {
    throw new MtuProfileError(`invalid mtu in profile ${id}`, { code: 'MTU_BAD_VALUE' });
  }
  return Math.round(n);
}

function getCatalog() {
  const bank = loadBankSync();
  return {
    version: bankVersion(bank),
    defaultProfile: getDefaultProfileId(bank),
    profiles: listProfiles(bank),
  };
}

module.exports = {
  MtuProfileError,
  ensureSeedBank,
  loadBankSync,
  invalidateCache,
  listProfiles,
  getDefaultProfileId,
  isKnownProfile,
  resolveMtuValue,
  getCatalog,
};
