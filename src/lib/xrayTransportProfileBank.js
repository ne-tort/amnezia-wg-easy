'use strict';

/**
 * VLESS/Xray transport profile bank — persisted in app_settings, seeded from JSON.
 */

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const BANK_KEY = 'xray_transport_profile_bank';
const SEED_PATHS = [
  path.join(__dirname, '../../config/xray-transport-profiles.seed.json'),
  path.join(__dirname, '../config/xray-transport-profiles.seed.json'),
  '/app/config/xray-transport-profiles.seed.json',
];

function getDb() {
  return require('./db');
}

function loadSeedBank() {
  for (const p of SEED_PATHS) {
    if (!fs.existsSync(p)) continue;
    try {
      const raw = JSON.parse(fs.readFileSync(p, 'utf8'));
      if (raw && typeof raw === 'object' && !Array.isArray(raw)) return normalizeBank(raw);
    } catch {
      /* try next */
    }
  }
  return {};
}

function normalizeProfile(entry, network) {
  const id = String(entry.id || '').trim() || crypto.randomBytes(4).toString('hex');
  const name = String(entry.name || id).trim() || id;
  const settings = entry.settings && typeof entry.settings === 'object' ? { ...entry.settings } : {};
  return { id, name, network, settings };
}

/**
 * @param {Record<string, unknown>} bank
 */
function normalizeBank(bank) {
  /** @type {Record<string, Array<object>>} */
  const out = {};
  for (const [network, list] of Object.entries(bank || {})) {
    const net = String(network).trim().toLowerCase();
    if (!net || !Array.isArray(list)) continue;
    out[net] = list.map((e) => normalizeProfile(e, net));
  }
  return out;
}

function readBankRaw() {
  const raw = getDb().appSettings.get(BANK_KEY);
  if (!raw) return null;
  try {
    const parsed = JSON.parse(String(raw));
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
      return normalizeBank(parsed);
    }
  } catch {
    /* fall through */
  }
  return null;
}

function writeBank(bank) {
  getDb().appSettings.set(BANK_KEY, JSON.stringify(normalizeBank(bank)));
}

function ensureBankSeeded() {
  const existing = readBankRaw();
  if (existing && Object.keys(existing).length) return existing;
  const seed = loadSeedBank();
  writeBank(seed);
  return seed;
}

function getBank() {
  return ensureBankSeeded();
}

function listProfiles(network) {
  const bank = getBank();
  const net = String(network || '').trim().toLowerCase();
  if (!net) {
    return Object.entries(bank).flatMap(([n, profiles]) => profiles.map((p) => ({ ...p, network: n })));
  }
  return (bank[net] || []).map((p) => ({ ...p, network: net }));
}

function saveProfile(network, profile) {
  const net = String(network || '').trim().toLowerCase();
  if (!net) throw Object.assign(new Error('Network is required'), { status: 400 });
  const name = String(profile.name || '').trim();
  if (!name) throw Object.assign(new Error('Profile name is required'), { status: 400 });
  const settings = profile.settings && typeof profile.settings === 'object' ? profile.settings : {};
  const bank = getBank();
  const list = bank[net] ? bank[net].slice() : [];
  let id = String(profile.id || '').trim();
  if (id) {
    const idx = list.findIndex((p) => p.id === id);
    if (idx >= 0) {
      list[idx] = { id, name, network: net, settings: { ...settings } };
    } else {
      list.push({ id, name, network: net, settings: { ...settings } });
    }
  } else {
    id = crypto.randomBytes(4).toString('hex');
    list.push({ id, name, network: net, settings: { ...settings } });
  }
  bank[net] = list;
  writeBank(bank);
  return { id, name, network: net, settings: { ...settings } };
}

module.exports = {
  BANK_KEY,
  ensureBankSeeded,
  getBank,
  listProfiles,
  saveProfile,
  loadSeedBank,
  normalizeBank,
};
