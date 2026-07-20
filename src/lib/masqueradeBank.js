'use strict';

/**
 * Hysteria masquerade URL bank (mirror sites) + HTTPS preflight.
 */

const fs = require('node:fs');
const path = require('node:path');
const config = require('../config');

const HYSTERIA_REL = 'hysteria';
const MIRROR_BANK_SEED = path.join(__dirname, '../../config/mirror-bank.seed.json');
const MIRROR_BANK_SEED_IN_IMAGE = '/app/config/mirror-bank.seed.json';

function mirrorBankPaths() {
  return [
    path.join(config.WG_PATH || '/tmp', HYSTERIA_REL, 'mirror-bank.json'),
    MIRROR_BANK_SEED,
    MIRROR_BANK_SEED_IN_IMAGE,
  ];
}

function loadMirrorBankDomains() {
  for (const p of mirrorBankPaths()) {
    if (!fs.existsSync(p)) continue;
    try {
      const raw = JSON.parse(fs.readFileSync(p, 'utf8'));
      const list = Array.isArray(raw) ? raw : (raw.domains || []);
      return list.map((d) => String(d).trim()).filter(Boolean);
    } catch {
      /* try next */
    }
  }
  return [];
}

function toMasqueradeUrl(domain) {
  const d = String(domain || '').trim().replace(/^https?:\/\//i, '').replace(/\/.*$/, '');
  if (!d) return '';
  return `https://${d}/`;
}

function parseMasqueradeUrl(url) {
  const raw = String(url || '').trim();
  if (!raw) return { ok: false, message: 'URL is required' };
  try {
    const u = new URL(raw);
    if (u.protocol !== 'https:') {
      return { ok: false, message: 'Masquerade URL must use https://' };
    }
    if (!u.hostname) {
      return { ok: false, message: 'Masquerade URL must include a hostname' };
    }
    return { ok: true, url: u.href.endsWith('/') ? u.href : `${u.href.replace(/\/$/, '')}/`, hostname: u.hostname };
  } catch {
    return { ok: false, message: 'Invalid masquerade URL' };
  }
}

async function fetchProbe(url, method) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 12_000);
  try {
    const res = await fetch(url, {
      method,
      redirect: 'follow',
      signal: controller.signal,
      headers: { 'User-Agent': 'amnezia-wg-easy-masquerade-preflight/1.0' },
    });
    clearTimeout(timer);
    return { ok: res.status > 0 && res.status < 500, status: res.status };
  } catch (err) {
    clearTimeout(timer);
    return { ok: false, status: 0, message: String(err.message || 'Request failed') };
  }
}

async function preflightMasqueradeUrl(url) {
  const parsed = parseMasqueradeUrl(url);
  if (!parsed.ok) return parsed;
  let probe = await fetchProbe(parsed.url, 'HEAD');
  if (!probe.ok && probe.status === 405) {
    probe = await fetchProbe(parsed.url, 'GET');
  }
  if (!probe.ok && probe.status === 0) {
    probe = await fetchProbe(parsed.url, 'GET');
  }
  return {
    ok: probe.ok,
    url: parsed.url,
    hostname: parsed.hostname,
    status: probe.status || null,
    message: probe.ok ? null : (probe.message || `HTTP ${probe.status || 'error'}`),
  };
}

function listMasqueradeBank() {
  return loadMirrorBankDomains().map((domain) => ({
    domain,
    url: toMasqueradeUrl(domain),
  }));
}

async function validateBankEntries(domains) {
  const list = domains && domains.length ? domains : loadMirrorBankDomains();
  const results = [];
  for (const domain of list) {
    const url = toMasqueradeUrl(domain);
    // eslint-disable-next-line no-await-in-loop
    const check = await preflightMasqueradeUrl(url);
    results.push({
      domain,
      url,
      ok: check.ok,
      status: check.status,
      message: check.message,
    });
  }
  return results;
}

function pickRandomMasqueradeUrl() {
  const domains = loadMirrorBankDomains();
  if (!domains.length) return '';
  return toMasqueradeUrl(domains[Math.floor(Math.random() * domains.length)]);
}

module.exports = {
  loadMirrorBankDomains,
  toMasqueradeUrl,
  parseMasqueradeUrl,
  preflightMasqueradeUrl,
  listMasqueradeBank,
  validateBankEntries,
  pickRandomMasqueradeUrl,
};
