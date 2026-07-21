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

const MIRROR_PROBE_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';
const MIRROR_PROBE_TIMEOUT_MS = 15_000;

function mirrorHostKey(hostname) {
  return String(hostname || '').trim().toLowerCase().replace(/^www\./, '');
}

function mirrorSameSite(requestHost, finalHost) {
  return mirrorHostKey(requestHost) === mirrorHostKey(finalHost);
}

function mirrorVisibleText(html) {
  return String(html || '')
    .replace(/<script[\s\S]*?<\/script>/gi, '')
    .replace(/<style[\s\S]*?<\/style>/gi, '')
    .replace(/<[^>]+>/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

/** True when HTML is a thin client shell (often hangs as nginx mirror stub). */
function mirrorLooksLikeSpaShell(html) {
  const sample = String(html || '').slice(0, 12_000).toLowerCase();
  if (html.length > 25_000) return false;
  const spa = /__next_data__|\/_next\/|id="__next"|id="root"|id="app"|ng-version|data-reactroot|nuxt|vite|webpackJsonp/.test(sample);
  const textLen = mirrorVisibleText(html).length;
  return spa && textLen < 500;
}

function mirrorDenyPage(html, status) {
  if (status === 401 || status === 403 || status === 429) return true;
  const lower = String(html || '').slice(0, 5000).toLowerCase();
  return /access denied|<title>forbidden|<h1>forbidden|request blocked|captcha|cf-browser-verification|akamai|bot detection|please enable cookies|errors\.edgesuite\.net|cloudflare/.test(lower);
}

/**
 * Strict mirror-stub check: GET with browser UA, 200 HTML, same-site redirect, no deny/SPA shell.
 * @param {string} domain
 * @returns {Promise<{ ok: boolean, domain: string, url: string, status?: number, finalHost?: string, bodyLen?: number, ms?: number, reasons?: string[], message?: string }>}
 */
async function validateMirrorHost(domain) {
  const host = String(domain || '').trim().toLowerCase().replace(/^https?:\/\//i, '').replace(/\/.*$/, '');
  const url = toMasqueradeUrl(host);
  if (!host) {
    return { ok: false, domain: host, url, reasons: ['empty'], message: 'empty host' };
  }
  const t0 = Date.now();
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), MIRROR_PROBE_TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      method: 'GET',
      redirect: 'follow',
      signal: controller.signal,
      headers: {
        'User-Agent': MIRROR_PROBE_UA,
        Accept: 'text/html,application/xhtml+xml;q=0.9,*/*;q=0.8',
      },
    });
    clearTimeout(timer);
    const ms = Date.now() - t0;
    const text = await res.text();
    const finalHost = new URL(res.url).hostname;
    const reasons = [];
    if (res.status !== 200) reasons.push(`status${res.status}`);
    if (ms >= 12_000) reasons.push('slow');
    if (text.length < 1500) reasons.push('short');
    if (!mirrorSameSite(host, finalHost)) reasons.push(`redirect:${finalHost}`);
    if (mirrorDenyPage(text, res.status)) reasons.push('deny');
    if (mirrorLooksLikeSpaShell(text)) reasons.push('spa-shell');
    const ok = reasons.length === 0;
    return {
      ok,
      domain: host,
      url,
      status: res.status,
      finalHost,
      bodyLen: text.length,
      ms,
      reasons,
      message: ok ? null : reasons.join(', '),
    };
  } catch (err) {
    clearTimeout(timer);
    const msg = String(err.message || 'Request failed');
    return {
      ok: false,
      domain: host,
      url,
      ms: Date.now() - t0,
      reasons: [`err:${msg.slice(0, 80)}`],
      message: msg,
    };
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
    // eslint-disable-next-line no-await-in-loop
    const check = await validateMirrorHost(domain);
    results.push({
      domain: check.domain,
      url: check.url,
      ok: check.ok,
      status: check.status,
      message: check.message,
      reasons: check.reasons,
      finalHost: check.finalHost,
      bodyLen: check.bodyLen,
      ms: check.ms,
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
  validateMirrorHost,
  listMasqueradeBank,
  validateBankEntries,
  pickRandomMasqueradeUrl,
  _mirrorProbe: {
    mirrorHostKey,
    mirrorSameSite,
    mirrorDenyPage,
    mirrorLooksLikeSpaShell,
  },
};
