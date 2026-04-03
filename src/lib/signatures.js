'use strict';

const fs = require('node:fs/promises');
const path = require('node:path');
const { spawn } = require('node:child_process');
const debug = require('debug')('signatures');

const { WG_PATH, OBFS_R_BYTES } = require('../config');

const SIGNATURES_PATH = path.join(WG_PATH, 'signatures.json');
const DEFAULT_SIGNATURES_PATH = path.join(process.cwd(), 'python_signatures', 'config', 'signatures.default.json');
const RUN_ALL_TIMEOUT_MS = 150000;

const DEFAULT_PROFILE_ID = 'dns';

let cache = null;
let regenerationInProgress = false;

/**
 * Normalize one profile entry from JSON: either legacy string (I1 only) or { i1..i5 }.
 */
function normalizeProfileEntry(raw) {
  if (raw == null) return {};
  let v = raw;
  if (typeof v === 'string') {
    const t = v.trim();
    if (t.startsWith('{')) {
      try {
        v = JSON.parse(t);
      } catch (_) {
        /* keep as string */
      }
    }
  }
  if (typeof v === 'string') {
    const s = v.trim();
    if (s.startsWith('<b 0x')) return { i1: s };
    return {};
  }
  if (typeof v === 'object' && v !== null && !Array.isArray(v)) {
    const out = {};
    for (const k of ['i1', 'i2', 'i3', 'i4', 'i5']) {
      if (typeof v[k] === 'string' && v[k].trim()) out[k] = v[k].trim();
    }
    return out;
  }
  return {};
}

/**
 * Load signatures from SIGNATURES_PATH. If file is missing, copy from bundled default
 * and retry. Caches result in memory.
 */
async function loadSignatures() {
  if (cache) return cache;
  let raw;
  try {
    raw = await fs.readFile(SIGNATURES_PATH, 'utf8');
  } catch (err) {
    if (err.code === 'ENOENT') {
      try {
        await fs.mkdir(path.dirname(SIGNATURES_PATH), { recursive: true });
        await fs.copyFile(DEFAULT_SIGNATURES_PATH, SIGNATURES_PATH);
        debug('Copied default signatures to %s', SIGNATURES_PATH);
        raw = await fs.readFile(SIGNATURES_PATH, 'utf8');
      } catch (copyErr) {
        debug('Default copy failed: %s', copyErr.message);
        const fromDb = tryGetSignaturesFromDb();
        cache = fromDb || getHardcodedFallback();
        return cache;
      }
    } else {
      debug('Read failed: %s', err.message);
      const fromDb = tryGetSignaturesFromDb();
      cache = fromDb || getHardcodedFallback();
      return cache;
    }
  }
  try {
    const data = JSON.parse(raw);
    if (data && typeof data === 'object') cache = data;
    else cache = tryGetSignaturesFromDb() || getHardcodedFallback();
  } catch (_) {
    cache = tryGetSignaturesFromDb() || getHardcodedFallback();
  }
  return cache;
}

function tryGetSignaturesFromDb() {
  try {
    const db = require('./db');
    const fromDb = db.protocolTemplates.getAll();
    if (fromDb && typeof fromDb === 'object' && Object.keys(fromDb).length > 0) return fromDb;
  } catch (_) {}
  return null;
}

/** Bundled CPS when no signatures.json: template until `run_all` without --dry-run (real capture). */
function getHardcodedFallback() {
  return {
    dns: {
      i1: '<b 0x084481800001000300000000077469636b65747306776964676574096b696e6f706f69736b0272750000010001c00c0005000100000039001806776964676574077469636b6574730679616e646578c025c0390005000100000039002b1765787465726e616c2d7469636b6574732d776964676574066166697368610679616e646578036e657400c05d000100010000001c000457fafe25>',
      i2: '<b 0xad3801000001000000000001076578616d706c6503636f6d000001000100002904d0000000000000>',
      i3: '<t>',
      i4: '<r 48>',
      i5: '<r 48>',
    },
    quic: {
      i1: '<b 0xc700000001><rc 8><t><r 100>',
      i2: '<b 0xf6ab3267fa><t><rc 20><r 80>',
      i3: '<t>',
      i4: '<r 48>',
      i5: '<r 48>',
    },
    sip: {
      i1: '<b 0x4f5054494f4e53207369703a7369702e6578616d706c652e636f6d205349502f322e30>',
      i2: '<rc 40><r 80>',
      i3: '<t>',
      i4: '<r 48>',
      i5: '<r 48>',
    },
    stun: {
      i1: '<b 0x000100002112a442544553545445535454455354>',
      i2: '<b 0x010100002112a442><rc 12><r 64>',
      i3: '<t>',
      i4: '<r 48>',
      i5: '<r 48>',
    },
    webrtc: {
      i1: '<b 0x000100002112a442000000000000000000000000>',
      i2: '<b 0x010100002112a442><rc 12><r 64>',
      i3: '<t>',
      i4: '<r 48>',
      i5: '<r 48>',
    },
    dtls: {
      i1: '<b 0x16fefd00000000000000000000001801000014000000000000000000>',
      i2: '<b 0x16fefd0000000000000000000000><r 96>',
      i3: '<t>',
      i4: '<r 48>',
      i5: '<r 48>',
    },
  };
}

function invalidateCache() {
  cache = null;
}

/**
 * Resolved CPS per profile (i1–i5). Uses only tags supported by amneziawg-go (<b>, <t>, <r>, <rc>, <rd>).
 * Never use <c> — not implemented in userspace core (see amneziawg-go #120).
 */
function getProfileSignatures(profileId, signaturesObj) {
  const sigs = signaturesObj || cache;
  const fallback = getHardcodedFallback();
  const rN = Number.isFinite(OBFS_R_BYTES) && OBFS_R_BYTES > 0 ? OBFS_R_BYTES : 48;
  const defaults = {
    i2: '<rc 24><r 80>',
    i3: '<t>',
    i4: `<r ${rN}>`,
    i5: `<r ${rN}>`,
  };

  let raw = sigs?.[profileId];
  if (raw == null) raw = sigs?.[DEFAULT_PROFILE_ID];
  let norm = normalizeProfileEntry(raw);

  if (!norm.i1) {
    const fb = fallback[profileId] || fallback[DEFAULT_PROFILE_ID];
    const fbNorm = normalizeProfileEntry(fb);
    norm = { ...fbNorm, ...norm };
  }
  if (!norm.i1) {
    const fb = fallback[DEFAULT_PROFILE_ID];
    const fbNorm = normalizeProfileEntry(fb);
    norm = { ...fbNorm, ...norm };
  }

  return {
    i1: norm.i1,
    i2: norm.i2 || defaults.i2,
    i3: norm.i3 || defaults.i3,
    i4: norm.i4 != null && norm.i4 !== '' ? norm.i4 : defaults.i4,
    i5: norm.i5 != null && norm.i5 !== '' ? norm.i5 : defaults.i5,
  };
}

/**
 * Return I1 CPS string for profileId (legacy).
 */
function getI1ForProfile(profileId, signaturesObj) {
  return getProfileSignatures(profileId, signaturesObj).i1;
}

/**
 * Run Python run_all to regenerate signatures. On success overwrites file and refreshes cache.
 */
function runSignatureGeneration() {
  return new Promise((resolve) => {
    if (regenerationInProgress) {
      resolve({ success: true, message: 'Already running' });
      return;
    }
    regenerationInProgress = true;

    let settled = false;
    const once = (result) => {
      if (settled) return;
      settled = true;
      regenerationInProgress = false;
      if (timeoutId !== null) clearTimeout(timeoutId);
      resolve(result);
    };

    const child = spawn(
      'python3',
      ['-m', 'python_signatures.run_all', '--out', SIGNATURES_PATH],
      { cwd: process.cwd(), env: { ...process.env, PYTHONPATH: process.cwd() } }
    );

    let timeoutId = setTimeout(() => {
      timeoutId = null;
      child.kill('SIGTERM');
      debug('run_all timeout after %d ms', RUN_ALL_TIMEOUT_MS);
      once({ success: false, message: 'Timeout' });
    }, RUN_ALL_TIMEOUT_MS);

    let stderr = '';
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.on('error', (err) => {
      debug('run_all spawn error: %s', err.message);
      once({ success: false, message: err.message });
    });
    child.on('close', (code) => {
      if (settled) return;
      if (timeoutId !== null) {
        clearTimeout(timeoutId);
        timeoutId = null;
      }
      if (code === 0) {
        invalidateCache();
        loadSignatures().then(() => once({ success: true })).catch((err) => {
          debug('loadSignatures after run_all: %s', err.message);
          once({ success: true });
        });
      } else {
        debug('run_all exit code %s stderr: %s', code, stderr);
        once({ success: false, message: stderr || `Exit code ${code}` });
      }
    });
  });
}

module.exports = {
  SIGNATURES_PATH,
  DEFAULT_PROFILE_ID,
  loadSignatures,
  invalidateCache,
  getI1ForProfile,
  getProfileSignatures,
  normalizeProfileEntry,
  runSignatureGeneration,
};
