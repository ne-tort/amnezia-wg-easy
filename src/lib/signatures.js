'use strict';

const fs = require('node:fs/promises');
const path = require('node:path');
const { spawn } = require('node:child_process');
const debug = require('debug')('signatures');

const { WG_PATH } = require('../config');

const SIGNATURES_PATH = path.join(WG_PATH, 'signatures.json');
const DEFAULT_SIGNATURES_PATH = path.join(process.cwd(), 'python_signatures', 'config', 'signatures.default.json');
const RUN_ALL_TIMEOUT_MS = 150000;

let cache = null;
let regenerationInProgress = false;

/**
 * Load signatures from SIGNATURES_PATH. If file is missing, copy from bundled default
 * and retry. Caches result in memory. Returns object { profileId: "<b 0x...>", ... }.
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

function getHardcodedFallback() {
  return {
    dns: '<b 0x084481800001000300000000077469636b65747306776964676574096b696e6f706f69736b0272750000010001c00c0005000100000039001806776964676574077469636b6574730679616e646578c025c0390005000100000039002b1765787465726e616c2d7469636b6574732d776964676574066166697368610679616e646578036e657400c05d000100010000001c000457fafe25>',
    quic: '<b 0x68747470733a2f2f6578616d706c652e636f6d2f>',
    sip: '<b 0x4f5054494f4e53207369703a7369702e6578616d706c652e636f6d205349502f322e30>',
    stun: '<b 0x000100002112a442544553545445535454455354>',
    webrtc: '<b 0x000100002112a442000000000000000000000000>',
    dtls: '<b 0x16fefd00000000000000000000001801000014000000000000000000>',
  };
}

function invalidateCache() {
  cache = null;
}

/**
 * Return I1 hex string for profileId. Uses cached signatures; falls back to default profile
 * if profileId unknown or missing. Call loadSignatures() once before (e.g. at startup or first use).
 */
function getI1ForProfile(profileId, signaturesObj) {
  const sigs = signaturesObj || cache;
  const DEFAULT_PROFILE_ID = 'dns';
  const fallback = getHardcodedFallback();
  if (!sigs) return fallback[DEFAULT_PROFILE_ID] || fallback.dns;
  const hex = sigs[profileId];
  if (typeof hex === 'string' && hex.startsWith('<b 0x')) return hex;
  return sigs[DEFAULT_PROFILE_ID] || fallback[DEFAULT_PROFILE_ID] || fallback.dns;
}

/**
 * Run Python run_all to regenerate signatures. On success overwrites file and refreshes cache.
 * On failure does not overwrite; returns { success: false, message }.
 * Uses explicit setTimeout + child.kill for timeout (spawn options.timeout not reliable across Node versions).
 * If a run is already in progress, does not spawn again (resolves with { success: true, message: 'Already running' }).
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
  loadSignatures,
  invalidateCache,
  getI1ForProfile,
  runSignatureGeneration,
};
