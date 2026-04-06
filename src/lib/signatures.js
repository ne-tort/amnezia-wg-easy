'use strict';

const fs = require('node:fs/promises');
const path = require('node:path');
const { spawn } = require('node:child_process');
const debug = require('debug')('signatures');

const { WG_PATH } = require('../config');

const SIGNATURES_PATH = path.join(WG_PATH, 'signatures.json');
const DEFAULT_SIGNATURES_PATH = path.join(process.cwd(), 'python_signatures', 'config', 'signatures.default.json');
const RUN_ALL_TIMEOUT_MS = 150000;

const DEFAULT_PROFILE_ID = 'dns';

let cache = null;
let regenerationInProgress = false;

/**
 * Normalize one profile entry from JSON: object with i1..i5 CPS strings.
 */
function normalizeProfileEntry(raw) {
  if (raw == null || typeof raw !== 'object' || Array.isArray(raw)) return {};
  const out = {};
  for (const k of ['i1', 'i2', 'i3', 'i4', 'i5']) {
    if (typeof raw[k] === 'string' && raw[k].trim()) out[k] = raw[k].trim();
  }
  return out;
}

function validateSignaturesObject(data) {
  if (!data || typeof data !== 'object' || Array.isArray(data)) return false;
  return true;
}

function isCompleteProfile(profile) {
  return Boolean(
    profile &&
    typeof profile.i1 === 'string' && profile.i1.trim() &&
    typeof profile.i2 === 'string' && profile.i2.trim() &&
    typeof profile.i3 === 'string' && profile.i3.trim() &&
    typeof profile.i4 === 'string' && profile.i4.trim() &&
    typeof profile.i5 === 'string' && profile.i5.trim()
  );
}

/**
 * Load signatures from SIGNATURES_PATH. If file is missing, copy from bundled default
 * and retry. Caches result in memory. No legacy hardcoded profile fallback.
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
        throw new Error(`Failed to initialize signatures.json from default bundle: ${copyErr.message}`);
      }
    } else {
      throw new Error(`Failed to read signatures.json: ${err.message}`);
    }
  }
  let data;
  try {
    data = JSON.parse(raw);
  } catch (err) {
    throw new Error(`Invalid JSON in signatures file ${SIGNATURES_PATH}: ${err.message}`);
  }
  if (!validateSignaturesObject(data)) {
    throw new Error(`signatures file must be an object map: ${SIGNATURES_PATH}`);
  }
  cache = data;
  return cache;
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
  if (!sigs || typeof sigs !== 'object') {
    throw new Error('signatures are not loaded; call loadSignatures() first');
  }

  const pid = typeof profileId === 'string' && profileId.trim() ? profileId.trim() : DEFAULT_PROFILE_ID;
  const raw = sigs?.[pid];
  if (raw == null) {
    throw new Error(`profile not found in signatures: ${pid}`);
  }
  const norm = normalizeProfileEntry(raw);
  if (!isCompleteProfile(norm)) {
    throw new Error(`profile is incomplete (i1..i5 required): ${pid}`);
  }
  return norm;
}

/**
 * Return I1 CPS string for profileId (legacy).
 */
function getI1ForProfile(profileId, signaturesObj) {
  return getProfileSignatures(profileId, signaturesObj).i1;
}

/**
 * Web-panel friendly payload for one profile.
 */
function getProfilePayload(profileId, signaturesObj) {
  const profile = getProfileSignatures(profileId, signaturesObj);
  const pid = typeof profileId === 'string' && profileId.trim() ? profileId.trim() : DEFAULT_PROFILE_ID;
  return {
    profile_id: pid,
    i1: profile.i1,
    i2: profile.i2,
    i3: profile.i3,
    i4: profile.i4,
    i5: profile.i5,
    source_meta: {
      source: 'signatures_json_cache',
      signatures_path: SIGNATURES_PATH,
    },
  };
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
  getProfilePayload,
  normalizeProfileEntry,
  runSignatureGeneration,
};
