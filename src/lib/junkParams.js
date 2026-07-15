'use strict';

/**
 * Protocol-aware AmneziaWG junk/header generation and validation.
 * Ranges: WG_PATH/junk-ranges.json (seeded from config/junk-ranges.seed.json).
 */

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { WG_PATH } = require('../config');

const BANK_PATH = path.join(WG_PATH, 'junk-ranges.json');
const SEED_CANDIDATES = [
  path.join(__dirname, '..', 'config', 'junk-ranges.seed.json'),
  path.join(__dirname, '..', '..', 'config', 'junk-ranges.seed.json'),
];

const HARD = {
  jcMin: 1,
  jcMax: 128,
  jAbsMax: 1280,
  s4Max: 32,
  hMin: 5,
  hMax: 2147483647,
  jSpanMin: 64,
};

/** @type {{ mtimeMs: number, bank: object } | null} */
let cache = null;

class JunkParamsError extends Error {
  constructor(message, { status = 400, code = 'JUNK_PARAMS_ERROR' } = {}) {
    super(message);
    this.name = 'JunkParamsError';
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

function ensureSeedBank() {
  const seedPath = resolveSeedPath();
  if (!seedPath) {
    throw new JunkParamsError('junk-ranges seed missing', {
      status: 500,
      code: 'JUNK_RANGES_SEED_MISSING',
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
  let st;
  try {
    st = fs.statSync(BANK_PATH);
  } catch (err) {
    throw new JunkParamsError(`junk-ranges unreadable: ${err.message}`, {
      status: 500,
      code: 'JUNK_RANGES_IO',
    });
  }
  if (cache && cache.mtimeMs === st.mtimeMs) return cache.bank;
  let data;
  try {
    data = JSON.parse(fs.readFileSync(BANK_PATH, 'utf8'));
  } catch (err) {
    throw new JunkParamsError(`junk-ranges invalid JSON: ${err.message}`, {
      status: 500,
      code: 'JUNK_RANGES_JSON',
    });
  }
  if (!data || typeof data !== 'object' || !data.defaults) {
    throw new JunkParamsError('junk-ranges missing defaults', {
      status: 500,
      code: 'JUNK_RANGES_SHAPE',
    });
  }
  cache = { mtimeMs: st.mtimeMs, bank: data };
  return data;
}

function invalidateCache() {
  cache = null;
}

function mergeRange(base, over) {
  if (!over || typeof over !== 'object') return { ...base };
  const out = { ...base };
  for (const k of Object.keys(over)) {
    if (over[k] && typeof over[k] === 'object' && !Array.isArray(over[k])) {
      out[k] = { ...(base[k] || {}), ...over[k] };
    } else {
      out[k] = over[k];
    }
  }
  return out;
}

function getRangesForProtocol(protocolId, bank = loadBankSync()) {
  const id = String(protocolId || '').trim();
  const defaults = bank.defaults || {};
  const over = (bank.protocols && id && bank.protocols[id]) || {};
  return mergeRange(defaults, over);
}

function rndInt(min, max) {
  const a = Math.ceil(Number(min));
  const b = Math.floor(Number(max));
  if (!Number.isFinite(a) || !Number.isFinite(b) || b < a) {
    throw new JunkParamsError(`invalid random range ${min}..${max}`);
  }
  if (a === b) return a;
  return crypto.randomInt(a, b + 1);
}

function rollField(spec, hardMin, hardMax) {
  const lo = Math.max(hardMin, Number(spec.min));
  const hi = Math.min(hardMax, Number(spec.max));
  if (!Number.isFinite(lo) || !Number.isFinite(hi) || hi < lo) {
    throw new JunkParamsError(`bad field range ${JSON.stringify(spec)}`);
  }
  return rndInt(lo, hi);
}

function generateHeaders(hSpec) {
  const mode = (hSpec && hSpec.mode) || 'single';
  const min = Math.max(HARD.hMin, Number(hSpec.min) || HARD.hMin);
  const max = Math.min(HARD.hMax, Number(hSpec.max) || HARD.hMax);
  const split = Math.max(4, Number(hSpec.poolSplit) || 4);
  if (max - min < split * 4) {
    throw new JunkParamsError('H pool too small', { code: 'JUNK_H_POOL' });
  }
  const zone = Math.floor((max - min + 1) / split);
  const pick = (zi) => {
    const zMin = min + zi * zone;
    const zMax = zi === split - 1 ? max : zMin + zone - 1;
    return rndInt(zMin, zMax);
  };
  if (mode !== 'single') {
    // Panel stores singles for amneziawg-go; still emit four distinct ints.
  }
  const h1 = pick(0);
  let h2 = pick(1);
  let h3 = pick(2);
  let h4 = pick(3);
  const used = new Set([h1]);
  const ensureUnique = (v, zi) => {
    let x = v;
    let guard = 0;
    while (used.has(x) && guard < 32) {
      x = pick(zi);
      guard += 1;
    }
    if (used.has(x)) x = Math.min(max, Math.max(min, x + 1));
    used.add(x);
    return x;
  };
  h2 = ensureUnique(h2, 1);
  h3 = ensureUnique(h3, 2);
  h4 = ensureUnique(h4, 3);
  return { h1, h2, h3, h4 };
}

/**
 * @returns {{
 *   jc: number, jmin: number, jmax: number,
 *   s1: number, s2: number, s3: number, s4: number,
 *   h1: number, h2: number, h3: number, h4: number
 * }}
 */
function generateJunk(protocolId, { bank } = {}) {
  const ranges = getRangesForProtocol(protocolId, bank || loadBankSync());
  let lastErr = 'generate failed';
  for (let attempt = 0; attempt < 48; attempt += 1) {
    try {
      const jc = rollField(ranges.jc, HARD.jcMin, HARD.jcMax);
      let jmin = rollField(ranges.jmin, 0, HARD.jAbsMax - 1);
      let jmax = rollField(ranges.jmax, 1, HARD.jAbsMax);
      if (jmax < jmin + HARD.jSpanMin) jmax = Math.min(HARD.jAbsMax, jmin + HARD.jSpanMin);
      if (jmax <= jmin) jmax = Math.min(HARD.jAbsMax, jmin + HARD.jSpanMin);
      if (jc >= 4 && jmax <= 81) jmax = Math.min(HARD.jAbsMax, 82 + rndInt(0, 40));

      let s1 = rollField(ranges.s1, 0, 1132);
      let s2 = rollField(ranges.s2, 0, 1188);
      let guard = 0;
      while (s2 === s1 + 56 && guard < 16) {
        s2 = rollField(ranges.s2, 0, 1188);
        guard += 1;
      }
      let s3 = rollField(ranges.s3, 0, 1216);
      guard = 0;
      while ((s3 === s1 + 56 || s3 === s2 + 92) && guard < 16) {
        s3 = rollField(ranges.s3, 0, 1216);
        guard += 1;
      }
      const s4 = rollField(ranges.s4, 0, HARD.s4Max);
      const headers = generateHeaders(ranges.h || {});

      const junk = {
        jc,
        jmin,
        jmax,
        s1,
        s2,
        s3,
        s4,
        h1: headers.h1,
        h2: headers.h2,
        h3: headers.h3,
        h4: headers.h4,
      };
      validateJunk(junk);
      return junk;
    } catch (err) {
      lastErr = err.message || lastErr;
    }
  }
  throw new JunkParamsError(`unable to generate valid junk: ${lastErr}`, {
    code: 'JUNK_GENERATE_FAILED',
  });
}

function toInt(v, name) {
  const n = typeof v === 'string' && /^-?\d+$/.test(v.trim())
    ? Number(v.trim())
    : Number(v);
  if (!Number.isInteger(n)) {
    throw new JunkParamsError(`${name} must be an integer`, { code: 'JUNK_INVALID' });
  }
  return n;
}

function normalizeJunk(raw) {
  if (!raw || typeof raw !== 'object') {
    throw new JunkParamsError('junk object required', { code: 'JUNK_INVALID' });
  }
  return {
    jc: toInt(raw.jc, 'jc'),
    jmin: toInt(raw.jmin, 'jmin'),
    jmax: toInt(raw.jmax, 'jmax'),
    s1: toInt(raw.s1, 's1'),
    s2: toInt(raw.s2, 's2'),
    s3: toInt(raw.s3, 's3'),
    s4: toInt(raw.s4, 's4'),
    h1: toInt(raw.h1, 'h1'),
    h2: toInt(raw.h2, 'h2'),
    h3: toInt(raw.h3, 'h3'),
    h4: toInt(raw.h4, 'h4'),
  };
}

function validateJunk(raw) {
  const j = normalizeJunk(raw);
  if (j.jc < HARD.jcMin || j.jc > HARD.jcMax) {
    throw new JunkParamsError(`jc out of range (${HARD.jcMin}..${HARD.jcMax})`, { code: 'JUNK_JC' });
  }
  if (j.jmin < 0 || j.jmax > HARD.jAbsMax || j.jmin >= j.jmax) {
    throw new JunkParamsError('jmin/jmax invalid', { code: 'JUNK_JSIZE' });
  }
  if (j.jmax < j.jmin + HARD.jSpanMin) {
    throw new JunkParamsError(`jmax must be >= jmin+${HARD.jSpanMin}`, { code: 'JUNK_JSPAN' });
  }
  if (j.s1 < 0 || j.s1 > 1132 || j.s2 < 0 || j.s2 > 1188 || j.s3 < 0 || j.s3 > 1216) {
    throw new JunkParamsError('s1/s2/s3 out of hard range', { code: 'JUNK_S' });
  }
  if (j.s4 < 0 || j.s4 > HARD.s4Max) {
    throw new JunkParamsError(`s4 must be 0..${HARD.s4Max}`, { code: 'JUNK_S4' });
  }
  if (j.s2 === j.s1 + 56) {
    throw new JunkParamsError('S1+56 must not equal S2', { code: 'JUNK_S_COLLISION' });
  }
  if (j.s3 === j.s2 + 92 || j.s3 === j.s1 + 56) {
    throw new JunkParamsError('S3 collides with S1/S2 sizes', { code: 'JUNK_S_COLLISION' });
  }
  const hs = [j.h1, j.h2, j.h3, j.h4];
  for (const h of hs) {
    if (h < HARD.hMin || h > HARD.hMax) {
      throw new JunkParamsError(`H out of range (${HARD.hMin}..${HARD.hMax})`, { code: 'JUNK_H' });
    }
  }
  if (new Set(hs).size !== 4) {
    throw new JunkParamsError('H1–H4 must be unique', { code: 'JUNK_H_UNIQUE' });
  }
  return j;
}

function parseJunkPins(raw) {
  if (raw == null || raw === '') return {};
  if (typeof raw === 'object' && !Array.isArray(raw)) return raw;
  try {
    const o = JSON.parse(String(raw));
    return o && typeof o === 'object' && !Array.isArray(o) ? o : {};
  } catch {
    return {};
  }
}

function stringifyJunkPins(pins) {
  return JSON.stringify(pins && typeof pins === 'object' ? pins : {});
}

/** Parse server junk for API/UI. Does not enforce hard limits (legacy DBs may have S4>32). */
function readServerJunk(server) {
  if (!server) return null;
  try {
    return normalizeJunk({
      jc: server.jc,
      jmin: server.jmin,
      jmax: server.jmax,
      s1: server.s1,
      s2: server.s2,
      s3: server.s3,
      s4: server.s4,
      h1: server.h1,
      h2: server.h2,
      h3: server.h3,
      h4: server.h4,
    });
  } catch {
    return null;
  }
}

function serverJunkFromConfig(server) {
  return validateJunk(readServerJunk(server) || server);
}

function applyJunkToServer(server, junk) {
  const j = validateJunk(junk);
  server.jc = j.jc;
  server.jmin = j.jmin;
  server.jmax = j.jmax;
  server.s1 = String(j.s1);
  server.s2 = String(j.s2);
  server.s3 = String(j.s3);
  server.s4 = String(j.s4);
  server.h1 = String(j.h1);
  server.h2 = String(j.h2);
  server.h3 = String(j.h3);
  server.h4 = String(j.h4);
  return j;
}

module.exports = {
  HARD,
  JunkParamsError,
  ensureSeedBank,
  loadBankSync,
  invalidateCache,
  getRangesForProtocol,
  generateJunk,
  normalizeJunk,
  validateJunk,
  parseJunkPins,
  stringifyJunkPins,
  readServerJunk,
  serverJunkFromConfig,
  applyJunkToServer,
};
