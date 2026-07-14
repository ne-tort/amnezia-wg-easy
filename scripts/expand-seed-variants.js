'use strict';

/**
 * Expand config/signatures.seed.json to N uniquely-i1 variants per protocol.
 * Live capture_udp_sig builder still dedupes identical i1 (is_duplicate_i1) and
 * caps static protocols via effective_target; this seed intentionally mutates
 * payloads so the panel has enough refresh choices out of the box.
 */
const fs = require('fs');
const path = require('path');

const TARGET = Number(process.argv[2] || 10);
const seedPath = path.join(__dirname, '..', 'config', 'signatures.seed.json');
const bank = JSON.parse(fs.readFileSync(seedPath, 'utf8'));

function mutateHexString(s, salt) {
  const m = String(s).match(/^(<b\s+0x)([0-9a-fA-F]+)(>)$/);
  if (!m) return s;
  const hex = m[2];
  if (hex.length < 4) return s;
  const buf = Buffer.from(hex, 'hex');
  for (let i = 0; i < buf.length; i++) {
    if (i < 4 || i >= buf.length - 8) {
      buf[i] = (buf[i] + salt * (i + 3) + 0x5a) & 0xff;
    }
  }
  return `${m[1]}${buf.toString('hex')}${m[3]}`;
}

function mutateSlots(slots, salt) {
  const out = {};
  for (const [k, v] of Object.entries(slots)) {
    out[k] = typeof v === 'string' ? mutateHexString(v, salt) : v;
  }
  return out;
}

let added = 0;
for (const variants of Object.values(bank.profiles || {})) {
  const v1 = variants['1'];
  if (!v1 || typeof v1 !== 'object') continue;
  const seenI1 = new Set();
  if (typeof v1.i1 === 'string') seenI1.add(v1.i1);
  for (let n = 2; n <= TARGET; n++) {
    const key = String(n);
    if (variants[key]) {
      if (typeof variants[key].i1 === 'string') seenI1.add(variants[key].i1);
      continue;
    }
    let salt = n;
    let candidate;
    for (let tries = 0; tries < 32; tries++) {
      candidate = mutateSlots(v1, salt);
      if (!candidate.i1 || !seenI1.has(candidate.i1)) break;
      salt += 17;
    }
    if (candidate.i1) seenI1.add(candidate.i1);
    variants[key] = candidate;
    added += 1;
  }
}

bank.version = Math.max(Number(bank.version) || 0, 3);
bank.target = TARGET;
fs.writeFileSync(seedPath, `${JSON.stringify(bank, null, 2)}\n`);
console.log('added', added, 'target', TARGET, 'version', bank.version);
for (const [p, v] of Object.entries(bank.profiles)) {
  const i1s = Object.values(v).map((x) => x && x.i1).filter(Boolean);
  const unique = new Set(i1s).size;
  console.log(p, 'variants', Object.keys(v).length, 'unique_i1', unique);
}
