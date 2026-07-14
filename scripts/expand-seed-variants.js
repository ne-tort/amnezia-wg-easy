'use strict';

/** Expand config/signatures.seed.json to 3 variants per protocol (deterministic mutations). */
const fs = require('fs');
const path = require('path');

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
  if (!variants['2']) {
    variants['2'] = mutateSlots(v1, 2);
    added += 1;
  }
  if (!variants['3']) {
    variants['3'] = mutateSlots(v1, 3);
    added += 1;
  }
}

bank.version = 2;
bank.target = 3;
fs.writeFileSync(seedPath, `${JSON.stringify(bank, null, 2)}\n`);
console.log('added', added);
for (const [p, v] of Object.entries(bank.profiles)) {
  console.log(p, Object.keys(v).join(','));
}
