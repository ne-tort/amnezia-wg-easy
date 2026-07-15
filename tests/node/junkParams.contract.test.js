'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

function withTempJunk(run) {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'awg-junk-'));
  process.env.WG_PATH = tmp;
  delete require.cache[require.resolve('../../src/config')];
  delete require.cache[require.resolve('../../src/lib/junkParams')];
  const mod = require('../../src/lib/junkParams');
  try {
    return run({ tmp, mod });
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}

test('seed creates junk-ranges.json and merges protocol overrides', () => {
  withTempJunk(({ tmp, mod }) => {
    mod.ensureSeedBank();
    assert.ok(fs.existsSync(path.join(tmp, 'junk-ranges.json')));
    const bank = mod.loadBankSync();
    assert.equal(bank.version, 1);
    const dns = mod.getRangesForProtocol('dns', bank);
    assert.equal(dns.jc.max, 8);
    const unknown = mod.getRangesForProtocol('nope', bank);
    assert.equal(unknown.jc.max, bank.defaults.jc.max);
  });
});

test('generateJunk respects protocol constraints', () => {
  withTempJunk(({ mod }) => {
    mod.ensureSeedBank();
    for (let i = 0; i < 20; i += 1) {
      const j = mod.generateJunk('dns');
      assert.ok(j.jc >= 4 && j.jc <= 8);
      assert.ok(j.jmax >= j.jmin + 64);
      assert.ok(j.s4 <= 32);
      assert.notEqual(j.s2, j.s1 + 56);
      assert.notEqual(j.s3, j.s2 + 92);
      assert.equal(new Set([j.h1, j.h2, j.h3, j.h4]).size, 4);
      mod.validateJunk(j);
    }
  });
});

test('validateJunk rejects S1/S2 collision', () => {
  withTempJunk(({ mod }) => {
    mod.ensureSeedBank();
    const j = mod.generateJunk('quic');
    j.s2 = j.s1 + 56;
    assert.throws(() => mod.validateJunk(j), /S1\+56/);
  });
});

test('generateJunk does not rewrite seed file', () => {
  withTempJunk(({ tmp, mod }) => {
    mod.ensureSeedBank();
    const bankPath = path.join(tmp, 'junk-ranges.json');
    const before = fs.statSync(bankPath).mtimeMs;
    mod.generateJunk('stun');
    const after = fs.statSync(bankPath).mtimeMs;
    assert.equal(before, after);
  });
});
