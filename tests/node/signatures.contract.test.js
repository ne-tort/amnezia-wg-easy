'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');

async function withTempSignatures(run) {
  const tmp = await fs.mkdtemp(path.join(os.tmpdir(), 'awg-signatures-'));
  process.env.WG_PATH = tmp;
  delete require.cache[require.resolve('../../src/config')];
  delete require.cache[require.resolve('../../src/lib/signatures')];
  const mod = require('../../src/lib/signatures');
  try {
    await run({ tmp, mod });
  } finally {
    await fs.rm(tmp, { recursive: true, force: true });
  }
}

test('getProfileSignatures returns full i1-i5 profile', async () => {
  await withTempSignatures(async ({ tmp, mod }) => {
    const file = path.join(tmp, 'signatures.json');
    await fs.writeFile(
      file,
      JSON.stringify({
        quic: { i1: '<b 0x01>', i2: '<b 0x02>', i3: '<b 0x03>', i4: '<b 0x04>', i5: '<b 0x05>' },
      }),
      'utf8'
    );
    await mod.loadSignatures();
    const p = mod.getProfileSignatures('quic');
    assert.equal(p.i1, '<b 0x01>');
    assert.equal(p.i5, '<b 0x05>');
  });
});

test('getProfileSignatures throws on incomplete profile', async () => {
  await withTempSignatures(async ({ tmp, mod }) => {
    const file = path.join(tmp, 'signatures.json');
    await fs.writeFile(file, JSON.stringify({ quic: { i1: '<b 0x01>' } }), 'utf8');
    await mod.loadSignatures();
    assert.throws(() => mod.getProfileSignatures('quic'), /incomplete/);
  });
});
