'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');

async function withTempBank(run) {
  const tmp = await fs.mkdtemp(path.join(os.tmpdir(), 'awg-bank-'));
  process.env.WG_PATH = tmp;
  delete require.cache[require.resolve('../../src/config')];
  delete require.cache[require.resolve('../../src/lib/signaturesBank')];
  const mod = require('../../src/lib/signaturesBank');
  try {
    await run({ tmp, mod });
  } finally {
    await fs.rm(tmp, { recursive: true, force: true });
  }
}

const sampleBank = {
  version: 1,
  target: 10,
  profiles: {
    dns: {
      1: { i1: '<b 0xaa>', i2: '<b 0xbb>' },
      2: { i1: '<b 0xcc>' },
    },
    stun: {
      1: { i1: '<b 0xdd>' },
    },
    empty_proto: {
      1: { i2: '<b 0xee>' },
    },
  },
};

test('listProtocols skips entries without i1', async () => {
  await withTempBank(async ({ tmp, mod }) => {
    await fs.writeFile(path.join(tmp, 'signatures.json'), JSON.stringify(sampleBank), 'utf8');
    const bank = await mod.loadBank();
    assert.deepEqual(mod.listProtocols(bank), ['dns', 'stun']);
  });
});

test('getEntry returns slots for protocol#variant', async () => {
  await withTempBank(async ({ tmp, mod }) => {
    await fs.writeFile(path.join(tmp, 'signatures.json'), JSON.stringify(sampleBank), 'utf8');
    const bank = await mod.loadBank();
    const e = mod.getEntry('dns', '2', bank);
    assert.equal(e.i1, '<b 0xcc>');
    assert.equal(e.i2, undefined);
  });
});

test('ensureBinding reassigns missing variant', async () => {
  await withTempBank(async ({ tmp, mod }) => {
    await fs.writeFile(path.join(tmp, 'signatures.json'), JSON.stringify(sampleBank), 'utf8');
    const bank = await mod.loadBank();
    const b = mod.ensureBinding('dns', '99', bank);
    assert.equal(b.changed, true);
    assert.equal(b.profile, 'dns');
    assert.ok(['1', '2'].includes(b.signature));
    assert.ok(b.slots.i1);
  });
});

test('ensureBinding switches protocol if removed', async () => {
  await withTempBank(async ({ tmp, mod }) => {
    await fs.writeFile(path.join(tmp, 'signatures.json'), JSON.stringify(sampleBank), 'utf8');
    const bank = await mod.loadBank();
    const b = mod.ensureBinding('gone', '1', bank);
    assert.equal(b.changed, true);
    assert.ok(['dns', 'stun'].includes(b.profile));
  });
});

test('missing file throws BankError', async () => {
  await withTempBank(async ({ mod }) => {
    await assert.rejects(() => mod.loadBank(), (err) => {
      assert.equal(err.name, 'BankError');
      assert.match(err.message, /missing/i);
      return true;
    });
  });
});

test('invalid JSON throws BankError', async () => {
  await withTempBank(async ({ tmp, mod }) => {
    await fs.writeFile(path.join(tmp, 'signatures.json'), '{not json', 'utf8');
    await assert.rejects(() => mod.loadBank(), (err) => {
      assert.equal(err.name, 'BankError');
      assert.match(err.message, /invalid/i);
      return true;
    });
  });
});

test('pickRandomVariant can exclude current', async () => {
  await withTempBank(async ({ tmp, mod }) => {
    await fs.writeFile(path.join(tmp, 'signatures.json'), JSON.stringify(sampleBank), 'utf8');
    const bank = await mod.loadBank();
    const next = mod.pickRandomVariant('dns', bank, { exclude: '1' });
    assert.equal(next, '2');
  });
});

test('getProfilesCatalog lists variants', async () => {
  await withTempBank(async ({ tmp, mod }) => {
    await fs.writeFile(path.join(tmp, 'signatures.json'), JSON.stringify(sampleBank), 'utf8');
    const bank = await mod.loadBank();
    const cat = mod.getProfilesCatalog(bank);
    assert.equal(cat.ok, true);
    const dns = cat.protocols.find((p) => p.id === 'dns');
    assert.deepEqual(dns.variants, ['1', '2']);
    assert.equal(dns.count, 2);
  });
});
