'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

function withTempBank(run) {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'awg-dns-prof-'));
  process.env.WG_PATH = tmp;
  delete require.cache[require.resolve('../../src/config')];
  delete require.cache[require.resolve('../../src/lib/dnsProfilesBank')];
  const mod = require('../../src/lib/dnsProfilesBank');
  try {
    return run({ tmp, mod });
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}

test('seed creates dns-profiles.json with numbered profiles', () => {
  withTempBank(({ tmp, mod }) => {
    mod.ensureSeedBank();
    assert.ok(fs.existsSync(path.join(tmp, 'dns-profiles.json')));
    const catalog = mod.getProfilesCatalog();
    assert.ok(catalog.profiles.length >= 2);
    assert.equal(catalog.profiles[0].id, '1');
    assert.ok(catalog.defaultProfile);
  });
});

test('renderForwardRecords includes dual Cloudflare DoT and Emercoin stubs', () => {
  withTempBank(({ mod }) => {
    mod.ensureSeedBank();
    const conf = mod.renderForwardRecords('1');
    assert.match(conf, /forward-tls-upstream: yes/);
    assert.match(conf, /1\.1\.1\.1@853#cloudflare-dns\.com/);
    assert.match(conf, /1\.0\.0\.1@853#cloudflare-dns\.com/);
    assert.match(conf, /stub-zone:/);
    assert.match(conf, /name: coin\./);
  });
});

test('Google UDP profile disables TLS', () => {
  withTempBank(({ mod }) => {
    mod.ensureSeedBank();
    const conf = mod.renderForwardRecords('5');
    assert.match(conf, /forward-tls-upstream: no/);
    assert.match(conf, /8\.8\.8\.8@53/);
    assert.match(conf, /8\.8\.4\.4@53/);
    assert.doesNotMatch(conf, /#dns\.google/);
  });
});

test('seed orders Cloudflare before niche resolvers', () => {
  withTempBank(({ mod }) => {
    mod.ensureSeedBank();
    const catalog = mod.getProfilesCatalog();
    assert.ok(catalog.profiles.length >= 10);
    assert.equal(catalog.profiles[0].id, '1');
    assert.match(catalog.profiles[0].name, /Cloudflare/i);
    assert.ok(catalog.profiles.some((p) => /AdGuard/i.test(p.name)));
    assert.ok(catalog.profiles.some((p) => /OpenDNS/i.test(p.name)));
  });
});

test('unknown profile throws 404', () => {
  withTempBank(({ mod }) => {
    mod.ensureSeedBank();
    assert.throws(() => mod.resolveProfile('999'), (err) => err.status === 404);
  });
});
