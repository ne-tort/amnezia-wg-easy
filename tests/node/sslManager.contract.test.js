'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');
const Module = require('node:module');

const srcRoot = path.resolve(__dirname, '../../src');

function loadSslManager({ dbPath, tlsOverrides = {}, x25519Text = null } = {}) {
  process.env.DB_PATH = dbPath;
  process.env.SESSION_SECRET = 'test-session-secret';

  const confFile = path.join(srcRoot, 'config.js');
  const dbFile = path.join(srcRoot, 'lib', 'db.js');
  const tlsFile = path.join(srcRoot, 'lib', 'tlsMaterial.js');
  const sslFile = path.join(srcRoot, 'lib', 'sslManager.js');
  const xrayFile = path.join(srcRoot, 'lib', 'amneziaXray.js');

  for (const f of [confFile, dbFile, tlsFile, sslFile, xrayFile]) {
    delete require.cache[f];
  }

  // eslint-disable-next-line import/no-dynamic-require, global-require
  const realTls = require(tlsFile);
  const tlsMock = {
    ...realTls,
    panelCertDomain: () => 'panel.example.com',
    certExistsInVolume: async () => true,
    getCertbotEmail: () => 'admin@example.com',
    normalizeHostname: (h) => String(h || '').trim().toLowerCase().replace(/\.$/, ''),
    isFqdn: (h) => /\./.test(h),
    certPathsForDomain: (d) => ({
      cert: `/etc/letsencrypt/live/${d}/fullchain.pem`,
      key: `/etc/letsencrypt/live/${d}/privkey.pem`,
    }),
    parseOpensslEnddate: () => Date.now() + 30 * 86400 * 1000,
    ensureSelfSignedCert: async () => undefined,
    issueLetsEncrypt: async () => undefined,
    injectManualPem: async () => undefined,
    resolveCertbotVolumeName: async () => 'test_certbot_conf',
    ...tlsOverrides,
  };
  require.cache[tlsFile] = {
    id: tlsFile,
    filename: tlsFile,
    loaded: true,
    exports: tlsMock,
  };

  if (x25519Text != null) {
    const originalRequire = Module.prototype.require;
    Module.prototype.require = function mockRequire(id) {
      if (id === 'node:child_process' || id === 'child_process') {
        return {
          execFile: (bin, args, opts, cb) => {
            const done = typeof opts === 'function' ? opts : cb;
            process.nextTick(() => done(null, { stdout: x25519Text, stderr: '' }));
          },
        };
      }
      return originalRequire.apply(this, arguments);
    };
    try {
      // eslint-disable-next-line import/no-dynamic-require, global-require
      const db = require(dbFile);
      db.getDb();
      // eslint-disable-next-line import/no-dynamic-require, global-require
      const sslManager = require(sslFile);
      return {
        sslManager,
        db,
        restore() {
          Module.prototype.require = originalRequire;
          try { db.closeDb(); } catch { /* ignore */ }
        },
      };
    } catch (err) {
      Module.prototype.require = originalRequire;
      throw err;
    }
  }

  // eslint-disable-next-line import/no-dynamic-require, global-require
  const db = require(dbFile);
  db.getDb();
  // eslint-disable-next-line import/no-dynamic-require, global-require
  const sslManager = require(sslFile);
  return {
    sslManager,
    db,
    restore() {
      try { db.closeDb(); } catch { /* ignore */ }
    },
  };
}

test('sslManager exports inventory API and TYPES', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'awg-ssl-'));
  const { sslManager, restore } = loadSslManager({ dbPath: path.join(tmp, 'panel.db') });
  try {
    assert.deepEqual([...sslManager.TYPES].sort(), [
      'lets_encrypt', 'manual', 'panel', 'reality', 'self_signed',
    ].sort());
    for (const name of [
      'list', 'get', 'syncPanel', 'createSelfSigned', 'createLetsEncrypt',
      'createReality', 'importPem', 'importPath', 'renew', 'remove',
    ]) {
      assert.equal(typeof sslManager[name], 'function', name);
    }
  } finally {
    restore();
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('syncPanel upserts managed panel row', async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'awg-ssl-'));
  const { sslManager, db, restore } = loadSslManager({
    dbPath: path.join(tmp, 'panel.db'),
    tlsOverrides: {
      // Skip docker openssl inspect
      certExistsInVolume: async () => false,
    },
  });
  try {
    const row = await sslManager.syncPanel();
    assert.ok(row);
    assert.equal(row.type, 'panel');
    assert.equal(row.domain, 'panel.example.com');
    assert.equal(row.managed, true);
    assert.equal(row.source, 'synced_panel');

    const again = await sslManager.syncPanel();
    assert.equal(again.id, row.id);

    const n = db.getDb().prepare("SELECT COUNT(*) AS n FROM ssl_certificates WHERE type = 'panel'").get().n;
    assert.equal(n, 1);

    await assert.rejects(() => sslManager.remove(row.id), /cannot be deleted/i);
  } finally {
    restore();
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('createReality stores keys and default dest', async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'awg-ssl-'));
  const { sslManager, restore } = loadSslManager({
    dbPath: path.join(tmp, 'panel.db'),
    x25519Text: 'Private key: PRIVKEYBASE64\nPublic key: PUBKEYBASE64\n',
  });
  try {
    const cert = await sslManager.createReality({ sni: 'www.cloudflare.com', label: 'cf' });
    assert.equal(cert.type, 'reality');
    assert.equal(cert.sni, 'www.cloudflare.com');
    assert.equal(cert.realityDest, 'www.cloudflare.com:443');
    assert.equal(cert.label, 'cf');
    assert.equal(cert.realityPublicKey, 'PUBKEYBASE64');
    assert.ok(cert.realityShortId);
    assert.equal(cert.realityShortId.length, 16);

    const detail = await sslManager.get(cert.id, { includeSecrets: true });
    assert.equal(detail.realityPrivateKey, 'PRIVKEYBASE64');

    const listed = await sslManager.list();
    const pub = listed.certs.find((c) => c.id === cert.id);
    assert.ok(pub);
    assert.equal(pub.realityPrivateKey, undefined);
  } finally {
    restore();
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});
