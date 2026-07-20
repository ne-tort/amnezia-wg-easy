'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');
const { execFileSync } = require('node:child_process');
const Module = require('node:module');

const srcRoot = path.resolve(__dirname, '../../src');

function makeSelfSignedPem() {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'awg-pem-'));
  const key = path.join(tmp, 'key.pem');
  const cert = path.join(tmp, 'cert.pem');
  try {
    execFileSync('openssl', [
      'req', '-x509', '-nodes', '-days', '1', '-newkey', 'rsa:2048',
      '-keyout', key, '-out', cert, '-subj', '/CN=test.example.com',
    ], { stdio: 'ignore' });
    return {
      certPem: fs.readFileSync(cert, 'utf8'),
      keyPem: fs.readFileSync(key, 'utf8'),
      cleanup() { fs.rmSync(tmp, { recursive: true, force: true }); },
    };
  } catch {
    fs.rmSync(tmp, { recursive: true, force: true });
    return null;
  }
}

function loadSslManager({ dbPath, tlsOverrides = {}, x25519Text = null } = {}) {
  process.env.NODE_ENV = 'test';
  process.env.AWG_SSL_SKIP_REALITY_CHECK = '1';
  process.env.DB_PATH = dbPath;
  process.env.SESSION_SECRET = 'test-session-secret';
  process.env.PANEL_DOMAIN = 'panel.example.com';
  process.env.SSL_MODE = 'selfsigned';

  const confFile = path.join(srcRoot, 'config.js');
  const dbFile = path.join(srcRoot, 'lib', 'db.js');
  const tlsFile = path.join(srcRoot, 'lib', 'tlsMaterial.js');
  const sslFile = path.join(srcRoot, 'lib', 'sslManager.js');
  const xrayFile = path.join(srcRoot, 'lib', 'amneziaXray.js');
  const portFile = path.join(srcRoot, 'lib', 'portPlan.js');

  for (const f of [confFile, dbFile, tlsFile, sslFile, xrayFile, portFile]) {
    delete require.cache[f];
  }

  // eslint-disable-next-line import/no-dynamic-require, global-require
  const realTls = require(tlsFile);
  const tlsMock = {
    ...realTls,
    panelCertDomain: () => 'panel.example.com',
    panelLiveDomain: () => 'panel.example.com',
    certExistsInVolume: async () => true,
    getCertbotEmail: () => 'admin@example.com',
    normalizeHostname: (h) => String(h || '').trim().toLowerCase().replace(/\.$/, ''),
    isFqdn: (h) => /\./.test(h) && !/^\d+\.\d+\.\d+\.\d+$/.test(h),
    certPathsForDomain: (d) => ({
      cert: `/etc/letsencrypt/live/${d}/fullchain.pem`,
      key: `/etc/letsencrypt/live/${d}/privkey.pem`,
      domain: d,
    }),
    parsePemMeta: realTls.parsePemMeta,
    ensureSelfSignedCert: async () => undefined,
    issueLetsEncrypt: async () => undefined,
    issueLetsEncryptIp: async () => undefined,
    injectManualPem: async () => undefined,
    readPemFromVolume: async () => null,
    copyLiveCert: async () => undefined,
    removeLiveCert: async () => true,
    resolveCertbotVolumeName: async () => 'test_certbot_conf',
    ...tlsOverrides,
  };
  require.cache[tlsFile] = {
    id: tlsFile,
    filename: tlsFile,
    loaded: true,
    exports: tlsMock,
  };

  // Mock portPlan.reloadNginx for assignPanel
  // eslint-disable-next-line import/no-dynamic-require, global-require
  const realPort = require(portFile);
  require.cache[portFile] = {
    id: portFile,
    filename: portFile,
    loaded: true,
    exports: {
      ...realPort,
      reloadNginx: async () => undefined,
      isIpLiteral: realPort.isIpLiteral,
    },
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

test('parsePemMeta extracts notAfter and fingerprint', () => {
  const pem = makeSelfSignedPem();
  if (!pem) {
    // openssl missing — skip meaningfully
    assert.ok(true);
    return;
  }
  try {
    // eslint-disable-next-line import/no-dynamic-require, global-require
    const tls = require(path.join(srcRoot, 'lib', 'tlsMaterial.js'));
    const meta = tls.parsePemMeta(pem.certPem);
    assert.ok(meta.notAfter);
    assert.ok(meta.fingerprintSha256);
    assert.ok(meta.fingerprintSha256.length >= 40);
  } finally {
    pem.cleanup();
  }
});

test('sslManager exports inventory API and TYPES without panel type', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'awg-ssl-'));
  const { sslManager, restore } = loadSslManager({ dbPath: path.join(tmp, 'panel.db') });
  try {
    assert.deepEqual([...sslManager.TYPES].sort(), [
      'lets_encrypt', 'lets_encrypt_ip', 'manual', 'masquerade', 'reality', 'self_signed',
    ].sort());
    for (const name of [
      'list', 'get', 'syncPanel', 'createSelfSigned', 'createLetsEncrypt',
      'createReality', 'createMasquerade', 'importPem', 'importPath', 'renew', 'remove', 'assignPanel',
      'recheckReality', 'regenerateReality', 'setAutoRenew', 'tickAutoRenew',
    ]) {
      assert.equal(typeof sslManager[name], 'function', name);
    }
  } finally {
    restore();
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('syncPanel upserts is_panel row with real material type', async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'awg-ssl-'));
  const { sslManager, db, restore } = loadSslManager({
    dbPath: path.join(tmp, 'panel.db'),
  });
  try {
    const row = await sslManager.syncPanel();
    assert.ok(row);
    assert.notEqual(row.type, 'panel');
    assert.equal(row.isPanel, true);
    assert.equal(row.domain, 'panel.example.com');
    assert.equal(row.managed, true);

    const again = await sslManager.syncPanel();
    assert.equal(again.id, row.id);

    const n = db.getDb().prepare('SELECT COUNT(*) AS n FROM ssl_certificates WHERE is_panel = 1').get().n;
    assert.equal(n, 1);

    await assert.rejects(() => sslManager.remove(row.id), /cannot be deleted/i);
  } finally {
    restore();
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('assignPanel clears previous panel flag', async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'awg-ssl-'));
  const { sslManager, db, restore } = loadSslManager({
    dbPath: path.join(tmp, 'panel.db'),
    tlsOverrides: {
      certExistsInVolume: async () => true,
      copyLiveCert: async () => undefined,
    },
  });
  try {
    const panel = await sslManager.syncPanel();
    const other = await sslManager.importPem({
      domain: 'other.example.com',
      certPem: '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----',
      keyPem: '-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----',
    });
    // parsePemMeta may fail on stub PEM — that's ok for role test
    assert.ok(other.id);
    assert.equal(other.isPanel, false);

    const assigned = await sslManager.assignPanel(other.id);
    assert.equal(assigned.isPanel, true);

    const old = db.getDb().prepare('SELECT is_panel FROM ssl_certificates WHERE id = ?').get(panel.id);
    assert.equal(old.is_panel, 0);

    const n = db.getDb().prepare('SELECT COUNT(*) AS n FROM ssl_certificates WHERE is_panel = 1').get().n;
    assert.equal(n, 1);
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
