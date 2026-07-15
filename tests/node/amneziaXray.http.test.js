'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');
const crypto = require('node:crypto');

const srcRoot = path.resolve(__dirname, '../../src');

class CookieJar {
  constructor() {
    this.cookies = new Map();
  }

  store(res) {
    const list = typeof res.headers.getSetCookie === 'function'
      ? res.headers.getSetCookie()
      : [];
    for (const raw of list) {
      const part = String(raw).split(';')[0];
      const eq = part.indexOf('=');
      if (eq <= 0) continue;
      this.cookies.set(part.slice(0, eq).trim(), part.slice(eq + 1));
    }
  }

  header() {
    return [...this.cookies.entries()].map(([k, v]) => `${k}=${v}`).join('; ');
  }
}

function clearSrcRequireCache() {
  for (const key of Object.keys(require.cache)) {
    if (key.replace(/\\/g, '/').includes('/src/')) {
      delete require.cache[key];
    }
  }
}

function installWireGuardMock(db) {
  const file = path.join(srcRoot, 'lib', 'WireGuard.js');
  const mock = {
    getClients: async () => ({
      clients: db.clients.getAll().map((r) => ({
        id: r.id,
        name: r.name,
        enabled: !!r.enabled,
        address: r.address,
        publicKey: r.public_key,
        downloadableConfig: true,
      })),
      serverCapabilities: {
        amneziaDnsAvailable: false,
        xrayAvailable: true,
        xray: { phase: 'running', desired: true, busy: false, sni: 'sni.example', fingerprint: 'chrome', flow: 'xtls-rprx-vision', port: 8443 },
      },
      serverJunk: null,
    }),
    saveConfig: async () => undefined,
  };
  require.cache[file] = {
    id: file, filename: file, loaded: true, exports: mock,
  };
}

function installXrayMock(state) {
  const file = path.join(srcRoot, 'lib', 'amneziaXray.js');
  const mock = {
    isAmneziaXrayAvailable: () => state.available === true,
    getStatus: () => ({
      desired: state.available,
      phase: state.available ? 'running' : 'off',
      available: state.available === true,
      busy: false,
      sni: 'www.gov.uk',
      fingerprint: 'chrome',
      flow: 'xtls-rprx-vision',
      port: 8443,
      fingerprints: ['chrome'],
      flows: ['xtls-rprx-vision', ''],
    }),
    enable: async () => mock.getStatus(),
    disable: async () => {
      state.available = false;
      return mock.getStatus();
    },
    forceCleanup: async () => {
      state.available = false;
      return mock.getStatus();
    },
    resetCredentials: async () => {
      state.resetCount = (state.resetCount || 0) + 1;
      return mock.getStatus();
    },
    ensureClientUuids: () => {},
    findEnabledClientByName: (name) => {
      const row = state.clients.find((c) => c.name === name && c.enabled);
      return row || null;
    },
    getClientXrayPayload: (client) => {
      if (!client) return null;
      return {
        uuid: client.xray_uuid,
        vlessUrl: `vless://${client.xray_uuid}@vpn.example.com:8443?encryption=none&security=reality`,
        subUrl: `/sub/${encodeURIComponent(client.name)}`,
        clientJson: { outbounds: [{ protocol: 'vless' }] },
      };
    },
  };
  require.cache[file] = {
    id: file, filename: file, loaded: true, exports: mock,
  };
}

async function api(base, jar, method, urlPath, body) {
  const headers = {};
  const cookie = jar.header();
  if (cookie) headers.Cookie = cookie;
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  const res = await fetch(`${base}${urlPath}`, {
    method,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  jar.store(res);
  let data = null;
  const text = await res.text();
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = text;
  }
  return { res, data, status: res.status, text };
}

async function setup() {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'awg-xray-http-'));
  process.env.DB_PATH = path.join(tmp, 'panel.db');
  process.env.SESSION_SECRET = 'xray-http-secret';
  process.env.ADMIN_USERNAME = 'admin';
  process.env.ADMIN_PASSWORD = 'adminpass';
  process.env.WG_PATH = tmp;
  clearSrcRequireCache();

  // eslint-disable-next-line import/no-dynamic-require, global-require
  const db = require(path.join(srcRoot, 'lib', 'db.js'));
  db.getDb();

  const now = Math.floor(Date.now() / 1000);
  const clientId = crypto.randomUUID();
  db.clients.create({
    id: clientId,
    name: 'Phone One',
    address: '10.8.0.2',
    public_key: 'pub',
    private_key: 'priv',
    enabled: 1,
    created_at: now,
    updated_at: now,
    rule_profile_id: 1,
    use_server_dns: 1,
  });
  db.clients.setXrayUuid(clientId, 'cccccccc-cccc-cccc-cccc-cccccccccccc');

  const state = {
    available: true,
    clients: [{
      id: clientId,
      name: 'Phone One',
      enabled: 1,
      xray_uuid: 'cccccccc-cccc-cccc-cccc-cccccccccccc',
    }],
  };
  installWireGuardMock(db);
  installXrayMock(state);

  // eslint-disable-next-line import/no-dynamic-require, global-require
  const { ensureFirstAdmin } = require(path.join(srcRoot, 'lib', 'ensureFirstAdmin.js'));
  await ensureFirstAdmin();

  // eslint-disable-next-line import/no-dynamic-require, global-require
  const auth = require(path.join(srcRoot, 'lib', 'auth.js'));
  const modId = auth.generateUserId();
  const modHash = await auth.hashPassword('modpass1');
  db.panelUsers.create({
    id: modId,
    username: 'modx',
    password_hash: modHash,
    role: 'moderator',
    is_active: 1,
    created_at: now,
    updated_at: now,
  });

  // eslint-disable-next-line import/no-dynamic-require, global-require
  const Server = require(path.join(srcRoot, 'lib', 'Server.js'));
  const server = new Server();
  await server.start({ port: 0, host: '127.0.0.1' });
  const base = `http://127.0.0.1:${server.listenPort}`;
  return { server, db, base, state };
}

test('HTTP Xray: admin enable ACL; mod forbidden; public /sub', async (t) => {
  const { server, db, base, state } = await setup();
  t.after(async () => {
    try { await server.stop(); } catch (_) { /* */ }
    try { db.closeDb(); } catch (_) { /* */ }
  });

  const adminJar = new CookieJar();
  let r = await api(base, adminJar, 'POST', '/api/session', {
    username: 'admin',
    password: 'adminpass',
  });
  assert.equal(r.status, 200);
  assert.ok(r.data.capabilities.includes('system.xray'));

  r = await api(base, adminJar, 'GET', '/api/amnezia-xray');
  assert.equal(r.status, 200);
  assert.equal(r.data.phase, 'running');

  const modJar = new CookieJar();
  r = await api(base, modJar, 'POST', '/api/session', {
    username: 'modx',
    password: 'modpass1',
  });
  assert.equal(r.status, 200);
  assert.equal(r.data.capabilities.includes('system.xray'), false);

  r = await api(base, modJar, 'GET', '/api/amnezia-xray');
  assert.equal(r.status, 403);

  r = await api(base, modJar, 'POST', '/api/amnezia-xray/enable', {
    sni: 'www.gov.uk',
  });
  assert.equal(r.status, 403);

  r = await api(base, modJar, 'POST', '/api/amnezia-xray/reset', {});
  assert.equal(r.status, 403);

  r = await api(base, adminJar, 'POST', '/api/amnezia-xray/reset', {});
  assert.equal(r.status, 200);
  assert.equal(state.resetCount, 1);

  // Public subscription — no cookie
  const emptyJar = new CookieJar();
  r = await api(base, emptyJar, 'GET', `/sub/${encodeURIComponent('Phone One')}`);
  assert.equal(r.status, 200);
  assert.equal(r.data.outbounds[0].protocol, 'vless');
  const uuidBefore = state.clients[0].xray_uuid;

  // Simulated toggle: available off then on — same client uuid in mock state
  state.available = false;
  r = await api(base, emptyJar, 'GET', `/sub/${encodeURIComponent('Phone One')}`);
  assert.equal(r.status, 503);
  state.available = true;
  r = await api(base, emptyJar, 'GET', `/sub/${encodeURIComponent('Phone One')}`);
  assert.equal(r.status, 200);
  assert.equal(state.clients[0].xray_uuid, uuidBefore);

  r = await api(base, emptyJar, 'GET', '/sub/UnknownName');
  assert.equal(r.status, 404);

  state.clients[0].enabled = 0;
  r = await api(base, emptyJar, 'GET', `/sub/${encodeURIComponent('Phone One')}`);
  assert.equal(r.status, 404);

  state.clients[0].enabled = 1;
  state.available = false;
  r = await api(base, emptyJar, 'GET', `/sub/${encodeURIComponent('Phone One')}`);
  assert.equal(r.status, 503);
});

test('HTTP Xray SNI Finder: admin ACL; private CIDR rejected', async (t) => {
  const { server, db, base } = await setup();
  t.after(async () => {
    try { await server.stop(); } catch (_) { /* */ }
    try { db.closeDb(); } catch (_) { /* */ }
  });

  const adminJar = new CookieJar();
  let r = await api(base, adminJar, 'POST', '/api/session', {
    username: 'admin',
    password: 'adminpass',
  });
  assert.equal(r.status, 200);

  r = await api(base, adminJar, 'GET', '/api/amnezia-xray/sni-cache');
  assert.equal(r.status, 200);
  assert.equal(typeof r.data.hasCache, 'boolean');
  assert.ok(r.data.scan);

  r = await api(base, adminJar, 'POST', '/api/amnezia-xray/sni-scan', {
    cidr: '10.0.0.0/24',
    force: true,
  });
  assert.equal(r.status, 400);
  assert.equal(r.data && r.data.data && r.data.data.code, 'CIDR_PRIVATE');

  r = await api(base, adminJar, 'POST', '/api/amnezia-xray/sni-recheck', {
    domain: 'not a domain!!',
  });
  assert.equal(r.status, 400);

  const modJar = new CookieJar();
  r = await api(base, modJar, 'POST', '/api/session', {
    username: 'modx',
    password: 'modpass1',
  });
  assert.equal(r.status, 200);
  r = await api(base, modJar, 'GET', '/api/amnezia-xray/sni-cache');
  assert.equal(r.status, 403);
  r = await api(base, modJar, 'POST', '/api/amnezia-xray/sni-scan', { cidr: '8.8.8.0/24' });
  assert.equal(r.status, 403);
  r = await api(base, modJar, 'POST', '/api/amnezia-xray/sni-recheck', { domain: 'example.com' });
  assert.equal(r.status, 403);
});
