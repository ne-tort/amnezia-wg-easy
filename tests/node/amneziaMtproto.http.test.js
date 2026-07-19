'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');

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

function installWireGuardMock() {
  const file = path.join(srcRoot, 'lib', 'WireGuard.js');
  const mock = {
    getClients: async () => ({
      clients: [],
      serverCapabilities: {
        amneziaDnsAvailable: false,
        xrayAvailable: false,
        mtprotoAvailable: false,
      },
      serverJunk: null,
    }),
    saveConfig: async () => undefined,
  };
  require.cache[file] = {
    id: file, filename: file, loaded: true, exports: mock,
  };
}

function installMtprotoMock(state) {
  const file = path.join(srcRoot, 'lib', 'amneziaMtproto.js');
  const mock = {
    isAmneziaMtprotoAvailable: () => state.phase === 'running',
    getStatus: () => ({
      desired: state.desired,
      phase: state.phase,
      available: state.phase === 'running',
      busy: false,
      sni: state.sni,
      sniStored: state.sni,
      port: state.port,
      publicPort: state.publicPort || 443,
      mode: state.mode || null,
      demuxPeers: state.demuxPeers || [],
      link: state.link,
      lastError: state.lastError,
    }),
    enable: async (opts = {}) => {
      const sni = String(opts.sni || state.sni || '').trim();
      const publicPort = opts.publicPort != null
        ? Number(opts.publicPort)
        : (state.publicPort || 443);
      const xrayPublic = state.xrayPublicPort != null ? Number(state.xrayPublicPort) : 443;
      if (
        sni
        && state.xraySni
        && sni.toLowerCase() === String(state.xraySni).toLowerCase()
        && publicPort === xrayPublic
      ) {
        const err = new Error('MTProto SNI must differ from Xray SNI when sharing a public port (demux)');
        err.status = 400;
        err.code = 'MTPROTO_SNI_CONFLICT';
        throw err;
      }
      state.desired = true;
      state.phase = 'running';
      state.sni = sni || state.sni;
      state.publicPort = publicPort;
      state.link = `tg://proxy?server=vpn.example.com&port=${publicPort}&secret=ee00`;
      return mock.getStatus();
    },
    disable: async () => {
      state.desired = false;
      state.phase = 'off';
      state.link = null;
      return mock.getStatus();
    },
    forceCleanup: async () => {
      state.desired = false;
      state.phase = 'off';
      return mock.getStatus();
    },
    resetSecret: async () => mock.getStatus(),
  };
  require.cache[file] = {
    id: file, filename: file, loaded: true, exports: mock,
  };
}

function installXrayStub() {
  const file = path.join(srcRoot, 'lib', 'amneziaXray.js');
  require.cache[file] = {
    id: file,
    filename: file,
    loaded: true,
    exports: {
      isAmneziaXrayAvailable: () => false,
      getStatus: () => ({ phase: 'off', desired: false, available: false }),
      enable: async () => ({}),
      disable: async () => ({}),
      forceCleanup: async () => ({}),
      resetCredentials: async () => ({}),
      ensureClientUuids: () => {},
      findEnabledClientByName: () => null,
      getClientXrayPayload: () => null,
      bootAmneziaXray: async () => ({}),
      stopAmneziaXray: () => {},
    },
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
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'awg-mtproto-http-'));
  process.env.DB_PATH = path.join(tmp, 'panel.db');
  process.env.SESSION_SECRET = 'mtproto-http-secret';
  process.env.ADMIN_USERNAME = 'admin';
  process.env.ADMIN_PASSWORD = 'adminpass';
  process.env.WG_PATH = tmp;
  clearSrcRequireCache();

  // eslint-disable-next-line import/no-dynamic-require, global-require
  const db = require(path.join(srcRoot, 'lib', 'db.js'));
  db.getDb();

  const state = {
    desired: false,
    phase: 'off',
    sni: null,
    port: 25002,
    publicPort: 443,
    link: null,
    lastError: null,
    xraySni: 'www.gov.uk',
    xrayPublicPort: 443,
  };
  installWireGuardMock();
  installXrayStub();
  installMtprotoMock(state);

  // eslint-disable-next-line import/no-dynamic-require, global-require
  const { ensureFirstAdmin } = require(path.join(srcRoot, 'lib', 'ensureFirstAdmin.js'));
  await ensureFirstAdmin();

  const now = Math.floor(Date.now() / 1000);
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

test('HTTP MTProto: ACL admin-only; SNI conflict only on shared public port; enable/disable', async (t) => {
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
  assert.ok(r.data.capabilities.includes('system.mtproto'));
  assert.equal(r.data.capabilities.includes('system.xray'), true);

  const modJar = new CookieJar();
  r = await api(base, modJar, 'POST', '/api/session', {
    username: 'modx',
    password: 'modpass1',
  });
  assert.equal(r.status, 200);
  assert.equal(r.data.capabilities.includes('system.mtproto'), false);

  r = await api(base, modJar, 'GET', '/api/amnezia-mtproto');
  assert.equal(r.status, 403);

  // Same SNI + same public port (default 443) → conflict
  r = await api(base, adminJar, 'POST', '/api/amnezia-mtproto/enable', {
    sni: 'www.gov.uk',
    address: 'vpn.example.com',
  });
  assert.equal(r.status, 400);

  // Same SNI + different public port → direct mode, OK
  r = await api(base, adminJar, 'POST', '/api/amnezia-mtproto/enable', {
    sni: 'www.gov.uk',
    address: 'vpn.example.com',
    publicPort: 8443,
  });
  assert.equal(r.status, 200);
  assert.equal(state.desired, true);
  assert.equal(state.publicPort, 8443);
  assert.match(state.link, /port=8443/);

  r = await api(base, adminJar, 'POST', '/api/amnezia-mtproto/disable', {});
  assert.equal(r.status, 200);
  assert.equal(state.desired, false);

  // Different SNI + shared public port → demux OK
  r = await api(base, adminJar, 'POST', '/api/amnezia-mtproto/enable', {
    sni: 'cdn.cloudflare.com',
    address: 'vpn.example.com',
    publicPort: 443,
  });
  assert.equal(r.status, 200);
  assert.equal(state.phase, 'running');
  assert.ok(r.data.link);

  r = await api(base, adminJar, 'POST', '/api/amnezia-mtproto/disable', {});
  assert.equal(r.status, 200);
  assert.equal(state.desired, false);
  assert.equal(state.phase, 'off');
});
