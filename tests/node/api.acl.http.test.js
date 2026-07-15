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
  let nextHost = 2;
  const mock = {
    getClients: async () => {
      const rows = db.clients.getAll();
      const creatorMap = db.clients.mapCreatedByUsernames(rows.map((r) => r.id));
      return {
        clients: rows.map((r) => ({
          id: r.id,
          name: r.name,
          enabled: !!r.enabled,
          address: r.address,
          publicKey: r.public_key,
          createdAt: new Date((r.created_at || 0) * 1000),
          updatedAt: new Date((r.updated_at || 0) * 1000),
          createdBy: r.created_by || null,
          createdByUsername: creatorMap[r.id] || null,
          downloadableConfig: true,
        })),
        serverCapabilities: { amneziaDnsAvailable: false },
        serverJunk: null,
      };
    },
    createClient: async ({ name, createdBy }) => {
      if (!name) throw new Error('Missing: Name');
      const id = crypto.randomUUID();
      const now = Math.floor(Date.now() / 1000);
      const address = `10.8.0.${nextHost}`;
      nextHost += 1;
      db.clients.create({
        id,
        name,
        address,
        public_key: `pub-${id}`,
        private_key: `priv-${id}`,
        enabled: 1,
        created_at: now,
        updated_at: now,
        rule_profile_id: 1,
        use_server_dns: 1,
        created_by: createdBy || null,
      });
      return { id, name, address, enabled: true };
    },
    deleteClient: async ({ clientId }) => {
      if (!db.clients.getById(clientId)) {
        const err = new Error(`Client Not Found: ${clientId}`);
        err.statusCode = 404;
        throw err;
      }
      db.clients.delete(clientId);
    },
  };
  require.cache[file] = {
    id: file,
    filename: file,
    loaded: true,
    exports: mock,
  };
}

async function setupServer() {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'awg-http-'));
  process.env.DB_PATH = path.join(tmp, 'panel.db');
  process.env.SESSION_SECRET = 'http-test-secret';
  process.env.ADMIN_USERNAME = 'admin';
  process.env.ADMIN_PASSWORD = 'adminpass';
  process.env.WG_PATH = tmp;
  clearSrcRequireCache();

  // eslint-disable-next-line import/no-dynamic-require, global-require
  const db = require(path.join(srcRoot, 'lib', 'db.js'));
  db.getDb();
  installWireGuardMock(db);

  // eslint-disable-next-line import/no-dynamic-require, global-require
  const { ensureFirstAdmin } = require(path.join(srcRoot, 'lib', 'ensureFirstAdmin.js'));
  await ensureFirstAdmin();

  // eslint-disable-next-line import/no-dynamic-require, global-require
  const Server = require(path.join(srcRoot, 'lib', 'Server.js'));
  const server = new Server();
  await server.start({ port: 0, host: '127.0.0.1' });
  const base = `http://127.0.0.1:${server.listenPort}`;
  return { server, db, base, tmp };
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
  return { res, data, status: res.status };
}

test('HTTP ACL: users CRUD, visibility, assign, auto-assign', async (t) => {
  const { server, db, base } = await setupServer();
  t.after(async () => {
    try {
      await server.stop();
    } catch (_) { /* ignore */ }
    try {
      db.closeDb();
    } catch (_) { /* ignore */ }
  });

  const adminJar = new CookieJar();
  let r = await api(base, adminJar, 'POST', '/api/session', {
    username: 'admin',
    password: 'adminpass',
  });
  assert.equal(r.status, 200);
  assert.equal(r.data.role, 'admin');
  assert.ok(Array.isArray(r.data.capabilities));

  r = await api(base, adminJar, 'POST', '/api/users', {
    username: 'mod1',
    password: 'modpass1',
    role: 'moderator',
    assigned_cidrs: ['10.8.0.0/24'],
  });
  assert.equal(r.status, 201);
  assert.equal(r.data.role, 'moderator');
  const modId = r.data.id;

  r = await api(base, adminJar, 'POST', '/api/users', {
    username: 'user1',
    password: 'userpass1',
    role: 'user',
    assigned_cidrs: ['10.8.0.0/24'],
  });
  assert.equal(r.status, 201);
  const userId = r.data.id;
  assert.deepEqual(r.data.assigned_cidrs, ['10.8.0.0/24']);

  r = await api(base, adminJar, 'GET', '/api/users');
  assert.equal(r.status, 200);
  assert.ok(r.data.length >= 3);

  // Admin creates unassigned client
  r = await api(base, adminJar, 'POST', '/api/wireguard/client', { name: 'orphan' });
  assert.equal(r.status, 200);
  const orphanId = r.data.id;
  assert.ok(orphanId);

  // Moderator cannot create panel users
  const modJar = new CookieJar();
  r = await api(base, modJar, 'POST', '/api/session', {
    username: 'mod1',
    password: 'modpass1',
  });
  assert.equal(r.status, 200);
  r = await api(base, modJar, 'POST', '/api/users', {
    username: 'nope',
    password: 'nope11',
    role: 'user',
  });
  assert.equal(r.status, 403);

  // Moderator can list users and assign client
  r = await api(base, modJar, 'GET', '/api/users');
  assert.equal(r.status, 200);
  r = await api(base, modJar, 'PUT', `/api/wireguard/client/${orphanId}/users`, {
    userIds: [userId],
  });
  assert.equal(r.status, 200);
  assert.equal(r.data.length, 1);
  assert.equal(r.data[0].id, userId);

  // Moderator creates client and assigns both
  r = await api(base, modJar, 'POST', '/api/wireguard/client', {
    name: 'shared',
    userIds: [userId, modId],
  });
  assert.equal(r.status, 200);
  const sharedId = r.data.id;

  // User sees only assigned clients
  const userJar = new CookieJar();
  r = await api(base, userJar, 'POST', '/api/session', {
    username: 'user1',
    password: 'userpass1',
  });
  assert.equal(r.status, 200);
  r = await api(base, userJar, 'GET', '/api/wireguard/client');
  assert.equal(r.status, 200);
  const ids = (r.data.clients || []).map((c) => c.id).sort();
  assert.deepEqual(ids, [orphanId, sharedId].sort());
  assert.ok(r.data.clients[0].users);

  // User 404 on foreign enable (create a client only admin sees)
  r = await api(base, adminJar, 'POST', '/api/wireguard/client', { name: 'secret' });
  const secretId = r.data.id;
  r = await api(base, userJar, 'POST', `/api/wireguard/client/${secretId}/enable`);
  assert.equal(r.status, 404);

  // User creates client → auto-assign self
  r = await api(base, userJar, 'POST', '/api/wireguard/client', { name: 'mine' });
  assert.equal(r.status, 200);
  const mineId = r.data.id;
  r = await api(base, userJar, 'GET', `/api/wireguard/client/${mineId}/users`);
  assert.equal(r.status, 200);
  assert.equal(r.data.length, 1);
  assert.equal(r.data[0].id, userId);

  // User cannot assign
  r = await api(base, userJar, 'PUT', `/api/wireguard/client/${mineId}/users`, {
    userIds: [userId, modId],
  });
  assert.equal(r.status, 403);

  // Last admin cannot be demoted
  const adminUser = (await api(base, adminJar, 'GET', '/api/users')).data
    .find((u) => u.username === 'admin');
  r = await api(base, adminJar, 'PATCH', `/api/users/${adminUser.id}`, { role: 'user' });
  assert.equal(r.status, 400);

  // Roles labels API (localized)
  r = await api(base, adminJar, 'GET', '/api/roles?lang=ru');
  assert.equal(r.status, 200);
  assert.equal(r.data.admin, 'Администратор');
  assert.equal(r.data.moderator, 'Модератор');
  assert.equal(r.data.user, 'Пользователь');

  r = await api(base, adminJar, 'GET', '/api/roles?lang=en');
  assert.equal(r.data.admin, 'Administrator');

  // Client stores creator username
  r = await api(base, userJar, 'POST', '/api/wireguard/client', { name: 'created-meta' });
  assert.equal(r.status, 200);
  const metaId = r.data.id;
  r = await api(base, userJar, 'GET', '/api/wireguard/client');
  const metaClient = (r.data.clients || []).find((c) => c.id === metaId);
  assert.ok(metaClient);
  assert.equal(metaClient.createdByUsername, 'user1');
});
