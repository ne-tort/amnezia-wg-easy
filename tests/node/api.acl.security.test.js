'use strict';

/**
 * Extended ACL / auth security scenarios (HTTP + cookie sessions).
 * Shares bootstrap pattern with api.acl.http.test.js.
 */

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

  clear() {
    this.cookies.clear();
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
    enableClient: async () => ({ success: true }),
    disableClient: async () => ({ success: true }),
    updateClientName: async () => ({ success: true }),
  };
  require.cache[file] = {
    id: file,
    filename: file,
    loaded: true,
    exports: mock,
  };
}

async function setupServer() {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'awg-http-sec-'));
  process.env.DB_PATH = path.join(tmp, 'panel.db');
  process.env.SESSION_SECRET = 'http-test-secret-sec';
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
  const cookie = jar ? jar.header() : '';
  if (cookie) headers.Cookie = cookie;
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  const res = await fetch(`${base}${urlPath}`, {
    method,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  if (jar) jar.store(res);
  let data = null;
  const text = await res.text();
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = text;
  }
  return { res, data, status: res.status };
}

async function login(base, username, password) {
  const jar = new CookieJar();
  const r = await api(base, jar, 'POST', '/api/session', { username, password });
  assert.equal(r.status, 200, `login ${username}: ${JSON.stringify(r.data)}`);
  return jar;
}

test('security: unauthenticated requests are rejected', async (t) => {
  const { server, db, base } = await setupServer();
  t.after(async () => {
    try { await server.stop(); } catch (_) { /* */ }
    try { db.closeDb(); } catch (_) { /* */ }
  });

  const empty = new CookieJar();
  assert.equal((await api(base, empty, 'GET', '/api/wireguard/client')).status, 401);
  assert.equal((await api(base, empty, 'GET', '/api/users')).status, 401);
  assert.equal((await api(base, empty, 'POST', '/api/wireguard/client', { name: 'x' })).status, 401);
  assert.equal((await api(base, empty, 'GET', '/api/app-settings')).status, 401);
  assert.equal((await api(base, empty, 'GET', '/api/amnezia-dns')).status, 401);

  // Public/session endpoints stay open
  assert.equal((await api(base, empty, 'GET', '/api/session')).status, 200);
  assert.equal((await api(base, empty, 'GET', '/api/session')).data.authenticated, false);
});

test('security: passwords never leak; bad login; inactive blocked', async (t) => {
  const { server, db, base } = await setupServer();
  t.after(async () => {
    try { await server.stop(); } catch (_) { /* */ }
    try { db.closeDb(); } catch (_) { /* */ }
  });

  const adminJar = await login(base, 'admin', 'adminpass');

  let r = await api(base, adminJar, 'POST', '/api/session', {
    username: 'admin',
    password: 'wrong-password',
  });
  assert.equal(r.status, 401);

  r = await api(base, adminJar, 'POST', '/api/users', {
    username: 'tempuser',
    password: 'temppass1',
    role: 'user',
    assigned_cidrs: ['10.8.0.0/24'],
  });
  assert.equal(r.status, 201);
  assert.equal(r.data.password_hash, undefined);
  assert.equal(r.data.password, undefined);
  const tempId = r.data.id;

  r = await api(base, adminJar, 'GET', '/api/users');
  assert.ok(r.data.every((u) => u.password_hash === undefined && u.password === undefined));

  r = await api(base, adminJar, 'GET', `/api/users/${tempId}`);
  assert.equal(r.status, 200);
  assert.equal(r.data.password_hash, undefined);

  // Deactivate — cannot login; existing session dies on next API call
  const tempJar = await login(base, 'tempuser', 'temppass1');
  r = await api(base, adminJar, 'DELETE', `/api/users/${tempId}`);
  assert.equal(r.status, 200);

  r = await api(base, new CookieJar(), 'POST', '/api/session', {
    username: 'tempuser',
    password: 'temppass1',
  });
  assert.equal(r.status, 401);

  r = await api(base, tempJar, 'GET', '/api/wireguard/client');
  assert.equal(r.status, 401);
});

test('security: role boundaries for system routes and user escalation', async (t) => {
  const { server, db, base } = await setupServer();
  t.after(async () => {
    try { await server.stop(); } catch (_) { /* */ }
    try { db.closeDb(); } catch (_) { /* */ }
  });

  const adminJar = await login(base, 'admin', 'adminpass');
  let r = await api(base, adminJar, 'POST', '/api/users', {
    username: 'modsec', password: 'modpass12', role: 'moderator',
    assigned_cidrs: ['10.8.0.0/24'],
  });
  const modId = r.data.id;
  r = await api(base, adminJar, 'POST', '/api/users', {
    username: 'usersec', password: 'userpass12', role: 'user',
    assigned_cidrs: ['10.8.0.0/24'],
  });
  const userId = r.data.id;

  const modJar = await login(base, 'modsec', 'modpass12');
  const userJar = await login(base, 'usersec', 'userpass12');

  // Moderator cannot mutate users
  assert.equal((await api(base, modJar, 'POST', '/api/users', {
    username: 'x', password: 'xxxxx1', role: 'user',
  })).status, 403);
  assert.equal((await api(base, modJar, 'PATCH', `/api/users/${userId}`, { role: 'admin' })).status, 403);
  assert.equal((await api(base, modJar, 'DELETE', `/api/users/${userId}`)).status, 403);

  // Moderator can read users, cannot touch settings / firewall
  assert.equal((await api(base, modJar, 'GET', '/api/users')).status, 200);
  assert.equal((await api(base, modJar, 'GET', '/api/app-settings')).status, 403);
  assert.equal((await api(base, modJar, 'PUT', '/api/app-settings', { key: 'x', value: 'y' })).status, 403);
  assert.equal((await api(base, modJar, 'GET', '/api/rule-profiles')).status, 403);
  assert.equal((await api(base, modJar, 'GET', '/api/global-firewall-rules')).status, 403);

  // Password targets + change: admin all; mod self+users; user self only
  r = await api(base, adminJar, 'GET', '/api/users/password-targets');
  assert.equal(r.status, 200);
  assert.ok(r.data.some((u) => u.id === modId));
  assert.ok(r.data.some((u) => u.id === userId));

  r = await api(base, modJar, 'GET', '/api/users/password-targets');
  assert.equal(r.status, 200);
  assert.ok(r.data.every((u) => u.id === modId || u.role === 'user'));
  assert.ok(!r.data.some((u) => u.role === 'admin'));

  r = await api(base, userJar, 'GET', '/api/users/password-targets');
  assert.equal(r.status, 200);
  assert.deepEqual(r.data.map((u) => u.id), [userId]);

  assert.equal((await api(base, modJar, 'POST', `/api/users/${userId}/password`, {
    password: 'newpass1', passwordConfirm: 'newpass1',
  })).status, 200);
  assert.equal((await api(base, modJar, 'POST', `/api/users/${modId}/password`, {
    password: 'modpass99', passwordConfirm: 'modpass99',
  })).status, 200);
  assert.equal((await api(base, modJar, 'POST', `/api/users/${(await api(base, adminJar, 'GET', '/api/users')).data.find((u) => u.username === 'admin').id}/password`, {
    password: 'hacked1', passwordConfirm: 'hacked1',
  })).status, 403);
  assert.equal((await api(base, userJar, 'POST', `/api/users/${modId}/password`, {
    password: 'hacked1', passwordConfirm: 'hacked1',
  })).status, 403);

  // Client firewall profile: admin only (mod/user 403 at ACL gate)
  r = await api(base, adminJar, 'POST', '/api/wireguard/client', { name: 'fw-acl' });
  assert.equal(r.status, 200);
  const fwClientId = r.data.id;
  r = await api(base, adminJar, 'PUT', `/api/wireguard/client/${fwClientId}/firewall-profile`, {
    rule_profile_id: 1,
  });
  assert.notEqual(r.status, 403);
  assert.equal((await api(base, modJar, 'PUT', `/api/wireguard/client/${fwClientId}/firewall-profile`, {
    rule_profile_id: 1,
  })).status, 403);
  assert.equal((await api(base, userJar, 'PUT', `/api/wireguard/client/${fwClientId}/firewall-profile`, {
    rule_profile_id: 1,
  })).status, 403);
  assert.equal((await api(base, modJar, 'GET', `/api/wireguard/client/${fwClientId}/firewall-rules`)).status, 403);
  assert.equal((await api(base, userJar, 'GET', `/api/wireguard/client/${fwClientId}/firewall-rules`)).status, 403);
  r = await api(base, adminJar, 'GET', `/api/wireguard/client/${fwClientId}/firewall-rules`);
  assert.notEqual(r.status, 403);

  // User cannot list users / system DNS / firewall / aggregate traffic / signatures
  assert.equal((await api(base, userJar, 'GET', '/api/users')).status, 403);
  assert.equal((await api(base, userJar, 'GET', '/api/amnezia-dns')).status, 403);
  assert.equal((await api(base, userJar, 'GET', '/api/rule-profiles')).status, 403);
  assert.equal((await api(base, userJar, 'GET', '/api/signatures/profiles')).status, 403);
  assert.equal((await api(base, userJar, 'GET', '/api/traffic/aggregate')).status, 403);
  assert.equal((await api(base, userJar, 'GET', '/api/app-settings')).status, 403);

  // User cannot escalate via create userIds
  r = await api(base, userJar, 'POST', '/api/wireguard/client', {
    name: 'escalation',
    userIds: [modId, userId],
  });
  assert.equal(r.status, 403);

  // User owns only auto-assigned self
  r = await api(base, userJar, 'POST', '/api/wireguard/client', { name: 'own-only' });
  assert.equal(r.status, 200);
  const ownId = r.data.id;
  r = await api(base, userJar, 'GET', `/api/wireguard/client/${ownId}/users`);
  assert.deepEqual(r.data.map((u) => u.id), [userId]);

  // User can mutate own, 404 on foreign
  r = await api(base, adminJar, 'POST', '/api/wireguard/client', { name: 'admin-only' });
  const foreignId = r.data.id;
  assert.equal((await api(base, userJar, 'PUT', `/api/wireguard/client/${foreignId}/name`, { name: 'hacked' })).status, 404);
  assert.equal((await api(base, userJar, 'DELETE', `/api/wireguard/client/${foreignId}`)).status, 404);
  assert.equal((await api(base, userJar, 'PUT', `/api/wireguard/client/${ownId}/name`, { name: 'renamed' })).status, 200);

  // Poisoned clientId
  assert.equal((await api(base, userJar, 'POST', '/api/wireguard/client/__proto__/enable')).status, 404);
  assert.equal((await api(base, adminJar, 'POST', '/api/wireguard/client/constructor/enable')).status, 404);
});

test('security: validation, role refresh, clear assignees, second admin demotion', async (t) => {
  const { server, db, base } = await setupServer();
  t.after(async () => {
    try { await server.stop(); } catch (_) { /* */ }
    try { db.closeDb(); } catch (_) { /* */ }
  });

  const adminJar = await login(base, 'admin', 'adminpass');

  // Invalid role / duplicate username / short password
  assert.equal((await api(base, adminJar, 'POST', '/api/users', {
    username: 'badrole', password: 'abcdef', role: 'superadmin',
  })).status, 400);
  assert.equal((await api(base, adminJar, 'POST', '/api/users', {
    username: 'shortpw', password: 'ab', role: 'user', assigned_cidrs: ['10.8.0.0/24'],
  })).status, 400);
  assert.equal((await api(base, adminJar, 'POST', '/api/users', {
    username: 'nocidr', password: 'abcdef', role: 'user',
  })).status, 400);
  let r = await api(base, adminJar, 'POST', '/api/users', {
    username: 'dup', password: 'duppass1', role: 'user', assigned_cidrs: ['10.8.0.0/24'],
  });
  assert.equal(r.status, 201);
  assert.equal((await api(base, adminJar, 'POST', '/api/users', {
    username: 'dup', password: 'duppass2', role: 'user', assigned_cidrs: ['10.8.0.0/24'],
  })).status, 409);

  // Second admin — first can be demoted; then last cannot
  r = await api(base, adminJar, 'POST', '/api/users', {
    username: 'admin2', password: 'adminpass2', role: 'admin',
    assigned_cidrs: ['10.8.0.0/24'],
  });
  assert.equal(r.status, 201);
  const admin2Id = r.data.id;
  const admin1 = (await api(base, adminJar, 'GET', '/api/users')).data
    .find((u) => u.username === 'admin');

  r = await api(base, adminJar, 'PATCH', `/api/users/${admin1.id}`, { role: 'moderator' });
  assert.equal(r.status, 200);
  assert.equal(r.data.role, 'moderator');

  // Session role refreshes from DB without re-login (fresh actor)
  r = await api(base, adminJar, 'POST', '/api/users', {
    username: 'shouldfail', password: 'should1', role: 'user',
    assigned_cidrs: ['10.8.0.0/24'],
  });
  assert.equal(r.status, 403);

  const admin2Jar = await login(base, 'admin2', 'adminpass2');
  r = await api(base, admin2Jar, 'DELETE', `/api/users/${admin2Id}`);
  assert.equal(r.status, 400, 'cannot deactivate last remaining admin');

  // Clear assignees → only admin/mod see orphan
  r = await api(base, admin2Jar, 'POST', '/api/users', {
    username: 'viewer', password: 'viewer12', role: 'user',
    assigned_cidrs: ['10.8.0.0/24'],
  });
  const viewerId = r.data.id;
  r = await api(base, admin2Jar, 'POST', '/api/wireguard/client', {
    name: 'shared-then-clear',
    userIds: [viewerId],
  });
  const cid = r.data.id;
  const viewerJar = await login(base, 'viewer', 'viewer12');
  assert.ok((await api(base, viewerJar, 'GET', '/api/wireguard/client')).data.clients
    .some((c) => c.id === cid));

  r = await api(base, admin2Jar, 'PUT', `/api/wireguard/client/${cid}/users`, { userIds: [] });
  assert.equal(r.status, 200);
  assert.equal(r.data.length, 0);
  const visible = (await api(base, viewerJar, 'GET', '/api/wireguard/client')).data.clients
    .map((c) => c.id);
  assert.equal(visible.includes(cid), false);
  assert.ok((await api(base, admin2Jar, 'GET', '/api/wireguard/client')).data.clients
    .some((c) => c.id === cid));

  // Soft-delete clears membership; user loses visibility
  r = await api(base, admin2Jar, 'PUT', `/api/wireguard/client/${cid}/users`, { userIds: [viewerId] });
  assert.equal(r.status, 200);
  r = await api(base, admin2Jar, 'DELETE', `/api/wireguard/client/${cid}`);
  assert.equal(r.status, 200);
  assert.equal((await api(base, viewerJar, 'GET', `/api/wireguard/client/${cid}/users`)).status, 404);
  assert.equal(db.clientPanelUsers.isAssigned(cid, viewerId), false);

  // Promote user → capabilities apply immediately
  r = await api(base, admin2Jar, 'PATCH', `/api/users/${viewerId}`, { role: 'moderator' });
  assert.equal(r.status, 200);
  assert.equal((await api(base, viewerJar, 'GET', '/api/users')).status, 200);
  assert.equal((await api(base, viewerJar, 'GET', '/api/app-settings')).status, 403);
});
