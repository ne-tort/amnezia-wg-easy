'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');
const crypto = require('node:crypto');

const srcRoot = path.resolve(__dirname, '../../src');

function clearSrcRequireCache() {
  for (const key of Object.keys(require.cache)) {
    if (key.replace(/\\/g, '/').includes('/src/')) {
      delete require.cache[key];
    }
  }
}

test('vpnAddress: contains, allocate order, skip gateway/broadcast, multi-range', () => {
  // eslint-disable-next-line import/no-dynamic-require, global-require
  const va = require(path.join(srcRoot, 'lib', 'vpnAddress.js'));

  assert.equal(va.cidrContains('10.8.0.0/24', '10.8.0.64/26'), true);
  assert.equal(va.cidrContains('10.8.0.0/24', '10.8.0.10/32'), true);
  assert.equal(va.cidrContains('10.8.0.0/24', '10.9.0.0/24'), false);
  assert.equal(va.cidrsOverlap('10.8.0.0/24', '10.8.0.128/25'), true);
  assert.equal(va.cidrsOverlap('10.8.0.0/25', '10.8.0.128/25'), false);

  const used = new Set(['10.8.0.2']);
  const ip = va.allocateAddress({
    ranges: ['10.8.0.0/30', '10.0.0.0/30'],
    usedSet: used,
    reservedGateways: ['10.8.0.1', '10.0.0.1'],
  });
  // /30: .0 network, .1 gw reserved, .2 used, .3 broadcast → pool exhausted → next range
  assert.equal(ip, '10.0.0.2');

  const first = va.allocateAddress({
    ranges: ['10.8.0.0/28'],
    usedSet: new Set(),
    reservedGateways: ['10.8.0.1'],
  });
  assert.equal(first, '10.8.0.2');

  const seed = va.seedPoolFromEnvTemplate('10.0.0.x');
  assert.equal(seed.cidr, '10.0.0.0/24');
  assert.equal(seed.gateway, '10.0.0.1');

  const v = va.validateAssignedCidrs(['10.8.0.64/26'], ['10.8.0.0/24']);
  assert.equal(v.ok, true);
  assert.deepEqual(v.cidrs, ['10.8.0.64/26']);
  assert.equal(va.validateAssignedCidrs(['10.9.0.0/24'], ['10.8.0.0/24']).ok, false);
});

test('db: seed pool from env; assigned_cidrs; gateway unique; delete reconciles', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'awg-pools-'));
  process.env.DB_PATH = path.join(tmp, 'panel.db');
  process.env.WG_DEFAULT_ADDRESS = '10.9.0.x';
  clearSrcRequireCache();
  // eslint-disable-next-line import/no-dynamic-require, global-require
  const db = require(path.join(srcRoot, 'lib', 'db.js'));
  db.getDb();
  const pools = db.vpnPools.list();
  assert.equal(pools.length, 1);
  assert.equal(pools[0].cidr, '10.9.0.0/24');
  assert.equal(pools[0].gateway, '10.9.0.1');
  assert.equal(pools[0].name, 'Default');

  const now = Math.floor(Date.now() / 1000);
  const uid = crypto.randomUUID();
  db.panelUsers.create({
    id: uid,
    username: `u-${uid.slice(0, 8)}`,
    password_hash: 'x',
    role: 'user',
    is_active: 1,
    created_at: now,
    updated_at: now,
  });
  const pub = db.panelUsers.update(uid, { assigned_cidrs: ['10.9.0.0/28'] });
  assert.deepEqual(pub.assigned_cidrs, ['10.9.0.0/28']);
  assert.deepEqual(db.panelUsers.findByIdPublic(uid).assigned_cidrs, ['10.9.0.0/28']);

  // Nested overlap allowed with unique gateway
  const nested = db.vpnPools.create({
    name: 'VIP',
    cidr: '10.9.0.0/25',
    gateway: '10.9.0.2',
  });
  assert.equal(nested.cidr, '10.9.0.0/25');

  let gwErr;
  try {
    db.vpnPools.create({ name: 'DupGw', cidr: '10.9.0.128/25', gateway: '10.9.0.1' });
  } catch (e) {
    gwErr = e;
  }
  // 10.9.0.1 not in 10.9.0.128/25 → invalid gateway first; use overlapping with same gw:
  try {
    db.vpnPools.create({ name: 'DupGw2', cidr: '10.9.0.0/26', gateway: '10.9.0.1' });
  } catch (e) {
    gwErr = e;
  }
  assert.equal(gwErr && gwErr.code, 'GATEWAY_EXISTS');

  const extra = db.vpnPools.create({ name: 'Extra', cidr: '10.10.0.0/24' });
  assert.equal(extra.cidr, '10.10.0.0/24');
  assert.equal(extra.gateway, '10.10.0.1');

  db.clients.create({
    id: 'c1',
    name: 'c1',
    address: '10.10.0.5',
    public_key: 'p',
    private_key: 's',
    enabled: 1,
    created_at: now,
    updated_at: now,
    rule_profile_id: 1,
  });
  // Client also covered by nothing else — delete extra → disable
  db.vpnPools.delete(extra.id);
  const c1 = db.clients.getById('c1');
  assert.equal(c1.enabled, 0);

  // Overlapping remain: client in 10.9.0.10 stays enabled after deleting nested /25
  db.clients.create({
    id: 'c2',
    name: 'c2',
    address: '10.9.0.10',
    public_key: 'p2',
    private_key: 's2',
    enabled: 1,
    created_at: now,
    updated_at: now,
    rule_profile_id: 1,
  });
  db.vpnPools.delete(nested.id);
  assert.equal(db.clients.getById('c2').enabled, 1);

  db.closeDb();
  delete process.env.WG_DEFAULT_ADDRESS;
});

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

function installWireGuardMock(db) {
  const file = path.join(srcRoot, 'lib', 'WireGuard.js');
  // eslint-disable-next-line import/no-dynamic-require, global-require
  const vpnAddress = require(path.join(srcRoot, 'lib', 'vpnAddress.js'));
  const ServerError = require(path.join(srcRoot, 'lib', 'ServerError.js'));
  const mock = {
    getClients: async () => ({
      clients: db.clients.getAll().map((r) => ({
        id: r.id,
        name: r.name,
        enabled: !!r.enabled,
        address: r.address,
      })),
      serverCapabilities: { amneziaDnsAvailable: false },
    }),
    createClient: async ({ name, createdBy, addressRanges }) => {
      if (!name) throw new Error('Missing: Name');
      const trimmedName = String(name).trim();
      if (db.clients.getAll().some((c) => c.name === trimmedName)) {
        throw new ServerError('Client name already exists', 409);
      }
      const pools = db.vpnPools.list();
      const ranges = Array.isArray(addressRanges) && addressRanges.length
        ? addressRanges
        : pools.map((p) => p.cidr);
      if (!ranges.length) {
        const err = new ServerError('No VPN address ranges available', 400);
        throw err;
      }
      const address = vpnAddress.allocateAddress({
        ranges,
        usedSet: db.clients.usedAddresses(),
        reservedGateways: pools.map((p) => p.gateway),
      });
      if (!address) throw new Error('Maximum number of clients reached.');
      const id = crypto.randomUUID();
      const now = Math.floor(Date.now() / 1000);
      db.clients.create({
        id,
        name: trimmedName,
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
      return { id, name: trimmedName, address, enabled: true };
    },
    updateClientName: async ({ clientId, name }) => {
      const trimmedName = String(name || '').trim();
      if (!trimmedName) throw new ServerError('Missing: Name', 400);
      const client = db.clients.getById(clientId);
      if (!client) throw new ServerError(`Client Not Found: ${clientId}`, 404);
      if (db.clients.getAll().some((c) => c.id !== clientId && c.name === trimmedName)) {
        throw new ServerError('Client name already exists', 409);
      }
      client.name = trimmedName;
      client.updated_at = Math.floor(Date.now() / 1000);
      db.clients.update(client);
    },
    enableClient: async ({ clientId }) => {
      const client = db.clients.getById(clientId);
      if (!client) throw new ServerError(`Client Not Found: ${clientId}`, 404);
      const poolCidrs = db.vpnPools.list().map((p) => p.cidr);
      if (!client.address || !vpnAddress.ipInAnyPool(client.address, poolCidrs)) {
        throw new ServerError('Client address is outside configured VPN pools; assign a valid IP first', 400);
      }
      client.enabled = 1;
      client.updated_at = Math.floor(Date.now() / 1000);
      db.clients.update(client);
    },
    saveConfig: async () => {},
    updateClientAddress: async ({ clientId, address, allowedRanges }) => {
      const Util = require(path.join(srcRoot, 'lib', 'Util.js'));
      if (!Util.isValidIPv4(address)) {
        throw new ServerError(`Invalid Address: ${address}`, 400);
      }
      const client = db.clients.getById(clientId);
      if (!client) throw new ServerError(`Client Not Found: ${clientId}`, 404);
      const pools = db.vpnPools.list();
      const poolCidrs = pools.map((p) => p.cidr);
      if (!vpnAddress.ipInAnyPool(address, poolCidrs)) {
        throw new ServerError('Address is outside configured VPN pools', 400);
      }
      if (Array.isArray(allowedRanges)) {
        if (!allowedRanges.some((cidr) => vpnAddress.ipInCidr(address, cidr))) {
          throw new ServerError('Address is outside your assigned CIDRs', 403);
        }
      }
      if (db.clients.usedAddresses(clientId).has(address)) {
        throw new ServerError('Address already in use', 409);
      }
      client.address = address;
      client.updated_at = Math.floor(Date.now() / 1000);
      db.clients.update(client);
    },
    deleteClient: async ({ clientId }) => {
      if (!db.clients.getById(clientId)) {
        throw new ServerError(`Client Not Found: ${clientId}`, 404);
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
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'awg-vpnpools-http-'));
  process.env.DB_PATH = path.join(tmp, 'panel.db');
  process.env.SESSION_SECRET = 'vpn-pools-test';
  process.env.ADMIN_USERNAME = 'admin';
  process.env.ADMIN_PASSWORD = 'adminpass';
  process.env.WG_PATH = tmp;
  process.env.WG_DEFAULT_ADDRESS = '10.8.0.x';
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

test('HTTP: vpn-pools admin, user allocate in assigned /28, address ACL', async (t) => {
  const { server, db, base } = await setupServer();
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

  r = await api(base, adminJar, 'GET', '/api/vpn-pools');
  assert.equal(r.status, 200);
  assert.equal(r.data.pools.length, 1);
  assert.equal(r.data.pools[0].cidr, '10.8.0.0/24');

  r = await api(base, adminJar, 'POST', '/api/vpn-pools', { name: 'LAN', cidr: '10.0.0.0/24' });
  assert.equal(r.status, 201);
  assert.equal(r.data.cidr, '10.0.0.0/24');
  assert.equal(r.data.name, 'LAN');
  const newPoolId = r.data.id;

  // Nested overlap with unique gateway OK
  r = await api(base, adminJar, 'POST', '/api/vpn-pools', {
    name: 'LAN-half',
    cidr: '10.0.0.0/25',
    gateway: '10.0.0.2',
  });
  assert.equal(r.status, 201);
  const halfId = r.data.id;

  // PUT update renaming pool works (was PATCH → HTML on some stacks)
  r = await api(base, adminJar, 'PUT', `/api/vpn-pools/${halfId}`, {
    name: 'LAN-half-renamed',
    cidr: '10.0.0.0/25',
    gateway: '10.0.0.2',
  });
  assert.equal(r.status, 200);
  assert.equal(r.data.name, 'LAN-half-renamed');

  // Same gateway rejected
  r = await api(base, adminJar, 'POST', '/api/vpn-pools', {
    name: 'BadGw',
    cidr: '10.20.0.0/24',
    gateway: '10.0.0.1',
  });
  assert.equal(r.status, 400);

  // Create without CIDR rejected
  r = await api(base, adminJar, 'POST', '/api/users', {
    username: 'cidruser',
    password: 'userpass1',
    role: 'user',
    assigned_cidrs: [],
  });
  assert.equal(r.status, 400);

  r = await api(base, adminJar, 'POST', '/api/users', {
    username: 'cidruser',
    password: 'userpass1',
    role: 'user',
    assigned_cidrs: ['10.0.0.0/28'],
  });
  assert.equal(r.status, 201);
  const userId = r.data.id;

  const userJar = new CookieJar();
  r = await api(base, userJar, 'POST', '/api/session', {
    username: 'cidruser',
    password: 'userpass1',
  });
  assert.equal(r.status, 200);

  r = await api(base, userJar, 'POST', '/api/wireguard/client', { name: 'in28' });
  assert.equal(r.status, 200);
  const a1 = r.data.client.address;
  assert.ok(a1.startsWith('10.0.0.'));
  const host = parseInt(a1.split('.')[3], 10);
  assert.ok(host >= 1 && host <= 14);
  assert.notEqual(a1, '10.0.0.1');

  // Duplicate name
  r = await api(base, userJar, 'POST', '/api/wireguard/client', { name: 'in28' });
  assert.equal(r.status, 409);

  r = await api(base, userJar, 'POST', '/api/wireguard/client', { name: 'in28b' });
  assert.equal(r.status, 200);
  assert.notEqual(r.data.client.address, a1);
  const clientId = r.data.id;

  // outside pool
  r = await api(base, adminJar, 'PUT', `/api/wireguard/client/${clientId}/address`, {
    address: '192.168.1.10',
  });
  assert.equal(r.status, 400);

  // outside user ranges
  r = await api(base, userJar, 'PUT', `/api/wireguard/client/${clientId}/address`, {
    address: '10.0.0.100',
  });
  assert.equal(r.status, 403);

  // in user /28
  r = await api(base, userJar, 'PUT', `/api/wireguard/client/${clientId}/address`, {
    address: '10.0.0.10',
  });
  assert.equal(r.status, 200);

  // DELETE overlapping half — clients still in 10.0.0.0/24 stay enabled
  r = await api(base, adminJar, 'DELETE', `/api/vpn-pools/${halfId}`);
  assert.equal(r.status, 200);
  assert.equal(db.clients.getById(clientId).enabled, 1);

  // DELETE main LAN pool — clients only in that pool get disabled
  r = await api(base, adminJar, 'DELETE', `/api/vpn-pools/${newPoolId}`);
  assert.equal(r.status, 200);
  assert.equal(db.clients.getById(clientId).enabled, 0);

  r = await api(base, adminJar, 'POST', `/api/wireguard/client/${clientId}/enable`);
  assert.equal(r.status, 400);

  // moderator cannot manage pools
  r = await api(base, adminJar, 'POST', '/api/users', {
    username: 'cidrmod',
    password: 'modpass12',
    role: 'moderator',
    assigned_cidrs: ['10.8.0.0/24'],
  });
  const modJar = new CookieJar();
  await api(base, modJar, 'POST', '/api/session', {
    username: 'cidrmod',
    password: 'modpass12',
  });
  assert.equal((await api(base, modJar, 'GET', '/api/vpn-pools')).status, 403);
});
