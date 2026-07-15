'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');

const srcRoot = path.resolve(__dirname, '../../src');

function loadFreshDb(dbPath) {
  process.env.DB_PATH = dbPath;
  process.env.SESSION_SECRET = 'test-session-secret';
  const confFile = path.join(srcRoot, 'config.js');
  const dbFile = path.join(srcRoot, 'lib', 'db.js');
  const aclFile = path.join(srcRoot, 'lib', 'acl.js');
  const authFile = path.join(srcRoot, 'lib', 'auth.js');
  for (const f of [confFile, dbFile, aclFile, authFile]) {
    delete require.cache[f];
  }
  // eslint-disable-next-line import/no-dynamic-require, global-require
  const db = require(dbFile);
  // eslint-disable-next-line import/no-dynamic-require, global-require
  const acl = require(aclFile);
  // eslint-disable-next-line import/no-dynamic-require, global-require
  const auth = require(authFile);
  db.getDb();
  return { db, acl, auth };
}

test('acl capability matrix', async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'awg-acl-'));
  const { acl } = loadFreshDb(path.join(tmp, 'panel.db'));
  assert.ok(acl.hasCapability('admin', acl.CAP.USERS_WRITE));
  assert.ok(acl.hasCapability('admin', acl.CAP.SYSTEM_SETTINGS));
  assert.ok(acl.hasCapability('moderator', acl.CAP.USERS_READ));
  assert.equal(acl.hasCapability('moderator', acl.CAP.USERS_WRITE), false);
  assert.equal(acl.hasCapability('moderator', acl.CAP.SYSTEM_SETTINGS), false);
  assert.equal(acl.hasCapability('moderator', acl.CAP.SYSTEM_FIREWALL), false);
  assert.ok(acl.hasCapability('admin', acl.CAP.SYSTEM_FIREWALL));
  assert.ok(acl.hasCapability('admin', acl.CAP.SYSTEM_XRAY));
  assert.equal(acl.hasCapability('moderator', acl.CAP.SYSTEM_XRAY), false);
  assert.ok(acl.hasCapability('moderator', acl.CAP.CLIENTS_ASSIGN));
  assert.ok(acl.hasCapability('user', acl.CAP.CLIENTS_WRITE));
  assert.equal(acl.hasCapability('user', acl.CAP.USERS_READ), false);
  assert.equal(acl.hasCapability('user', acl.CAP.CLIENTS_READ_ALL), false);
  assert.ok(acl.capabilitiesForRole('admin').includes(acl.CAP.USERS_WRITE));
});

test('acl canChangePassword + listPasswordTargets', async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'awg-acl-pw-'));
  const { db, acl, auth } = loadFreshDb(path.join(tmp, 'panel.db'));
  const now = Math.floor(Date.now() / 1000);
  const adminId = auth.generateUserId();
  const modId = auth.generateUserId();
  const userId = auth.generateUserId();
  const user2Id = auth.generateUserId();
  db.panelUsers.create({
    id: adminId, username: 'admin', password_hash: 'x', role: 'admin',
    is_active: 1, created_at: now, updated_at: now,
  });
  db.panelUsers.create({
    id: modId, username: 'mod', password_hash: 'x', role: 'moderator',
    is_active: 1, created_at: now, updated_at: now,
  });
  db.panelUsers.create({
    id: userId, username: 'bob', password_hash: 'x', role: 'user',
    is_active: 1, created_at: now, updated_at: now,
  });
  db.panelUsers.create({
    id: user2Id, username: 'alice', password_hash: 'x', role: 'user',
    is_active: 1, created_at: now, updated_at: now,
  });
  const admin = { id: adminId, role: 'admin' };
  const mod = { id: modId, role: 'moderator' };
  const user = { id: userId, role: 'user' };
  const adminRow = db.panelUsers.findById(adminId);
  const modRow = db.panelUsers.findById(modId);
  const userRow = db.panelUsers.findById(userId);
  const user2Row = db.panelUsers.findById(user2Id);

  assert.equal(acl.canChangePassword(admin, userRow), true);
  assert.equal(acl.canChangePassword(admin, modRow), true);
  assert.equal(acl.canChangePassword(mod, userRow), true);
  assert.equal(acl.canChangePassword(mod, adminRow), false);
  assert.equal(acl.canChangePassword(mod, modRow), true);
  assert.equal(acl.canChangePassword(user, user2Row), false);
  assert.equal(acl.canChangePassword(user, userRow), true);

  const modTargets = acl.listPasswordTargets(mod).map((u) => u.id).sort();
  assert.deepEqual(modTargets, [modId, userId, user2Id].sort());
  const userTargets = acl.listPasswordTargets(user).map((u) => u.id);
  assert.deepEqual(userTargets, [userId]);
});

test('roleLabels returns localized dictionary', async () => {
  const roleLabels = require(path.join(srcRoot, 'lib', 'roleLabels'));
  const ru = roleLabels.getRoleLabels('ru');
  assert.equal(ru.admin, 'Администратор');
  assert.equal(ru.user, 'Пользователь');
  const en = roleLabels.getRoleLabels('en');
  assert.equal(en.moderator, 'Moderator');
});

test('acl filterClientsForActor + canAccessClient', async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'awg-acl-'));
  const { db, acl, auth } = loadFreshDb(path.join(tmp, 'panel.db'));
  const now = Math.floor(Date.now() / 1000);
  const adminId = auth.generateUserId();
  const userId = auth.generateUserId();
  db.panelUsers.create({
    id: adminId, username: 'admin', password_hash: 'x', role: 'admin',
    is_active: 1, created_at: now, updated_at: now,
  });
  db.panelUsers.create({
    id: userId, username: 'bob', password_hash: 'x', role: 'user',
    is_active: 1, created_at: now, updated_at: now,
  });
  db.clients.create({
    id: 'c1', name: 'one', address: '10.8.0.2', public_key: 'p1', private_key: 's1',
    enabled: 1, created_at: now, updated_at: now, rule_profile_id: 1,
  });
  db.clients.create({
    id: 'c2', name: 'two', address: '10.8.0.3', public_key: 'p2', private_key: 's2',
    enabled: 1, created_at: now, updated_at: now, rule_profile_id: 1,
  });
  db.clientPanelUsers.assign('c1', userId);

  const admin = { id: adminId, role: 'admin' };
  const user = { id: userId, role: 'user' };
  const all = [{ id: 'c1' }, { id: 'c2' }];
  assert.equal(acl.filterClientsForActor(admin, all).length, 2);
  assert.deepEqual(acl.filterClientsForActor(user, all).map((c) => c.id), ['c1']);
  assert.equal(acl.canAccessClient(user, 'c1'), true);
  assert.equal(acl.canAccessClient(user, 'c2'), false);
  assert.equal(acl.canAccessClient(admin, 'c2'), true);
});

test('validateAdminInvariant blocks last admin demotion', async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'awg-acl-'));
  const { db, acl, auth } = loadFreshDb(path.join(tmp, 'panel.db'));
  const now = Math.floor(Date.now() / 1000);
  const adminId = auth.generateUserId();
  db.panelUsers.create({
    id: adminId, username: 'admin', password_hash: 'x', role: 'admin',
    is_active: 1, created_at: now, updated_at: now,
  });
  const target = db.panelUsers.findById(adminId);
  const bad = acl.validateAdminInvariant(target, 'user', 1);
  assert.equal(bad.ok, false);
  const alsoBad = acl.validateAdminInvariant(target, 'admin', 0);
  assert.equal(alsoBad.ok, false);
});
