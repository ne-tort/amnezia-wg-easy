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
  const authFile = path.join(srcRoot, 'lib', 'auth.js');
  for (const f of [confFile, dbFile, authFile]) delete require.cache[f];
  // eslint-disable-next-line import/no-dynamic-require, global-require
  const db = require(dbFile);
  // eslint-disable-next-line import/no-dynamic-require, global-require
  const auth = require(authFile);
  db.getDb();
  return { db, auth };
}

test('client_panel_users assign / set / cascade with client soft? hard delete FKs', async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'awg-own-'));
  const { db, auth } = loadFreshDb(path.join(tmp, 'panel.db'));
  const now = Math.floor(Date.now() / 1000);
  const u1 = auth.generateUserId();
  const u2 = auth.generateUserId();
  db.panelUsers.create({
    id: u1, username: 'u1', password_hash: 'x', role: 'user',
    is_active: 1, created_at: now, updated_at: now,
  });
  db.panelUsers.create({
    id: u2, username: 'u2', password_hash: 'x', role: 'moderator',
    is_active: 1, created_at: now, updated_at: now,
  });
  db.clients.create({
    id: 'cli-a', name: 'A', address: '10.8.0.2', public_key: 'pa', private_key: 'sa',
    enabled: 1, created_at: now, updated_at: now, rule_profile_id: 1,
  });

  db.clientPanelUsers.assign('cli-a', u1);
  assert.deepEqual(db.clientPanelUsers.listUserIds('cli-a'), [u1]);
  assert.equal(db.clientPanelUsers.isAssigned('cli-a', u1), true);

  const users = db.clientPanelUsers.setUsers('cli-a', [u1, u2]);
  assert.equal(users.length, 2);
  assert.deepEqual(db.clientPanelUsers.listClientIdsForUser(u2), ['cli-a']);

  const map = db.clientPanelUsers.mapForClientIds(['cli-a']);
  assert.equal(map['cli-a'].length, 2);

  // Soft-delete client does not CASCADE (FK is ON DELETE CASCADE of hard delete).
  // Hard delete via SQL to verify FK:
  db.getDb().prepare('DELETE FROM clients WHERE id = ?').run('cli-a');
  assert.deepEqual(db.clientPanelUsers.listUserIds('cli-a'), []);
});

test('soft-delete client clears panel-user assignments', async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'awg-own-'));
  const { db, auth } = loadFreshDb(path.join(tmp, 'panel.db'));
  const now = Math.floor(Date.now() / 1000);
  const u1 = auth.generateUserId();
  db.panelUsers.create({
    id: u1, username: 'u1', password_hash: 'x', role: 'user',
    is_active: 1, created_at: now, updated_at: now,
  });
  db.clients.create({
    id: 'cli-soft', name: 'Soft', address: '10.8.0.9', public_key: 'ps', private_key: 'ss',
    enabled: 1, created_at: now, updated_at: now, rule_profile_id: 1,
  });
  db.clientPanelUsers.assign('cli-soft', u1);
  assert.equal(db.clientPanelUsers.isAssigned('cli-soft', u1), true);
  db.clients.delete('cli-soft');
  assert.equal(db.clients.getById('cli-soft'), undefined);
  assert.equal(db.clientPanelUsers.isAssigned('cli-soft', u1), false);
  assert.deepEqual(db.clientPanelUsers.listClientIdsForUser(u1), []);
});

test('panelUsers list / update / countActiveAdmins', async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'awg-users-'));
  const { db, auth } = loadFreshDb(path.join(tmp, 'panel.db'));
  const now = Math.floor(Date.now() / 1000);
  const a1 = auth.generateUserId();
  const a2 = auth.generateUserId();
  db.panelUsers.create({
    id: a1, username: 'admin1', password_hash: 'x', role: 'admin',
    is_active: 1, created_at: now, updated_at: now,
  });
  db.panelUsers.create({
    id: a2, username: 'admin2', password_hash: 'x', role: 'admin',
    is_active: 1, created_at: now, updated_at: now,
  });
  assert.equal(db.panelUsers.countActiveAdmins(), 2);
  const listed = db.panelUsers.list();
  assert.equal(listed.length, 2);
  assert.equal(listed[0].password_hash, undefined);
  db.panelUsers.update(a2, { is_active: 0 });
  assert.equal(db.panelUsers.countActiveAdmins(), 1);
  db.panelUsers.update(a2, { role: 'user', is_active: 1 });
  assert.equal(db.panelUsers.countActiveAdmins(), 1);
});

test('clients.replaceAll preserves xray_uuid (Xray toggle → saveConfig path)', async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'awg-xray-uuid-'));
  const { db } = loadFreshDb(path.join(tmp, 'panel.db'));
  const now = Math.floor(Date.now() / 1000);
  const uuid = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
  db.clients.create({
    id: 'cli-x', name: 'X', address: '10.8.0.11', public_key: 'px', private_key: 'sx',
    enabled: 1, created_at: now, updated_at: now, rule_profile_id: 1,
  });
  db.clients.setXrayUuid('cli-x', uuid);
  assert.equal(db.clients.getById('cli-x').xray_uuid, uuid);

  const row = db.clients.getById('cli-x');
  db.clients.replaceAll([{
    id: row.id,
    name: row.name,
    address: row.address,
    public_key: row.public_key,
    private_key: row.private_key,
    pre_shared_key: row.pre_shared_key,
    enabled: row.enabled,
    note: row.note,
    created_at: row.created_at,
    updated_at: now,
    expires_at: row.expires_at,
    rule_profile_id: row.rule_profile_id,
    default_profile: row.default_profile,
    default_signature: row.default_signature,
    default_level: row.default_level,
    use_server_dns: row.use_server_dns,
    junk_pins: row.junk_pins,
    mtu_profile: row.mtu_profile,
    created_by: row.created_by,
    xray_uuid: row.xray_uuid,
  }]);
  assert.equal(db.clients.getById('cli-x').xray_uuid, uuid);
});
