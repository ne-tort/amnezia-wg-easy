'use strict';

const path = require('node:path');
const fs = require('node:fs');
const Database = require('better-sqlite3');
const { runMigrations } = require('./migrate');

const { DB_PATH } = require('../config');

let db = null;

/**
 * Opens the SQLite database, runs migrations, returns the same instance on subsequent calls.
 * Ensures the directory for DB_PATH exists.
 */
function getDb() {
  if (db) return db;
  const dir = path.dirname(DB_PATH);
  fs.mkdirSync(dir, { recursive: true });
  db = new Database(DB_PATH);
  runMigrations(db);
  vpnPoolsEnsureSeeded();
  return db;
}

// * Panel users (auth)
function panelUsersFindByUsername(username) {
  return getDb().prepare('SELECT * FROM panel_users WHERE username = ? AND is_active = 1').get(username);
}

function panelUsersFindById(id) {
  return getDb().prepare('SELECT * FROM panel_users WHERE id = ?').get(id);
}

function panelUsersCreate(row) {
  try {
    getDb().prepare(
      `INSERT INTO panel_users (id, username, password_hash, role, is_active, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`
    ).run(
      row.id,
      row.username,
      row.password_hash,
      row.role,
      row.is_active ?? 1,
      row.created_at,
      row.updated_at
    );
  } catch (e) {
    if (
      (e.code === 'SQLITE_CONSTRAINT' || e.code === 'SQLITE_CONSTRAINT_UNIQUE')
      && (e.message || '').includes('UNIQUE')
    ) {
      const err = new Error('Username already exists');
      err.code = 'USERNAME_EXISTS';
      throw err;
    }
    throw e;
  }
}

function panelUsersUpdateLastLogin(id, last_login_at) {
  getDb().prepare('UPDATE panel_users SET last_login_at = ? WHERE id = ?').run(last_login_at, id);
}

function panelUsersCount() {
  return getDb().prepare('SELECT COUNT(*) AS n FROM panel_users').get().n;
}

function panelUsersUpdatePasswordHash(id, password_hash) {
  const now = Math.floor(Date.now() / 1000);
  getDb().prepare('UPDATE panel_users SET password_hash = ?, updated_at = ? WHERE id = ?').run(password_hash, now, id);
}

/** Public fields only (never password_hash). */
function panelUsersToPublic(row) {
  if (!row) return null;
  const { parseAssignedCidrsField } = require('./vpnAddress');
  return {
    id: row.id,
    username: row.username,
    role: row.role,
    is_active: row.is_active ? 1 : 0,
    created_at: row.created_at,
    updated_at: row.updated_at,
    last_login_at: row.last_login_at ?? null,
    assigned_cidrs: parseAssignedCidrsField(row.assigned_cidrs),
  };
}

function panelUsersList() {
  return getDb()
    .prepare(
      `SELECT id, username, role, is_active, created_at, updated_at, last_login_at, assigned_cidrs
       FROM panel_users
       ORDER BY created_at ASC`
    )
    .all()
    .map(panelUsersToPublic);
}

function panelUsersFindByIdPublic(id) {
  const row = panelUsersFindById(id);
  return panelUsersToPublic(row);
}

function panelUsersCountActiveAdmins() {
  return getDb()
    .prepare(`SELECT COUNT(*) AS n FROM panel_users WHERE role = 'admin' AND is_active = 1`)
    .get().n;
}

/**
 * Partial update: role, is_active, password_hash, and/or assigned_cidrs.
 * Caller enforces last-admin and ACL rules. assigned_cidrs must already be validated.
 */
function panelUsersUpdate(id, fields) {
  const row = panelUsersFindById(id);
  if (!row) return null;
  const now = Math.floor(Date.now() / 1000);
  const role = fields.role !== undefined ? fields.role : row.role;
  const is_active = fields.is_active !== undefined ? (fields.is_active ? 1 : 0) : row.is_active;
  const password_hash = fields.password_hash !== undefined ? fields.password_hash : row.password_hash;
  const { stringifyAssignedCidrs } = require('./vpnAddress');
  const assigned_cidrs = fields.assigned_cidrs !== undefined
    ? stringifyAssignedCidrs(fields.assigned_cidrs)
    : (row.assigned_cidrs != null ? row.assigned_cidrs : '[]');
  getDb()
    .prepare(
      `UPDATE panel_users
       SET role = ?, is_active = ?, password_hash = ?, assigned_cidrs = ?, updated_at = ?
       WHERE id = ?`
    )
    .run(role, is_active, password_hash, assigned_cidrs, now, id);
  return panelUsersFindByIdPublic(id);
}

function panelUsersDeactivate(id) {
  return panelUsersUpdate(id, { is_active: 0 });
}

/** Best-effort: drop express-session rows that contain this userId. */
function panelUsersDestroySessions(userId) {
  try {
    const tables = getDb()
      .prepare(`SELECT name FROM sqlite_master WHERE type='table' AND name IN ('sessions', 'session')`)
      .all()
      .map((r) => r.name);
    for (const name of tables) {
      getDb()
        .prepare(`DELETE FROM ${name} WHERE sess LIKE ?`)
        .run(`%"userId":"${userId}"%`);
    }
  } catch {
    // Session table may not exist yet; inactive flag is enough.
  }
}

// * Client ↔ panel user assignments (M:N)
function clientPanelUsersListUserIds(clientId) {
  return getDb()
    .prepare('SELECT user_id FROM client_panel_users WHERE client_id = ?')
    .all(clientId)
    .map((r) => r.user_id);
}

function clientPanelUsersListUsers(clientId) {
  return getDb()
    .prepare(
      `SELECT u.id, u.username, u.role, u.is_active, u.created_at, u.updated_at, u.last_login_at
       FROM client_panel_users c
       JOIN panel_users u ON u.id = c.user_id
       WHERE c.client_id = ?
       ORDER BY u.username ASC`
    )
    .all(clientId)
    .map(panelUsersToPublic);
}

function clientPanelUsersListClientIdsForUser(userId) {
  return getDb()
    .prepare('SELECT client_id FROM client_panel_users WHERE user_id = ?')
    .all(userId)
    .map((r) => r.client_id);
}

function clientPanelUsersIsAssigned(clientId, userId) {
  const row = getDb()
    .prepare('SELECT 1 AS ok FROM client_panel_users WHERE client_id = ? AND user_id = ?')
    .get(clientId, userId);
  return !!row;
}

function clientPanelUsersAssign(clientId, userId) {
  getDb()
    .prepare(
      `INSERT OR IGNORE INTO client_panel_users (client_id, user_id) VALUES (?, ?)`
    )
    .run(clientId, userId);
}

function clientPanelUsersUnassign(clientId, userId) {
  getDb()
    .prepare('DELETE FROM client_panel_users WHERE client_id = ? AND user_id = ?')
    .run(clientId, userId);
}

/** Replace full assignee set for a client. Invalid user ids are skipped if missing. */
function clientPanelUsersSetUsers(clientId, userIds) {
  const ids = Array.isArray(userIds) ? [...new Set(userIds.map(String))] : [];
  const run = getDb().transaction(() => {
    getDb().prepare('DELETE FROM client_panel_users WHERE client_id = ?').run(clientId);
    const insert = getDb().prepare(
      `INSERT INTO client_panel_users (client_id, user_id) VALUES (?, ?)`
    );
    for (const uid of ids) {
      const u = panelUsersFindById(uid);
      if (!u) continue;
      insert.run(clientId, uid);
    }
  });
  run();
  return clientPanelUsersListUsers(clientId);
}

/** Map clientId → public users[] for batch enrichment. */
function clientPanelUsersMapForClientIds(clientIds) {
  const map = Object.create(null);
  if (!clientIds || !clientIds.length) return map;
  for (const id of clientIds) map[id] = [];
  const placeholders = clientIds.map(() => '?').join(',');
  const rows = getDb()
    .prepare(
      `SELECT c.client_id AS client_id, u.id, u.username, u.role, u.is_active,
              u.created_at, u.updated_at, u.last_login_at
       FROM client_panel_users c
       JOIN panel_users u ON u.id = c.user_id
       WHERE c.client_id IN (${placeholders})
       ORDER BY u.username ASC`
    )
    .all(...clientIds);
  for (const r of rows) {
    if (!map[r.client_id]) map[r.client_id] = [];
    map[r.client_id].push(panelUsersToPublic(r));
  }
  return map;
}

/** Close DB (tests). Next getDb() reopens. */
function closeDb() {
  if (db) {
    try {
      db.close();
    } catch {
      // ignore
    }
    db = null;
  }
}

// * Server config (singleton)
function serverConfigGet() {
  return getDb().prepare('SELECT * FROM server_config WHERE id = 1').get();
}

function serverConfigUpsert(row) {
  const stmt = getDb().prepare(`
    INSERT INTO server_config (id, private_key, public_key, address, jc, jmin, jmax, s1, s2, s3, s4, h1, h2, h3, h4, i2, i3, i4, i5, updated_at)
    VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(id) DO UPDATE SET
      private_key=excluded.private_key, public_key=excluded.public_key, address=excluded.address,
      jc=excluded.jc, jmin=excluded.jmin, jmax=excluded.jmax,
      s1=excluded.s1, s2=excluded.s2, s3=excluded.s3, s4=excluded.s4,
      h1=excluded.h1, h2=excluded.h2, h3=excluded.h3, h4=excluded.h4,
      i2=excluded.i2, i3=excluded.i3, i4=excluded.i4, i5=excluded.i5,
      updated_at=excluded.updated_at
  `);
  stmt.run(
    row.private_key, row.public_key, row.address,
    row.jc, row.jmin, row.jmax,
    row.s1, row.s2, row.s3, row.s4,
    row.h1, row.h2, row.h3, row.h4,
    row.i2 ?? null, row.i3 ?? null, row.i4 ?? null, row.i5 ?? null,
    row.updated_at
  );
}

// * Clients (active = deleted_at IS NULL)
function clientsGetAll() {
  return getDb().prepare('SELECT * FROM clients WHERE deleted_at IS NULL ORDER BY created_at ASC').all();
}

function clientsGetEnabledForWireGuard() {
  const now = Math.floor(Date.now() / 1000);
  return getDb().prepare(
    'SELECT * FROM clients WHERE deleted_at IS NULL AND enabled = 1 AND (expires_at IS NULL OR expires_at > ?) ORDER BY address'
  ).all(now);
}

function clientsGetById(id) {
  return getDb().prepare('SELECT * FROM clients WHERE id = ? AND deleted_at IS NULL').get(id);
}

function clientsGetByIdIncludingDeleted(id) {
  return getDb().prepare('SELECT * FROM clients WHERE id = ?').get(id);
}

/** clientId → creator username (null if unknown). */
function clientsMapCreatedByUsernames(clientIds) {
  const map = Object.create(null);
  if (!Array.isArray(clientIds) || !clientIds.length) return map;
  const placeholders = clientIds.map(() => '?').join(',');
  const rows = getDb().prepare(
    `SELECT c.id, u.username
     FROM clients c
     LEFT JOIN panel_users u ON u.id = c.created_by
     WHERE c.id IN (${placeholders})`
  ).all(...clientIds);
  for (const r of rows) {
    map[r.id] = r.username || null;
  }
  return map;
}

function clientsCreate(row) {
  getDb().prepare(
    `INSERT INTO clients (id, name, address, public_key, private_key, pre_shared_key, enabled, note, created_at, updated_at, expires_at, rule_profile_id, default_profile, default_signature, default_level, use_server_dns, junk_pins, mtu_profile, created_by)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(
    row.id, row.name, row.address, row.public_key, row.private_key, row.pre_shared_key ?? null,
    row.enabled ?? 1, row.note ?? null, row.created_at, row.updated_at,
    row.expires_at ?? null, row.rule_profile_id ?? null, row.default_profile ?? null,
    row.default_signature ?? null, row.default_level ?? null,
    row.use_server_dns === 0 ? 0 : 1,
    row.junk_pins ?? null,
    row.mtu_profile ?? null,
    row.created_by ?? null
  );
}

function clientsUpdate(row) {
  getDb().prepare(
    `UPDATE clients SET name=?, address=?, public_key=?, private_key=?, pre_shared_key=?, enabled=?, note=?, updated_at=?, expires_at=?, rule_profile_id=?, default_profile=?, default_signature=?, default_level=?, use_server_dns=?, junk_pins=?, mtu_profile=?
     WHERE id = ?`
  ).run(
    row.name, row.address, row.public_key, row.private_key, row.pre_shared_key ?? null,
    row.enabled ?? 1, row.note ?? null, row.updated_at, row.expires_at ?? null,
    row.rule_profile_id ?? null, row.default_profile ?? null, row.default_signature ?? null,
    row.default_level ?? null,
    row.use_server_dns === 0 ? 0 : 1,
    row.junk_pins ?? null,
    row.mtu_profile ?? null,
    row.id
  );
}

function clientsSetDeletedAt(id, deletedAt) {
  const now = Math.floor(Date.now() / 1000);
  getDb().prepare('UPDATE clients SET deleted_at = ?, updated_at = ? WHERE id = ?').run(deletedAt, now, id);
}

function clientsGetDeleted() {
  return getDb().prepare('SELECT * FROM clients WHERE deleted_at IS NOT NULL ORDER BY deleted_at DESC').all();
}

function clientsDisableExpired() {
  const now = Math.floor(Date.now() / 1000);
  const r = getDb().prepare(
    'UPDATE clients SET enabled = 0, updated_at = ? WHERE deleted_at IS NULL AND enabled = 1 AND expires_at IS NOT NULL AND expires_at <= ?'
  ).run(now, now);
  return r.changes > 0;
}

function clientsSetXrayUuid(id, uuid) {
  const now = Math.floor(Date.now() / 1000);
  getDb().prepare('UPDATE clients SET xray_uuid = ?, updated_at = ? WHERE id = ?').run(uuid || null, now, id);
}

function clientsSetHysteriaPassword(id, password) {
  const now = Math.floor(Date.now() / 1000);
  getDb().prepare('UPDATE clients SET hysteria_password = ?, updated_at = ? WHERE id = ?').run(password || null, now, id);
}

function clientsSetNaivePassword(id, password) {
  const now = Math.floor(Date.now() / 1000);
  getDb().prepare('UPDATE clients SET naive_password = ?, updated_at = ? WHERE id = ?').run(password || null, now, id);
}

function clientsGetByName(name) {
  return getDb().prepare('SELECT * FROM clients WHERE name = ? AND deleted_at IS NULL').get(name);
}

function clientsDelete(id) {
  const row = clientsGetByIdIncludingDeleted(id);
  if (!row) return;
  if (row.deleted_at != null) return;
  const now = Math.floor(Date.now() / 1000);
  const run = getDb().transaction(() => {
    getDb().prepare('DELETE FROM client_panel_users WHERE client_id = ?').run(id);
    getDb().prepare('UPDATE clients SET rule_profile_id = NULL, deleted_at = ?, updated_at = ? WHERE id = ?').run(now, now, id);
  });
  run();
}

function clientsReplaceAll(rows) {
  const database = getDb();
  database.prepare('DELETE FROM clients WHERE deleted_at IS NULL').run();
  const stmt = database.prepare(
    `INSERT INTO clients (id, name, address, public_key, private_key, pre_shared_key, enabled, note, created_at, updated_at, expires_at, rule_profile_id, default_profile, default_signature, default_level, use_server_dns, junk_pins, mtu_profile, created_by, xray_uuid, naive_password)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  );
  for (const row of rows) {
    stmt.run(
      row.id, row.name, row.address, row.public_key, row.private_key, row.pre_shared_key ?? null,
      row.enabled ?? 1, row.note ?? null, row.created_at, row.updated_at,
      row.expires_at ?? null, row.rule_profile_id ?? null, row.default_profile ?? null,
      row.default_signature ?? null, row.default_level ?? null,
      row.use_server_dns === 0 ? 0 : 1,
      row.junk_pins ?? null,
      row.mtu_profile ?? null,
      row.created_by ?? null,
      row.xray_uuid ?? null,
      row.naive_password ?? null
    );
  }
}

// * Client config versions
function clientConfigVersionsGetByClientId(clientId) {
  return getDb().prepare('SELECT * FROM client_config_versions WHERE client_id = ? ORDER BY version DESC').all(clientId);
}

function clientConfigVersionsGetById(versionId) {
  return getDb().prepare('SELECT * FROM client_config_versions WHERE id = ?').get(versionId);
}

function clientConfigVersionsGetLatestVersion(clientId) {
  const row = getDb().prepare('SELECT MAX(version) AS v FROM client_config_versions WHERE client_id = ?').get(clientId);
  return row?.v ?? 0;
}

function clientConfigVersionsGetLatest(clientId) {
  return getDb().prepare('SELECT * FROM client_config_versions WHERE client_id = ? ORDER BY version DESC LIMIT 1').get(clientId);
}

function clientConfigVersionsInsert(row) {
  const latest = clientConfigVersionsGetLatest(row.client_id);
  if (latest && latest.config_raw === (row.config_raw ?? null)) {
    return latest.version;
  }
  const nextVersion = (latest ? latest.version : 0) + 1;
  getDb().prepare(
    `INSERT INTO client_config_versions (client_id, version, created_at, private_key, address, dns, mtu, jc, jmin, jmax, s1, s2, s3, s4, h1, h2, h3, h4, i_block, peer_public_key, preshared_key, allowed_ips, persistent_keepalive, endpoint, config_raw, obfuscation_level, obfuscation_profile)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(
    row.client_id, nextVersion, row.created_at,
    row.private_key ?? null, row.address ?? null, row.dns ?? null, row.mtu ?? null,
    row.jc ?? null, row.jmin ?? null, row.jmax ?? null,
    row.s1 ?? null, row.s2 ?? null, row.s3 ?? null, row.s4 ?? null,
    row.h1 ?? null, row.h2 ?? null, row.h3 ?? null, row.h4 ?? null,
    row.i_block ?? null, row.peer_public_key ?? null, row.preshared_key ?? null,
    row.allowed_ips ?? null, row.persistent_keepalive ?? null, row.endpoint ?? null,
    row.config_raw ?? null,
    row.obfuscation_level ?? null, row.obfuscation_profile ?? null
  );
  return nextVersion;
}

// * Rule profiles (ordered by sort_order)
function ruleProfilesGetAll() {
  return getDb().prepare('SELECT * FROM rule_profiles ORDER BY sort_order ASC, id ASC').all();
}

function ruleProfilesGetById(id) {
  return getDb().prepare('SELECT * FROM rule_profiles WHERE id = ?').get(id);
}

function clientsCountByRuleProfileId(ruleProfileId) {
  const row = getDb().prepare(
    'SELECT COUNT(*) AS n FROM clients WHERE deleted_at IS NULL AND rule_profile_id = ?'
  ).get(ruleProfileId);
  return row ? row.n : 0;
}

function ruleProfilesCreate(row) {
  const r = getDb().prepare(
    `INSERT INTO rule_profiles (name, description, sort_order) VALUES (?, ?, ?)`
  ).run(
    row.name,
    row.description ?? null,
    row.sort_order != null ? row.sort_order : 10
  );
  return r.lastInsertRowid;
}

function ruleProfilesUpdate(id, row) {
  getDb().prepare(
    `UPDATE rule_profiles SET name = ?, description = ?, sort_order = ? WHERE id = ?`
  ).run(
    row.name,
    row.description ?? null,
    row.sort_order != null ? row.sort_order : 0,
    id
  );
}

function ruleProfilesDelete(id) {
  getDb().prepare('UPDATE clients SET rule_profile_id = NULL WHERE rule_profile_id = ?').run(id);
  getDb().prepare('DELETE FROM rule_profiles WHERE id = ?').run(id);
}

// * IP rules
function ipRulesGetByProfileId(ruleProfileId) {
  return getDb().prepare('SELECT * FROM ip_rules WHERE rule_profile_id = ? ORDER BY sort_order, id').all(ruleProfileId);
}

function ipRulesGetMaxSortOrderForProfile(ruleProfileId) {
  const row = getDb().prepare('SELECT COALESCE(MAX(sort_order), -1) AS max_sort FROM ip_rules WHERE rule_profile_id = ?').get(ruleProfileId);
  return row?.max_sort ?? -1;
}

function ipRulesGetById(id) {
  return getDb().prepare('SELECT * FROM ip_rules WHERE id = ?').get(id);
}

function ipRulesCreate(row) {
  const r = getDb().prepare(
    `INSERT INTO ip_rules (rule_profile_id, action, destination_cidr, port_range, protocol, sort_order)
     VALUES (?, ?, ?, ?, ?, ?)`
  ).run(
    row.rule_profile_id, row.action, row.destination_cidr, row.port_range ?? null, row.protocol ?? null, row.sort_order ?? 0
  );
  return r.lastInsertRowid;
}

function ipRulesUpdate(id, row) {
  getDb().prepare(
    `UPDATE ip_rules SET action = ?, destination_cidr = ?, port_range = ?, protocol = ?, sort_order = ?
     WHERE id = ?`
  ).run(row.action, row.destination_cidr, row.port_range ?? null, row.protocol ?? null, row.sort_order ?? 0, id);
}

function ipRulesDelete(id) {
  getDb().prepare('DELETE FROM ip_rules WHERE id = ?').run(id);
}

// * Global firewall rules (apply before profile rules)
function globalFirewallRulesGetAll() {
  return getDb().prepare('SELECT * FROM global_firewall_rules ORDER BY sort_order ASC, id ASC').all();
}

function globalFirewallRulesGetMaxSortOrder() {
  const row = getDb().prepare('SELECT COALESCE(MAX(sort_order), -1) AS max_sort FROM global_firewall_rules').get();
  return row?.max_sort ?? -1;
}

function globalFirewallRulesCreate(row) {
  const r = getDb().prepare(
    `INSERT INTO global_firewall_rules (action, destination_cidr, port_range, protocol, sort_order)
     VALUES (?, ?, ?, ?, ?)`
  ).run(
    row.action, row.destination_cidr, row.port_range ?? null, row.protocol ?? null, row.sort_order ?? 0
  );
  return r.lastInsertRowid;
}

function globalFirewallRulesUpdate(id, row) {
  getDb().prepare(
    `UPDATE global_firewall_rules SET action = ?, destination_cidr = ?, port_range = ?, protocol = ?, sort_order = ?
     WHERE id = ?`
  ).run(row.action, row.destination_cidr, row.port_range ?? null, row.protocol ?? null, row.sort_order ?? 0, id);
}

function globalFirewallRulesDelete(id) {
  getDb().prepare('DELETE FROM global_firewall_rules WHERE id = ?').run(id);
}

// * Client firewall rules (per-client; highest priority)
function clientFirewallRulesGetByClientId(clientId) {
  return getDb().prepare('SELECT * FROM client_firewall_rules WHERE client_id = ? ORDER BY sort_order ASC, id ASC').all(clientId);
}

function clientFirewallRulesGetMaxSortOrderForClient(clientId) {
  const row = getDb().prepare('SELECT COALESCE(MAX(sort_order), -1) AS max_sort FROM client_firewall_rules WHERE client_id = ?').get(clientId);
  return row?.max_sort ?? -1;
}

function clientFirewallRulesGetById(id) {
  return getDb().prepare('SELECT * FROM client_firewall_rules WHERE id = ?').get(id);
}

function clientFirewallRulesCreate(row) {
  const r = getDb().prepare(
    `INSERT INTO client_firewall_rules (client_id, action, destination_cidr, port_range, protocol, sort_order)
     VALUES (?, ?, ?, ?, ?, ?)`
  ).run(
    row.client_id, row.action, row.destination_cidr, row.port_range ?? null, row.protocol ?? null, row.sort_order ?? 0
  );
  return r.lastInsertRowid;
}

function clientFirewallRulesUpdate(id, row) {
  getDb().prepare(
    `UPDATE client_firewall_rules SET action = ?, destination_cidr = ?, port_range = ?, protocol = ?, sort_order = ?
     WHERE id = ?`
  ).run(row.action, row.destination_cidr, row.port_range ?? null, row.protocol ?? null, row.sort_order ?? 0, id);
}

function clientFirewallRulesDelete(id) {
  getDb().prepare('DELETE FROM client_firewall_rules WHERE id = ?').run(id);
}

// * App settings
function appSettingsGet(key) {
  const row = getDb().prepare('SELECT value FROM app_settings WHERE key = ?').get(key);
  return row?.value ?? null;
}

function appSettingsGetAll() {
  const rows = getDb().prepare('SELECT key, value FROM app_settings').all();
  return Object.fromEntries(rows.map((r) => [r.key, r.value]));
}

function appSettingsSet(key, value) {
  getDb().prepare('INSERT OR REPLACE INTO app_settings (key, value) VALUES (?, ?)').run(key, value == null ? '' : String(value));
}

// * Protocol templates
function protocolTemplatesGetAll() {
  const rows = getDb().prepare('SELECT profile_id, default_hex FROM protocol_templates').all();
  return Object.fromEntries(rows.map((r) => [r.profile_id, r.default_hex]));
}

function protocolTemplatesGetByProfileId(profileId) {
  const row = getDb().prepare('SELECT default_hex FROM protocol_templates WHERE profile_id = ?').get(profileId);
  return row?.default_hex ?? null;
}

// * Traffic history: snapshot (last WG counters) and deltas (per-sample increments)
function foldTrafficBySource(rows) {
  const awg = { rx: 0, tx: 0 };
  const xray = { rx: 0, tx: 0 };
  for (const r of rows || []) {
    const bucket = r.source === 'xray' ? xray : awg;
    bucket.rx += Number(r.rx) || 0;
    bucket.tx += Number(r.tx) || 0;
  }
  return {
    rx: awg.rx + xray.rx,
    tx: awg.tx + xray.tx,
    awg,
    xray,
  };
}

function trafficSnapshotGetAll() {
  return getDb().prepare('SELECT client_id, last_rx, last_tx, sampled_at FROM traffic_snapshot').all();
}

function trafficSnapshotGetByClientId(clientId) {
  return getDb().prepare('SELECT client_id, last_rx, last_tx, sampled_at FROM traffic_snapshot WHERE client_id = ?').get(clientId);
}

function trafficSnapshotUpsert(clientId, lastRx, lastTx, sampledAt) {
  getDb().prepare(
    `INSERT INTO traffic_snapshot (client_id, last_rx, last_tx, sampled_at) VALUES (?, ?, ?, ?)
     ON CONFLICT(client_id) DO UPDATE SET last_rx = excluded.last_rx, last_tx = excluded.last_tx, sampled_at = excluded.sampled_at`
  ).run(clientId, lastRx, lastTx, sampledAt);
}

function trafficSnapshotUpsertMany(rows) {
  const stmt = getDb().prepare(
    `INSERT INTO traffic_snapshot (client_id, last_rx, last_tx, sampled_at) VALUES (?, ?, ?, ?)
     ON CONFLICT(client_id) DO UPDATE SET last_rx = excluded.last_rx, last_tx = excluded.last_tx, sampled_at = excluded.sampled_at`
  );
  for (const r of rows) {
    stmt.run(r.client_id, r.last_rx, r.last_tx, r.sampled_at);
  }
}

function trafficXraySnapshotGetAll() {
  return getDb().prepare(
    'SELECT client_id, last_rx, last_tx, sampled_at, last_activity_at FROM traffic_xray_snapshot'
  ).all();
}

function trafficXraySnapshotUpsert(clientId, lastRx, lastTx, sampledAt, lastActivityAt = null) {
  getDb().prepare(
    `INSERT INTO traffic_xray_snapshot (client_id, last_rx, last_tx, sampled_at, last_activity_at)
     VALUES (?, ?, ?, ?, ?)
     ON CONFLICT(client_id) DO UPDATE SET
       last_rx = excluded.last_rx,
       last_tx = excluded.last_tx,
       sampled_at = excluded.sampled_at,
       last_activity_at = excluded.last_activity_at`
  ).run(clientId, lastRx, lastTx, sampledAt, lastActivityAt);
}

function trafficXraySnapshotUpsertMany(rows) {
  const stmt = getDb().prepare(
    `INSERT INTO traffic_xray_snapshot (client_id, last_rx, last_tx, sampled_at, last_activity_at)
     VALUES (?, ?, ?, ?, ?)
     ON CONFLICT(client_id) DO UPDATE SET
       last_rx = excluded.last_rx,
       last_tx = excluded.last_tx,
       sampled_at = excluded.sampled_at,
       last_activity_at = excluded.last_activity_at`
  );
  for (const r of rows) {
    stmt.run(r.client_id, r.last_rx, r.last_tx, r.sampled_at, r.last_activity_at ?? null);
  }
}

function trafficDeltasInsertBatch(rows) {
  if (rows.length === 0) return;
  const stmt = getDb().prepare(
    'INSERT INTO traffic_deltas (client_id, ts, rx_delta, tx_delta, source) VALUES (?, ?, ?, ?, ?)'
  );
  for (const r of rows) {
    stmt.run(r.client_id, r.ts, r.rx_delta, r.tx_delta, r.source || 'awg');
  }
}

function trafficDeltasSumByClientAndPeriod(clientId, tsFrom) {
  const rows = getDb()
    .prepare(
      `SELECT COALESCE(source, 'awg') AS source,
              COALESCE(SUM(rx_delta), 0) AS rx,
              COALESCE(SUM(tx_delta), 0) AS tx
       FROM traffic_deltas
       WHERE client_id = ? AND ts >= ?
       GROUP BY COALESCE(source, 'awg')`
    )
    .all(clientId, tsFrom);
  return foldTrafficBySource(rows);
}

function trafficDeltasSumByPeriod(tsFrom) {
  const rows = getDb()
    .prepare(
      `SELECT COALESCE(source, 'awg') AS source,
              COALESCE(SUM(rx_delta), 0) AS rx,
              COALESCE(SUM(tx_delta), 0) AS tx
       FROM traffic_deltas
       WHERE ts >= ?
       GROUP BY COALESCE(source, 'awg')`
    )
    .all(tsFrom);
  return foldTrafficBySource(rows);
}

function trafficDeltasDeleteByClientId(clientId) {
  return getDb().prepare('DELETE FROM traffic_deltas WHERE client_id = ?').run(clientId);
}

// * VPN address pools
function vpnPoolsSyncInternetOnlyDenies() {
  const pools = vpnPoolsList();
  const existing = getDb()
    .prepare(
      `SELECT id, destination_cidr FROM ip_rules
       WHERE rule_profile_id = 2 AND action = 'deny'`
    )
    .all();
  const existingCidrs = new Set(existing.map((r) => r.destination_cidr));
  let maxSort = getDb()
    .prepare(`SELECT COALESCE(MAX(sort_order), 0) AS m FROM ip_rules WHERE rule_profile_id = 2`)
    .get().m;
  for (const pool of pools) {
    if (existingCidrs.has(pool.cidr)) continue;
    maxSort += 10;
    getDb()
      .prepare(
        `INSERT INTO ip_rules (rule_profile_id, action, destination_cidr, sort_order)
         VALUES (2, 'deny', ?, ?)`
      )
      .run(pool.cidr, maxSort);
  }
}

function vpnPoolsAssignPrimaryToEmptyAdmins() {
  const primary = vpnPoolsGetPrimary();
  if (!primary || !primary.cidr) return;
  const { parseAssignedCidrsField, stringifyAssignedCidrs } = require('./vpnAddress');
  const admins = getDb()
    .prepare(`SELECT id, assigned_cidrs FROM panel_users WHERE role = 'admin' AND is_active = 1`)
    .all();
  const now = Math.floor(Date.now() / 1000);
  for (const u of admins) {
    const list = parseAssignedCidrsField(u.assigned_cidrs);
    if (list.length) continue;
    getDb()
      .prepare('UPDATE panel_users SET assigned_cidrs = ?, updated_at = ? WHERE id = ?')
      .run(stringifyAssignedCidrs([primary.cidr]), now, u.id);
  }
}

function vpnPoolsEnsureSeeded() {
  const n = db.prepare('SELECT COUNT(*) AS n FROM vpn_address_pools').get().n;
  if (n > 0) {
    db.prepare(`UPDATE vpn_address_pools SET name = 'Default' WHERE name = '' OR name IS NULL`).run();
    vpnPoolsAssignPrimaryToEmptyAdmins();
    return;
  }
  const { WG_DEFAULT_ADDRESS } = require('../config');
  const { seedPoolFromEnvTemplate } = require('./vpnAddress');
  const seed = seedPoolFromEnvTemplate(WG_DEFAULT_ADDRESS);
  const now = Math.floor(Date.now() / 1000);
  db.prepare(
    `INSERT INTO vpn_address_pools (cidr, gateway, sort_order, created_at, name) VALUES (?, ?, 0, ?, 'Default')`
  ).run(seed.cidr, seed.gateway, now);
  // Align legacy Internet-only deny with seeded primary pool when different from hardcoded seed.
  const deny10 = db.prepare(
    `SELECT id FROM ip_rules WHERE rule_profile_id = 2 AND action = 'deny' AND destination_cidr = '10.8.0.0/24'`
  ).get();
  if (deny10 && seed.cidr !== '10.8.0.0/24') {
    db.prepare(`UPDATE ip_rules SET destination_cidr = ? WHERE id = ?`).run(seed.cidr, deny10.id);
  }
  vpnPoolsSyncInternetOnlyDenies();
  vpnPoolsAssignPrimaryToEmptyAdmins();
}

function vpnPoolsList() {
  return getDb()
    .prepare(
      `SELECT id, name, cidr, gateway, sort_order, created_at
       FROM vpn_address_pools
       ORDER BY sort_order ASC, id ASC`
    )
    .all();
}

function vpnPoolsGetPrimary() {
  const rows = vpnPoolsList();
  return rows[0] || null;
}

function vpnPoolsGetById(id) {
  return getDb().prepare('SELECT * FROM vpn_address_pools WHERE id = ?').get(id);
}

function vpnPoolsAssertUniqueGateway(gateway, excludeId = null) {
  const rows = vpnPoolsList();
  for (const p of rows) {
    if (excludeId != null && p.id === excludeId) continue;
    if (p.gateway === gateway) {
      const err = new Error(`Gateway ${gateway} is already used by pool ${p.cidr}`);
      err.code = 'GATEWAY_EXISTS';
      throw err;
    }
  }
}

/**
 * Disable active clients whose address is outside the union of current pools.
 * @returns {number} number of clients disabled
 */
function clientsReconcileAddressesAgainstPools() {
  const vpnAddress = require('./vpnAddress');
  const poolCidrs = vpnPoolsList().map((p) => p.cidr);
  const now = Math.floor(Date.now() / 1000);
  let disabled = 0;
  for (const c of clientsGetAll()) {
    if (!c.address || !vpnAddress.ipInAnyPool(c.address, poolCidrs)) {
      if (c.enabled) {
        getDb().prepare('UPDATE clients SET enabled = 0, updated_at = ? WHERE id = ?').run(now, c.id);
        disabled += 1;
      }
    }
  }
  return disabled;
}

/**
 * @param {{ name?: string, cidr: string, gateway?: string, sort_order?: number }} input
 */
function vpnPoolsCreate(input) {
  const vpnAddress = require('./vpnAddress');
  const norm = vpnAddress.normalizeCidr(input.cidr, { minPrefix: 8, maxPrefix: 30 });
  if (!norm.ok) {
    const err = new Error(norm.message);
    err.code = 'INVALID_CIDR';
    throw err;
  }
  const name = typeof input.name === 'string' ? input.name.trim() : '';
  if (!name) {
    const err = new Error('Pool name is required');
    err.code = 'INVALID_NAME';
    throw err;
  }
  const gateway = input.gateway
    ? String(input.gateway).trim()
    : vpnAddress.defaultGatewayForCidr(norm.cidr);
  if (!gateway || !vpnAddress.ipInCidr(gateway, norm.cidr)) {
    const err = new Error('Gateway must be an IPv4 inside the pool CIDR');
    err.code = 'INVALID_GATEWAY';
    throw err;
  }
  vpnPoolsAssertUniqueGateway(gateway);
  const now = Math.floor(Date.now() / 1000);
  let sortOrder = input.sort_order;
  if (sortOrder == null) {
    const m = getDb().prepare('SELECT COALESCE(MAX(sort_order), -1) AS m FROM vpn_address_pools').get().m;
    sortOrder = m + 1;
  }
  try {
    const info = getDb()
      .prepare(
        `INSERT INTO vpn_address_pools (cidr, gateway, sort_order, created_at, name) VALUES (?, ?, ?, ?, ?)`
      )
      .run(norm.cidr, gateway, sortOrder, now, name);
    vpnPoolsSyncInternetOnlyDenies();
    return vpnPoolsGetById(info.lastInsertRowid);
  } catch (e) {
    if (e.code === 'GATEWAY_EXISTS') throw e;
    if ((e.code || '').includes('CONSTRAINT') || (e.message || '').includes('UNIQUE')) {
      const err = new Error('Pool CIDR already exists');
      err.code = 'POOL_EXISTS';
      throw err;
    }
    throw e;
  }
}

/**
 * @param {number} id
 * @param {{ name?: string, cidr?: string, gateway?: string, sort_order?: number }} fields
 */
function vpnPoolsUpdate(id, fields) {
  const pool = vpnPoolsGetById(id);
  if (!pool) return null;
  const vpnAddress = require('./vpnAddress');
  const oldCidr = pool.cidr;
  let cidr = pool.cidr;
  let gateway = pool.gateway;
  let name = pool.name || '';
  let sortOrder = pool.sort_order;
  if (fields.name !== undefined) {
    name = typeof fields.name === 'string' ? fields.name.trim() : '';
    if (!name) {
      const err = new Error('Pool name is required');
      err.code = 'INVALID_NAME';
      throw err;
    }
  }
  if (fields.cidr !== undefined) {
    const norm = vpnAddress.normalizeCidr(fields.cidr, { minPrefix: 8, maxPrefix: 30 });
    if (!norm.ok) {
      const err = new Error(norm.message);
      err.code = 'INVALID_CIDR';
      throw err;
    }
    cidr = norm.cidr;
  }
  if (fields.gateway !== undefined && String(fields.gateway).trim()) {
    gateway = String(fields.gateway).trim();
  } else if (fields.cidr !== undefined) {
    gateway = vpnAddress.defaultGatewayForCidr(cidr);
  }
  if (!gateway || !vpnAddress.ipInCidr(gateway, cidr)) {
    const err = new Error('Gateway must be an IPv4 inside the pool CIDR');
    err.code = 'INVALID_GATEWAY';
    throw err;
  }
  vpnPoolsAssertUniqueGateway(gateway, id);
  if (fields.sort_order !== undefined) sortOrder = fields.sort_order;
  try {
    getDb()
      .prepare(
        `UPDATE vpn_address_pools SET name = ?, cidr = ?, gateway = ?, sort_order = ? WHERE id = ?`
      )
      .run(name, cidr, gateway, sortOrder, id);
  } catch (e) {
    if (e.code === 'GATEWAY_EXISTS') throw e;
    if ((e.code || '').includes('CONSTRAINT') || (e.message || '').includes('UNIQUE')) {
      const err = new Error('Pool CIDR already exists');
      err.code = 'POOL_EXISTS';
      throw err;
    }
    throw e;
  }
  if (oldCidr !== cidr) {
    const { parseAssignedCidrsField, stringifyAssignedCidrs, validateAssignedCidrs } = require('./vpnAddress');
    const poolCidrs = vpnPoolsList().map((p) => p.cidr);
    const users = getDb().prepare('SELECT id, assigned_cidrs FROM panel_users').all();
    const now = Math.floor(Date.now() / 1000);
    for (const u of users) {
      let list = parseAssignedCidrsField(u.assigned_cidrs).map((c) => (c === oldCidr ? cidr : c));
      const validated = validateAssignedCidrs(list, poolCidrs);
      list = validated.ok ? validated.cidrs : list.filter((c) => poolCidrs.some((p) => vpnAddress.cidrContains(p, c)));
      getDb()
        .prepare('UPDATE panel_users SET assigned_cidrs = ?, updated_at = ? WHERE id = ?')
        .run(stringifyAssignedCidrs(list), now, u.id);
    }
  }
  vpnPoolsSyncInternetOnlyDenies();
  clientsReconcileAddressesAgainstPools();
  return vpnPoolsGetById(id);
}

function vpnPoolsDelete(id) {
  const pool = vpnPoolsGetById(id);
  if (!pool) return null;
  const { parseAssignedCidrsField, stringifyAssignedCidrs } = require('./vpnAddress');
  getDb().prepare('DELETE FROM vpn_address_pools WHERE id = ?').run(id);
  // Strip this CIDR from panel user assignments
  const users = getDb().prepare('SELECT id, assigned_cidrs FROM panel_users').all();
  for (const u of users) {
    const list = parseAssignedCidrsField(u.assigned_cidrs).filter((c) => c !== pool.cidr);
    getDb()
      .prepare('UPDATE panel_users SET assigned_cidrs = ? WHERE id = ?')
      .run(stringifyAssignedCidrs(list), u.id);
  }
  vpnPoolsSyncInternetOnlyDenies();
  clientsReconcileAddressesAgainstPools();
  return pool;
}

/**
 * Sync which panel users have this pool.cidr in assigned_cidrs.
 * Selected users get cidr prepended if missing (default = first).
 * Unselected users lose this cidr.
 * @param {number} poolId
 * @param {string[]} userIds
 */
function vpnPoolsSetUsers(poolId, userIds) {
  const pool = vpnPoolsGetById(poolId);
  if (!pool) return null;
  const { parseAssignedCidrsField, stringifyAssignedCidrs } = require('./vpnAddress');
  const selected = new Set(Array.isArray(userIds) ? userIds.map(String) : []);
  const allUsers = getDb().prepare('SELECT id, assigned_cidrs FROM panel_users WHERE is_active = 1').all();
  for (const u of allUsers) {
    let list = parseAssignedCidrsField(u.assigned_cidrs);
    const has = list.includes(pool.cidr);
    if (selected.has(u.id)) {
      if (!has) list = [pool.cidr, ...list];
    } else if (has) {
      list = list.filter((c) => c !== pool.cidr);
    }
    getDb()
      .prepare('UPDATE panel_users SET assigned_cidrs = ?, updated_at = ? WHERE id = ?')
      .run(stringifyAssignedCidrs(list), Math.floor(Date.now() / 1000), u.id);
  }
  return panelUsersList().filter((u) => (u.assigned_cidrs || []).includes(pool.cidr));
}

function vpnPoolsListUserIds(poolId) {
  const pool = vpnPoolsGetById(poolId);
  if (!pool) return [];
  const { parseAssignedCidrsField } = require('./vpnAddress');
  return getDb()
    .prepare('SELECT id, assigned_cidrs FROM panel_users WHERE is_active = 1')
    .all()
    .filter((u) => parseAssignedCidrsField(u.assigned_cidrs).includes(pool.cidr))
    .map((u) => u.id);
}

/** All client addresses including soft-deleted (for allocator uniqueness). */
function clientsUsedAddresses(excludeClientId = null) {
  const rows = getDb().prepare('SELECT id, address FROM clients WHERE address IS NOT NULL').all();
  const set = new Set();
  for (const r of rows) {
    if (excludeClientId && r.id === excludeClientId) continue;
    if (r.address) set.add(r.address);
  }
  return set;
}

module.exports = {
  getDb,
  closeDb,
  panelUsers: {
    findByUsername: panelUsersFindByUsername,
    findById: panelUsersFindById,
    findByIdPublic: panelUsersFindByIdPublic,
    toPublic: panelUsersToPublic,
    list: panelUsersList,
    create: panelUsersCreate,
    update: panelUsersUpdate,
    deactivate: panelUsersDeactivate,
    updateLastLogin: panelUsersUpdateLastLogin,
    count: panelUsersCount,
    countActiveAdmins: panelUsersCountActiveAdmins,
    updatePasswordHash: panelUsersUpdatePasswordHash,
    destroySessions: panelUsersDestroySessions,
  },
  clientPanelUsers: {
    listUserIds: clientPanelUsersListUserIds,
    listUsers: clientPanelUsersListUsers,
    listClientIdsForUser: clientPanelUsersListClientIdsForUser,
    isAssigned: clientPanelUsersIsAssigned,
    assign: clientPanelUsersAssign,
    unassign: clientPanelUsersUnassign,
    setUsers: clientPanelUsersSetUsers,
    mapForClientIds: clientPanelUsersMapForClientIds,
  },
  serverConfig: {
    get: serverConfigGet,
    upsert: serverConfigUpsert,
  },
  clients: {
    getAll: clientsGetAll,
    getEnabledForWireGuard: clientsGetEnabledForWireGuard,
    getById: clientsGetById,
    getDeleted: clientsGetDeleted,
    disableExpired: clientsDisableExpired,
    create: clientsCreate,
    update: clientsUpdate,
    delete: clientsDelete,
    replaceAll: clientsReplaceAll,
    mapCreatedByUsernames: clientsMapCreatedByUsernames,
    usedAddresses: clientsUsedAddresses,
    setXrayUuid: clientsSetXrayUuid,
    setNaivePassword: clientsSetNaivePassword,
    getByName: clientsGetByName,
  },
  vpnPools: {
    ensureSeeded: () => {
      getDb();
    },
    list: vpnPoolsList,
    getPrimary: vpnPoolsGetPrimary,
    getById: vpnPoolsGetById,
    create: vpnPoolsCreate,
    update: vpnPoolsUpdate,
    delete: vpnPoolsDelete,
    setUsers: vpnPoolsSetUsers,
    listUserIds: vpnPoolsListUserIds,
    syncInternetOnlyDenies: vpnPoolsSyncInternetOnlyDenies,
    reconcileClientAddresses: clientsReconcileAddressesAgainstPools,
    assignPrimaryToEmptyAdmins: vpnPoolsAssignPrimaryToEmptyAdmins,
  },
  clientConfigVersions: {
    getByClientId: clientConfigVersionsGetByClientId,
    getById: clientConfigVersionsGetById,
    getLatestVersion: clientConfigVersionsGetLatestVersion,
    insert: clientConfigVersionsInsert,
  },
  ruleProfiles: {
    getAll: ruleProfilesGetAll,
    getById: ruleProfilesGetById,
    create: ruleProfilesCreate,
    update: ruleProfilesUpdate,
    delete: ruleProfilesDelete,
  },
  clientsCountByRuleProfileId: clientsCountByRuleProfileId,
  ipRules: {
    getByProfileId: ipRulesGetByProfileId,
    getMaxSortOrderForProfile: ipRulesGetMaxSortOrderForProfile,
    getById: ipRulesGetById,
    create: ipRulesCreate,
    update: ipRulesUpdate,
    delete: ipRulesDelete,
  },
  globalFirewallRules: {
    getAll: globalFirewallRulesGetAll,
    getMaxSortOrder: globalFirewallRulesGetMaxSortOrder,
    create: globalFirewallRulesCreate,
    update: globalFirewallRulesUpdate,
    delete: globalFirewallRulesDelete,
  },
  clientFirewallRules: {
    getByClientId: clientFirewallRulesGetByClientId,
    getMaxSortOrderForClient: clientFirewallRulesGetMaxSortOrderForClient,
    getById: clientFirewallRulesGetById,
    create: clientFirewallRulesCreate,
    update: clientFirewallRulesUpdate,
    delete: clientFirewallRulesDelete,
  },
  appSettings: {
    get: appSettingsGet,
    getAll: appSettingsGetAll,
    set: appSettingsSet,
  },
  protocolTemplates: {
    getAll: protocolTemplatesGetAll,
    getByProfileId: protocolTemplatesGetByProfileId,
  },
  traffic: {
    snapshot: {
      getAll: trafficSnapshotGetAll,
      getByClientId: trafficSnapshotGetByClientId,
      upsert: trafficSnapshotUpsert,
      upsertMany: trafficSnapshotUpsertMany,
    },
    xraySnapshot: {
      getAll: trafficXraySnapshotGetAll,
      upsert: trafficXraySnapshotUpsert,
      upsertMany: trafficXraySnapshotUpsertMany,
    },
    deltas: {
      insertBatch: trafficDeltasInsertBatch,
      sumByClientAndPeriod: trafficDeltasSumByClientAndPeriod,
      sumByPeriod: trafficDeltasSumByPeriod,
      deleteByClientId: trafficDeltasDeleteByClientId,
    },
  },
};
