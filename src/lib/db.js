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
    if (e.code === 'SQLITE_CONSTRAINT' && (e.message || '').includes('UNIQUE')) {
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

function clientsCreate(row) {
  getDb().prepare(
    `INSERT INTO clients (id, name, address, public_key, private_key, pre_shared_key, enabled, note, created_at, updated_at, expires_at, rule_profile_id, default_profile, default_level, use_server_dns)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(
    row.id, row.name, row.address, row.public_key, row.private_key, row.pre_shared_key ?? null,
    row.enabled ?? 1, row.note ?? null, row.created_at, row.updated_at,
    row.expires_at ?? null, row.rule_profile_id ?? null, row.default_profile ?? null, row.default_level ?? null,
    row.use_server_dns === 0 ? 0 : 1
  );
}

function clientsUpdate(row) {
  getDb().prepare(
    `UPDATE clients SET name=?, address=?, public_key=?, private_key=?, pre_shared_key=?, enabled=?, note=?, updated_at=?, expires_at=?, rule_profile_id=?, default_profile=?, default_level=?, use_server_dns=?
     WHERE id = ?`
  ).run(
    row.name, row.address, row.public_key, row.private_key, row.pre_shared_key ?? null,
    row.enabled ?? 1, row.note ?? null, row.updated_at, row.expires_at ?? null,
    row.rule_profile_id ?? null, row.default_profile ?? null, row.default_level ?? null,
    row.use_server_dns === 0 ? 0 : 1,
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

function clientsDelete(id) {
  const row = clientsGetByIdIncludingDeleted(id);
  if (!row) return;
  if (row.deleted_at != null) return;
  const now = Math.floor(Date.now() / 1000);
  getDb().prepare('UPDATE clients SET rule_profile_id = NULL, deleted_at = ?, updated_at = ? WHERE id = ?').run(now, now, id);
}

function clientsReplaceAll(rows) {
  const database = getDb();
  database.prepare('DELETE FROM clients WHERE deleted_at IS NULL').run();
  const stmt = database.prepare(
    `INSERT INTO clients (id, name, address, public_key, private_key, pre_shared_key, enabled, note, created_at, updated_at, expires_at, rule_profile_id, default_profile, default_level, use_server_dns)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  );
  for (const row of rows) {
    stmt.run(
      row.id, row.name, row.address, row.public_key, row.private_key, row.pre_shared_key ?? null,
      row.enabled ?? 1, row.note ?? null, row.created_at, row.updated_at,
      row.expires_at ?? null, row.rule_profile_id ?? null, row.default_profile ?? null, row.default_level ?? null,
      row.use_server_dns === 0 ? 0 : 1
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

// * Rule profiles (Synology first via sort_order)
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

function trafficDeltasInsertBatch(rows) {
  if (rows.length === 0) return;
  const stmt = getDb().prepare('INSERT INTO traffic_deltas (client_id, ts, rx_delta, tx_delta) VALUES (?, ?, ?, ?)');
  for (const r of rows) {
    stmt.run(r.client_id, r.ts, r.rx_delta, r.tx_delta);
  }
}

function trafficDeltasSumByClientAndPeriod(clientId, tsFrom) {
  const row = getDb()
    .prepare(
      'SELECT COALESCE(SUM(rx_delta), 0) AS rx, COALESCE(SUM(tx_delta), 0) AS tx FROM traffic_deltas WHERE client_id = ? AND ts >= ?'
    )
    .get(clientId, tsFrom);
  return { rx: row.rx ?? 0, tx: row.tx ?? 0 };
}

function trafficDeltasSumByPeriod(tsFrom) {
  const row = getDb()
    .prepare('SELECT COALESCE(SUM(rx_delta), 0) AS rx, COALESCE(SUM(tx_delta), 0) AS tx FROM traffic_deltas WHERE ts >= ?')
    .get(tsFrom);
  return { rx: row.rx ?? 0, tx: row.tx ?? 0 };
}

function trafficDeltasDeleteByClientId(clientId) {
  return getDb().prepare('DELETE FROM traffic_deltas WHERE client_id = ?').run(clientId);
}

module.exports = {
  getDb,
  panelUsers: {
    findByUsername: panelUsersFindByUsername,
    findById: panelUsersFindById,
    create: panelUsersCreate,
    updateLastLogin: panelUsersUpdateLastLogin,
    count: panelUsersCount,
    updatePasswordHash: panelUsersUpdatePasswordHash,
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
    deltas: {
      insertBatch: trafficDeltasInsertBatch,
      sumByClientAndPeriod: trafficDeltasSumByClientAndPeriod,
      sumByPeriod: trafficDeltasSumByPeriod,
      deleteByClientId: trafficDeltasDeleteByClientId,
    },
  },
};
