'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const srcRoot = path.resolve(__dirname, '../../src');

function loadFreshDb(dbPath) {
  process.env.DB_PATH = dbPath;
  process.env.SESSION_SECRET = 'test-session-secret';
  const confFile = path.join(srcRoot, 'config.js');
  const dbFile = path.join(srcRoot, 'lib', 'db.js');
  for (const f of [confFile, dbFile]) delete require.cache[f];
  // eslint-disable-next-line import/no-dynamic-require, global-require
  const db = require(dbFile);
  db.getDb();
  return db;
}

test('traffic deltas fold awg+xray by source', (t) => {
  try {
    // eslint-disable-next-line global-require, import/no-extraneous-dependencies
    require('better-sqlite3');
  } catch (err) {
    t.skip(`better-sqlite3 unavailable: ${err && err.message}`);
    return;
  }

  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'awg-traf-'));
  const db = loadFreshDb(path.join(tmp, 'panel.db'));
  const now = Math.floor(Date.now() / 1000);
  db.clients.create({
    id: 'c1', name: 'cli', address: '10.8.0.2', public_key: 'pk', private_key: 'sk',
    enabled: 1, created_at: now, updated_at: now, rule_profile_id: 1,
  });

  db.traffic.deltas.insertBatch([
    { client_id: 'c1', ts: now - 10, rx_delta: 100, tx_delta: 200, source: 'awg' },
    { client_id: 'c1', ts: now - 5, rx_delta: 50, tx_delta: 50, source: 'xray' },
  ]);

  const sum = db.traffic.deltas.sumByClientAndPeriod('c1', now - 3600);
  assert.equal(sum.rx, 150);
  assert.equal(sum.tx, 250);
  assert.equal(sum.awg.rx, 100);
  assert.equal(sum.awg.tx, 200);
  assert.equal(sum.xray.rx, 50);
  assert.equal(sum.xray.tx, 50);

  const agg = db.traffic.deltas.sumByPeriod(now - 3600);
  assert.equal(agg.rx + agg.tx, 400);
  assert.equal(agg.xray.rx + agg.xray.tx, 100);
});

test('xray snapshot persists last_activity_at', (t) => {
  try {
    // eslint-disable-next-line global-require, import/no-extraneous-dependencies
    require('better-sqlite3');
  } catch (err) {
    t.skip(`better-sqlite3 unavailable: ${err && err.message}`);
    return;
  }

  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'awg-traf-act-'));
  const db = loadFreshDb(path.join(tmp, 'panel.db'));
  const now = Math.floor(Date.now() / 1000);
  db.clients.create({
    id: 'c2', name: 'cli2', address: '10.8.0.3', public_key: 'pk2', private_key: 'sk2',
    enabled: 1, created_at: now, updated_at: now, rule_profile_id: 1,
  });

  db.traffic.xraySnapshot.upsertMany([{
    client_id: 'c2',
    last_rx: 10,
    last_tx: 20,
    sampled_at: now,
    last_activity_at: now - 15,
  }]);

  const rows = db.traffic.xraySnapshot.getAll();
  const row = rows.find((r) => r.client_id === 'c2');
  assert.ok(row);
  assert.equal(row.last_rx, 10);
  assert.equal(row.last_tx, 20);
  assert.equal(row.last_activity_at, now - 15);
});

test('trafficRecorder noteXrayActivity feeds getXrayLastActivityMap', (t) => {
  try {
    // eslint-disable-next-line global-require, import/no-extraneous-dependencies
    require('better-sqlite3');
  } catch (err) {
    t.skip(`better-sqlite3 unavailable: ${err && err.message}`);
    return;
  }

  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'awg-traf-note-'));
  const dbPath = path.join(tmp, 'panel.db');
  process.env.DB_PATH = dbPath;
  process.env.SESSION_SECRET = 'test-session-secret';

  const confFile = path.join(srcRoot, 'config.js');
  const dbFile = path.join(srcRoot, 'lib', 'db.js');
  const trFile = path.join(srcRoot, 'lib', 'trafficRecorder.js');
  for (const f of [confFile, dbFile, trFile]) delete require.cache[f];

  // eslint-disable-next-line import/no-dynamic-require, global-require
  const db = require(dbFile);
  db.getDb();
  // eslint-disable-next-line import/no-dynamic-require, global-require
  const trafficRecorder = require(trFile);

  const now = Math.floor(Date.now() / 1000);
  db.clients.create({
    id: 'c3', name: 'cli3', address: '10.8.0.4', public_key: 'pk3', private_key: 'sk3',
    enabled: 1, created_at: now, updated_at: now, rule_profile_id: 1,
  });

  trafficRecorder.noteXrayActivity('c3', now - 5);
  const map = trafficRecorder.getXrayLastActivityMap();
  assert.equal(map.get('c3'), now - 5);

  trafficRecorder._flush();
  const row = db.traffic.xraySnapshot.getAll().find((r) => r.client_id === 'c3');
  assert.ok(row);
  assert.equal(row.last_activity_at, now - 5);
});
