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
