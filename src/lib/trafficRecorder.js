'use strict';

const Util = require('./Util');
const db = require('./db');
const {
  TRAFFIC_SAMPLE_INTERVAL_SEC,
  TRAFFIC_FLUSH_INTERVAL_SEC,
  TRAFFIC_BUFFER_MAX,
} = require('../config');

const AWG_IFACE = 'awg0';

let sampleTimer = null;
let flushTimer = null;
/** @type {Map<string, { last_rx: number, last_tx: number }>|null} */
let snapshotMap = null;
/** @type {Map<string, { last_rx: number, last_tx: number, last_activity_at: number|null }>|null} */
let xraySnapshotMap = null;
const buffer = [];

function loadSnapshot() {
  const rows = db.traffic.snapshot.getAll();
  snapshotMap = new Map(rows.map((r) => [r.client_id, { last_rx: r.last_rx, last_tx: r.last_tx }]));
}

function loadXraySnapshot() {
  try {
    const rows = db.traffic.xraySnapshot.getAll();
    xraySnapshotMap = new Map(rows.map((r) => [r.client_id, {
      last_rx: r.last_rx,
      last_tx: r.last_tx,
      last_activity_at: r.last_activity_at != null ? Number(r.last_activity_at) : null,
    }]));
  } catch {
    xraySnapshotMap = new Map();
  }
}

function getPublicKeyToClientId() {
  const clients = db.clients.getAll();
  return new Map(clients.map((c) => [c.public_key, c.id]));
}

function getNameToClientId() {
  const clients = db.clients.getAll();
  return new Map(clients.map((c) => [c.name, c.id]));
}

/**
 * In-memory (and DB-backed after flush) map of clientId → unix seconds of last Xray activity.
 * Used by WireGuard.getClients() for online presence without docker exec on every poll.
 * @returns {Map<string, number>}
 */
function getXrayLastActivityMap() {
  if (xraySnapshotMap === null) loadXraySnapshot();
  const out = new Map();
  for (const [clientId, v] of xraySnapshotMap.entries()) {
    if (v.last_activity_at != null && Number.isFinite(v.last_activity_at)) {
      out.set(clientId, v.last_activity_at);
    }
  }
  return out;
}

function noteXrayActivity(clientId, tsSec) {
  if (!clientId) return;
  if (xraySnapshotMap === null) loadXraySnapshot();
  const prev = xraySnapshotMap.get(clientId) || { last_rx: 0, last_tx: 0, last_activity_at: null };
  const ts = tsSec != null ? tsSec : Math.floor(Date.now() / 1000);
  xraySnapshotMap.set(clientId, {
    last_rx: prev.last_rx,
    last_tx: prev.last_tx,
    last_activity_at: ts,
  });
}

async function sampleAwg() {
  let dump;
  try {
    dump = await Util.exec(`wg show ${AWG_IFACE} dump`, { log: false });
  } catch (err) {
    if (process.env.NODE_ENV !== 'test') {
      // eslint-disable-next-line no-console
      console.error('Traffic recorder: wg dump failed', err.message);
    }
    return;
  }

  if (snapshotMap === null) loadSnapshot();

  const pubKeyToClientId = getPublicKeyToClientId();
  const now = Math.floor(Date.now() / 1000);

  const lines = dump.trim().split('\n').slice(1);
  for (const line of lines) {
    const parts = line.split('\t');
    const publicKey = parts[0];
    const transferRx = Number(parts[5]) || 0;
    const transferTx = Number(parts[6]) || 0;

    const clientId = pubKeyToClientId.get(publicKey);
    if (!clientId) continue;

    const prev = snapshotMap.get(clientId) || { last_rx: 0, last_tx: 0 };
    const deltaRx = Math.max(0, transferRx - prev.last_rx);
    const deltaTx = Math.max(0, transferTx - prev.last_tx);

    if (deltaRx > 0 || deltaTx > 0) {
      buffer.push({
        client_id: clientId, ts: now, rx_delta: deltaRx, tx_delta: deltaTx, source: 'awg',
      });
    }

    snapshotMap.set(clientId, { last_rx: transferRx, last_tx: transferTx });
  }
}

/**
 * Xray Stats: uplink = client→server (map to rx), downlink = server→client (map to tx).
 * Also records last_activity_at from traffic deltas and optional online stats.
 */
async function sampleXray() {
  let amneziaXray;
  try {
    // eslint-disable-next-line global-require
    amneziaXray = require('./amneziaXray');
  } catch {
    return;
  }
  if (!amneziaXray.isAmneziaXrayAvailable || !amneziaXray.isAmneziaXrayAvailable()) {
    return;
  }

  let statsMap;
  try {
    statsMap = await amneziaXray.queryUserTrafficStats();
  } catch (err) {
    if (process.env.NODE_ENV !== 'test') {
      // eslint-disable-next-line no-console
      console.error('Traffic recorder: xray stats failed', err.message);
    }
    return;
  }

  if (xraySnapshotMap === null) loadXraySnapshot();

  const nameToId = getNameToClientId();
  const now = Math.floor(Date.now() / 1000);

  if (statsMap && statsMap.size > 0) {
    for (const [email, counters] of statsMap.entries()) {
      const clientId = nameToId.get(email);
      if (!clientId) continue;
      const transferRx = Number(counters.uplink) || 0;
      const transferTx = Number(counters.downlink) || 0;
      const prev = xraySnapshotMap.get(clientId) || { last_rx: 0, last_tx: 0, last_activity_at: null };
      // Counter reset (container restart) → take absolute as new baseline without huge delta
      let deltaRx = transferRx - prev.last_rx;
      let deltaTx = transferTx - prev.last_tx;
      if (deltaRx < 0) deltaRx = 0;
      if (deltaTx < 0) deltaTx = 0;

      let lastActivity = prev.last_activity_at != null ? prev.last_activity_at : null;
      if (deltaRx > 0 || deltaTx > 0) {
        buffer.push({
          client_id: clientId, ts: now, rx_delta: deltaRx, tx_delta: deltaTx, source: 'xray',
        });
        lastActivity = now;
      }
      xraySnapshotMap.set(clientId, {
        last_rx: transferRx,
        last_tx: transferTx,
        last_activity_at: lastActivity,
      });
    }
  }

  // Idle VLESS sessions: mark activity when Xray reports the user online (if API supported).
  if (typeof amneziaXray.queryOnlineUserEmails === 'function') {
    try {
      const online = await amneziaXray.queryOnlineUserEmails();
      for (const email of online) {
        const clientId = nameToId.get(email);
        if (!clientId) continue;
        noteXrayActivity(clientId, now);
      }
    } catch (err) {
      if (process.env.NODE_ENV !== 'test') {
        // eslint-disable-next-line no-console
        console.error('Traffic recorder: xray online stats failed', err.message);
      }
    }
  }
}

async function sample() {
  await sampleAwg();
  await sampleXray();
  if (buffer.length >= TRAFFIC_BUFFER_MAX) flush();
}

function flush() {
  const toInsert = buffer.splice(0, buffer.length);
  const sampledAt = Math.floor(Date.now() / 1000);
  // AWG snapshots only when we recorded deltas (legacy behaviour).
  const snapshotRows = (toInsert.length > 0 && snapshotMap !== null)
    ? Array.from(snapshotMap.entries()).map(([client_id, v]) => ({
      client_id,
      last_rx: v.last_rx,
      last_tx: v.last_tx,
      sampled_at: sampledAt,
    }))
    : [];
  // Xray snapshots include last_activity_at; persist whenever the map is loaded.
  const xrayRows = xraySnapshotMap === null ? [] : Array.from(xraySnapshotMap.entries()).map(([client_id, v]) => ({
    client_id,
    last_rx: v.last_rx,
    last_tx: v.last_tx,
    sampled_at: sampledAt,
    last_activity_at: v.last_activity_at != null ? v.last_activity_at : null,
  }));

  if (toInsert.length === 0 && xrayRows.length === 0) return;

  const database = db.getDb();
  try {
    database.transaction(() => {
      if (toInsert.length > 0) db.traffic.deltas.insertBatch(toInsert);
      if (snapshotRows.length > 0) db.traffic.snapshot.upsertMany(snapshotRows);
      if (xrayRows.length > 0 && db.traffic.xraySnapshot) {
        db.traffic.xraySnapshot.upsertMany(xrayRows);
      }
    })();
  } catch (err) {
    if (process.env.NODE_ENV !== 'test') {
      // eslint-disable-next-line no-console
      console.error('Traffic recorder: flush failed', err.message);
    }
    buffer.unshift(...toInsert);
  }
}

function startTrafficRecorder() {
  if (sampleTimer != null) return;

  loadSnapshot();
  loadXraySnapshot();
  sampleTimer = setInterval(sample, TRAFFIC_SAMPLE_INTERVAL_SEC * 1000);
  flushTimer = setInterval(flush, TRAFFIC_FLUSH_INTERVAL_SEC * 1000);
  sample().catch((err) => {
    if (process.env.NODE_ENV !== 'test') {
      // eslint-disable-next-line no-console
      console.error('Traffic recorder: initial sample failed', err);
    }
  });
}

function stopTrafficRecorder() {
  if (sampleTimer != null) {
    clearInterval(sampleTimer);
    sampleTimer = null;
  }
  if (flushTimer != null) {
    clearInterval(flushTimer);
    flushTimer = null;
  }
  flush();
}

// * Called when client traffic history is reset so the next sample does not record one huge delta.
function updateSnapshotForClient(clientId, lastRx, lastTx) {
  if (snapshotMap !== null) snapshotMap.set(clientId, { last_rx: lastRx, last_tx: lastTx });
}

function updateXraySnapshotForClient(clientId, lastRx, lastTx) {
  if (xraySnapshotMap !== null) {
    const prev = xraySnapshotMap.get(clientId) || { last_activity_at: null };
    xraySnapshotMap.set(clientId, {
      last_rx: lastRx,
      last_tx: lastTx,
      last_activity_at: prev.last_activity_at != null ? prev.last_activity_at : null,
    });
  }
}

module.exports = {
  startTrafficRecorder,
  stopTrafficRecorder,
  updateSnapshotForClient,
  updateXraySnapshotForClient,
  getXrayLastActivityMap,
  noteXrayActivity,
  // test helpers
  _sampleXray: sampleXray,
  _flush: flush,
  _loadXraySnapshot: loadXraySnapshot,
};
