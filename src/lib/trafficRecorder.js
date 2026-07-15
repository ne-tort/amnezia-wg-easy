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
/** @type {Map<string, { last_rx: number, last_tx: number }>|null} */
let xraySnapshotMap = null;
const buffer = [];

function loadSnapshot() {
  const rows = db.traffic.snapshot.getAll();
  snapshotMap = new Map(rows.map((r) => [r.client_id, { last_rx: r.last_rx, last_tx: r.last_tx }]));
}

function loadXraySnapshot() {
  try {
    const rows = db.traffic.xraySnapshot.getAll();
    xraySnapshotMap = new Map(rows.map((r) => [r.client_id, { last_rx: r.last_rx, last_tx: r.last_tx }]));
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
  if (!statsMap || statsMap.size === 0) return;

  if (xraySnapshotMap === null) loadXraySnapshot();

  const nameToId = getNameToClientId();
  const now = Math.floor(Date.now() / 1000);

  for (const [email, counters] of statsMap.entries()) {
    const clientId = nameToId.get(email);
    if (!clientId) continue;
    const transferRx = Number(counters.uplink) || 0;
    const transferTx = Number(counters.downlink) || 0;
    const prev = xraySnapshotMap.get(clientId) || { last_rx: 0, last_tx: 0 };
    // Counter reset (container restart) → take absolute as new baseline without huge delta
    let deltaRx = transferRx - prev.last_rx;
    let deltaTx = transferTx - prev.last_tx;
    if (deltaRx < 0) deltaRx = 0;
    if (deltaTx < 0) deltaTx = 0;

    if (deltaRx > 0 || deltaTx > 0) {
      buffer.push({
        client_id: clientId, ts: now, rx_delta: deltaRx, tx_delta: deltaTx, source: 'xray',
      });
    }
    xraySnapshotMap.set(clientId, { last_rx: transferRx, last_tx: transferTx });
  }
}

async function sample() {
  await sampleAwg();
  await sampleXray();
  if (buffer.length >= TRAFFIC_BUFFER_MAX) flush();
}

function flush() {
  if (buffer.length === 0) return;

  const toInsert = buffer.splice(0, buffer.length);
  const snapshotRows = snapshotMap === null ? [] : Array.from(snapshotMap.entries()).map(([client_id, v]) => ({
    client_id,
    last_rx: v.last_rx,
    last_tx: v.last_tx,
    sampled_at: Math.floor(Date.now() / 1000),
  }));
  const xrayRows = xraySnapshotMap === null ? [] : Array.from(xraySnapshotMap.entries()).map(([client_id, v]) => ({
    client_id,
    last_rx: v.last_rx,
    last_tx: v.last_tx,
    sampled_at: Math.floor(Date.now() / 1000),
  }));

  const database = db.getDb();
  try {
    database.transaction(() => {
      db.traffic.deltas.insertBatch(toInsert);
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
  if (xraySnapshotMap !== null) xraySnapshotMap.set(clientId, { last_rx: lastRx, last_tx: lastTx });
}

module.exports = {
  startTrafficRecorder,
  stopTrafficRecorder,
  updateSnapshotForClient,
  updateXraySnapshotForClient,
};
