'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const { computeClientPresence, DEFAULT_ONLINE_WINDOW_MS } = require(
  path.resolve(__dirname, '../../src/lib/clientPresence.js')
);

test('computeClientPresence: offline when no activity', () => {
  const p = computeClientPresence({}, { now: 1_000_000 });
  assert.equal(p.isOnline, false);
  assert.deepEqual(p.onlineSources, []);
  assert.equal(p.latestActivityAt, null);
});

test('computeClientPresence: AWG handshake within window', () => {
  const now = 1_000_000_000;
  const hs = new Date(now - 60_000);
  const p = computeClientPresence({ latestHandshakeAt: hs }, { now, windowMs: DEFAULT_ONLINE_WINDOW_MS });
  assert.equal(p.isOnline, true);
  assert.deepEqual(p.onlineSources, ['awg']);
  assert.equal(p.latestActivityAt.getTime(), hs.getTime());
});

test('computeClientPresence: Xray activity within window', () => {
  const now = 1_000_000_000;
  const xa = new Date(now - 120_000);
  const p = computeClientPresence({ latestXrayActivityAt: xa }, { now });
  assert.equal(p.isOnline, true);
  assert.deepEqual(p.onlineSources, ['xray']);
  assert.equal(p.latestActivityAt.getTime(), xa.getTime());
});

test('computeClientPresence: both sources; latestActivityAt is max', () => {
  const now = 1_000_000_000;
  const hs = new Date(now - 300_000);
  const xa = new Date(now - 30_000);
  const p = computeClientPresence({
    latestHandshakeAt: hs,
    latestXrayActivityAt: xa,
  }, { now });
  assert.equal(p.isOnline, true);
  assert.deepEqual(p.onlineSources, ['awg', 'xray']);
  assert.equal(p.latestActivityAt.getTime(), xa.getTime());
});

test('computeClientPresence: stale activity is offline', () => {
  const now = 1_000_000_000;
  const hs = new Date(now - DEFAULT_ONLINE_WINDOW_MS - 1);
  const xa = new Date(now - DEFAULT_ONLINE_WINDOW_MS - 5_000);
  const p = computeClientPresence({
    latestHandshakeAt: hs,
    latestXrayActivityAt: xa,
  }, { now });
  assert.equal(p.isOnline, false);
  assert.deepEqual(p.onlineSources, []);
  assert.equal(p.latestActivityAt.getTime(), hs.getTime());
});
