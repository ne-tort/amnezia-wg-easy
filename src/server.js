'use strict';

// * Single startup sequence: DB (migrations) → first admin → WG sync → firewall → HTTP.
const Server = require('./lib/Server');
const server = new Server();
const db = require('./lib/db');
const { ensureFirstAdmin } = require('./lib/ensureFirstAdmin');
const WireGuard = require('./lib/WireGuard');
const { applyFirewall } = require('./lib/firewall');
const { bootAmneziaDns, stopAmneziaDns, startDnsProfileProbes } = require('./lib/amneziaDns');
const { bootAmneziaXray, stopAmneziaXray } = require('./lib/amneziaXray');
const { startTrafficRecorder, stopTrafficRecorder } = require('./lib/trafficRecorder');
const { stopProbeScheduler } = require('./lib/dnsProfileProbe');

async function main() {
  // * Ensure static signature bank exists before any client/API code touches it.
  const { ensureSeedBank } = require('./lib/signaturesBank');
  ensureSeedBank();
  try {
    require('./lib/dnsProfilesBank').ensureSeedBank();
  } catch (err) {
    // eslint-disable-next-line no-console
    console.warn('Amnezia DNS profiles seed:', err && err.message ? err.message : err);
  }

  db.getDb();

  // * Sync endpoint from env to app_settings so client configs use current WG_HOST:WG_PORT after restart.
  const { WG_HOST, WG_PORT } = require('./config');
  if (WG_HOST) {
    db.appSettings.set('endpoint', `${WG_HOST}:${WG_PORT || '51820'}`);
  }

  // * When LANGUAGE is set in .env (e.g. remote-deploy YAML), sync to app_settings for GET /api/lang.
  if (process.env.LANGUAGE && String(process.env.LANGUAGE).trim()) {
    const raw = String(process.env.LANGUAGE).trim().toLowerCase();
    const code = raw === 'en' || raw === 'english' ? 'en' : (raw === 'ru' || raw === 'russian' ? 'ru' : null);
    if (code) db.appSettings.set('language', code);
  }

  await ensureFirstAdmin();
  if (db.panelUsers.count() === 0) {
    // eslint-disable-next-line no-console
    console.error('No panel users. Set ADMIN_USERNAME and ADMIN_PASSWORD and restart.');
    process.exit(1);
  }

  // * getConfig() persists awg0.conf with ListenPort from WG_PORT and brings awg0 up; restart container after changing WG_PORT.
  await WireGuard.getConfig();

  const firewallApplied = applyFirewall();
  if (!firewallApplied && process.env.FIREWALL_FAIL_FAST === '1') {
    // eslint-disable-next-line no-console
    console.error('Firewall apply failed and FIREWALL_FAIL_FAST=1. Exiting.');
    process.exit(1);
  }

  // Start HTTP before DNS reconcile — enable/reinstall can take up to ~90s and must not block the panel.
  await server.start();
  startTrafficRecorder();
  // Background DNS-profile latency cache (5 min TTL) — UI must not wait on open.
  startDnsProfileProbes();
  bootAmneziaDns().catch((err) => {
    // eslint-disable-next-line no-console
    console.error('Amnezia DNS boot:', err && err.message ? err.message : err);
  });
  bootAmneziaXray().catch((err) => {
    // eslint-disable-next-line no-console
    console.error('Amnezia Xray boot:', err && err.message ? err.message : err);
  });
}

main().catch((err) => {
  // eslint-disable-next-line no-console
  console.error(err);
  process.exit(1);
});

process.on('SIGTERM', async () => {
  // eslint-disable-next-line no-console
  console.log('SIGTERM signal received.');
  stopTrafficRecorder();
  stopProbeScheduler();
  stopAmneziaDns();
  stopAmneziaXray();
  await WireGuard.Shutdown();
  process.exit(0);
});

process.on('SIGINT', () => {
  // eslint-disable-next-line no-console
  console.log('SIGINT signal received.');
});
