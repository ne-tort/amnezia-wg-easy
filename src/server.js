'use strict';

// * Single startup sequence: DB (migrations) → first admin → WG sync → firewall → HTTP.
const Server = require('./lib/Server');
const server = new Server();
const db = require('./lib/db');
const { ensureFirstAdmin } = require('./lib/ensureFirstAdmin');
const WireGuard = require('./lib/WireGuard');
const { applyFirewall } = require('./lib/firewall');
const { startAmneziaDns, stopAmneziaDns } = require('./lib/amneziaDns');
const { startTrafficRecorder, stopTrafficRecorder } = require('./lib/trafficRecorder');

async function main() {
  // * Ensure static signature bank exists before any client/API code touches it.
  const { ensureSeedBank } = require('./lib/signaturesBank');
  ensureSeedBank();

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
  // * Start Amnezia DNS (dnsmasq) after WG interface is up so it can bind to 0.0.0.0 including awg0.
  startAmneziaDns();

  const firewallApplied = applyFirewall();
  if (!firewallApplied && process.env.FIREWALL_FAIL_FAST === '1') {
    // eslint-disable-next-line no-console
    console.error('Firewall apply failed and FIREWALL_FAIL_FAST=1. Exiting.');
    process.exit(1);
  }

  await server.start();
  startTrafficRecorder();
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
  stopAmneziaDns();
  await WireGuard.Shutdown();
  process.exit(0);
});

process.on('SIGINT', () => {
  // eslint-disable-next-line no-console
  console.log('SIGINT signal received.');
});
