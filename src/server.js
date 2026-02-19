'use strict';

// * Single startup sequence: DB (migrations) → first admin → WG sync → firewall → HTTP.
const Server = require('./lib/Server');
const server = new Server();
const db = require('./lib/db');
const { ensureFirstAdmin } = require('./lib/ensureFirstAdmin');
const WireGuard = require('./lib/WireGuard');
const { applyFirewall } = require('./lib/firewall');

async function main() {
  db.getDb();

  await ensureFirstAdmin();
  if (db.panelUsers.count() === 0) {
    // eslint-disable-next-line no-console
    console.error('No panel users. Set ADMIN_USERNAME and ADMIN_PASSWORD and restart.');
    process.exit(1);
  }

  await WireGuard.getConfig();

  const firewallApplied = applyFirewall();
  if (!firewallApplied && process.env.FIREWALL_FAIL_FAST === '1') {
    // eslint-disable-next-line no-console
    console.error('Firewall apply failed and FIREWALL_FAIL_FAST=1. Exiting.');
    process.exit(1);
  }

  await server.start();
}

main().catch((err) => {
  // eslint-disable-next-line no-console
  console.error(err);
  process.exit(1);
});

process.on('SIGTERM', async () => {
  // eslint-disable-next-line no-console
  console.log('SIGTERM signal received.');
  await WireGuard.Shutdown();
  process.exit(0);
});

process.on('SIGINT', () => {
  // eslint-disable-next-line no-console
  console.log('SIGINT signal received.');
});
