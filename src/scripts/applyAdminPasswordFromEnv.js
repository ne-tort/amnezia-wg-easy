'use strict';

const db = require('../lib/db');
const auth = require('../lib/auth');

const adminUser = (process.env.ADMIN_USERNAME || '').trim();
const adminPass = typeof process.env.ADMIN_PASSWORD === 'string' ? process.env.ADMIN_PASSWORD : '';
const minLen = 5;

async function main() {
  if (!adminUser) {
    console.error('applyAdminPasswordFromEnv: ADMIN_USERNAME empty, skip');
    process.exit(0);
  }
  if (!adminPass || adminPass.length < minLen) {
    console.error('applyAdminPasswordFromEnv: ADMIN_PASSWORD missing or shorter than 5 chars, skip');
    process.exit(0);
  }
  if (adminPass.length > 256) {
    console.error('applyAdminPasswordFromEnv: ADMIN_PASSWORD longer than 256 chars, skip');
    process.exit(0);
  }

  db.getDb();
  const row = db.panelUsers.findByUsername(adminUser);
  if (!row) {
    console.error(`applyAdminPasswordFromEnv: panel user ${JSON.stringify(adminUser)} not found or inactive`);
    process.exit(1);
  }

  const password_hash = await auth.hashPassword(adminPass);
  db.panelUsers.updatePasswordHash(row.id, password_hash);
  console.error('applyAdminPasswordFromEnv: password hash updated for admin user');
  process.exit(0);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
