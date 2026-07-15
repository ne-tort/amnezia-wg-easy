'use strict';

const db = require('./db');
const auth = require('./auth');
const { ADMIN_USERNAME, ADMIN_PASSWORD } = require('../config');

/**
 * If no panel users exist and ADMIN_PASSWORD is set, create one admin user.
 * Call once at startup (fire-and-forget or await).
 */
async function ensureFirstAdmin() {
  if (!ADMIN_PASSWORD || typeof ADMIN_PASSWORD !== 'string') return;
  if (db.panelUsers.count() > 0) {
    // Existing install: ensure seeded Default pool is assigned to admins with empty list.
    db.vpnPools.assignPrimaryToEmptyAdmins();
    return;
  }

  const now = Math.floor(Date.now() / 1000);
  const password_hash = await auth.hashPassword(ADMIN_PASSWORD);
  const id = auth.generateUserId();
  db.panelUsers.create({
    id,
    username: ADMIN_USERNAME || 'admin',
    password_hash,
    role: 'admin',
    is_active: 1,
    created_at: now,
    updated_at: now,
  });
  // Same Default pool as for everyone else — no special privileges, just assign on first boot.
  db.vpnPools.assignPrimaryToEmptyAdmins();
}

module.exports = { ensureFirstAdmin };
