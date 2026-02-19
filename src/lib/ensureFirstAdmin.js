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
  if (db.panelUsers.count() > 0) return;

  const now = Math.floor(Date.now() / 1000);
  const password_hash = await auth.hashPassword(ADMIN_PASSWORD);
  db.panelUsers.create({
    id: auth.generateUserId(),
    username: ADMIN_USERNAME || 'admin',
    password_hash,
    role: 'admin',
    is_active: 1,
    created_at: now,
    updated_at: now,
  });
}

module.exports = { ensureFirstAdmin };
