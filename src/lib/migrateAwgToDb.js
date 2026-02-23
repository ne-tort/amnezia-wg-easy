'use strict';

const path = require('node:path');
const fs = require('node:fs').promises;
const db = require('./db');
const { WG_PATH } = require('../config');

const AWG_JSON = 'awg0.json';

/**
 * If server_config is empty and awg0.json exists, copy server and clients into DB.
 * Returns true if migration was performed, false otherwise.
 */
async function migrateAwgToDb() {
  if (db.serverConfig.get()) return false;
  const awgPath = path.join(WG_PATH, AWG_JSON);
  let raw;
  try {
    raw = await fs.readFile(awgPath, 'utf8');
  } catch (err) {
    if (err.code === 'ENOENT') return false;
    throw err;
  }
  const config = JSON.parse(raw);
  const server = config.server;
  if (!server || !config.clients) return false;

  const now = Math.floor(Date.now() / 1000);
  const h1 = typeof server.h1 === 'string' && server.h1.includes('-') ? server.h1.split('-').map((x) => parseInt(x.trim(), 10))[0] : server.h1;
  const h2 = typeof server.h2 === 'string' && server.h2.includes('-') ? server.h2.split('-').map((x) => parseInt(x.trim(), 10))[0] : server.h2;
  const h3 = typeof server.h3 === 'string' && server.h3.includes('-') ? server.h3.split('-').map((x) => parseInt(x.trim(), 10))[0] : server.h3;
  const h4 = typeof server.h4 === 'string' && server.h4.includes('-') ? server.h4.split('-').map((x) => parseInt(x.trim(), 10))[0] : server.h4;

  db.serverConfig.upsert({
    private_key: server.privateKey,
    public_key: server.publicKey,
    address: server.address,
    jc: Number(server.jc) || 8,
    jmin: Number(server.jmin) || 64,
    jmax: Number(server.jmax) || 1000,
    s1: String(server.s1),
    s2: String(server.s2),
    s3: String(server.s3),
    s4: String(server.s4),
    h1: String(h1 ?? server.h1),
    h2: String(h2 ?? server.h2),
    h3: String(h3 ?? server.h3),
    h4: String(h4 ?? server.h4),
    i2: server.i2 ?? null,
    i3: server.i3 ?? null,
    i4: server.i4 ?? null,
    i5: server.i5 ?? null,
    updated_at: now,
  });

  for (const [clientId, c] of Object.entries(config.clients)) {
    const created = c.createdAt ? new Date(c.createdAt).getTime() / 1000 : now;
    const updated = c.updatedAt ? new Date(c.updatedAt).getTime() / 1000 : now;
    db.clients.create({
      id: clientId,
      name: c.name || clientId,
      address: c.address,
      public_key: c.publicKey,
      private_key: c.privateKey,
      pre_shared_key: c.preSharedKey ?? null,
      enabled: c.enabled !== false ? 1 : 0,
      note: null,
      created_at: Math.floor(created),
      updated_at: Math.floor(updated),
      expires_at: null,
      rule_profile_id: null,
      default_profile: null,
      default_level: null,
      use_server_dns: 1,
    });
  }
  return true;
}

module.exports = { migrateAwgToDb };
