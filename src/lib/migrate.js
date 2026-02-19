'use strict';

/**
 * Runs pending .sql migrations from migrations/ directory.
 * Creates schema_migrations table if missing; runs each file not yet applied in name order.
 * Call with runMigrations(db) where db is a better-sqlite3 Database instance.
 */

const fs = require('node:fs');
const path = require('node:path');

const migrationsDir = path.join(__dirname, '..', '..', 'migrations');

function runMigrations(db) {
  db.exec(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      version TEXT PRIMARY KEY,
      applied_at INTEGER NOT NULL
    );
  `);

  const applied = new Set(
    db.prepare('SELECT version FROM schema_migrations').all().map((r) => r.version)
  );

  let files = [];
  try {
    files = fs.readdirSync(migrationsDir)
      .filter((f) => f.endsWith('.sql'))
      .sort();
  } catch (err) {
    if (err.code !== 'ENOENT') throw err;
    return;
  }

  const now = Math.floor(Date.now() / 1000);
  for (const file of files) {
    const version = file;
    if (applied.has(version)) continue;

    const filePath = path.join(migrationsDir, file);
    const sql = fs.readFileSync(filePath, 'utf8');

    const run = db.transaction(() => {
      db.exec(sql);
      db.prepare('INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)').run(version, now);
    });
    run();
  }
}

module.exports = { runMigrations, migrationsDir };
