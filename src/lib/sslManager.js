'use strict';

/**
 * SSL Certificate Manager — inventory of PEM certs (certbot volume) + Reality key sets.
 * Isolated from sidecar enable paths; wraps tlsMaterial for issue/import.
 */

const crypto = require('node:crypto');
const fs = require('node:fs');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');
const db = require('./db');
const tlsMaterial = require('./tlsMaterial');

const execFileAsync = promisify(execFile);

const TYPES = Object.freeze(['self_signed', 'lets_encrypt', 'panel', 'reality', 'manual']);
const XRAY_IMAGE = 'amnezia-xray';

function nowSec() {
  return Math.floor(Date.now() / 1000);
}

function newId() {
  return crypto.randomUUID();
}

function database() {
  return db.getDb();
}

function runCmd(bin, args, { timeout = 60_000 } = {}) {
  return execFileAsync(bin, args, { timeout, maxBuffer: 4 * 1024 * 1024 })
    .then(({ stdout, stderr }) => ({
      ok: true,
      stdout: String(stdout || ''),
      stderr: String(stderr || ''),
    }))
    .catch((err) => ({
      ok: false,
      stdout: String((err && err.stdout) || ''),
      stderr: String((err && err.stderr) || err.message || ''),
      error: err,
    }));
}

function httpError(status, message, code) {
  const err = new Error(message);
  err.status = status;
  if (code) err.code = code;
  return err;
}

function rowToPublic(row, { includeSecrets = false } = {}) {
  if (!row) return null;
  const out = {
    id: row.id,
    type: row.type,
    label: row.label || '',
    domain: row.domain || '',
    sni: row.sni || row.domain || '',
    email: row.email || '',
    storageKey: row.storage_key || '',
    notAfter: row.not_after || null,
    issuer: row.issuer || '',
    fingerprintSha256: row.fingerprint_sha256 || '',
    realityDest: row.reality_dest || '',
    realityPublicKey: row.reality_public_key || '',
    realityShortId: row.reality_short_id || '',
    source: row.source || '',
    managed: !!row.managed,
    notes: row.notes || '',
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
  if (includeSecrets && row.type === 'reality') {
    out.realityPrivateKey = row.reality_private_key || '';
  }
  if (includeSecrets && row.storage_key && row.type !== 'reality') {
    const paths = tlsMaterial.certPathsForDomain(row.storage_key);
    out.certPath = paths.cert;
    out.keyPath = paths.key;
  }
  return out;
}

function getRaw(id) {
  return database().prepare('SELECT * FROM ssl_certificates WHERE id = ?').get(id);
}

function getByIdSync(id, { includeSecrets = false } = {}) {
  const row = getRaw(id);
  if (!row) throw httpError(404, 'Certificate not found', 'SSL_NOT_FOUND');
  return rowToPublic(row, { includeSecrets });
}

async function getById(id, { includeSecrets = false, refreshMeta = true } = {}) {
  let row = getRaw(id);
  if (!row) throw httpError(404, 'Certificate not found', 'SSL_NOT_FOUND');
  if (refreshMeta && row.type !== 'reality' && row.storage_key) {
    try {
      await applyPemMeta(row.id, row.storage_key);
      row = getRaw(id) || row;
    } catch { /* keep stale meta */ }
  }
  return rowToPublic(row, { includeSecrets });
}

function insertRow(fields) {
  const t = nowSec();
  const id = fields.id || newId();
  database().prepare(`
    INSERT INTO ssl_certificates (
      id, type, label, domain, sni, email, storage_key,
      not_after, issuer, fingerprint_sha256,
      reality_private_key, reality_public_key, reality_short_id, reality_dest,
      source, managed, notes, created_at, updated_at
    ) VALUES (
      @id, @type, @label, @domain, @sni, @email, @storage_key,
      @not_after, @issuer, @fingerprint_sha256,
      @reality_private_key, @reality_public_key, @reality_short_id, @reality_dest,
      @source, @managed, @notes, @created_at, @updated_at
    )
  `).run({
    id,
    type: fields.type,
    label: fields.label || null,
    domain: fields.domain || null,
    sni: fields.sni || fields.domain || null,
    email: fields.email || null,
    storage_key: fields.storage_key || null,
    not_after: fields.not_after != null ? fields.not_after : null,
    issuer: fields.issuer || null,
    fingerprint_sha256: fields.fingerprint_sha256 || null,
    reality_private_key: fields.reality_private_key || null,
    reality_public_key: fields.reality_public_key || null,
    reality_short_id: fields.reality_short_id || null,
    reality_dest: fields.reality_dest || null,
    source: fields.source || null,
    managed: fields.managed ? 1 : 0,
    notes: fields.notes || null,
    created_at: t,
    updated_at: t,
  });
  return getByIdSync(id, { includeSecrets: true });
}

function updateRow(id, patch) {
  const cur = getRaw(id);
  if (!cur) throw httpError(404, 'Certificate not found', 'SSL_NOT_FOUND');
  const next = { ...cur };
  for (const [k, v] of Object.entries(patch)) {
    if (v !== undefined) next[k] = v;
  }
  next.updated_at = nowSec();
  database().prepare(`
    UPDATE ssl_certificates SET
      type=@type, label=@label, domain=@domain, sni=@sni, email=@email, storage_key=@storage_key,
      not_after=@not_after, issuer=@issuer, fingerprint_sha256=@fingerprint_sha256,
      reality_private_key=@reality_private_key, reality_public_key=@reality_public_key,
      reality_short_id=@reality_short_id, reality_dest=@reality_dest,
      source=@source, managed=@managed, notes=@notes, updated_at=@updated_at
    WHERE id=@id
  `).run({
    id,
    type: next.type,
    label: next.label,
    domain: next.domain,
    sni: next.sni,
    email: next.email,
    storage_key: next.storage_key,
    not_after: next.not_after,
    issuer: next.issuer,
    fingerprint_sha256: next.fingerprint_sha256,
    reality_private_key: next.reality_private_key,
    reality_public_key: next.reality_public_key,
    reality_short_id: next.reality_short_id,
    reality_dest: next.reality_dest,
    source: next.source,
    managed: next.managed ? 1 : 0,
    notes: next.notes,
    updated_at: next.updated_at,
  });
  return getByIdSync(id, { includeSecrets: true });
}

async function inspectVolumeCert(storageKey) {
  const key = String(storageKey || '').trim().toLowerCase();
  if (!key || !(await tlsMaterial.certExistsInVolume(key))) {
    return { notAfter: null, issuer: '', fingerprintSha256: '' };
  }
  const vol = await tlsMaterial.resolveCertbotVolumeName();
  const paths = tlsMaterial.certPathsForDomain(key);
  const r = await runCmd('docker', [
    'run', '--rm',
    '-v', `${vol}:/etc/letsencrypt:ro`,
    'alpine:3.20',
    'sh', '-c',
    `apk add --no-cache openssl >/dev/null 2>&1
     openssl x509 -in '${paths.cert}' -noout -enddate -issuer -fingerprint -sha256 2>/dev/null`,
  ], { timeout: 60_000 });
  if (!r.ok) return { notAfter: null, issuer: '', fingerprintSha256: '' };
  const lines = r.stdout.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
  let notAfter = null;
  let issuer = '';
  let fingerprintSha256 = '';
  for (const line of lines) {
    if (/^notAfter=/i.test(line)) {
      const ms = tlsMaterial.parseOpensslEnddate(line);
      if (ms != null) notAfter = Math.floor(ms / 1000);
    } else if (/^issuer=/i.test(line)) {
      issuer = line.replace(/^issuer=/i, '').trim();
    } else if (/fingerprint=/i.test(line)) {
      fingerprintSha256 = line.split('=')[1].trim().replace(/:/g, '').toLowerCase();
    }
  }
  return { notAfter, issuer, fingerprintSha256 };
}

async function applyPemMeta(id, storageKey) {
  const meta = await inspectVolumeCert(storageKey);
  return updateRow(id, {
    not_after: meta.notAfter,
    issuer: meta.issuer || null,
    fingerprint_sha256: meta.fingerprintSha256 || null,
  });
}

async function syncPanel({ inspect = false } = {}) {
  const domain = tlsMaterial.panelCertDomain();
  if (!domain) return null;
  let meta = { notAfter: null, issuer: '', fingerprintSha256: '' };
  if (inspect) {
    try {
      const exists = await tlsMaterial.certExistsInVolume(domain);
      if (exists) meta = await inspectVolumeCert(domain);
    } catch {
      /* keep empty / stale */
    }
  }
  const row = database().prepare(
    "SELECT * FROM ssl_certificates WHERE type = 'panel' LIMIT 1",
  ).get();
  if (!row) {
    return insertRow({
      type: 'panel',
      label: 'Panel',
      domain,
      sni: domain,
      storage_key: domain,
      not_after: meta.notAfter,
      issuer: meta.issuer,
      fingerprint_sha256: meta.fingerprintSha256,
      source: 'synced_panel',
      managed: 1,
    });
  }
  const patch = {
    domain,
    sni: domain,
    storage_key: domain,
    source: 'synced_panel',
    managed: 1,
  };
  if (inspect) {
    patch.not_after = meta.notAfter;
    patch.issuer = meta.issuer;
    patch.fingerprint_sha256 = meta.fingerprintSha256;
  }
  return updateRow(row.id, patch);
}

/**
 * Fast inventory list: DB rows only (no docker openssl per cert — that blocked the UI).
 * Meta refresh happens on get()/renew/create.
 */
async function list() {
  await syncPanel({ inspect: false }).catch(() => null);
  const rows = database().prepare(
    'SELECT * FROM ssl_certificates ORDER BY managed DESC, type ASC, domain ASC',
  ).all();
  return {
    certs: rows.map((row) => rowToPublic(row, { includeSecrets: false })),
    certbotEmail: tlsMaterial.getCertbotEmail() || '',
  };
}

async function generateRealityKeypair() {
  const r = await runCmd('docker', ['run', '--rm', '--entrypoint', 'xray', XRAY_IMAGE, 'x25519'], {
    timeout: 60_000,
  });
  if (!r.ok) {
    throw httpError(500, (r.stderr || 'xray x25519 failed').trim().slice(0, 300), 'SSL_REALITY_KEYS');
  }
  const amneziaXray = require('./amneziaXray');
  return amneziaXray.parseX25519Output(`${r.stdout}\n${r.stderr}`);
}

function normalizeDomainInput(raw) {
  const d = tlsMaterial.normalizeHostname(raw);
  if (!d) throw httpError(400, 'Domain is required', 'SSL_BAD_DOMAIN');
  return d;
}

async function createSelfSigned(opts = {}) {
  const domain = normalizeDomainInput(opts.domain);
  await tlsMaterial.ensureSelfSignedCert(domain);
  const meta = await inspectVolumeCert(domain);
  const existing = database().prepare(
    "SELECT id FROM ssl_certificates WHERE storage_key = ? AND type = 'self_signed'",
  ).get(domain);
  const patch = {
    label: opts.label != null ? String(opts.label).trim() : domain,
    domain,
    sni: domain,
    storage_key: domain,
    not_after: meta.notAfter,
    issuer: meta.issuer,
    fingerprint_sha256: meta.fingerprintSha256,
    source: 'generated',
  };
  if (existing) return updateRow(existing.id, patch);
  return insertRow({ type: 'self_signed', ...patch });
}

async function createLetsEncrypt(opts = {}) {
  const domain = normalizeDomainInput(opts.domain);
  if (!tlsMaterial.isFqdn(domain)) {
    throw httpError(400, 'Let\'s Encrypt requires a valid FQDN', 'SSL_BAD_DOMAIN');
  }
  const email = String(opts.email || tlsMaterial.getCertbotEmail() || '').trim();
  await tlsMaterial.issueLetsEncrypt(domain, email);
  const meta = await inspectVolumeCert(domain);
  const existing = database().prepare(
    "SELECT id FROM ssl_certificates WHERE storage_key = ?",
  ).get(domain);
  const patch = {
    type: 'lets_encrypt',
    label: opts.label != null ? String(opts.label).trim() : domain,
    domain,
    sni: domain,
    email,
    storage_key: domain,
    not_after: meta.notAfter,
    issuer: meta.issuer,
    fingerprint_sha256: meta.fingerprintSha256,
    source: 'issued',
  };
  if (existing) {
    const cur = getRaw(existing.id);
    if (cur && cur.managed) throw httpError(400, 'Cannot overwrite panel certificate entry', 'SSL_MANAGED');
    return updateRow(existing.id, patch);
  }
  return insertRow(patch);
}

async function createReality(opts = {}) {
  const sni = normalizeDomainInput(opts.sni || opts.domain);
  let dest = String(opts.dest || opts.realityDest || '').trim();
  if (!dest) dest = `${sni}:443`;
  const keys = await generateRealityKeypair();
  const shortId = crypto.randomBytes(8).toString('hex');
  return insertRow({
    type: 'reality',
    label: opts.label != null ? String(opts.label).trim() : sni,
    domain: sni,
    sni,
    reality_private_key: keys.privateKey,
    reality_public_key: keys.publicKey,
    reality_short_id: shortId,
    reality_dest: dest,
    source: 'generated',
  });
}

async function importPem(opts = {}) {
  const domain = normalizeDomainInput(opts.domain);
  const certPem = String(opts.certPem || opts.cert_pem || '').trim();
  const keyPem = String(opts.keyPem || opts.key_pem || '').trim();
  if (!certPem || !keyPem) {
    throw httpError(400, 'Certificate and private key PEM are required', 'SSL_PEM_MISSING');
  }
  await tlsMaterial.injectManualPem(domain, certPem, keyPem);
  const meta = await inspectVolumeCert(domain);
  const existing = database().prepare(
    'SELECT id FROM ssl_certificates WHERE storage_key = ?',
  ).get(domain);
  const patch = {
    type: 'manual',
    label: opts.label != null ? String(opts.label).trim() : domain,
    domain,
    sni: domain,
    storage_key: domain,
    not_after: meta.notAfter,
    issuer: meta.issuer,
    fingerprint_sha256: meta.fingerprintSha256,
    source: opts.source || 'imported_pem',
  };
  if (existing) {
    const cur = getRaw(existing.id);
    if (cur && cur.managed) throw httpError(400, 'Cannot overwrite panel certificate', 'SSL_MANAGED');
    return updateRow(existing.id, patch);
  }
  return insertRow(patch);
}

async function importPath(opts = {}) {
  const domain = normalizeDomainInput(opts.domain);
  const certPath = String(opts.certPath || opts.cert_path || '').trim();
  const keyPath = String(opts.keyPath || opts.key_path || '').trim();
  if (!certPath || !keyPath) {
    throw httpError(400, 'Certificate and key file paths are required', 'SSL_PATH_MISSING');
  }
  if (!fs.existsSync(certPath) || !fs.existsSync(keyPath)) {
    throw httpError(400, 'Certificate or key file not found on panel filesystem', 'SSL_PATH_MISSING');
  }
  return importPem({
    domain,
    label: opts.label,
    certPem: fs.readFileSync(certPath, 'utf8'),
    keyPem: fs.readFileSync(keyPath, 'utf8'),
    source: 'imported_path',
  });
}

async function renew(id) {
  const row = getRaw(id);
  if (!row) throw httpError(404, 'Certificate not found', 'SSL_NOT_FOUND');
  if (row.type !== 'lets_encrypt') {
    throw httpError(400, 'Only Let\'s Encrypt certificates can be renewed', 'SSL_RENEW_TYPE');
  }
  const domain = row.storage_key || row.domain;
  const email = row.email || tlsMaterial.getCertbotEmail();
  await tlsMaterial.issueLetsEncrypt(domain, email);
  const meta = await inspectVolumeCert(domain);
  return updateRow(id, {
    not_after: meta.notAfter,
    issuer: meta.issuer,
    fingerprint_sha256: meta.fingerprintSha256,
    source: 'issued',
  });
}

async function remove(id) {
  const row = getRaw(id);
  if (!row) throw httpError(404, 'Certificate not found', 'SSL_NOT_FOUND');
  if (row.managed || row.type === 'panel') {
    throw httpError(400, 'Panel certificate cannot be deleted', 'SSL_MANAGED');
  }
  const panelDomain = tlsMaterial.panelCertDomain();
  if (row.storage_key && row.type !== 'reality' && panelDomain && row.storage_key === panelDomain) {
    throw httpError(400, 'Refusing to delete panel domain inventory entry', 'SSL_MANAGED');
  }
  database().prepare('DELETE FROM ssl_certificates WHERE id = ?').run(id);
  return { success: true, id };
}

module.exports = {
  TYPES,
  list,
  get: getById,
  syncPanel,
  createSelfSigned,
  createLetsEncrypt,
  createReality,
  importPem,
  importPath,
  renew,
  remove,
};
