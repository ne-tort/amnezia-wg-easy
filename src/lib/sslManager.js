'use strict';

/**
 * SSL Certificate Manager — inventory of PEM certs (certbot volume) + Reality key sets.
 * Panel is a role (is_panel), not a certificate type.
 */

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');
const db = require('./db');
const tlsMaterial = require('./tlsMaterial');

const execFileAsync = promisify(execFile);

const TYPES = Object.freeze(['self_signed', 'lets_encrypt', 'reality', 'manual']);
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

function isPanelRow(row) {
  return !!(row && (row.is_panel || row.managed));
}

function guessPanelMaterialType() {
  const mode = String(process.env.SSL_MODE || '').toLowerCase();
  if (mode === 'certbot' || mode === 'acme') return 'lets_encrypt';
  if (mode === 'selfsigned') return 'self_signed';
  return 'self_signed';
}

function rowToPublic(row, { includeSecrets = false } = {}) {
  if (!row) return null;
  const isPanel = isPanelRow(row);
  const out = {
    id: row.id,
    type: row.type === 'panel' ? guessPanelMaterialType() : row.type,
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
    isPanel,
    managed: isPanel,
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

async function getById(id, { includeSecrets = false } = {}) {
  return getByIdSync(id, { includeSecrets });
}

function metaFromPem(certPem) {
  return tlsMaterial.parsePemMeta(certPem);
}

async function metaFromVolume(storageKey) {
  const pem = await tlsMaterial.readPemFromVolume(storageKey);
  return pem ? metaFromPem(pem) : { notAfter: null, issuer: '', fingerprintSha256: '' };
}

function installDir() {
  return process.env.AWG_INSTALL_DIR || '/opt/amnezia-wg-easy';
}

function confDir() {
  return process.env.AWG_CONF_DIR || '/etc/amnezia-wg-easy';
}

function upsertKeyValueFile(filePath, key, value) {
  const k = String(key || '').trim();
  const v = String(value == null ? '' : value).trim();
  if (!k || !filePath) return false;
  try {
    let text = '';
    if (fs.existsSync(filePath)) {
      text = fs.readFileSync(filePath, 'utf8');
    }
    const re = new RegExp(`^${k.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}=.*$`, 'm');
    if (re.test(text)) {
      text = text.replace(re, `${k}=${v}`);
    } else {
      text = `${text.replace(/\s*$/, '')}\n${k}=${v}\n`;
    }
    fs.writeFileSync(filePath, text, 'utf8');
    return true;
  } catch {
    return false;
  }
}

/**
 * Persist active panel TLS identity for install.sh redeploy reuse
 * (storage_key of is_panel cert — may differ from stale PANEL_DOMAIN/SSL_HOST).
 */
function persistPanelSslHost(host) {
  const h = tlsMaterial.normalizeHostname(host);
  if (!h || h === 'localhost') return;
  const config = require('../config');
  const paths = [
    path.join(config.WG_PATH, 'ssl-panel-host'),
    path.join(installDir(), '.ssl-panel-host'),
  ];
  for (const p of paths) {
    try {
      fs.mkdirSync(path.dirname(p), { recursive: true });
      fs.writeFileSync(p, `${h}\n`, 'utf8');
    } catch { /* optional paths */ }
  }
  upsertKeyValueFile(path.join(installDir(), '.env'), 'SSL_HOST', h);
  upsertKeyValueFile(path.join(confDir(), 'install.conf'), 'SSL_HOST', h);
}

function insertRow(fields) {
  const t = nowSec();
  const id = fields.id || newId();
  const isPanel = fields.is_panel ? 1 : 0;
  database().prepare(`
    INSERT INTO ssl_certificates (
      id, type, label, domain, sni, email, storage_key,
      not_after, issuer, fingerprint_sha256,
      reality_private_key, reality_public_key, reality_short_id, reality_dest,
      source, managed, is_panel, notes, created_at, updated_at
    ) VALUES (
      @id, @type, @label, @domain, @sni, @email, @storage_key,
      @not_after, @issuer, @fingerprint_sha256,
      @reality_private_key, @reality_public_key, @reality_short_id, @reality_dest,
      @source, @managed, @is_panel, @notes, @created_at, @updated_at
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
    managed: isPanel || fields.managed ? 1 : 0,
    is_panel: isPanel,
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
  if (patch.is_panel !== undefined) {
    next.is_panel = patch.is_panel ? 1 : 0;
    next.managed = next.is_panel ? 1 : (patch.managed !== undefined ? (patch.managed ? 1 : 0) : next.managed);
  }
  next.updated_at = nowSec();
  database().prepare(`
    UPDATE ssl_certificates SET
      type=@type, label=@label, domain=@domain, sni=@sni, email=@email, storage_key=@storage_key,
      not_after=@not_after, issuer=@issuer, fingerprint_sha256=@fingerprint_sha256,
      reality_private_key=@reality_private_key, reality_public_key=@reality_public_key,
      reality_short_id=@reality_short_id, reality_dest=@reality_dest,
      source=@source, managed=@managed, is_panel=@is_panel, notes=@notes, updated_at=@updated_at
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
    managed: next.is_panel ? 1 : (next.managed ? 1 : 0),
    is_panel: next.is_panel ? 1 : 0,
    notes: next.notes,
    updated_at: next.updated_at,
  });
  return getByIdSync(id, { includeSecrets: true });
}

function clearPanelFlags() {
  database().prepare('UPDATE ssl_certificates SET is_panel = 0, managed = 0 WHERE is_panel = 1 OR managed = 1').run();
}

/**
 * Ensure a panel-role inventory row exists (DB only, no volume inspect).
 */
async function refreshRowMetaFromVolume(rowOrId) {
  const raw = typeof rowOrId === 'string'
    ? getRaw(rowOrId)
    : (rowOrId && rowOrId.storage_key != null ? rowOrId : getRaw(rowOrId && rowOrId.id));
  if (!raw || raw.type === 'reality' || !raw.storage_key) {
    return raw ? getByIdSync(raw.id, { includeSecrets: true }) : null;
  }
  const meta = await metaFromVolume(raw.storage_key);
  if (meta.notAfter == null && !meta.fingerprintSha256) {
    return getByIdSync(raw.id, { includeSecrets: true });
  }
  const same = meta.notAfter === raw.not_after
    && (meta.issuer || '') === (raw.issuer || '')
    && (meta.fingerprintSha256 || '') === (raw.fingerprint_sha256 || '');
  if (same) {
    return getByIdSync(raw.id, { includeSecrets: true });
  }
  return updateRow(raw.id, {
    not_after: meta.notAfter != null ? meta.notAfter : raw.not_after,
    issuer: meta.issuer || raw.issuer,
    fingerprint_sha256: meta.fingerprintSha256 || raw.fingerprint_sha256,
  });
}

async function syncPanel() {
  const domain = tlsMaterial.panelLiveDomain();
  if (!domain) return null;

  const existingPanel = database().prepare(
    'SELECT * FROM ssl_certificates WHERE is_panel = 1 LIMIT 1',
  ).get();
  if (existingPanel) {
    const key = existingPanel.storage_key || existingPanel.domain || domain;
    persistPanelSslHost(key);
    updateRow(existingPanel.id, { is_panel: 1, managed: 1 });
    return refreshRowMetaFromVolume(existingPanel.id);
  }

  const byKey = database().prepare(
    'SELECT * FROM ssl_certificates WHERE storage_key = ? LIMIT 1',
  ).get(domain);
  if (byKey && byKey.type !== 'reality') {
    clearPanelFlags();
    persistPanelSslHost(byKey.storage_key || domain);
    updateRow(byKey.id, { is_panel: 1, managed: 1 });
    return refreshRowMetaFromVolume(byKey.id);
  }

  const meta = await metaFromVolume(domain);
  persistPanelSslHost(domain);
  return insertRow({
    type: guessPanelMaterialType(),
    label: 'Panel',
    domain,
    sni: domain,
    storage_key: domain,
    not_after: meta.notAfter,
    issuer: meta.issuer,
    fingerprint_sha256: meta.fingerprintSha256,
    source: 'synced_panel',
    managed: 1,
    is_panel: 1,
  });
}

async function list() {
  await syncPanel().catch(() => null);
  let rows = database().prepare(
    'SELECT * FROM ssl_certificates ORDER BY is_panel DESC, type ASC, domain ASC',
  ).all();
  // Refresh expiry/fingerprint from live PEM so UI matches volume after renew/assign.
  for (const row of rows) {
    if (row.type === 'reality' || !row.storage_key) continue;
    await refreshRowMetaFromVolume(row).catch(() => null);
  }
  rows = database().prepare(
    'SELECT * FROM ssl_certificates ORDER BY is_panel DESC, type ASC, domain ASC',
  ).all();
  let publicIp = '';
  try {
    const wgHost = String(require('../config').WG_HOST || '').trim();
    const portPlan = require('./portPlan');
    if (wgHost && portPlan.isIpLiteral(wgHost)) publicIp = wgHost;
    else {
      const preview = await require('./sniFinder').getPublicIpPreview();
      if (preview && preview.publicIp) publicIp = String(preview.publicIp).trim();
    }
  } catch { /* optional */ }
  return {
    certs: rows.map((row) => rowToPublic(row, { includeSecrets: false })),
    certbotEmail: tlsMaterial.getCertbotEmail() || '',
    panelDomain: tlsMaterial.panelLiveDomain() || '',
    publicIp,
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

function normalizeDomainInput(raw, { optional = false } = {}) {
  const d = tlsMaterial.normalizeHostname(raw);
  if (!d) {
    if (optional) return '';
    throw httpError(400, 'Domain is required', 'SSL_BAD_DOMAIN');
  }
  return d;
}

function defaultSelfSignedHost() {
  return tlsMaterial.panelLiveDomain()
    || tlsMaterial.normalizeHostname(require('../config').WG_HOST)
    || 'panel.local';
}

async function createSelfSigned(opts = {}) {
  let domain = normalizeDomainInput(opts.domain, { optional: true });
  if (!domain) domain = defaultSelfSignedHost();
  const issued = await tlsMaterial.ensureSelfSignedCert(domain);
  const meta = issued.certPem
    ? metaFromPem(issued.certPem)
    : await metaFromVolume(domain);
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
  if (existing) {
    return updateRow(existing.id, patch);
  }
  return insertRow({ type: 'self_signed', ...patch });
}

async function createLetsEncrypt(opts = {}) {
  const host = normalizeDomainInput(opts.domain || opts.ip);
  const email = String(opts.email || tlsMaterial.getCertbotEmail() || '').trim();
  const force = opts.force === true;
  const portPlan = require('./portPlan');
  if (portPlan.isIpLiteral(host)) {
    await tlsMaterial.issueLetsEncryptIp(host, email, { force });
  } else if (!tlsMaterial.isFqdn(host)) {
    throw httpError(400, 'Let\'s Encrypt requires a valid FQDN or IP', 'SSL_BAD_DOMAIN');
  } else {
    await tlsMaterial.issueLetsEncrypt(host, email, { force });
  }
  const meta = await metaFromVolume(host);
  const existing = database().prepare(
    'SELECT id FROM ssl_certificates WHERE storage_key = ?',
  ).get(host);
  const patch = {
    type: 'lets_encrypt',
    label: opts.label != null ? String(opts.label).trim() : host,
    domain: host,
    sni: host,
    email,
    storage_key: host,
    not_after: meta.notAfter,
    issuer: meta.issuer,
    fingerprint_sha256: meta.fingerprintSha256,
    source: 'issued',
  };
  if (existing) {
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
  const meta = metaFromPem(certPem);
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
    return updateRow(existing.id, { ...patch, type: 'manual' });
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

async function renew(id, opts = {}) {
  const row = getRaw(id);
  if (!row) throw httpError(404, 'Certificate not found', 'SSL_NOT_FOUND');
  if (row.type !== 'lets_encrypt') {
    throw httpError(400, 'Only Let\'s Encrypt certificates can be renewed', 'SSL_RENEW_TYPE');
  }
  const domain = row.storage_key || row.domain;
  const email = row.email || tlsMaterial.getCertbotEmail();
  const force = opts.force !== false;
  const beforeMeta = await metaFromVolume(domain);
  const portPlan = require('./portPlan');
  // Sync-only when live PEM is healthy and caller did not request force ACME.
  const liveHealthy = beforeMeta.notAfter != null
    && beforeMeta.notAfter * 1000 > Date.now() + 14 * 24 * 60 * 60 * 1000;
  const nearExpiry = !(beforeMeta.notAfter != null
    && beforeMeta.notAfter * 1000 > Date.now() + 30 * 24 * 60 * 60 * 1000);

  if (force || nearExpiry || !liveHealthy) {
    if (portPlan.isIpLiteral(domain)) {
      await tlsMaterial.issueLetsEncryptIp(domain, email, { force: force || nearExpiry });
    } else {
      await tlsMaterial.issueLetsEncrypt(domain, email, { force: force || nearExpiry });
    }
  }

  const meta = await metaFromVolume(domain);
  if (meta.notAfter == null) {
    throw httpError(500, 'Renew completed but could not read new certificate metadata', 'SSL_RENEW_META');
  }
  // LE often returns the same leaf on force renew (certificate reuse). Accept when still healthy.
  if (
    force
    && beforeMeta.notAfter != null
    && meta.notAfter <= beforeMeta.notAfter
  ) {
    const minMs = portPlan.isIpLiteral(domain)
      ? 1 * 24 * 60 * 60 * 1000
      : 14 * 24 * 60 * 60 * 1000;
    if (meta.notAfter * 1000 <= Date.now() + minMs) {
      throw httpError(
        400,
        'Renew did not extend certificate lifetime',
        'CERT_RENEW_NO_EXTEND',
      );
    }
  }
  const updated = updateRow(id, {
    not_after: meta.notAfter,
    issuer: meta.issuer,
    fingerprint_sha256: meta.fingerprintSha256,
    source: 'issued',
  });
  if (isPanelRow(row)) {
    persistPanelSslHost(domain);
  }
  return updated;
}

/**
 * Assign inventory cert as panel TLS: copy PEM into live/${PANEL_DOMAIN}/ and reload nginx.
 * Persists storage_key as the redeploy reuse default (even when PANEL_DOMAIN is still old).
 */
async function assignPanel(id) {
  const row = getRaw(id);
  if (!row) throw httpError(404, 'Certificate not found', 'SSL_NOT_FOUND');
  if (row.type === 'reality') {
    throw httpError(400, 'REALITY keys cannot be used as panel TLS', 'SSL_BAD_TYPE');
  }
  const storageKey = row.storage_key || row.domain;
  if (!storageKey) {
    throw httpError(400, 'Certificate has no storage key', 'SSL_NO_STORAGE');
  }
  const panelKey = tlsMaterial.panelLiveDomain();
  if (!panelKey) {
    throw httpError(400, 'PANEL_DOMAIN is not configured', 'SSL_NO_PANEL_DOMAIN');
  }
  if (!(await tlsMaterial.certExistsInVolume(storageKey))) {
    throw httpError(400, `Certificate files missing in volume for ${storageKey}`, 'SSL_MISSING');
  }
  if (storageKey !== panelKey) {
    await tlsMaterial.copyLiveCert(storageKey, panelKey);
  }
  clearPanelFlags();
  const meta = await metaFromVolume(storageKey);
  const updated = updateRow(id, {
    is_panel: 1,
    managed: 1,
    not_after: meta.notAfter != null ? meta.notAfter : row.not_after,
    issuer: meta.issuer || row.issuer,
    fingerprint_sha256: meta.fingerprintSha256 || row.fingerprint_sha256,
  });
  persistPanelSslHost(storageKey);
  const portPlan = require('./portPlan');
  await portPlan.reloadNginx();
  return updated;
}

async function remove(id) {
  const row = getRaw(id);
  if (!row) throw httpError(404, 'Certificate not found', 'SSL_NOT_FOUND');
  if (isPanelRow(row)) {
    throw httpError(400, 'Panel certificate cannot be deleted', 'SSL_MANAGED');
  }
  const panelKey = tlsMaterial.panelLiveDomain();
  if (row.storage_key && row.type !== 'reality') {
    if (!panelKey || row.storage_key !== panelKey) {
      await tlsMaterial.removeLiveCert(row.storage_key).catch(() => false);
    }
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
  assignPanel,
  parsePemMeta: tlsMaterial.parsePemMeta,
};
