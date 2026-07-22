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

const TYPES = Object.freeze(['self_signed', 'lets_encrypt', 'lets_encrypt_ip', 'reality', 'manual', 'masquerade']);
const LE_TYPES = Object.freeze(['lets_encrypt', 'lets_encrypt_ip']);
const XRAY_IMAGE = 'amnezia-xray';
const REALITY_CHECK_TTL_SEC = 24 * 60 * 60;
const LIST_CACHE_MS = 30_000;

/** @type {{ at: number, data: any } | null} */
let listCache = null;

function invalidateListCache() {
  listCache = null;
}

const SIDECAR_CERT_FILTERS = Object.freeze({
  // Publicly-trusted only (Chromium/Naive rejects self-signed by default).
  // LE domain + LE bare-IP (shortlived iPAddress SAN) + imported CA PEMs.
  naive: ['lets_encrypt', 'lets_encrypt_ip', 'manual'],
  hysteria: ['self_signed', 'lets_encrypt', 'lets_encrypt_ip', 'manual'],
  xray_reality: ['reality'],
  xray_tls: ['self_signed', 'lets_encrypt', 'lets_encrypt_ip', 'manual'],
  masquerade: ['masquerade'],
});

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
    realityStatus: row.reality_status || null,
    realityCheckedAt: row.reality_checked_at || null,
    realityCheckDetail: row.reality_check_detail || null,
    masqueradeUrl: row.masquerade_url || '',
    autoRenew: !!(row.auto_renew),
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
  const autoRenew = fields.auto_renew != null
    ? (fields.auto_renew ? 1 : 0)
    : (LE_TYPES.includes(fields.type) ? 1 : 0);
  database().prepare(`
    INSERT INTO ssl_certificates (
      id, type, label, domain, sni, email, storage_key,
      not_after, issuer, fingerprint_sha256,
      reality_private_key, reality_public_key, reality_short_id, reality_dest,
      reality_status, reality_checked_at, reality_check_detail, masquerade_url,
      source, managed, is_panel, auto_renew, notes, created_at, updated_at
    ) VALUES (
      @id, @type, @label, @domain, @sni, @email, @storage_key,
      @not_after, @issuer, @fingerprint_sha256,
      @reality_private_key, @reality_public_key, @reality_short_id, @reality_dest,
      @reality_status, @reality_checked_at, @reality_check_detail, @masquerade_url,
      @source, @managed, @is_panel, @auto_renew, @notes, @created_at, @updated_at
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
    reality_status: fields.reality_status || null,
    reality_checked_at: fields.reality_checked_at != null ? fields.reality_checked_at : null,
    reality_check_detail: fields.reality_check_detail || null,
    masquerade_url: fields.masquerade_url || null,
    source: fields.source || null,
    managed: isPanel || fields.managed ? 1 : 0,
    is_panel: isPanel,
    auto_renew: autoRenew,
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
  if (patch.auto_renew !== undefined) {
    next.auto_renew = patch.auto_renew ? 1 : 0;
  }
  next.updated_at = nowSec();
  database().prepare(`
    UPDATE ssl_certificates SET
      type=@type, label=@label, domain=@domain, sni=@sni, email=@email, storage_key=@storage_key,
      not_after=@not_after, issuer=@issuer, fingerprint_sha256=@fingerprint_sha256,
      reality_private_key=@reality_private_key, reality_public_key=@reality_public_key,
      reality_short_id=@reality_short_id, reality_dest=@reality_dest,
      reality_status=@reality_status, reality_checked_at=@reality_checked_at,
      reality_check_detail=@reality_check_detail, masquerade_url=@masquerade_url,
      source=@source, managed=@managed, is_panel=@is_panel, auto_renew=@auto_renew,
      notes=@notes, updated_at=@updated_at
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
    reality_status: next.reality_status || null,
    reality_checked_at: next.reality_checked_at != null ? next.reality_checked_at : null,
    reality_check_detail: next.reality_check_detail || null,
    masquerade_url: next.masquerade_url || null,
    source: next.source,
    managed: next.is_panel ? 1 : (next.managed ? 1 : 0),
    is_panel: next.is_panel ? 1 : 0,
    auto_renew: next.auto_renew ? 1 : 0,
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

async function list({ force = false } = {}) {
  if (!force && listCache && (Date.now() - listCache.at) < LIST_CACHE_MS) {
    return listCache.data;
  }
  await syncPanel().catch(() => null);
  let rows = database().prepare(
    'SELECT * FROM ssl_certificates ORDER BY is_panel DESC, type ASC, domain ASC',
  ).all();
  // Refresh expiry/fingerprint from live PEM — parallel, non-blocking for list latency.
  await Promise.all(rows.map((row) => {
    if (row.type === 'reality' || row.type === 'masquerade' || !row.storage_key) return null;
    return refreshRowMetaFromVolume(row).catch(() => null);
  }));
  // Lazy Reality recheck for stale TTL — do not block list response.
  const now = nowSec();
  for (const row of rows) {
    if (row.type !== 'reality') continue;
    const checked = row.reality_checked_at || 0;
    if (checked && (now - checked) < REALITY_CHECK_TTL_SEC) continue;
    recheckReality(row.id).catch(() => null);
  }
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
  const data = {
    certs: rows.map((row) => rowToPublic(row, { includeSecrets: false })),
    certbotEmail: tlsMaterial.getCertbotEmail() || '',
    panelDomain: tlsMaterial.panelLiveDomain() || '',
    publicIp,
  };
  listCache = { at: Date.now(), data };
  return data;
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
  invalidateListCache();
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
  invalidateListCache();
  const host = normalizeDomainInput(opts.domain || opts.ip);
  const email = String(opts.email || tlsMaterial.getCertbotEmail() || '').trim();
  const force = opts.force === true;
  const portPlan = require('./portPlan');
  const isIp = portPlan.isIpLiteral(host);
  if (isIp) {
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
    type: isIp ? 'lets_encrypt_ip' : 'lets_encrypt',
    label: opts.label != null ? String(opts.label).trim() : host,
    domain: host,
    sni: host,
    email,
    storage_key: host,
    not_after: meta.notAfter,
    issuer: meta.issuer,
    fingerprint_sha256: meta.fingerprintSha256,
    source: 'issued',
    auto_renew: opts.auto_renew != null ? (opts.auto_renew ? 1 : 0) : 1,
  };
  if (existing) {
    return updateRow(existing.id, patch);
  }
  return insertRow(patch);
}

async function applyRealityCheck(sni) {
  // Contract/unit tests and offline CI: skip live TLS probe.
  if (process.env.NODE_ENV === 'test' || process.env.AWG_SSL_SKIP_REALITY_CHECK === '1') {
    return {
      reality_status: 'ok',
      reality_checked_at: nowSec(),
      reality_check_detail: 'test-skip',
      alive: true,
      entry: { domain: sni, alive: true },
    };
  }
  const sniFinder = require('./sniFinder');
  const entry = await sniFinder.recheckDomain(sni);
  const ok = !!(entry && entry.alive);
  return {
    reality_status: ok ? 'ok' : 'fail',
    reality_checked_at: nowSec(),
    reality_check_detail: ok
      ? `alive ip=${entry.ip || ''} alpn=${entry.alpn || ''}`
      : (entry && entry.ip ? `dead ip=${entry.ip}` : 'no public DNS / TLS check failed'),
    alive: ok,
    entry,
  };
}

async function createReality(opts = {}) {
  invalidateListCache();
  const sni = normalizeDomainInput(opts.sni || opts.domain);
  if (!tlsMaterial.isFqdn(sni)) {
    throw httpError(400, 'Reality requires a valid FQDN SNI', 'SSL_BAD_DOMAIN');
  }
  const existing = database().prepare(
    'SELECT * FROM ssl_certificates WHERE type = ? AND (sni = ? OR domain = ?) LIMIT 1',
  ).get('reality', sni, sni);
  if (existing && opts.reuse !== false) {
    const check = await applyRealityCheck(sni);
    if (!check.alive) {
      throw httpError(400, `Reality SNI «${sni}» failed health check: ${check.reality_check_detail}`, 'SSL_REALITY_INVALID');
    }
    return updateRow(existing.id, {
      reality_status: check.reality_status,
      reality_checked_at: check.reality_checked_at,
      reality_check_detail: check.reality_check_detail,
    });
  }
  const check = await applyRealityCheck(sni);
  if (!check.alive) {
    throw httpError(400, `Reality SNI «${sni}» failed health check: ${check.reality_check_detail}`, 'SSL_REALITY_INVALID');
  }
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
    reality_status: check.reality_status,
    reality_checked_at: check.reality_checked_at,
    reality_check_detail: check.reality_check_detail,
    source: 'generated',
  });
}

async function recheckReality(id) {
  const row = getRaw(id);
  if (!row) throw httpError(404, 'Certificate not found', 'SSL_NOT_FOUND');
  if (row.type !== 'reality') {
    throw httpError(400, 'Only Reality certificates can be rechecked', 'SSL_RECHECK_TYPE');
  }
  const sni = row.sni || row.domain;
  const check = await applyRealityCheck(sni);
  return updateRow(id, {
    reality_status: check.reality_status,
    reality_checked_at: check.reality_checked_at,
    reality_check_detail: check.reality_check_detail,
  });
}

async function regenerateReality(id) {
  invalidateListCache();
  const row = getRaw(id);
  if (!row) throw httpError(404, 'Certificate not found', 'SSL_NOT_FOUND');
  if (row.type !== 'reality') {
    throw httpError(400, 'Only Reality certificates can be regenerated', 'SSL_REGENERATE_TYPE');
  }
  const sni = row.sni || row.domain;
  const check = await applyRealityCheck(sni);
  if (!check.alive) {
    throw httpError(400, `Reality SNI «${sni}» failed health check: ${check.reality_check_detail}`, 'SSL_REALITY_INVALID');
  }
  const keys = await generateRealityKeypair();
  const shortId = crypto.randomBytes(8).toString('hex');
  const dest = row.reality_dest || `${sni}:443`;
  return updateRow(id, {
    reality_private_key: keys.privateKey,
    reality_public_key: keys.publicKey,
    reality_short_id: shortId,
    reality_dest: dest,
    reality_status: check.reality_status,
    reality_checked_at: check.reality_checked_at,
    reality_check_detail: check.reality_check_detail,
    source: 'regenerated',
  });
}

function setAutoRenew(id, enabled) {
  invalidateListCache();
  const row = getRaw(id);
  if (!row) throw httpError(404, 'Certificate not found', 'SSL_NOT_FOUND');
  if (row.type === 'reality') {
    throw httpError(400, 'Reality certificates do not support auto-renew', 'SSL_AUTO_RENEW_TYPE');
  }
  if (!LE_TYPES.includes(row.type) && row.type !== 'self_signed') {
    throw httpError(400, 'Auto-renew is only for Let\'s Encrypt and self-signed', 'SSL_AUTO_RENEW_TYPE');
  }
  return updateRow(id, { auto_renew: enabled ? 1 : 0 });
}

async function importPem(opts = {}) {
  invalidateListCache();
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

async function createMasquerade(opts = {}) {
  invalidateListCache();
  let url = String(opts.url || opts.masqueradeUrl || opts.masquerade_url || '').trim();
  if (!url) throw httpError(400, 'Masquerade URL is required', 'SSL_MASQUERADE_URL');
  try {
    const u = new URL(url);
    if (u.protocol !== 'https:') {
      throw httpError(400, 'Masquerade URL must use https://', 'SSL_MASQUERADE_URL');
    }
    url = u.toString();
  } catch (err) {
    if (err && err.code === 'SSL_MASQUERADE_URL') throw err;
    throw httpError(400, 'Invalid masquerade URL', 'SSL_MASQUERADE_URL');
  }
  const host = new URL(url).hostname.toLowerCase();
  const existing = database().prepare(
    'SELECT * FROM ssl_certificates WHERE type = ? AND (masquerade_url = ? OR domain = ?) LIMIT 1',
  ).get('masquerade', url, host);
  if (existing && opts.reuse !== false) {
    return updateRow(existing.id, {
      masquerade_url: url,
      domain: host,
      sni: host,
      label: opts.label != null ? String(opts.label).trim() : (existing.label || host),
    });
  }
  return insertRow({
    type: 'masquerade',
    label: opts.label != null ? String(opts.label).trim() : host,
    domain: host,
    sni: host,
    masquerade_url: url,
    source: opts.source || 'manual',
  });
}

async function importPath(opts = {}) {
  invalidateListCache();
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
  invalidateListCache();
  const row = getRaw(id);
  if (!row) throw httpError(404, 'Certificate not found', 'SSL_NOT_FOUND');
  if (!LE_TYPES.includes(row.type) && row.type !== 'self_signed') {
    throw httpError(400, 'Only Let\'s Encrypt or self-signed certificates can be renewed', 'SSL_RENEW_TYPE');
  }
  const domain = row.storage_key || row.domain;
  const force = opts.force !== false;

  if (row.type === 'self_signed') {
    await tlsMaterial.ensureSelfSignedCert(domain, { force: true });
    const meta = await metaFromVolume(domain);
    return updateRow(id, {
      not_after: meta.notAfter,
      issuer: meta.issuer,
      fingerprint_sha256: meta.fingerprintSha256,
      source: 'generated',
    });
  }

  const email = row.email || tlsMaterial.getCertbotEmail();
  const beforeMeta = await metaFromVolume(domain);
  const portPlan = require('./portPlan');
  const isIp = row.type === 'lets_encrypt_ip' || portPlan.isIpLiteral(domain);
  const liveHealthy = beforeMeta.notAfter != null
    && beforeMeta.notAfter * 1000 > Date.now() + (isIp ? 1 : 14) * 24 * 60 * 60 * 1000;
  const nearExpiry = !(beforeMeta.notAfter != null
    && beforeMeta.notAfter * 1000 > Date.now() + (isIp ? 2 : 30) * 24 * 60 * 60 * 1000);

  if (force || nearExpiry || !liveHealthy) {
    if (isIp) {
      await tlsMaterial.issueLetsEncryptIp(domain, email, { force: force || nearExpiry });
    } else {
      await tlsMaterial.issueLetsEncrypt(domain, email, { force: force || nearExpiry });
    }
  }

  const meta = await metaFromVolume(domain);
  if (meta.notAfter == null) {
    throw httpError(500, 'Renew completed but could not read new certificate metadata', 'SSL_RENEW_META');
  }
  if (
    force
    && beforeMeta.notAfter != null
    && meta.notAfter <= beforeMeta.notAfter
  ) {
    const minMs = isIp ? 1 * 24 * 60 * 60 * 1000 : 14 * 24 * 60 * 60 * 1000;
    if (meta.notAfter * 1000 <= Date.now() + minMs) {
      throw httpError(
        400,
        'Renew did not extend certificate lifetime',
        'CERT_RENEW_NO_EXTEND',
      );
    }
  }
  const updated = updateRow(id, {
    type: isIp ? 'lets_encrypt_ip' : 'lets_encrypt',
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
 * Auto-renew tick: renew LE/self-signed rows with auto_renew=1 near expiry.
 */
async function tickAutoRenew() {
  const rows = database().prepare(
    `SELECT * FROM ssl_certificates WHERE auto_renew = 1 AND type IN ('lets_encrypt','lets_encrypt_ip','self_signed')`,
  ).all();
  const results = [];
  for (const row of rows) {
    const notAfter = row.not_after;
    const isIp = row.type === 'lets_encrypt_ip';
    const thresholdDays = row.type === 'self_signed' ? 30 : (isIp ? 2 : 30);
    const due = notAfter == null
      || (notAfter * 1000 <= Date.now() + thresholdDays * 24 * 60 * 60 * 1000);
    if (!due) {
      results.push({ id: row.id, skipped: true });
      continue;
    }
    try {
      await renew(row.id, { force: true });
      results.push({ id: row.id, ok: true });
    } catch (err) {
      results.push({ id: row.id, ok: false, error: err.message || String(err) });
    }
  }
  return results;
}

/**
 * Resolve inventory cert for sidecar enable. Returns raw row + typed material.
 */
function requireSidecarCert(id, filterKey) {
  const allowed = SIDECAR_CERT_FILTERS[filterKey];
  if (!allowed) throw httpError(500, `Unknown cert filter ${filterKey}`, 'SSL_FILTER');
  const cid = String(id || '').trim();
  if (!cid) throw httpError(400, 'sslCertId is required', 'SSL_CERT_REQUIRED');
  const row = getRaw(cid);
  if (!row) throw httpError(404, 'Certificate not found', 'SSL_NOT_FOUND');
  if (!allowed.includes(row.type)) {
    throw httpError(400, `Certificate type «${row.type}» is not allowed here`, 'SSL_CERT_TYPE');
  }
  return row;
}

function peekCert(id) {
  const row = getRaw(String(id || '').trim());
  return row ? rowToPublic(row, { includeSecrets: false }) : null;
}

/**
 * Assign inventory cert as panel TLS: copy PEM into live/${PANEL_DOMAIN}/ and reload nginx.
 * Persists storage_key as the redeploy reuse default (even when PANEL_DOMAIN is still old).
 */
async function assignPanel(id) {
  invalidateListCache();
  const row = getRaw(id);
  if (!row) throw httpError(404, 'Certificate not found', 'SSL_NOT_FOUND');
  if (row.type === 'reality' || row.type === 'masquerade') {
    throw httpError(400, 'This certificate type cannot be used as panel TLS', 'SSL_BAD_TYPE');
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
  invalidateListCache();
  const row = getRaw(id);
  if (!row) throw httpError(404, 'Certificate not found', 'SSL_NOT_FOUND');
  if (isPanelRow(row)) {
    throw httpError(400, 'Panel certificate cannot be deleted', 'SSL_MANAGED');
  }
  const panelKey = tlsMaterial.panelLiveDomain();
  if (row.storage_key && row.type !== 'reality' && row.type !== 'masquerade') {
    if (!panelKey || row.storage_key !== panelKey) {
      await tlsMaterial.removeLiveCert(row.storage_key).catch(() => false);
    }
  }
  database().prepare('DELETE FROM ssl_certificates WHERE id = ?').run(id);
  return { success: true, id };
}

module.exports = {
  TYPES,
  LE_TYPES,
  SIDECAR_CERT_FILTERS,
  REALITY_CHECK_TTL_SEC,
  invalidateListCache,
  list,
  get: getById,
  getRaw,
  peekCert,
  requireSidecarCert,
  syncPanel,
  createSelfSigned,
  createLetsEncrypt,
  createReality,
  createMasquerade,
  recheckReality,
  regenerateReality,
  setAutoRenew,
  importPem,
  importPath,
  renew,
  tickAutoRenew,
  remove,
  assignPanel,
  parsePemMeta: tlsMaterial.parsePemMeta,
};
