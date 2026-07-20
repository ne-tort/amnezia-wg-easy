'use strict';

/**
 * TLS certificate material: panel reuse, manual PEM/paths, Let's Encrypt issue.
 * Certs live in the nginx certbot volume at /etc/letsencrypt/live/{domain}/.
 */

const fs = require('node:fs');
const path = require('node:path');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');
const config = require('../config');

const execFileAsync = promisify(execFile);
const NGINX_CONTAINER = 'nginx';

const CERT_SOURCES = Object.freeze(['self_signed', 'panel', 'manual_pem', 'manual_path', 'issue_le']);

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

function isFqdn(host) {
  const s = String(host || '').trim().toLowerCase();
  if (!s || s === 'localhost') return false;
  const portPlan = require('./portPlan');
  if (portPlan.isIpLiteral(s)) return false;
  return s.includes('.');
}

function panelCertDomain() {
  const d = (config.PANEL_DOMAIN || '').trim();
  if (d && d !== 'localhost' && isFqdn(d)) return d;
  return '';
}

function certPathsForDomain(domain) {
  const d = String(domain || '').trim().toLowerCase();
  const base = `/etc/letsencrypt/live/${d}`;
  return {
    cert: `${base}/fullchain.pem`,
    key: `${base}/privkey.pem`,
    domain: d,
  };
}

async function resolveNginxVolume(destination, fallbackSuffix) {
  const dest = String(destination || '').trim();
  const r = await runCmd('docker', [
    'inspect', '-f',
    `{{range .Mounts}}{{if eq .Destination "${dest}"}}{{.Name}}{{end}}{{end}}`,
    NGINX_CONTAINER,
  ]);
  const name = (r.ok ? r.stdout : '').trim();
  if (name) return name;
  return `${process.env.COMPOSE_PROJECT_NAME || 'amnezia-wg-easy'}_${fallbackSuffix}`;
}

async function resolveCertbotVolumeName() {
  return resolveNginxVolume('/etc/letsencrypt', 'certbot_conf');
}

async function resolveCertbotWwwVolumeName() {
  return resolveNginxVolume('/var/www/certbot', 'certbot_www');
}

async function certExistsInVolume(domain) {
  const vol = await resolveCertbotVolumeName();
  const paths = certPathsForDomain(domain);
  const r = await runCmd('docker', [
    'run', '--rm',
    '-v', `${vol}:/etc/letsencrypt:ro`,
    'alpine:3.20',
    'sh', '-c', `test -f '${paths.cert}' && test -f '${paths.key}' && echo ok`,
  ]);
  return r.ok && r.stdout.trim() === 'ok';
}

const CERTBOT_EMAIL_KEY = 'certbot_email';

function getCertbotEmail() {
  try {
    const fromDb = require('./db').appSettings.get(CERTBOT_EMAIL_KEY);
    const stored = String(fromDb || '').trim();
    if (stored && stored.includes('@')) return stored;
  } catch { /* db may be unavailable in scripts */ }
  const fromEnv = String(process.env.CERTBOT_EMAIL || '').trim();
  if (fromEnv && fromEnv.includes('@')) return fromEnv;
  return '';
}

function setCertbotEmail(email) {
  const em = String(email || '').trim();
  if (!em || !em.includes('@')) return;
  try {
    require('./db').appSettings.set(CERTBOT_EMAIL_KEY, em);
  } catch { /* ignore */ }
}

/**
 * Issue or renew LE cert for domain via certbot webroot (nginx must serve /.well-known).
 */
async function issueLetsEncrypt(domain, email) {
  const d = String(domain || '').trim().toLowerCase();
  if (!isFqdn(d)) {
    const err = new Error(`Invalid certificate domain: ${d}`);
    err.status = 400;
    err.code = 'CERT_BAD_DOMAIN';
    throw err;
  }
  const em = String(email || getCertbotEmail() || '').trim();
  if (!em || !em.includes('@')) {
    const err = new Error('Email is required for Let\'s Encrypt');
    err.status = 400;
    err.code = 'CERT_NO_EMAIL';
    throw err;
  }
  setCertbotEmail(em);

  const vol = await resolveCertbotVolumeName();
  const wwwVol = await resolveCertbotWwwVolumeName();
  const r = await runCmd('docker', [
    'run', '--rm',
    '-v', `${vol}:/etc/letsencrypt`,
    '-v', `${wwwVol}:/var/www/certbot`,
    'certbot/certbot',
    'certonly', '--webroot', '-w', '/var/www/certbot',
    '-d', d,
    '--email', em,
    '--agree-tos',
    '--non-interactive',
    '--keep-until-expiring',
  ], { timeout: 300_000 });

  if (!r.ok) {
    let detail = (r.stderr || r.stdout || 'certbot failed').trim().replace(/\s+/g, ' ').slice(0, 400);
    if (/405|Method Not Allowed/i.test(detail)) {
      detail = `Let's Encrypt HTTP-01 got Method Not Allowed for ${d}. `
        + 'Ensure domain A record points to this server, port 80 is open to nginx, '
        + 'and /.well-known/acme-challenge/ is reachable over HTTP (not blocked by CDN). '
        + detail.slice(0, 220);
    } else if (/404|NXDOMAIN|Timeout|Connection refused/i.test(detail)) {
      detail = `Let's Encrypt could not validate ${d} via HTTP-01 on port 80. `
        + 'Check A-record → panel IP and that host port 80 publishes nginx. '
        + detail.slice(0, 220);
    }
    const err = new Error(detail);
    err.status = 400;
    err.code = 'CERT_ISSUE_FAILED';
    throw err;
  }
  if (!(await certExistsInVolume(d))) {
    const err = new Error(`Certificate files missing after issue for ${d}`);
    err.status = 400;
    err.code = 'CERT_ISSUE_FAILED';
    throw err;
  }
  return certPathsForDomain(d);
}

/**
 * Write manual PEM into certbot volume live/{domain}/.
 */
async function injectManualPem(domain, certPem, keyPem) {
  const d = String(domain || '').trim().toLowerCase();
  if (!certPem || !keyPem) {
    const err = new Error('Certificate and private key PEM are required');
    err.status = 400;
    err.code = 'CERT_PEM_MISSING';
    throw err;
  }
  const vol = await resolveCertbotVolumeName();
  const tmpDir = path.join(config.WG_PATH || '/tmp', '_tls_inject');
  fs.mkdirSync(tmpDir, { recursive: true });
  const certFile = path.join(tmpDir, 'fullchain.pem');
  const keyFile = path.join(tmpDir, 'privkey.pem');
  fs.writeFileSync(certFile, certPem.endsWith('\n') ? certPem : `${certPem}\n`, { mode: 0o644 });
  fs.writeFileSync(keyFile, keyPem.endsWith('\n') ? keyPem : `${keyPem}\n`, { mode: 0o600 });

  const r = await runCmd('docker', [
    'run', '--rm',
    '-v', `${vol}:/etc/letsencrypt`,
    '-v', `${tmpDir}:/src:ro`,
    'alpine:3.20',
    'sh', '-c', `
      mkdir -p '/etc/letsencrypt/live/${d}'
      cp /src/fullchain.pem '/etc/letsencrypt/live/${d}/fullchain.pem'
      cp /src/privkey.pem '/etc/letsencrypt/live/${d}/privkey.pem'
      chmod 644 '/etc/letsencrypt/live/${d}/fullchain.pem'
      chmod 600 '/etc/letsencrypt/live/${d}/privkey.pem'
    `,
  ], { timeout: 30_000 });

  try {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  } catch { /* ignore */ }

  if (!r.ok) {
    const err = new Error((r.stderr || 'inject cert failed').trim().slice(0, 300));
    err.status = 400;
    err.code = 'CERT_INJECT_FAILED';
    throw err;
  }
  return certPathsForDomain(d);
}

/**
 * Generate a self-signed TLS cert and store it in the certbot volume (live/{domain}/).
 */
async function ensureSelfSignedCert(domain) {
  const d = String(domain || 'localhost').trim().toLowerCase();
  if (!d) {
    const err = new Error('Certificate domain is required for self-signed cert');
    err.status = 400;
    err.code = 'CERT_BAD_DOMAIN';
    throw err;
  }
  if (await certExistsInVolume(d)) {
    return certPathsForDomain(d);
  }

  const tmpDir = path.join(config.WG_PATH || '/tmp', '_tls_selfsigned');
  fs.mkdirSync(tmpDir, { recursive: true });
  const certFile = path.join(tmpDir, 'fullchain.pem');
  const keyFile = path.join(tmpDir, 'privkey.pem');

  const localOpenssl = await runCmd('openssl', [
    'req', '-x509', '-nodes', '-days', '825', '-newkey', 'rsa:2048',
    '-keyout', keyFile,
    '-out', certFile,
    '-subj', `/CN=${d}`,
  ], { timeout: 30_000 });

  if (!localOpenssl.ok) {
    const r = await runCmd('docker', [
      'run', '--rm',
      '-v', `${tmpDir}:/out`,
      'alpine:3.20',
      'sh', '-c', `apk add --no-cache openssl >/dev/null
openssl req -x509 -nodes -days 825 -newkey rsa:2048 \
  -keyout /out/privkey.pem -out /out/fullchain.pem \
  -subj "/CN=${d}"`,
    ], { timeout: 120_000 });
    if (!r.ok) {
      const err = new Error((r.stderr || 'self-signed cert generation failed').trim().slice(0, 300));
      err.status = 400;
      err.code = 'CERT_SELF_SIGNED_FAILED';
      throw err;
    }
  }

  if (!fs.existsSync(certFile) || !fs.existsSync(keyFile)) {
    const err = new Error('Self-signed certificate files were not created');
    err.status = 400;
    err.code = 'CERT_SELF_SIGNED_FAILED';
    throw err;
  }

  const certPem = fs.readFileSync(certFile, 'utf8');
  const keyPem = fs.readFileSync(keyFile, 'utf8');
  try {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  } catch { /* ignore */ }
  return injectManualPem(d, certPem, keyPem);
}

/**
 * Resolve cert paths for a service enable request.
 * @param {{ certSource?: string, domain: string, certPem?: string, keyPem?: string, certPath?: string, keyPath?: string, issueIfMissing?: boolean }} opts
 */
async function resolveCertMaterial(opts = {}) {
  const source = String(opts.certSource || 'self_signed').trim().toLowerCase();
  const domain = String(opts.domain || '').trim().toLowerCase();

  if (source === 'manual_path') {
    const cert = String(opts.certPath || '').trim();
    const key = String(opts.keyPath || '').trim();
    if (!cert || !key) {
      const err = new Error('Certificate and key file paths are required');
      err.status = 400;
      err.code = 'CERT_PATH_MISSING';
      throw err;
    }
    return { cert, key, domain, source };
  }

  if (source === 'manual_pem') {
    return injectManualPem(domain, opts.certPem, opts.keyPem).then((p) => ({ ...p, source }));
  }

  if (source === 'self_signed') {
    const certDomain = domain || 'hysteria.local';
    return ensureSelfSignedCert(certDomain).then((p) => ({ ...p, source: 'self_signed' }));
  }

  let certDomain = domain;
  if (source === 'panel') {
    certDomain = panelCertDomain() || domain;
    if (!certDomain) {
      const err = new Error('Panel certificate domain (PANEL_DOMAIN FQDN) is not configured');
      err.status = 400;
      err.code = 'CERT_PANEL_DOMAIN_MISSING';
      throw err;
    }
  }

  if (!(await certExistsInVolume(certDomain))) {
    if (source === 'issue_le') {
      await issueLetsEncrypt(certDomain, opts.email);
    } else if (opts.issueIfMissing) {
      await issueLetsEncrypt(certDomain, opts.email);
    } else {
      const err = new Error(`Certificate not found for ${certDomain} in certbot volume`);
      err.status = 400;
      err.code = 'CERT_MISSING';
      throw err;
    }
  }
  return { ...certPathsForDomain(certDomain), source: source === 'panel' ? 'panel' : source };
}

/**
 * Block panel cert reuse on the same *TCP* public port as panel HTTPS.
 * Hysteria is UDP — call sites must not use this for hysteria.
 */
function assertPanelCertReuseAllowed(serviceId, publicPort) {
  if (serviceId === 'hysteria') return;
  const panelPort = parseInt(String(config.PANEL_HTTPS_PORT || '443'), 10);
  const pub = parseInt(String(publicPort), 10);
  if (Number.isFinite(panelPort) && pub === panelPort) {
    const err = new Error(`${serviceId} cannot reuse panel certificate on the same public port (${pub})`);
    err.status = 400;
    err.code = 'CERT_PORT_CONFLICT';
    err.field = 'certSource';
    throw err;
  }
}

/** Normalize hostname for LE / Naive SNI: strip scheme, path, port. */
function normalizeHostname(raw) {
  let s = String(raw || '').trim().toLowerCase();
  if (!s) return '';
  s = s.replace(/^https?:\/\//i, '');
  s = s.split('/')[0];
  s = s.split('?')[0];
  // strip :port if not IPv6
  if (s.includes(':') && !s.includes(']')) {
    const parts = s.split(':');
    if (parts.length === 2 && /^\d+$/.test(parts[1])) s = parts[0];
  }
  return s.replace(/\.$/, '');
}

module.exports = {
  CERT_SOURCES,
  CERTBOT_EMAIL_KEY,
  NGINX_CONTAINER,
  isFqdn,
  panelCertDomain,
  certPathsForDomain,
  resolveCertbotVolumeName,
  resolveCertbotWwwVolumeName,
  certExistsInVolume,
  issueLetsEncrypt,
  injectManualPem,
  ensureSelfSignedCert,
  resolveCertMaterial,
  assertPanelCertReuseAllowed,
  getCertbotEmail,
  setCertbotEmail,
  normalizeHostname,
};
