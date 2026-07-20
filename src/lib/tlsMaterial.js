'use strict';

/**
 * TLS certificate material: panel reuse, manual PEM/paths, Let's Encrypt issue.
 * Certs live in the nginx certbot volume at /etc/letsencrypt/live/{domain}/.
 */

const crypto = require('node:crypto');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');
const config = require('../config');

const execFileAsync = promisify(execFile);
const NGINX_CONTAINER = 'nginx';

const CERT_SOURCES = Object.freeze(['self_signed', 'panel', 'manual_pem', 'manual_path', 'issue_le']);

function runCmd(bin, args, { timeout = 60_000, input } = {}) {
  const opts = { timeout, maxBuffer: 4 * 1024 * 1024 };
  if (input != null) opts.input = input;
  return execFileAsync(bin, args, opts)
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

/** FQDN panel domain for sidecar `certSource: panel` (empty when panel is bare IP). */
function panelCertDomain() {
  const d = (config.PANEL_DOMAIN || '').trim();
  if (d && d !== 'localhost' && isFqdn(d)) return d;
  return '';
}

/**
 * Directory name under live/ used by nginx ssl_certificate (FQDN or IP from PANEL_DOMAIN).
 */
function panelLiveDomain() {
  const d = String(config.PANEL_DOMAIN || '').trim().toLowerCase();
  if (!d || d === 'localhost') return '';
  return d;
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

/**
 * Parse certificate PEM with Node crypto (no docker/openssl).
 * @returns {{ notAfter: number|null, issuer: string, fingerprintSha256: string }}
 */
function parsePemMeta(certPem) {
  const pem = String(certPem || '').trim();
  if (!pem) return { notAfter: null, issuer: '', fingerprintSha256: '' };
  try {
    const x509 = new crypto.X509Certificate(pem);
    const ms = Date.parse(x509.validTo);
    return {
      notAfter: Number.isFinite(ms) ? Math.floor(ms / 1000) : null,
      issuer: String(x509.issuer || '').trim(),
      fingerprintSha256: String(x509.fingerprint256 || '').replace(/:/g, '').toLowerCase(),
    };
  } catch {
    return { notAfter: null, issuer: '', fingerprintSha256: '' };
  }
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
  ], { timeout: 20_000 });
  return r.ok && r.stdout.trim() === 'ok';
}

async function readPemFromVolume(domain) {
  const d = String(domain || '').trim().toLowerCase();
  if (!d) return null;
  const vol = await resolveCertbotVolumeName();
  const paths = certPathsForDomain(d);
  const r = await runCmd('docker', [
    'run', '--rm',
    '-v', `${vol}:/etc/letsencrypt:ro`,
    'alpine:3.20',
    'cat', paths.cert,
  ], { timeout: 15_000 });
  if (!r.ok || !String(r.stdout || '').includes('BEGIN CERTIFICATE')) return null;
  return String(r.stdout);
}

async function readKeyFromVolume(domain) {
  const d = String(domain || '').trim().toLowerCase();
  if (!d) return null;
  const vol = await resolveCertbotVolumeName();
  const paths = certPathsForDomain(d);
  const r = await runCmd('docker', [
    'run', '--rm',
    '-v', `${vol}:/etc/letsencrypt:ro`,
    'alpine:3.20',
    'cat', paths.key,
  ], { timeout: 15_000 });
  if (!r.ok || !String(r.stdout || '').includes('BEGIN')) return null;
  return String(r.stdout);
}

async function backupLivePair(domain) {
  const cert = await readPemFromVolume(domain);
  const key = await readKeyFromVolume(domain);
  if (cert && key) return { cert, key };
  return null;
}

async function copyLiveCert(fromDomain, toDomain) {
  const from = String(fromDomain || '').trim().toLowerCase();
  const to = String(toDomain || '').trim().toLowerCase();
  if (!from || !to) {
    const err = new Error('copyLiveCert requires from and to domains');
    err.status = 400;
    err.code = 'CERT_COPY_BAD_DOMAIN';
    throw err;
  }
  if (from === to) return certPathsForDomain(to);
  const vol = await resolveCertbotVolumeName();
  const r = await runCmd('docker', [
    'run', '--rm',
    '-v', `${vol}:/etc/letsencrypt`,
    'alpine:3.20',
    'sh', '-c', `
      set -e
      test -f '/etc/letsencrypt/live/${from}/fullchain.pem'
      test -f '/etc/letsencrypt/live/${from}/privkey.pem'
      mkdir -p '/etc/letsencrypt/live/${to}'
      cp '/etc/letsencrypt/live/${from}/fullchain.pem' '/etc/letsencrypt/live/${to}/fullchain.pem'
      cp '/etc/letsencrypt/live/${from}/privkey.pem' '/etc/letsencrypt/live/${to}/privkey.pem'
      chmod 644 '/etc/letsencrypt/live/${to}/fullchain.pem'
      chmod 600 '/etc/letsencrypt/live/${to}/privkey.pem'
    `,
  ], { timeout: 30_000 });
  if (!r.ok) {
    const err = new Error((r.stderr || 'copy cert failed').trim().slice(0, 300));
    err.status = 400;
    err.code = 'CERT_COPY_FAILED';
    throw err;
  }
  return certPathsForDomain(to);
}

async function removeLiveCert(domain) {
  const d = String(domain || '').trim().toLowerCase();
  if (!d) return false;
  const panel = panelLiveDomain();
  if (panel && d === panel) {
    const err = new Error('Refusing to delete panel live certificate directory');
    err.status = 400;
    err.code = 'CERT_PANEL_LIVE';
    throw err;
  }
  const vol = await resolveCertbotVolumeName();
  const r = await runCmd('docker', [
    'run', '--rm',
    '-v', `${vol}:/etc/letsencrypt`,
    'alpine:3.20',
    'sh', '-c', `rm -rf '/etc/letsencrypt/live/${d}' '/etc/letsencrypt/archive/${d}' '/etc/letsencrypt/renewal/${d}.conf'`,
  ], { timeout: 30_000 });
  return r.ok;
}

/** Minimum remaining lifetime before we treat an existing cert as reusable. */
const CERT_REUSE_MIN_REMAINING_MS = 2 * 24 * 60 * 60 * 1000;

/** After force renew, accept unchanged notAfter (LE cert reuse) if this much life remains. */
const CERT_FORCE_RENEW_ACCEPT_REUSE_MS = 14 * 24 * 60 * 60 * 1000;
const CERT_FORCE_RENEW_ACCEPT_REUSE_IP_MS = 1 * 24 * 60 * 60 * 1000;

function metaRemainingMs(meta) {
  if (!meta || meta.notAfter == null) return null;
  return meta.notAfter * 1000 - Date.now();
}

function metaHealthyForReuse(meta, minRemainingMs) {
  const left = metaRemainingMs(meta);
  return left != null && left > Math.max(0, Number(minRemainingMs) || 0);
}

/**
 * Parse openssl `-enddate` output (`notAfter=Jul 20 15:12:24 2026 GMT`).
 * @returns {number|null} epoch ms
 */
function parseOpensslEnddate(line) {
  const raw = String(line || '').trim();
  const m = raw.match(/^notAfter=(.+)$/i);
  if (!m) return null;
  const ms = Date.parse(m[1].trim());
  return Number.isFinite(ms) ? ms : null;
}

/**
 * True when live/{domain} PEM pair exists and notAfter is far enough in the future.
 */
async function certUsableInVolume(domain, { minRemainingMs = CERT_REUSE_MIN_REMAINING_MS } = {}) {
  const d = String(domain || '').trim().toLowerCase();
  if (!d) return false;
  const pem = await readPemFromVolume(d);
  if (!pem) return false;
  const meta = parsePemMeta(pem);
  if (meta.notAfter == null) return false;
  return meta.notAfter * 1000 > Date.now() + Math.max(0, Number(minRemainingMs) || 0);
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

function certbotIssueError(detail, domain) {
  let msg = String(detail || 'certbot failed').trim().replace(/\s+/g, ' ').slice(0, 400);
  if (/405|Method Not Allowed/i.test(msg)) {
    msg = `Let's Encrypt HTTP-01 got Method Not Allowed for ${domain}. `
      + 'Ensure domain/IP points to this server, port 80 is open to nginx, '
      + 'and /.well-known/acme-challenge/ is reachable over HTTP. '
      + msg.slice(0, 220);
  } else if (/404|NXDOMAIN|Timeout|Connection refused/i.test(msg)) {
    msg = `Let's Encrypt could not validate ${domain} via HTTP-01 on port 80. `
      + 'Check DNS/A-record → panel IP and that host port 80 publishes nginx. '
      + msg.slice(0, 220);
  }
  const err = new Error(msg);
  err.status = 400;
  err.code = 'CERT_ISSUE_FAILED';
  return err;
}

/**
 * Issue or renew LE cert for FQDN via certbot webroot (nginx must serve /.well-known).
 * On force renew: backup existing PEM first; restore if issue fails and live files disappear.
 * @param {string} domain
 * @param {string} email
 * @param {{ force?: boolean }} [opts]
 */
async function issueLetsEncrypt(domain, email, opts = {}) {
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

  const force = opts.force === true;
  const vol = await resolveCertbotVolumeName();
  const wwwVol = await resolveCertbotWwwVolumeName();
  const existed = await certExistsInVolume(d);
  const backup = (force || existed) ? await backupLivePair(d) : null;

  async function restoreIfNeeded() {
    if (!backup) return;
    const still = await certExistsInVolume(d);
    if (!still) {
      await injectManualPem(d, backup.cert, backup.key).catch(() => null);
    }
  }

  // Prefer renew when lineage already exists (avoids "live directory exists").
  let r = { ok: false, stderr: '', stdout: '' };
  if (existed && force) {
    r = await runCmd('docker', [
      'run', '--rm',
      '-v', `${vol}:/etc/letsencrypt`,
      '-v', `${wwwVol}:/var/www/certbot`,
      'certbot/certbot',
      'renew',
      '--cert-name', d,
      '--force-renewal',
      '--no-random-sleep-on-renew',
      '--non-interactive',
    ], { timeout: 300_000 });
  }

  if (!r.ok) {
    const args = [
      'run', '--rm',
      '-v', `${vol}:/etc/letsencrypt`,
      '-v', `${wwwVol}:/var/www/certbot`,
      'certbot/certbot',
      'certonly', '--webroot', '-w', '/var/www/certbot',
      '-d', d,
      '--cert-name', d,
      '--email', em,
      '--agree-tos',
      '--non-interactive',
      force ? '--force-renewal' : '--keep-until-expiring',
    ];
    r = await runCmd('docker', args, { timeout: 300_000 });
  }

  if (!r.ok) {
    await restoreIfNeeded();
    throw certbotIssueError(r.stderr || r.stdout, d);
  }
  if (!(await certExistsInVolume(d))) {
    await restoreIfNeeded();
    const err = new Error(`Certificate files missing after issue for ${d}`);
    err.status = 400;
    err.code = 'CERT_ISSUE_FAILED';
    throw err;
  }

  // Force renew: LE may reuse an identical leaf (same notAfter). Try --new-key once; if still
  // unchanged but plenty of lifetime remains, accept and let the caller sync DB metadata.
  if (force && backup && backup.cert) {
    const before = parsePemMeta(backup.cert);
    let after = parsePemMeta(await readPemFromVolume(d));
    if (
      before.notAfter != null
      && after.notAfter != null
      && after.notAfter <= before.notAfter
    ) {
      const retry = await runCmd('docker', [
        'run', '--rm',
        '-v', `${vol}:/etc/letsencrypt`,
        '-v', `${wwwVol}:/var/www/certbot`,
        'certbot/certbot',
        'certonly', '--webroot', '-w', '/var/www/certbot',
        '-d', d,
        '--cert-name', d,
        '--email', em,
        '--agree-tos',
        '--non-interactive',
        '--force-renewal',
        '--new-key',
      ], { timeout: 300_000 });
      if (!retry.ok) {
        // ACME failed — keep existing live cert if still healthy.
        if (metaHealthyForReuse(before, CERT_FORCE_RENEW_ACCEPT_REUSE_MS)) {
          return certPathsForDomain(d);
        }
        await restoreIfNeeded();
        throw certbotIssueError(retry.stderr || retry.stdout || 'force renew did not extend certificate', d);
      }
      after = parsePemMeta(await readPemFromVolume(d));
      if (after.notAfter == null || after.notAfter <= before.notAfter) {
        if (metaHealthyForReuse(after.notAfter != null ? after : before, CERT_FORCE_RENEW_ACCEPT_REUSE_MS)) {
          return certPathsForDomain(d);
        }
        const err = new Error(
          `Renew completed but certificate expiry did not extend for ${d} (still ${before.notAfter})`,
        );
        err.status = 400;
        err.code = 'CERT_RENEW_NO_EXTEND';
        throw err;
      }
    }
  }

  return certPathsForDomain(d);
}

/**
 * Issue LE shortlived cert for a public IP (HTTP-01 webroot), same idea as install.sh acme shortlived.
 * @param {string} ip
 * @param {string} email
 * @param {{ force?: boolean }} [opts]
 */
async function issueLetsEncryptIp(ip, email, opts = {}) {
  const portPlan = require('./portPlan');
  const d = String(ip || '').trim().toLowerCase();
  if (!portPlan.isIpLiteral(d)) {
    const err = new Error(`Invalid certificate IP: ${d}`);
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

  const force = opts.force === true;
  const vol = await resolveCertbotVolumeName();
  const wwwVol = await resolveCertbotWwwVolumeName();
  const existed = await certExistsInVolume(d);
  const backup = (force || existed) ? await backupLivePair(d) : null;

  async function restoreIfNeeded() {
    if (!backup) return;
    if (!(await certExistsInVolume(d))) {
      await injectManualPem(d, backup.cert, backup.key).catch(() => null);
    }
  }

  // Prefer certbot shortlived + webroot (nginx already serves ACME on :80).
  const certbotArgs = [
    'run', '--rm',
    '-v', `${vol}:/etc/letsencrypt`,
    '-v', `${wwwVol}:/var/www/certbot`,
    'certbot/certbot',
    'certonly', '--webroot', '-w', '/var/www/certbot',
    '-d', d,
    '--cert-name', d,
    '--email', em,
    '--agree-tos',
    '--non-interactive',
    '--certificate-profile', 'shortlived',
    force ? '--force-renewal' : '--keep-until-expiring',
  ];
  let r = await runCmd('docker', certbotArgs, { timeout: 300_000 });

  if (!r.ok) {
    // Fallback: acme.sh webroot shortlived (install.sh uses standalone; panel keeps nginx up).
    r = await runCmd('docker', [
      'run', '--rm',
      '-v', `${vol}:/acme-out`,
      '-v', `${wwwVol}:/var/www/certbot`,
      '-e', 'LE_WORKING_DIR=/acme-out/acme.sh',
      '--entrypoint', 'acme.sh',
      'neilpang/acme.sh',
      '--issue',
      '-d', d,
      '-w', '/var/www/certbot',
      '--server', 'letsencrypt',
      '--certificate-profile', 'shortlived',
      '--days', '6',
      '-m', em,
      ...(force ? ['--force'] : []),
    ], { timeout: 300_000 });

    if (!r.ok) {
      await restoreIfNeeded();
      throw certbotIssueError(r.stderr || r.stdout, d);
    }

    const install = await runCmd('docker', [
      'run', '--rm',
      '-v', `${vol}:/acme-out`,
      '-e', 'LE_WORKING_DIR=/acme-out/acme.sh',
      '--entrypoint', 'acme.sh',
      'neilpang/acme.sh',
      '--install-cert', '-d', d,
      '--fullchain-file', `/acme-out/live/${d}/fullchain.pem`,
      '--key-file', `/acme-out/live/${d}/privkey.pem`,
      '--reloadcmd', 'true',
    ], { timeout: 60_000 });
    if (!install.ok) {
      const copy = await runCmd('docker', [
        'run', '--rm',
        '-v', `${vol}:/acme-out`,
        'alpine:3.20',
        'sh', '-c', `
          set -e
          SRC=$(ls -d /acme-out/acme.sh/${d}_ecc /acme-out/acme.sh/${d} 2>/dev/null | head -1)
          test -n "$SRC"
          mkdir -p '/acme-out/live/${d}'
          cp "$SRC/fullchain.cer" '/acme-out/live/${d}/fullchain.pem' 2>/dev/null || cp "$SRC/fullchain.pem" '/acme-out/live/${d}/fullchain.pem'
          cp "$SRC/${d}.key" '/acme-out/live/${d}/privkey.pem' 2>/dev/null || cp "$SRC/privkey.pem" '/acme-out/live/${d}/privkey.pem'
          chmod 644 '/acme-out/live/${d}/fullchain.pem'
          chmod 600 '/acme-out/live/${d}/privkey.pem'
        `,
      ], { timeout: 30_000 });
      if (!copy.ok) {
        await restoreIfNeeded();
        throw certbotIssueError(install.stderr || copy.stderr || 'acme install-cert failed', d);
      }
    }
  }

  if (!(await certExistsInVolume(d))) {
    await restoreIfNeeded();
    const err = new Error(`Certificate files missing after IP issue for ${d}`);
    err.status = 400;
    err.code = 'CERT_ISSUE_FAILED';
    throw err;
  }

  if (force && backup && backup.cert) {
    const before = parsePemMeta(backup.cert);
    const after = parsePemMeta(await readPemFromVolume(d));
    if (
      before.notAfter != null
      && after.notAfter != null
      && after.notAfter <= before.notAfter
    ) {
      if (metaHealthyForReuse(after, CERT_FORCE_RENEW_ACCEPT_REUSE_IP_MS)) {
        return certPathsForDomain(d);
      }
      const err = new Error(
        `IP renew completed but certificate expiry did not extend for ${d}`,
      );
      err.status = 400;
      err.code = 'CERT_RENEW_NO_EXTEND';
      throw err;
    }
  }

  return certPathsForDomain(d);
}

/**
 * Write manual PEM into certbot volume live/{domain}/.
 * Does NOT bind-mount panel WG_PATH (Docker-from-container host path mismatch).
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
  const certB64 = Buffer.from(certPem.endsWith('\n') ? certPem : `${certPem}\n`).toString('base64');
  const keyB64 = Buffer.from(keyPem.endsWith('\n') ? keyPem : `${keyPem}\n`).toString('base64');
  const script = [
    'set -e',
    `mkdir -p '/etc/letsencrypt/live/${d}'`,
    `printf '%s' '${certB64}' | base64 -d > '/etc/letsencrypt/live/${d}/fullchain.pem'`,
    `printf '%s' '${keyB64}' | base64 -d > '/etc/letsencrypt/live/${d}/privkey.pem'`,
    `chmod 644 '/etc/letsencrypt/live/${d}/fullchain.pem'`,
    `chmod 600 '/etc/letsencrypt/live/${d}/privkey.pem'`,
    `test -s '/etc/letsencrypt/live/${d}/fullchain.pem'`,
    `test -s '/etc/letsencrypt/live/${d}/privkey.pem'`,
  ].join('\n');

  const r = await runCmd('docker', [
    'run', '--rm', '-i',
    '-v', `${vol}:/etc/letsencrypt`,
    'alpine:3.20',
    'sh', '-s',
  ], { timeout: 30_000, input: script });

  if (!r.ok) {
    const err = new Error((r.stderr || 'inject cert failed').trim().slice(0, 300));
    err.status = 400;
    err.code = 'CERT_INJECT_FAILED';
    throw err;
  }
  return { ...certPathsForDomain(d), certPem, keyPem };
}

/**
 * Generate a self-signed TLS cert directly inside the certbot volume (no host tmp bind).
 */
async function ensureSelfSignedCert(domain, opts = {}) {
  const d = String(domain || 'localhost').trim().toLowerCase();
  const force = opts.force === true;
  if (!d) {
    const err = new Error('Certificate domain is required for self-signed cert');
    err.status = 400;
    err.code = 'CERT_BAD_DOMAIN';
    throw err;
  }
  if (!force && await certExistsInVolume(d)) {
    const certPem = await readPemFromVolume(d);
    return { ...certPathsForDomain(d), certPem: certPem || undefined };
  }
  if (force && await certExistsInVolume(d)) {
    const vol = await resolveCertbotVolumeName();
    await runCmd('docker', [
      'run', '--rm',
      '-v', `${vol}:/etc/letsencrypt`,
      'alpine:3.20',
      'sh', '-c', `rm -rf '/etc/letsencrypt/live/${d}' '/etc/letsencrypt/archive/${d}'`,
    ], { timeout: 30_000 });
  }

  const vol = await resolveCertbotVolumeName();
  const cn = d.replace(/'/g, '');
  const r = await runCmd('docker', [
    'run', '--rm',
    '-v', `${vol}:/etc/letsencrypt`,
    'alpine:3.20',
    'sh', '-c', `
      set -e
      apk add --no-cache openssl >/dev/null
      mkdir -p '/etc/letsencrypt/live/${cn}'
      openssl req -x509 -nodes -days 825 -newkey rsa:2048 \
        -keyout '/etc/letsencrypt/live/${cn}/privkey.pem' \
        -out '/etc/letsencrypt/live/${cn}/fullchain.pem' \
        -subj '/CN=${cn}'
      chmod 644 '/etc/letsencrypt/live/${cn}/fullchain.pem'
      chmod 600 '/etc/letsencrypt/live/${cn}/privkey.pem'
    `,
  ], { timeout: 120_000 });

  if (!r.ok) {
    const err = new Error((r.stderr || 'self-signed cert generation failed').trim().slice(0, 300));
    err.status = 400;
    err.code = 'CERT_SELF_SIGNED_FAILED';
    throw err;
  }
  const certPem = await readPemFromVolume(d);
  if (!certPem) {
    const err = new Error('Self-signed certificate files were not created');
    err.status = 400;
    err.code = 'CERT_SELF_SIGNED_FAILED';
    throw err;
  }
  return { ...certPathsForDomain(d), certPem };
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
    certDomain = panelLiveDomain() || panelCertDomain() || domain;
    if (!certDomain) {
      const err = new Error('Panel certificate domain (PANEL_DOMAIN) is not configured');
      err.status = 400;
      err.code = 'CERT_PANEL_DOMAIN_MISSING';
      throw err;
    }
  }

  // LE: reuse live PEM when still valid; otherwise certbot --keep-until-expiring.
  if (source === 'issue_le' || opts.issueIfMissing) {
    if (!(await certUsableInVolume(certDomain))) {
      const portPlan = require('./portPlan');
      if (portPlan.isIpLiteral(certDomain)) {
        await issueLetsEncryptIp(certDomain, opts.email, { force: false });
      } else {
        await issueLetsEncrypt(certDomain, opts.email, { force: false });
      }
    }
  } else if (!(await certExistsInVolume(certDomain))) {
    const err = new Error(`Certificate not found for ${certDomain} in certbot volume`);
    err.status = 400;
    err.code = 'CERT_MISSING';
    throw err;
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
  panelLiveDomain,
  certPathsForDomain,
  resolveCertbotVolumeName,
  resolveCertbotWwwVolumeName,
  certExistsInVolume,
  certUsableInVolume,
  readPemFromVolume,
  readKeyFromVolume,
  copyLiveCert,
  removeLiveCert,
  parsePemMeta,
  parseOpensslEnddate,
  CERT_REUSE_MIN_REMAINING_MS,
  issueLetsEncrypt,
  issueLetsEncryptIp,
  injectManualPem,
  ensureSelfSignedCert,
  resolveCertMaterial,
  assertPanelCertReuseAllowed,
  getCertbotEmail,
  setCertbotEmail,
  normalizeHostname,
};
