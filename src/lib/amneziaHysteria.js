'use strict';

/**
 * Amnezia Hysteria orchestration: Hysteria2 Docker container (amnezia-hysteria).
 * Desired state in app_settings; per-client password on clients.hysteria_password.
 * UDP direct publish (not TCP demux).
 */

const { spawn, execFile } = require('node:child_process');
const { promisify } = require('node:util');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const config = require('../config');

const execFileAsync = promisify(execFile);

const CONTAINER_NAME = 'amnezia-hysteria';
const IMAGE_NAME = 'amnezia-hysteria';
const DOCKERFILE_FOLDER = '/opt/amnezia/hysteria';
const PANEL_CONTAINER = 'amnezia-awg';
const NGINX_CONTAINER = 'nginx';
const HYSTERIA_REL = 'hysteria';
const SERVER_YAML = 'server.yaml';
/** Fixed listen port inside the container (host maps publicPort → this). */
const LISTEN_PORT = 443;

const DESIRED_KEY = 'amnezia_hysteria_desired';
const SNI_KEY = 'amnezia_hysteria_sni';
const PUBLIC_PORT_KEY = 'amnezia_hysteria_public_port';
const ADDRESS_KEY = 'amnezia_hysteria_address';
const MASQUERADE_KEY = 'amnezia_hysteria_masquerade_url';
const MASQUERADE_TYPE_KEY = 'amnezia_hysteria_masquerade_type';
const OBFS_TYPE_KEY = 'amnezia_hysteria_obfs_type';
const OBFS_PASSWORD_KEY = 'amnezia_hysteria_obfs_password';
const BANDWIDTH_UP_KEY = 'amnezia_hysteria_bandwidth_up';
const BANDWIDTH_DOWN_KEY = 'amnezia_hysteria_bandwidth_down';
const IGNORE_CLIENT_BW_KEY = 'amnezia_hysteria_ignore_client_bandwidth';
const CERT_SOURCE_KEY = 'amnezia_hysteria_cert_source';
const CERT_DOMAIN_KEY = 'amnezia_hysteria_cert_domain';
const TLS_INSECURE_CLIENT_KEY = 'amnezia_hysteria_tls_insecure_client';

const DEFAULT_SNI = 'www.sbb.ch';
const DEFAULT_MASQUERADE = 'https://www.sbb.ch/';

const MIRROR_BANK_SEED = path.join(__dirname, '..', '..', 'config', 'mirror-bank.seed.json');
const MIRROR_BANK_SEED_IN_IMAGE = path.join(__dirname, '..', 'config', 'mirror-bank.seed.json');

const ENABLE_TIMEOUT_MS = 180_000;
const RECONCILE_INTERVAL_MS = 30_000;

/** @type {'off'|'installing'|'running'|'degraded'|'removing'|'error'} */
let phase = 'off';
let lastError = null;
let lastSmoke = null;
let updatedAt = Date.now();
/** @type {Promise<any>|null} */
let activeJob = null;
let reconcileTimer = null;

function getDb() {
  return require('./db');
}

function getDesired() {
  const raw = getDb().appSettings.get(DESIRED_KEY);
  if (raw === null || raw === undefined || raw === '') return null;
  return raw === '1' || raw === 'true' || raw === 'yes' || raw === 'on';
}

function setDesired(on) {
  getDb().appSettings.set(DESIRED_KEY, on ? '1' : '0');
}

function getSetting(key, fallback = '') {
  const raw = getDb().appSettings.get(key);
  if (raw === null || raw === undefined || raw === '') return fallback;
  return String(raw);
}

function setSetting(key, value) {
  getDb().appSettings.set(key, value == null ? '' : String(value));
}

function getPublicPort() {
  const fromDb = getSetting(PUBLIC_PORT_KEY, '');
  if (fromDb && /^\d+$/.test(fromDb)) return parseInt(fromDb, 10);
  const fromEnv = parseInt(String(process.env.HYSTERIA_PUBLIC_PORT || '').trim(), 10);
  if (Number.isFinite(fromEnv) && fromEnv >= 1 && fromEnv <= 65535) return fromEnv;
  return 443;
}

function getClientFacingPort() {
  return getPublicPort();
}

function isIpLiteral(host) {
  const h = String(host || '').trim().toLowerCase().replace(/^\[|\]$/g, '');
  if (!h) return false;
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(h)) return true;
  if (h.includes(':')) return true;
  return false;
}

function getSni() {
  const raw = getDb().appSettings.get(SNI_KEY);
  if (raw === '') return '';
  if (raw != null && String(raw).trim()) return String(raw).trim();
  try {
    const picked = require('./sniFinder').pickDefaultSni();
    if (picked) return picked;
  } catch {
    /* optional */
  }
  return DEFAULT_SNI;
}

function getSniStored() {
  return getSetting(SNI_KEY, '') || null;
}

function loadMirrorBankDomains() {
  return require('./masqueradeBank').loadMirrorBankDomains();
}

function pickDefaultMasqueradeUrl() {
  const picked = require('./masqueradeBank').pickRandomMasqueradeUrl();
  if (picked) return picked;
  try {
    const sni = require('./sniFinder').pickDefaultSni();
    if (sni) return `https://${sni}/`;
  } catch {
    /* optional */
  }
  return DEFAULT_MASQUERADE;
}

function getMasqueradeUrl() {
  const stored = getSetting(MASQUERADE_KEY, '').trim();
  if (stored) return stored;
  return pickDefaultMasqueradeUrl();
}

function getMasqueradeUrlStored() {
  return getSetting(MASQUERADE_KEY, '').trim() || null;
}

function getMasqueradeType() {
  const t = getSetting(MASQUERADE_TYPE_KEY, 'proxy').trim().toLowerCase();
  return t === 'file' || t === 'string' ? t : 'proxy';
}

function getObfsType() {
  return getSetting(OBFS_TYPE_KEY, '').trim().toLowerCase();
}

function getObfsPassword() {
  return getSetting(OBFS_PASSWORD_KEY, '').trim();
}

function getBandwidthUp() {
  return getSetting(BANDWIDTH_UP_KEY, '').trim();
}

function getBandwidthDown() {
  return getSetting(BANDWIDTH_DOWN_KEY, '').trim();
}

function getIgnoreClientBandwidth() {
  const raw = getSetting(IGNORE_CLIENT_BW_KEY, '');
  return raw === '1' || raw === 'true' || raw === 'yes' || raw === 'on';
}

function getCertSource() {
  const tlsMaterial = require('./tlsMaterial');
  const s = getSetting(CERT_SOURCE_KEY, 'self_signed').trim().toLowerCase();
  return tlsMaterial.CERT_SOURCES.includes(s) ? s : 'self_signed';
}

function getCertDomainStored() {
  return getSetting(CERT_DOMAIN_KEY, '').trim().toLowerCase() || null;
}

function getTlsInsecureClient() {
  const raw = getSetting(TLS_INSECURE_CLIENT_KEY, '');
  if (raw === '1' || raw === 'true' || raw === 'yes' || raw === 'on') return true;
  if (raw === '0' || raw === 'false' || raw === 'no' || raw === 'off') return false;
  return getCertSource() === 'self_signed';
}

/**
 * TLS cert live dir: override → panel (when cert_source=panel) → SNI for issue_le / SNI cert.
 */
function resolveCertDomain() {
  const override = getCertDomainStored();
  if (override) return override;
  const source = getCertSource();
  const sni = getSni();
  if (source === 'panel') {
    const panel = require('./tlsMaterial').panelCertDomain();
    if (panel) return panel;
  }
  if (source === 'issue_le' || source !== 'panel') {
    if (sni) return sni;
  }
  const panelDomain = (config.PANEL_DOMAIN || '').trim();
  if (panelDomain && panelDomain !== 'localhost' && !isIpLiteral(panelDomain)) {
    return panelDomain;
  }
  return sni || panelDomain || 'localhost';
}

function certPathsForDomain(domain) {
  const base = `/etc/letsencrypt/live/${domain}`;
  return {
    cert: `${base}/fullchain.pem`,
    key: `${base}/privkey.pem`,
  };
}

function setPhase(next, err = null) {
  phase = next;
  if (err != null) lastError = String(err.message || err);
  else if (next === 'running' || next === 'off') lastError = null;
  updatedAt = Date.now();
}

function runCmd(bin, args, { timeout = 20_000 } = {}) {
  return execFileAsync(bin, args, { timeout, maxBuffer: 2 * 1024 * 1024 })
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

function hysteriaHostDir() {
  return path.join(config.WG_PATH, HYSTERIA_REL);
}

function serverYamlPath() {
  return path.join(hysteriaHostDir(), SERVER_YAML);
}

function ensureHysteriaDir() {
  fs.mkdirSync(hysteriaHostDir(), { recursive: true });
}

/**
 * Username for Hysteria userpass from client display name.
 * @param {string} name
 */
function clientNameSlug(name) {
  const slug = String(name || '')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 48);
  return slug || 'client';
}

function yamlQuote(value) {
  const s = String(value);
  if (/[:#\n\r\t'"\\]/.test(s) || /^\s|\s$/.test(s)) {
    return JSON.stringify(s);
  }
  return s;
}

async function dockerContainerRunning() {
  const r = await runCmd('docker', [
    'inspect', '-f', '{{.State.Running}}', CONTAINER_NAME,
  ]);
  return r.ok && r.stdout.trim() === 'true';
}

async function resolveAwgVolumeName() {
  const r = await runCmd('docker', [
    'inspect', '-f',
    '{{range .Mounts}}{{if eq .Destination "/opt/amnezia/awg"}}{{.Name}}{{end}}{{end}}',
    PANEL_CONTAINER,
  ]);
  const name = (r.ok ? r.stdout : '').trim();
  if (!name) {
    throw new Error('panel data volume not found (is amnezia-awg running with /opt/amnezia/awg?)');
  }
  return name;
}

async function resolveCertbotVolumeName() {
  const r = await runCmd('docker', [
    'inspect', '-f',
    '{{range .Mounts}}{{if eq .Destination "/etc/letsencrypt"}}{{.Name}}{{end}}{{end}}',
    NGINX_CONTAINER,
  ]);
  const name = (r.ok ? r.stdout : '').trim();
  if (!name) {
    throw new Error('certbot volume not found (is nginx running with /etc/letsencrypt?)');
  }
  return name;
}

async function ensureHysteriaImage() {
  const inspect = await runCmd('docker', ['image', 'inspect', IMAGE_NAME]);
  if (inspect.ok) return;

  const dockerfilePath = path.join(DOCKERFILE_FOLDER, 'Dockerfile');
  if (!fs.existsSync(dockerfilePath)) {
    throw new Error('amnezia-hysteria image missing; run deploy.sh');
  }
  const dockerfile = fs.readFileSync(dockerfilePath, 'utf8');
  await new Promise((resolve, reject) => {
    const child = spawn('docker', ['build', '-t', IMAGE_NAME, '-'], {
      stdio: ['pipe', 'ignore', 'pipe'],
    });
    let err = '';
    const timer = setTimeout(() => {
      try { child.kill('SIGKILL'); } catch (_) { /* ignore */ }
      reject(new Error('docker build amnezia-hysteria timed out'));
    }, 600_000);
    child.stderr.on('data', (d) => { err += String(d); });
    child.on('error', (e) => {
      clearTimeout(timer);
      reject(e);
    });
    child.on('close', (code) => {
      clearTimeout(timer);
      if (code === 0) resolve();
      else reject(new Error((err || `docker build failed (${code})`).trim().slice(0, 400)));
    });
    child.stdin.write(dockerfile);
    child.stdin.end();
  });
}

function generatePassword() {
  return crypto.randomBytes(16).toString('base64url');
}

/**
 * Ensure every client has a stable hysteria_password; return enabled clients for auth map.
 * @returns {Array<{ id: string, name: string, username: string, hysteria_password: string, enabled: number }>}
 */
function ensureClientPasswords() {
  const db = getDb();
  const rows = db.clients.getAll();
  const out = [];
  const usedUsernames = new Set();
  for (const row of rows) {
    let password = row.hysteria_password;
    if (!password) {
      password = generatePassword();
      db.clients.setHysteriaPassword(row.id, password);
      row.hysteria_password = password;
    }
    let username = clientNameSlug(row.name);
    if (usedUsernames.has(username)) {
      username = `${username}-${String(row.id).slice(0, 8)}`;
    }
    usedUsernames.add(username);
    if (row.enabled) {
      out.push({
        id: row.id,
        name: row.name,
        username,
        hysteria_password: password,
        enabled: row.enabled,
      });
    }
  }
  return out;
}

/**
 * @param {Array<{ username: string, hysteria_password: string }>} clients
 */
function buildUserpassMap(clients) {
  /** @type {Record<string, string>} */
  const map = {};
  for (const c of clients) {
    map[c.username] = c.hysteria_password;
  }
  return map;
}

function buildServerYamlObject({
  userpass, masqueradeUrl, masqueradeType, certDomain, sni,
  obfsType, obfsPassword, bandwidthUp, bandwidthDown, ignoreClientBandwidth,
}) {
  const paths = certPathsForDomain(certDomain);
  /** @type {Record<string, unknown>} */
  const obj = {
    listen: `:${LISTEN_PORT}`,
    tls: {
      cert: paths.cert,
      key: paths.key,
      sni,
    },
    auth: {
      type: 'userpass',
      userpass,
    },
  };
  const mType = masqueradeType || getMasqueradeType();
  if (mType === 'file') {
    obj.masquerade = { type: 'file', file: { dir: '/var/www/html' } };
  } else if (mType === 'string') {
    obj.masquerade = { type: 'string', string: { content: masqueradeUrl || 'ok', headers: {} } };
  } else {
    obj.masquerade = {
      type: 'proxy',
      proxy: {
        url: masqueradeUrl,
        rewriteHost: true,
      },
    };
  }
  const oType = obfsType != null ? obfsType : getObfsType();
  const oPass = obfsPassword != null ? obfsPassword : getObfsPassword();
  if (oType && oPass) {
    obj.obfs = { type: oType, [oType]: { password: oPass } };
  }
  const up = bandwidthUp != null ? bandwidthUp : getBandwidthUp();
  const down = bandwidthDown != null ? bandwidthDown : getBandwidthDown();
  if (up || down) {
    obj.bandwidth = {};
    if (up) obj.bandwidth.up = up;
    if (down) obj.bandwidth.down = down;
  }
  const ignoreBw = ignoreClientBandwidth != null ? ignoreClientBandwidth : getIgnoreClientBandwidth();
  if (ignoreBw) obj.ignoreClientBandwidth = true;
  return obj;
}

function renderServerYaml(obj) {
  const lines = [
    `listen: ${obj.listen}`,
    '',
    'tls:',
    `  cert: ${obj.tls.cert}`,
    `  key: ${obj.tls.key}`,
  ];
  if (obj.tls.sni) {
    lines.push(`  sni: ${yamlQuote(obj.tls.sni)}`);
  }
  lines.push('', 'auth:', '  type: userpass', '  userpass:');
  for (const [user, pass] of Object.entries(obj.auth.userpass || {})) {
    lines.push(`    ${yamlQuote(user)}: ${yamlQuote(pass)}`);
  }
  if (obj.masquerade) {
    lines.push('', 'masquerade:', `  type: ${obj.masquerade.type}`);
    if (obj.masquerade.type === 'proxy' && obj.masquerade.proxy) {
      lines.push('  proxy:');
      lines.push(`    url: ${yamlQuote(obj.masquerade.proxy.url)}`);
      lines.push('    rewriteHost: true');
    } else if (obj.masquerade.type === 'file' && obj.masquerade.file) {
      lines.push('  file:');
      lines.push(`    dir: ${yamlQuote(obj.masquerade.file.dir)}`);
    } else if (obj.masquerade.type === 'string' && obj.masquerade.string) {
      lines.push('  string:');
      lines.push(`    content: ${yamlQuote(obj.masquerade.string.content)}`);
    }
  }
  if (obj.obfs && obj.obfs.type) {
    lines.push('', 'obfs:', `  type: ${yamlQuote(obj.obfs.type)}`);
    const inner = obj.obfs[obj.obfs.type];
    if (inner && inner.password) {
      lines.push(`  ${obj.obfs.type}:`);
      lines.push(`    password: ${yamlQuote(inner.password)}`);
    }
  }
  if (obj.bandwidth && (obj.bandwidth.up || obj.bandwidth.down)) {
    lines.push('', 'bandwidth:');
    if (obj.bandwidth.up) lines.push(`  up: ${yamlQuote(obj.bandwidth.up)}`);
    if (obj.bandwidth.down) lines.push(`  down: ${yamlQuote(obj.bandwidth.down)}`);
  }
  if (obj.ignoreClientBandwidth) {
    lines.push('', 'ignoreClientBandwidth: true');
  }
  return `${lines.join('\n')}\n`;
}

function writeServerYaml(obj) {
  ensureHysteriaDir();
  const p = serverYamlPath();
  fs.writeFileSync(p, renderServerYaml(obj), 'utf8');
  return p;
}

/**
 * Build hy2:// share link.
 */
function buildHy2Url({
  username, password, host, port, sni, remark,
  obfsType, obfsPassword, insecure,
}) {
  const user = encodeURIComponent(username);
  const pass = encodeURIComponent(password);
  const params = new URLSearchParams();
  if (sni) params.set('sni', sni);
  params.set('insecure', insecure ? '1' : '0');
  const oType = obfsType || getObfsType();
  const oPass = obfsPassword || getObfsPassword();
  if (oType && oPass) {
    params.set('obfs', oType);
    params.set('obfs-password', oPass);
  }
  let url = `hy2://${user}:${pass}@${host}:${Number(port)}/?${params.toString()}`;
  if (remark) url += `#${encodeURIComponent(remark)}`;
  return url;
}

function getPublicHost() {
  const stored = getSetting(ADDRESS_KEY, '').trim();
  if (stored) return stored;
  const wg = (config.WG_HOST || '').trim();
  if (wg) return wg;
  return '127.0.0.1';
}

function getAddress() {
  return getSetting(ADDRESS_KEY, '').trim();
}

/**
 * @param {{ id: string, name: string, hysteria_password?: string, enabled?: number }} client
 * @param {{ baseUrl?: string }} [opts]
 */
function getClientHysteriaPayload(client, opts = {}) {
  if (!client || !client.hysteria_password) return null;
  const host = getPublicHost();
  const port = getClientFacingPort();
  const sni = getSni();
  const username = clientNameSlug(client.name);
  const hy2Url = buildHy2Url({
    username,
    password: client.hysteria_password,
    host,
    port,
    sni,
    remark: client.name,
    insecure: getTlsInsecureClient(),
  });

  const base = (opts.baseUrl || '').replace(/\/+$/, '');
  const subPrefix = String(
    opts.subPublicPrefix != null ? opts.subPublicPrefix : (require('../config').SUB_PUBLIC_PREFIX || '/sub'),
  ).replace(/\/+$/, '') || '/sub';
  const subPath = `${subPrefix}/${encodeURIComponent(client.name)}`;
  const subUrl = base ? `${base}${subPath}` : subPath;

  return {
    username,
    password: client.hysteria_password,
    hy2Url,
    subUrl,
    subPath,
    port,
    sni,
    host,
    masqueradeUrl: getMasqueradeUrl(),
    masqueradeType: getMasqueradeType(),
    certDomain: resolveCertDomain(),
    obfsType: getObfsType() || null,
    tlsInsecure: getTlsInsecureClient(),
  };
}

function buildAmneziaHysteriaContainer(client) {
  const payload = getClientHysteriaPayload(client);
  if (!payload) return null;
  return {
    container: CONTAINER_NAME,
    hysteria: {
      hy2_url: payload.hy2Url,
      port: String(payload.port),
      sni: payload.sni,
      username: payload.username,
      transport_proto: 'udp',
    },
  };
}

async function probeListenInsideContainer(port) {
  const p = String(port);
  const ss = await runCmd('docker', [
    'exec', CONTAINER_NAME, 'sh', '-c',
    `(command -v ss >/dev/null && ss -uln | grep -q ':${p} ') || (command -v netstat >/dev/null && netstat -uln | grep -q ':${p} ')`,
  ], { timeout: 8_000 });
  if (ss.ok) return { ok: true, via: 'ss/netstat', out: 'listening' };

  const inspect = await runCmd('docker', [
    'inspect', '-f',
    `{{range $p, $conf := .NetworkSettings.Ports}}{{if eq $p "${p}/udp"}}{{(index $conf 0).HostPort}}{{end}}{{end}}`,
    CONTAINER_NAME,
  ], { timeout: 8_000 });
  if (inspect.ok && inspect.stdout.trim()) {
    return { ok: true, via: 'docker-ports', out: inspect.stdout.trim() };
  }
  return { ok: false, via: 'probe', out: (ss.stderr || ss.stdout || 'not listening').trim().slice(0, 160) };
}

async function runSmoke() {
  const containerUp = await dockerContainerRunning();
  let versionOk = false;
  let versionOut = '';
  let configTest = { ok: false, via: 'skip', out: 'container down' };
  let dial = { ok: false, via: 'skip', out: 'container down' };
  const port = LISTEN_PORT;
  if (containerUp) {
    const ver = await runCmd('docker', ['exec', CONTAINER_NAME, 'hysteria', 'version'], { timeout: 10_000 });
    versionOk = ver.ok;
    versionOut = (ver.stdout || ver.stderr || '').trim().slice(0, 120);
    const test = await runCmd('docker', [
      'exec', CONTAINER_NAME, 'hysteria', 'server', '-c', '/opt/amnezia/awg/hysteria/server.yaml', '--test',
    ], { timeout: 15_000 });
    configTest = {
      ok: test.ok,
      via: 'hysteria-test',
      out: (test.stderr || test.stdout || (test.ok ? 'ok' : 'failed')).trim().slice(0, 160),
    };
    dial = await probeListenInsideContainer(port);
  }
  const ok = containerUp && versionOk && configTest.ok && dial.ok;
  lastSmoke = {
    ok,
    containerUp,
    versionOk,
    versionOut,
    configTest,
    dial,
    port,
    at: Date.now(),
  };
  return lastSmoke;
}

async function removeHysteriaContainer() {
  await runCmd('docker', ['stop', CONTAINER_NAME]);
  await runCmd('docker', ['rm', '-fv', CONTAINER_NAME]);
}

async function containerManagedByUs() {
  const r = await runCmd('docker', [
    'inspect', '-f', '{{index .Config.Labels "amnezia.managed"}} {{index .Config.Labels "amnezia.service"}}',
    CONTAINER_NAME,
  ]);
  if (!r.ok) return false;
  const parts = r.stdout.trim().split(/\s+/);
  return parts[0] === '1' && parts[1] === 'hysteria';
}

async function inspectContainerPublicPort() {
  const r = await runCmd('docker', [
    'inspect', '-f',
    '{{range $p, $conf := .NetworkSettings.Ports}}{{if eq $p "443/udp"}}{{(index $conf 0).HostPort}}{{end}}{{end}}',
    CONTAINER_NAME,
  ]);
  if (!r.ok) return null;
  const n = parseInt(r.stdout.trim(), 10);
  return Number.isFinite(n) ? n : null;
}

async function ensureHysteriaContainer() {
  await ensureHysteriaImage();
  const awgVolume = await resolveAwgVolumeName();
  const certVolume = await resolveCertbotVolumeName();
  const portPlan = require('./portPlan');
  const publicPort = getPublicPort();
  const network = await portPlan.resolveNginxNetwork();

  const running = await dockerContainerRunning();
  if (running && await containerManagedByUs()) {
    const curPub = await inspectContainerPublicPort();
    if (curPub === publicPort) {
      return { reused: true };
    }
  }

  if ((await runCmd('docker', ['inspect', CONTAINER_NAME])).ok) {
    await removeHysteriaContainer();
  }

  const runArgs = [
    'run', '-d',
    '--log-driver', 'none',
    '--restart', 'unless-stopped',
    '--name', CONTAINER_NAME,
    '--label', 'amnezia.managed=1',
    '--label', 'amnezia.service=hysteria',
    '--label', `amnezia.public_port=${publicPort}`,
    '--label', `amnezia.listen_port=${LISTEN_PORT}`,
    '-v', `${awgVolume}:/opt/amnezia/awg:rw`,
    '-v', `${certVolume}:/etc/letsencrypt:ro`,
    '-p', `${publicPort}:${LISTEN_PORT}/udp`,
  ];
  if (network) runArgs.push('--network', network);
  runArgs.push(IMAGE_NAME);

  const run = await runCmd('docker', runArgs, { timeout: 60_000 });
  if (!run.ok) {
    throw new Error(run.stderr.trim() || 'docker run amnezia-hysteria failed');
  }
  return { reused: false };
}

async function reloadHysteriaConfig() {
  const up = await dockerContainerRunning();
  if (!up) return;
  await runCmd('docker', ['restart', CONTAINER_NAME], { timeout: 60_000 });
}

async function syncClientsFromDb() {
  if (getDesired() !== true && phase !== 'running' && phase !== 'degraded') {
    return { skipped: true };
  }
  const enabled = ensureClientPasswords();
  const userpass = buildUserpassMap(enabled);
  const certDomain = resolveCertDomain();
  const sni = getSni();
  const masqueradeUrl = getMasqueradeUrl();
  const obj = buildServerYamlObject({
    userpass,
    masqueradeUrl,
    certDomain,
    sni,
  });
  writeServerYaml(obj);

  if (await dockerContainerRunning()) {
    const test = await runCmd('docker', [
      'exec', CONTAINER_NAME, 'hysteria', 'server', '-c', '/opt/amnezia/awg/hysteria/server.yaml', '--test',
    ], { timeout: 15_000 });
    if (!test.ok) {
      throw new Error((test.stderr || test.stdout || 'hysteria config test failed').trim().slice(0, 300));
    }
    await reloadHysteriaConfig();
  }
  return { ok: true, clients: enabled.length };
}

function isAmneziaHysteriaAvailable() {
  return phase === 'running' && lastSmoke && lastSmoke.ok === true;
}

function getStatus() {
  const desired = getDesired();
  const portPlan = require('./portPlan');
  const plan = portPlan.computePlan();
  const smokeOk = !!(lastSmoke && lastSmoke.ok === true);
  const healthy = phase === 'running' && smokeOk;
  return {
    desired: desired === true,
    desiredSet: desired !== null,
    phase,
    available: healthy,
    healthy,
    lastError,
    smoke: lastSmoke,
    container: CONTAINER_NAME,
    address: getPublicHost(),
    addressStored: getAddress() || null,
    sni: getSni(),
    sniStored: getSniStored(),
    masqueradeUrl: getMasqueradeUrl(),
    masqueradeUrlStored: getMasqueradeUrlStored(),
    masqueradeType: getMasqueradeType(),
    obfsType: getObfsType() || null,
    bandwidthUp: getBandwidthUp() || null,
    bandwidthDown: getBandwidthDown() || null,
    ignoreClientBandwidth: getIgnoreClientBandwidth(),
    certSource: getCertSource(),
    certDomain: resolveCertDomain(),
    certDomainStored: getCertDomainStored(),
    tlsInsecureClient: getTlsInsecureClient(),
    publicPort: getClientFacingPort(),
    listenPort: LISTEN_PORT,
    mode: 'udpDirect',
    udpDirect: plan.udpDirect || [],
    updatedAt,
    busy: Boolean(activeJob),
  };
}

async function regenerateClientConfigs() {
  try {
    const WireGuard = require('./WireGuard');
    await WireGuard.saveConfig();
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Amnezia Hysteria: saveConfig after toggle failed:', err.message);
  }
}

async function forceCleanup() {
  await removeHysteriaContainer();
  lastSmoke = null;
  setPhase('off');
}

async function enableInternal(opts = {}) {
  setPhase('installing');
  setDesired(true);
  const deadline = Date.now() + ENABLE_TIMEOUT_MS;
  try {
    const sidecarValidate = require('./sidecarValidate');
    const validation = sidecarValidate.validateHysteria(opts);
    if (!validation.ok) {
      const msg = Object.values(validation.fieldErrors || {}).join('; ') || 'Invalid Hysteria settings';
      throw Object.assign(new Error(msg), {
        status: 400,
        code: validation.code || 'HYSTERIA_VALIDATION',
        fieldErrors: validation.fieldErrors,
      });
    }

    const publicPort = opts.publicPort != null
      ? parseInt(String(opts.publicPort).trim(), 10)
      : getPublicPort();
    if (!Number.isFinite(publicPort) || publicPort < 1 || publicPort > 65535) {
      throw Object.assign(new Error('Invalid Hysteria public port (1–65535)'), {
        status: 400,
        code: 'HYSTERIA_BAD_PUBLIC_PORT',
      });
    }
    setSetting(PUBLIC_PORT_KEY, String(publicPort));

    const certSource = opts.certSource != null
      ? String(opts.certSource).trim().toLowerCase()
      : getCertSource();
    const certDomainOverride = opts.certDomain != null ? String(opts.certDomain).trim().toLowerCase() : '';
    const tlsMaterial = require('./tlsMaterial');
    const emailOpt = opts.email != null ? opts.email : (opts.certbotEmail != null ? opts.certbotEmail : null);
    if (emailOpt) tlsMaterial.setCertbotEmail(emailOpt);

    let sni = tlsMaterial.normalizeHostname(opts.sni != null ? String(opts.sni) : '');
    if (certSource === 'issue_le') {
      sni = sni || tlsMaterial.normalizeHostname(getSniStored() || getSni() || '');
    } else if (certSource === 'self_signed' || certSource === 'panel') {
      // empty SNI OK (bare IP / no client SNI)
      sni = sni || '';
    } else {
      sni = sni || tlsMaterial.normalizeHostname(getSniStored() || '') || '';
    }

    if (certSource === 'issue_le' && sni) {
      const { domainHasPublicDns } = require('./sniFinder');
      if (!(await domainHasPublicDns(sni))) {
        throw Object.assign(
          new Error(
            `SNI «${sni}» не резолвится в публичном DNS (нужен реальный hostname)`,
          ),
          { status: 400, code: 'HYSTERIA_SNI_NO_DNS' },
        );
      }
    }

    const addressRaw = opts.address != null ? String(opts.address).trim() : '';
    const address = addressRaw || getAddress() || getPublicHost();
    if (!address) {
      throw Object.assign(new Error('Hysteria address is required'), { status: 400, code: 'HYSTERIA_BAD_ADDRESS' });
    }

    const masqueradeRaw = opts.masqueradeUrl != null ? String(opts.masqueradeUrl).trim() : '';
    const masqueradeUrl = masqueradeRaw || getMasqueradeUrlStored() || pickDefaultMasqueradeUrl();
    const masqueradeType = opts.masqueradeType != null
      ? String(opts.masqueradeType).trim().toLowerCase()
      : getMasqueradeType();
    const obfsType = opts.obfsType != null ? String(opts.obfsType).trim().toLowerCase() : getObfsType();
    const obfsPassword = opts.obfsPassword != null ? String(opts.obfsPassword).trim() : getObfsPassword();
    const bandwidthUp = opts.bandwidthUp != null ? String(opts.bandwidthUp).trim() : getBandwidthUp();
    const bandwidthDown = opts.bandwidthDown != null ? String(opts.bandwidthDown).trim() : getBandwidthDown();
    const ignoreClientBw = opts.ignoreClientBandwidth != null
      ? (opts.ignoreClientBandwidth === true || opts.ignoreClientBandwidth === '1'
        || opts.ignoreClientBandwidth === 'true')
      : getIgnoreClientBandwidth();
    let tlsInsecure = opts.tlsInsecureClient != null
      ? (opts.tlsInsecureClient === true || opts.tlsInsecureClient === '1'
        || opts.tlsInsecureClient === 'true')
      : getTlsInsecureClient();
    if (certSource === 'self_signed' && opts.tlsInsecureClient == null) {
      tlsInsecure = true;
    }
    if (certSource === 'issue_le') tlsInsecure = false;

    setSetting(SNI_KEY, sni);
    setSetting(ADDRESS_KEY, address);
    setSetting(MASQUERADE_KEY, masqueradeUrl);
    setSetting(MASQUERADE_TYPE_KEY, masqueradeType === 'file' || masqueradeType === 'string' ? masqueradeType : 'proxy');
    setSetting(OBFS_TYPE_KEY, obfsType);
    setSetting(OBFS_PASSWORD_KEY, obfsPassword);
    setSetting(BANDWIDTH_UP_KEY, bandwidthUp);
    setSetting(BANDWIDTH_DOWN_KEY, bandwidthDown);
    setSetting(IGNORE_CLIENT_BW_KEY, ignoreClientBw ? '1' : '0');
    setSetting(CERT_SOURCE_KEY, certSource);
    setSetting(CERT_DOMAIN_KEY, certDomainOverride);
    setSetting(TLS_INSECURE_CLIENT_KEY, tlsInsecure ? '1' : '0');

    // Hysteria is UDP — panel cert on same port as panel HTTPS is allowed
    let certDomainForIssue = certDomainOverride;
    if (!certDomainForIssue) {
      if (certSource === 'panel') {
        certDomainForIssue = tlsMaterial.panelCertDomain() || 'localhost';
      } else if (certSource === 'issue_le') {
        certDomainForIssue = sni;
      } else {
        certDomainForIssue = sni || 'hysteria.local';
      }
    }
    await tlsMaterial.resolveCertMaterial({
      certSource,
      domain: certDomainForIssue,
      certPem: opts.certPem,
      keyPem: opts.keyPem,
      certPath: opts.certPath,
      keyPath: opts.keyPath,
      email: emailOpt || tlsMaterial.getCertbotEmail(),
      issueIfMissing: certSource === 'issue_le',
    });
    if (!(await tlsMaterial.certExistsInVolume(resolveCertDomain()))) {
      throw Object.assign(
        new Error(`Certificate not found for ${resolveCertDomain()}`),
        { status: 400, code: 'HYSTERIA_CERT_MISSING' },
      );
    }

    const portPlan = require('./portPlan');
    await portPlan.assertHostUdpPortsAvailable([publicPort], { allowSidecar: true });

    const enabled = ensureClientPasswords();
    const obj = buildServerYamlObject({
      userpass: buildUserpassMap(enabled),
      masqueradeUrl,
      certDomain: resolveCertDomain(),
      sni,
    });
    writeServerYaml(obj);

    await ensureHysteriaContainer();
    try {
      await portPlan.applyPlan();
    } catch (planErr) {
      // eslint-disable-next-line no-console
      console.error('Hysteria enable: portPlan.applyPlan failed:', planErr && planErr.message);
      setPhase('degraded', planErr);
    }
    await ensureHysteriaContainer();
    try {
      await portPlan.applyPlan();
    } catch (planErr) {
      // eslint-disable-next-line no-console
      console.error('Hysteria enable: portPlan retry failed:', planErr && planErr.message);
      if (phase !== 'degraded') setPhase('degraded', planErr);
    }

    let ready = false;
    while (Date.now() < deadline) {
      if (await dockerContainerRunning()) {
        const smoke = await runSmoke();
        if (smoke.ok) {
          ready = true;
          break;
        }
      }
      await new Promise((r) => setTimeout(r, 1500));
    }
    if (!ready) {
      const smoke = await runSmoke();
      throw Object.assign(
        new Error(
          `Hysteria did not become ready in time (listen=${smoke.dial && smoke.dial.out}; configTest=${smoke.configTest && smoke.configTest.out}; versionOk=${smoke.versionOk})`,
        ),
        { code: 'HYSTERIA_TIMEOUT', status: 504 },
      );
    }

    setPhase('running');
    await regenerateClientConfigs();
    return getStatus();
  } catch (err) {
    await forceCleanup();
    setDesired(false);
    try {
      await require('./portPlan').applyPlan();
    } catch { /* ignore */ }
    setPhase('error', err);
    await regenerateClientConfigs();
    throw err;
  }
}

async function disableInternal() {
  setPhase('removing');
  setDesired(false);
  try {
    await forceCleanup();
    try {
      await require('./portPlan').applyPlan();
    } catch { /* nginx may be down */ }
    setPhase('off');
    await regenerateClientConfigs();
    return getStatus();
  } catch (err) {
    setPhase('error', err);
    throw err;
  }
}

function withJob(fn) {
  if (activeJob) {
    const err = new Error('Amnezia Hysteria operation already in progress');
    err.status = 409;
    return Promise.reject(err);
  }
  activeJob = Promise.resolve()
    .then(fn)
    .finally(() => {
      activeJob = null;
    });
  return activeJob;
}

function enable(opts = {}) {
  return withJob(() => enableInternal(opts));
}

function disable() {
  return withJob(disableInternal);
}

function forceCleanupApi() {
  return withJob(async () => {
    setDesired(false);
    await forceCleanup();
    try {
      await require('./portPlan').applyPlan();
    } catch { /* ignore */ }
    setPhase('off');
    await regenerateClientConfigs();
    return getStatus();
  });
}

async function resetCredentialsInternal() {
  const rows = getDb().clients.getAll();
  for (const row of rows) {
    getDb().clients.setHysteriaPassword(row.id, generatePassword());
  }
  ensureClientPasswords();
  if (getDesired() === true || phase === 'running' || phase === 'degraded') {
    await syncClientsFromDb();
  } else {
    const enabled = ensureClientPasswords();
    writeServerYaml(buildServerYamlObject({
      userpass: buildUserpassMap(enabled),
      masqueradeUrl: getMasqueradeUrl(),
      certDomain: resolveCertDomain(),
      sni: getSni(),
    }));
  }
  await regenerateClientConfigs();
  return getStatus();
}

function resetCredentials() {
  return withJob(resetCredentialsInternal);
}

function findEnabledClientByName(name) {
  if (!name) return null;
  const rows = getDb().clients.getAll();
  const row = rows.find((c) => c.name === name);
  if (!row || !row.enabled) return null;
  if (!row.hysteria_password) {
    const password = generatePassword();
    getDb().clients.setHysteriaPassword(row.id, password);
    row.hysteria_password = password;
  }
  return row;
}

async function reconcile() {
  if (activeJob) return;
  const desired = getDesired();
  if (desired !== true) {
    if (await dockerContainerRunning() || phase === 'running' || phase === 'degraded' || phase === 'error') {
      try {
        await forceCleanup();
        try {
          await require('./portPlan').applyPlan();
        } catch { /* ignore */ }
      } catch {
        setPhase('off');
      }
    } else {
      setPhase('off');
    }
    return;
  }
  try {
    if (!getSetting(PUBLIC_PORT_KEY, '')) {
      setSetting(PUBLIC_PORT_KEY, String(getPublicPort()));
    }
    if (!(await dockerContainerRunning())) {
      setPhase('degraded', new Error('amnezia-hysteria container not running'));
      await syncClientsFromDb();
      await ensureHysteriaContainer();
    } else {
      await ensureHysteriaContainer();
    }
    await require('./portPlan').applyPlan();
    const smoke = await runSmoke();
    if (smoke.ok) setPhase('running');
    else setPhase('degraded', new Error(`smoke failed: ${smoke.dial && smoke.dial.out}`));
  } catch (err) {
    setPhase('degraded', err);
  }
}

function startReconcileTimer() {
  if (reconcileTimer) return;
  reconcileTimer = setInterval(() => {
    reconcile().catch(() => { /* ignore */ });
  }, RECONCILE_INTERVAL_MS);
  if (typeof reconcileTimer.unref === 'function') reconcileTimer.unref();
}

function stopReconcileTimer() {
  if (reconcileTimer) {
    clearInterval(reconcileTimer);
    reconcileTimer = null;
  }
}

async function bootAmneziaHysteria() {
  startReconcileTimer();
  await reconcile();
  return getStatus();
}

function stopAmneziaHysteria() {
  stopReconcileTimer();
}

module.exports = {
  CONTAINER_NAME,
  IMAGE_NAME,
  LISTEN_PORT,
  DEFAULT_SNI,
  DEFAULT_MASQUERADE,
  enable,
  disable,
  forceCleanup: forceCleanupApi,
  resetCredentials,
  getStatus,
  isAmneziaHysteriaAvailable,
  syncClientsFromDb,
  ensureClientPasswords,
  getClientHysteriaPayload,
  buildAmneziaHysteriaContainer,
  buildHy2Url,
  buildServerYamlObject,
  renderServerYaml,
  clientNameSlug,
  resolveCertDomain,
  certPathsForDomain,
  getPublicHost,
  getClientFacingPort,
  findEnabledClientByName,
  bootAmneziaHysteria,
  stopAmneziaHysteria,
  regenerateClientConfigs,
  ensureHysteriaContainer,
  pickDefaultMasqueradeUrl,
};
