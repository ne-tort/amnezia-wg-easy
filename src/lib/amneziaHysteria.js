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
const OBFS_GECKO_MIN_KEY = 'amnezia_hysteria_obfs_gecko_min';
const OBFS_GECKO_MAX_KEY = 'amnezia_hysteria_obfs_gecko_max';
const CONGESTION_TYPE_KEY = 'amnezia_hysteria_congestion_type';
const BBR_PROFILE_KEY = 'amnezia_hysteria_bbr_profile';
const ECH_ENABLED_KEY = 'amnezia_hysteria_ech_enabled';
const ECH_CONFIG_LIST_KEY = 'amnezia_hysteria_ech_config_list';
const echKeygen = require('./echKeygen');
const LISTEN_MODE_KEY = 'amnezia_hysteria_listen_mode';
const PORT_RANGE_KEY = 'amnezia_hysteria_port_range';
const REALM_URI_KEY = 'amnezia_hysteria_realm_uri';
const BANDWIDTH_UP_KEY = 'amnezia_hysteria_bandwidth_up';
const BANDWIDTH_DOWN_KEY = 'amnezia_hysteria_bandwidth_down';
const IGNORE_CLIENT_BW_KEY = 'amnezia_hysteria_ignore_client_bandwidth';
const CERT_SOURCE_KEY = 'amnezia_hysteria_cert_source';
const CERT_DOMAIN_KEY = 'amnezia_hysteria_cert_domain';
const SSL_CERT_ID_KEY = 'amnezia_hysteria_ssl_cert_id';
const TLS_INSECURE_CLIENT_KEY = 'amnezia_hysteria_tls_insecure_client';
const CORE_KEY = 'amnezia_hysteria_core';
const CORES = Object.freeze(['original', 'xray']);

const DEFAULT_SNI = 'www.sbb.ch';
const DEFAULT_MASQUERADE = 'https://www.sbb.ch/';

const MIRROR_BANK_SEED = path.join(__dirname, '..', '..', 'config', 'mirror-bank.seed.json');
const MIRROR_BANK_SEED_IN_IMAGE = path.join(__dirname, '..', 'config', 'mirror-bank.seed.json');

const {
  DOCKER_RESTART_POLICY,
  RECONCILE_INTERVAL_MS,
  ENABLE_TIMEOUT_MS,
  SMOKE_WAIT_MS,
  observeSidecarHealth,
} = require('./sidecarOrchestrator');

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

function getCore() {
  const raw = getSetting(CORE_KEY, 'original').trim().toLowerCase();
  return CORES.includes(raw) ? raw : 'original';
}

function setCore(core) {
  const c = String(core || 'original').trim().toLowerCase();
  setSetting(CORE_KEY, CORES.includes(c) ? c : 'original');
}

function isXrayCoreDesired() {
  return getDesired() === true && getCore() === 'xray';
}

/**
 * Build Hy2 inbound object for shared amnezia-xray server.json.
 * @param {{ listenPort: number }} opts
 */
function buildXrayInboundConfig(opts = {}) {
  const { buildHysteriaInbound } = require('./xrayHysteriaInbound');
  const tlsMaterial = require('./tlsMaterial');
  const clients = ensureClientPasswords();
  const users = clients.map((c) => ({
    auth: c.hysteria_password,
    email: c.name || c.username || c.id,
  }));
  const sni = getSni();
  const certDomain = getSetting(CERT_DOMAIN_KEY, '') || sni;
  const paths = tlsMaterial.certPathsForDomain(certDomain);
  const masqType = getMasqueradeType();
  const masqUrl = getMasqueradeUrl();
  /** @type {Record<string, unknown>|undefined} */
  let masquerade;
  if (masqType === 'proxy' && masqUrl) {
    masquerade = { type: 'proxy', url: masqUrl, rewriteHost: true };
  } else if (masqType === 'string') {
    masquerade = { type: 'string', content: masqUrl || 'ok' };
  } else if (masqType === 'file') {
    masquerade = { type: 'file', dir: '/var/www/html' };
  }
  const obfsType = getObfsType();
  const obfsPassword = getObfsPassword();
  const salamanderPassword = (
    (obfsType === 'salamander' || obfsType === 'gecko') && obfsPassword
  ) ? obfsPassword : '';
  const up = getBandwidthUp();
  const down = getBandwidthDown();
  return buildHysteriaInbound({
    port: opts.listenPort || 34443,
    users,
    sni,
    tlsCert: paths.cert,
    tlsKey: paths.key,
    up: up || undefined,
    down: down || undefined,
    masquerade,
    obfsType: obfsType || undefined,
    salamanderPassword: salamanderPassword || undefined,
    obfsPassword: salamanderPassword || undefined,
    obfsGeckoMin: getObfsGeckoMin(),
    obfsGeckoMax: getObfsGeckoMax(),
    udpIdleTimeout: 60,
  });
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

function getObfsGeckoMin() {
  const raw = getSetting(OBFS_GECKO_MIN_KEY, '').trim();
  return raw ? parseInt(raw, 10) : null;
}

function getObfsGeckoMax() {
  const raw = getSetting(OBFS_GECKO_MAX_KEY, '').trim();
  return raw ? parseInt(raw, 10) : null;
}

function getCongestionType() {
  const t = getSetting(CONGESTION_TYPE_KEY, 'bbr').trim().toLowerCase();
  return t === 'reno' ? 'reno' : 'bbr';
}

function getBbrProfile() {
  const p = getSetting(BBR_PROFILE_KEY, 'standard').trim().toLowerCase();
  if (p === 'conservative' || p === 'aggressive') return p;
  return 'standard';
}

function getEchEnabled() {
  const raw = getSetting(ECH_ENABLED_KEY, '');
  return raw === '1' || raw === 'true' || raw === 'yes' || raw === 'on';
}

function getEchConfigList() {
  return getSetting(ECH_CONFIG_LIST_KEY, '').trim();
}

function getListenMode() {
  const m = getSetting(LISTEN_MODE_KEY, 'direct').trim().toLowerCase();
  if (m === 'port_hopping' || m === 'realms') return m;
  return 'direct';
}

function getPortRange() {
  return getSetting(PORT_RANGE_KEY, '').trim();
}

function getRealmUri() {
  return getSetting(REALM_URI_KEY, '').trim();
}

function hysteriaHostDir() {
  return path.join(config.WG_PATH, HYSTERIA_REL);
}

function echKeyPathHost() {
  return path.join(hysteriaHostDir(), 'ech.pem');
}

function echKeyPathContainer() {
  return '/opt/amnezia/awg/hysteria/ech.pem';
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

async function dockerContainerStatus() {
  const r = await runCmd('docker', [
    'inspect', '-f', '{{.State.Status}}', CONTAINER_NAME,
  ]);
  if (!r.ok) return '';
  return String(r.stdout || '').trim().toLowerCase();
}

/** docker run -d can leave the container in "created" until the port bind finishes — start/wait. */
async function waitForHysteriaRunning(timeoutMs = 60_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const status = await dockerContainerStatus();
    if (status === 'running') return true;
    if (status === 'created' || status === 'exited' || status === 'dead') {
      await runCmd('docker', ['start', CONTAINER_NAME], { timeout: 30_000 });
    }
    await new Promise((r) => setTimeout(r, 1000));
  }
  return dockerContainerRunning();
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
  obfsType, obfsPassword, obfsGeckoMin, obfsGeckoMax,
  bandwidthUp, bandwidthDown, ignoreClientBandwidth,
  congestionType, bbrProfile, echEnabled, listenMode, portRange, realmUri,
}) {
  const paths = certPathsForDomain(certDomain);
  const mode = listenMode != null ? listenMode : getListenMode();
  let listen = `:${LISTEN_PORT}`;
  if (mode === 'port_hopping') {
    const range = (portRange != null ? portRange : getPortRange()) || '20000-50000';
    listen = `:${range}`;
  } else if (mode === 'realms') {
    const uri = (realmUri != null ? realmUri : getRealmUri()) || '';
    if (uri) listen = uri;
  }
  /** @type {Record<string, unknown>} */
  const obj = {
    listen,
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
  const echOn = echEnabled != null ? echEnabled : getEchEnabled();
  if (echOn && fs.existsSync(echKeyPathHost())) {
    obj.tls.ech = { keyPath: echKeyPathContainer() };
  }
  const mType = masqueradeType || getMasqueradeType();
  if (!masqueradeUrl && mType === 'proxy') {
    // No camouflage URL — minimal string response for unauthenticated probes
    obj.masquerade = { type: 'string', string: { content: 'ok', headers: {} } };
  } else if (mType === 'file') {
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
    /** @type {Record<string, unknown>} */
    const inner = { password: oPass };
    if (oType === 'gecko') {
      const gmin = obfsGeckoMin != null ? obfsGeckoMin : getObfsGeckoMin();
      const gmax = obfsGeckoMax != null ? obfsGeckoMax : getObfsGeckoMax();
      if (gmin != null && Number.isFinite(gmin)) inner.minPacketSize = gmin;
      if (gmax != null && Number.isFinite(gmax)) inner.maxPacketSize = gmax;
    }
    obj.obfs = { type: oType, [oType]: inner };
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
  const cType = congestionType != null ? congestionType : getCongestionType();
  const bbrProf = bbrProfile != null ? bbrProfile : getBbrProfile();
  obj.congestion = { type: cType };
  if (cType === 'bbr') obj.congestion.bbrProfile = bbrProf;
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
  if (obj.tls.ech && obj.tls.ech.keyPath) {
    lines.push('  ech:');
    lines.push(`    keyPath: ${yamlQuote(obj.tls.ech.keyPath)}`);
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
      if (inner.minPacketSize != null) {
        lines.push(`    minPacketSize: ${inner.minPacketSize}`);
      }
      if (inner.maxPacketSize != null) {
        lines.push(`    maxPacketSize: ${inner.maxPacketSize}`);
      }
    }
  }
  if (obj.congestion && obj.congestion.type) {
    lines.push('', 'congestion:');
    lines.push(`  type: ${yamlQuote(obj.congestion.type)}`);
    if (obj.congestion.bbrProfile) {
      lines.push(`  bbrProfile: ${yamlQuote(obj.congestion.bbrProfile)}`);
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
  obfsType, obfsPassword, insecure, ech,
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
  const echList = ech != null ? ech : getEchConfigList();
  if (echList) params.set('ech', echList);
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
  // Host-side publish map is reliable even when the image has no ss/netstat.
  const inspect = await runCmd('docker', [
    'inspect', '-f',
    `{{range $p, $conf := .NetworkSettings.Ports}}{{if eq $p "${p}/udp"}}{{(index $conf 0).HostPort}}{{end}}{{end}}`,
    CONTAINER_NAME,
  ], { timeout: 8_000 });
  if (inspect.ok && inspect.stdout.trim()) {
    return { ok: true, via: 'docker-ports', out: inspect.stdout.trim() };
  }

  const ss = await runCmd('docker', [
    'exec', CONTAINER_NAME, 'sh', '-c',
    `(command -v ss >/dev/null && ss -uln | grep -Eq '[:.]${p}([[:space:]]|$)') || (command -v netstat >/dev/null && netstat -uln | grep -Eq '[:.]${p}([[:space:]]|$)')`,
  ], { timeout: 8_000 });
  if (ss.ok) return { ok: true, via: 'ss/netstat', out: 'listening' };

  const status = await dockerContainerStatus();
  if (status === 'running') {
    const ver = await runCmd('docker', ['exec', CONTAINER_NAME, 'hysteria', 'version'], { timeout: 8_000 });
    if (ver.ok) return { ok: true, via: 'process', out: 'hysteria running (udp)' };
  }

  return { ok: false, via: 'probe', out: (ss.stderr || ss.stdout || status || 'not listening').trim().slice(0, 160) };
}

async function runSmoke() {
  const containerUp = await dockerContainerRunning();
  let versionOk = false;
  let versionOut = '';
  let dial = { ok: false, via: 'skip', out: 'container down' };
  const port = LISTEN_PORT;
  if (containerUp) {
    const ver = await runCmd('docker', ['exec', CONTAINER_NAME, 'hysteria', 'version'], { timeout: 10_000 });
    versionOk = ver.ok;
    versionOut = (ver.stdout || ver.stderr || '').trim().slice(0, 120);
    // Hysteria 2 has no `server --test`; treat process + UDP listen as health.
    dial = await probeListenInsideContainer(port);
  }
  const ok = containerUp && versionOk && dial.ok;
  lastSmoke = {
    ok,
    containerUp,
    versionOk,
    versionOut,
    dial,
    port,
    at: Date.now(),
  };
  return lastSmoke;
}

async function removeHysteriaContainer() {
  await runCmd('docker', ['stop', CONTAINER_NAME], { timeout: 30_000 });
  await runCmd('docker', ['rm', '-fv', CONTAINER_NAME], { timeout: 30_000 });
  const left = await runCmd('docker', ['inspect', CONTAINER_NAME], { timeout: 5_000 });
  if (left.ok) {
    throw new Error('failed to remove amnezia-hysteria container');
  }
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
      await waitForHysteriaRunning(30_000);
      return { reused: true };
    }
  }

  if ((await runCmd('docker', ['inspect', CONTAINER_NAME])).ok) {
    await removeHysteriaContainer();
  }

  const runArgs = [
    'run', '-d',
    '--log-driver', 'none',
    '--restart', DOCKER_RESTART_POLICY,
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
  const up = await waitForHysteriaRunning(60_000);
  if (!up) {
    const status = await dockerContainerStatus();
    throw new Error(`amnezia-hysteria did not reach running state (status=${status || 'missing'})`);
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
    core: getCore(),
    cores: CORES,
    address: getPublicHost(),
    addressStored: getAddress() || null,
    sni: getSni(),
    sniStored: getSniStored(),
    masqueradeUrl: getMasqueradeUrl(),
    masqueradeUrlStored: getMasqueradeUrlStored(),
    masqueradeType: getMasqueradeType(),
    obfsType: getObfsType() || null,
    obfsPassword: getObfsPassword() || null,
    obfsGeckoMin: getObfsGeckoMin(),
    obfsGeckoMax: getObfsGeckoMax(),
    congestionType: getCongestionType(),
    bbrProfile: getBbrProfile(),
    echEnabled: getEchEnabled(),
    echConfigList: getEchConfigList() || null,
    listenMode: getListenMode(),
    portRange: getPortRange() || null,
    realmUri: getRealmUri() || null,
    bandwidthUp: getBandwidthUp() || null,
    bandwidthDown: getBandwidthDown() || null,
    ignoreClientBandwidth: getIgnoreClientBandwidth(),
    certSource: getCertSource(),
    certDomain: resolveCertDomain(),
    certDomainStored: getCertDomainStored(),
    sslCertId: getSetting(SSL_CERT_ID_KEY, '') || null,
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
    const portPlan = require('./portPlan');
    const occ = portPlan.validateOccupancyConflicts('hysteria', opts);
    if (!occ.ok) {
      throw Object.assign(new Error(Object.values(occ.fieldErrors || {}).join('; ') || 'Port conflict'), {
        status: 409,
        code: occ.code || 'HOST_UDP_PORT_BUSY',
        fieldErrors: occ.fieldErrors,
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

    const coreEarly = opts.core != null ? String(opts.core).trim().toLowerCase() : getCore();
    await portPlan.assertHostUdpPortsAvailable([publicPort], {
      owner: coreEarly === 'xray' ? 'xray' : 'hysteria',
    });

    setDesired(true);
    const { resolveOptsSslCert } = require('./sidecarAutoCert');
    opts = await resolveOptsSslCert(opts, 'hysteria');

    setSetting(PUBLIC_PORT_KEY, String(publicPort));

    const sslManager = require('./sslManager');
    const sslCertId = String(opts.sslCertId || opts.ssl_cert_id || '').trim()
      || getSetting(SSL_CERT_ID_KEY, '');
    let inventoryCert = null;
    if (sslCertId) {
      inventoryCert = sslManager.requireSidecarCert(sslCertId, 'hysteria');
    }

    let certSource = opts.certSource != null
      ? String(opts.certSource).trim().toLowerCase()
      : getCertSource();
    let certDomainOverride = opts.certDomain != null ? String(opts.certDomain).trim().toLowerCase() : '';
    const tlsMaterial = require('./tlsMaterial');
    const emailOpt = opts.email != null ? opts.email : (opts.certbotEmail != null ? opts.certbotEmail : null);
    if (emailOpt) tlsMaterial.setCertbotEmail(emailOpt);

    let sni = tlsMaterial.normalizeHostname(opts.sni != null ? String(opts.sni) : '');
    if (inventoryCert) {
      sni = tlsMaterial.normalizeHostname(inventoryCert.sni || inventoryCert.domain || '') || '';
      if (inventoryCert.type === 'self_signed') certSource = 'self_signed';
      else if (inventoryCert.type === 'lets_encrypt' || inventoryCert.type === 'lets_encrypt_ip') certSource = 'issue_le';
      else if (inventoryCert.type === 'manual') certSource = 'manual_path';
      certDomainOverride = inventoryCert.storage_key || inventoryCert.domain || certDomainOverride;
    } else if (certSource === 'issue_le') {
      sni = sni || tlsMaterial.normalizeHostname(getSniStored() || getSni() || '');
    } else if (certSource === 'self_signed' || certSource === 'panel') {
      sni = sni || '';
    } else {
      sni = sni || tlsMaterial.normalizeHostname(getSniStored() || '') || '';
    }

    if (!inventoryCert && certSource === 'issue_le' && sni) {
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
    // Empty string from UI = intentionally no masquerade; only fall back when field omitted
    const masqueradeUrl = opts.masqueradeUrl != null
      ? masqueradeRaw
      : (getMasqueradeUrlStored() || pickDefaultMasqueradeUrl());
    const masqueradeType = opts.masqueradeType != null
      ? String(opts.masqueradeType).trim().toLowerCase()
      : (masqueradeUrl ? getMasqueradeType() : 'string');
    const obfsType = opts.obfsType != null ? String(opts.obfsType).trim().toLowerCase() : getObfsType();
    let obfsPassword = opts.obfsPassword != null ? String(opts.obfsPassword).trim() : getObfsPassword();
    if ((obfsType === 'salamander' || obfsType === 'gecko') && !obfsPassword) {
      obfsPassword = generatePassword();
    }
    const obfsGeckoMin = opts.obfsGeckoMin != null ? opts.obfsGeckoMin : (opts.obfs_gecko_min != null ? opts.obfs_gecko_min : null);
    const obfsGeckoMax = opts.obfsGeckoMax != null ? opts.obfsGeckoMax : (opts.obfs_gecko_max != null ? opts.obfs_gecko_max : null);
    const congestionType = opts.congestionType != null ? String(opts.congestionType).trim().toLowerCase()
      : (opts.congestion_type != null ? String(opts.congestion_type).trim().toLowerCase() : getCongestionType());
    const bbrProfile = opts.bbrProfile != null ? String(opts.bbrProfile).trim().toLowerCase()
      : (opts.bbr_profile != null ? String(opts.bbr_profile).trim().toLowerCase() : getBbrProfile());
    const echEnabled = opts.echEnabled != null
      ? (opts.echEnabled === true || opts.echEnabled === '1' || opts.echEnabled === 'true')
      : getEchEnabled();
    const listenMode = opts.listenMode != null ? String(opts.listenMode).trim().toLowerCase()
      : (opts.listen_mode != null ? String(opts.listen_mode).trim().toLowerCase() : getListenMode());
    const portRange = opts.portRange != null ? String(opts.portRange).trim()
      : (opts.port_range != null ? String(opts.port_range).trim() : getPortRange());
    const realmUri = opts.realmUri != null ? String(opts.realmUri).trim()
      : (opts.realm_uri != null ? String(opts.realm_uri).trim() : getRealmUri());
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
    setSetting(OBFS_GECKO_MIN_KEY, obfsGeckoMin != null ? String(obfsGeckoMin) : '');
    setSetting(OBFS_GECKO_MAX_KEY, obfsGeckoMax != null ? String(obfsGeckoMax) : '');
    setSetting(CONGESTION_TYPE_KEY, congestionType);
    setSetting(BBR_PROFILE_KEY, bbrProfile);
    setSetting(ECH_ENABLED_KEY, echEnabled ? '1' : '0');
    setSetting(LISTEN_MODE_KEY, listenMode);
    setSetting(PORT_RANGE_KEY, portRange);
    setSetting(REALM_URI_KEY, realmUri);
    setSetting(BANDWIDTH_UP_KEY, bandwidthUp);
    setSetting(BANDWIDTH_DOWN_KEY, bandwidthDown);
    setSetting(IGNORE_CLIENT_BW_KEY, ignoreClientBw ? '1' : '0');
    setSetting(CERT_SOURCE_KEY, certSource);
    setSetting(CERT_DOMAIN_KEY, certDomainOverride);
    setSetting(TLS_INSECURE_CLIENT_KEY, tlsInsecure ? '1' : '0');
    const core = opts.core != null ? String(opts.core).trim().toLowerCase() : getCore();
    setCore(core);
    if (inventoryCert) {
      setSetting(SSL_CERT_ID_KEY, inventoryCert.id);
    }

    // Hysteria is UDP — panel cert on same port as panel HTTPS is allowed
    if (inventoryCert) {
      const key = inventoryCert.storage_key || inventoryCert.domain;
      if (!(await tlsMaterial.certExistsInVolume(key))) {
        throw Object.assign(new Error(`Certificate files missing for ${key}`), {
          status: 400,
          code: 'HYSTERIA_CERT_MISSING',
        });
      }
      setSetting(CERT_DOMAIN_KEY, key);
    } else {
      let certDomainForIssue = certDomainOverride;
      if (!certDomainForIssue) {
        if (certSource === 'panel') {
          certDomainForIssue = tlsMaterial.panelCertDomain() || 'localhost';
        } else if (certSource === 'issue_le') {
          certDomainForIssue = sni;
        } else {
          certDomainForIssue = sni || require('./sidecarAutoCert').AUTO_SELF_SIGNED_HOST;
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
    }
    if (!(await tlsMaterial.certExistsInVolume(resolveCertDomain()))) {
      throw Object.assign(
        new Error(`Certificate not found for ${resolveCertDomain()}`),
        { status: 400, code: 'HYSTERIA_CERT_MISSING' },
      );
    }

    // UDP occupancy already asserted before setDesired
    const enabled = ensureClientPasswords();
    fs.mkdirSync(hysteriaHostDir(), { recursive: true });

    if (getCore() === 'xray') {
      // Shared amnezia-xray process (salamander/gecko via finalmask; no ECH/Hy2 YAML).
      await removeHysteriaContainer();
      const amneziaXray = require('./amneziaXray');
      await amneziaXray.syncClientsFromDb();
      await amneziaXray.ensureXrayContainer();
      await amneziaXray.reloadXrayConfig();
      try {
        await portPlan.applyPlan();
      } catch (planErr) {
        // eslint-disable-next-line no-console
        console.error('Hysteria(xray) enable: portPlan.applyPlan failed:', planErr && planErr.message);
        setPhase('degraded', planErr);
      }
      await regenerateClientConfigs();
      const xrayUp = (await runCmd('docker', ['inspect', '-f', '{{.State.Running}}', 'amnezia-xray'])).stdout.trim() === 'true';
      lastSmoke = { ok: !!xrayUp, via: 'xray-shared', at: Date.now() };
      if (Date.now() > deadline) {
        throw Object.assign(new Error('Hysteria (xray) enable timed out'), { status: 504, code: 'HYSTERIA_TIMEOUT' });
      }
      setPhase(xrayUp ? 'running' : 'degraded', xrayUp ? null : new Error('amnezia-xray not running'));
      return getStatus();
    }

    if (echEnabled) {
      await echKeygen.ensureEchMaterial({
        enabled: true,
        outPath: echKeyPathHost(),
        excludeSni: sni,
        getSetting,
        setSetting,
        runCmd,
        resolveVolume: resolveAwgVolumeName,
      });
    }

    const obj = buildServerYamlObject({
      userpass: buildUserpassMap(enabled),
      masqueradeUrl,
      certDomain: resolveCertDomain(),
      sni,
      obfsType,
      obfsPassword,
      obfsGeckoMin,
      obfsGeckoMax,
      congestionType,
      bbrProfile,
      echEnabled,
      listenMode,
      portRange,
      realmUri,
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
    const smokeDeadline = Date.now() + SMOKE_WAIT_MS;
    while (Date.now() < smokeDeadline) {
      if (Date.now() > deadline) {
        throw Object.assign(new Error('Hysteria enable timed out during setup'), {
          status: 504,
          code: 'HYSTERIA_TIMEOUT',
        });
      }
      await waitForHysteriaRunning(5_000);
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
          `Hysteria did not become ready in time (listen=${smoke.dial && smoke.dial.out}; versionOk=${smoke.versionOk})`,
        ),
        { code: 'HYSTERIA_TIMEOUT', status: 504 },
      );
    }

    if (echEnabled && !getEchConfigList()) {
      const logs = await runCmd('docker', ['logs', '--tail', '80', CONTAINER_NAME], { timeout: 15_000 });
      const fromLog = echKeygen.extractConfigListFromLog(logs.ok ? logs.stdout : '');
      if (fromLog) setSetting(ECH_CONFIG_LIST_KEY, fromLog);
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
  const wasXray = getCore() === 'xray';
  setDesired(false);
  try {
    await forceCleanup();
    if (wasXray) {
      try {
        const amneziaXray = require('./amneziaXray');
        await amneziaXray.syncClientsFromDb();
        await amneziaXray.ensureXrayContainer();
        await amneziaXray.reloadXrayConfig();
      } catch (err) {
        // eslint-disable-next-line no-console
        console.error('Hysteria disable: xray resync failed:', err && err.message);
      }
    }
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
  if (activeJob) return activeJob;
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
    if (getCore() === 'xray') {
      const xrayObserve = await observeSidecarHealth('amnezia-xray', async () => {
        const up = (await runCmd('docker', ['inspect', '-f', '{{.State.Running}}', 'amnezia-xray'])).stdout.trim() === 'true';
        return { ok: up };
      });
      lastSmoke = { ok: !xrayObserve.unhealthy, via: 'xray-shared', at: Date.now() };
      if (!xrayObserve.unhealthy) setPhase('running');
      else setPhase('degraded', xrayObserve.reason);
      return;
    }
    const { smoke, unhealthy, reason } = await observeSidecarHealth(CONTAINER_NAME, runSmoke);
    lastSmoke = smoke;
    if (!unhealthy) setPhase('running');
    else setPhase('degraded', reason);
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
  isXrayCoreDesired,
  buildXrayInboundConfig,
  getCore,
  getPublicPort,
  CORES,
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
