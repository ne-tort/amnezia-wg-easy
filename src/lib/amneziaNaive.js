'use strict';

/**
 * Amnezia Naive orchestration: Caddy forward_proxy Docker container (amnezia-naive).
 * Desired state in app_settings; per-client naive_password for forward_proxy basic_auth.
 */

const { spawn, execFile } = require('node:child_process');
const { promisify } = require('node:util');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const config = require('../config');

const execFileAsync = promisify(execFile);

const CONTAINER_NAME = 'amnezia-naive';
const IMAGE_NAME = 'amnezia-naive';
const DOCKERFILE_FOLDER = '/opt/amnezia/naive';
const PANEL_CONTAINER = 'amnezia-awg';
const NAIVE_REL = 'naive';
const CADDYFILE_NAME = 'Caddyfile';
/** Internal TCP listen inside amnezia-naive (nginx demux upstream). */
const INTERNAL_PORT = 8443;

const DESIRED_KEY = 'amnezia_naive_desired';
const SNI_KEY = 'amnezia_naive_sni';
const PUBLIC_PORT_KEY = 'amnezia_naive_public_port';
const ADDRESS_KEY = 'amnezia_naive_address';
const PROBE_KEY = 'amnezia_naive_probe_resistance_domain';

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

function getPort() {
  return INTERNAL_PORT;
}

function getPublicPort() {
  const fromDb = getSetting(PUBLIC_PORT_KEY, '');
  if (fromDb && /^\d+$/.test(fromDb)) return parseInt(fromDb, 10);
  const fromEnv = parseInt(String(process.env.NAIVE_PUBLIC_PORT || '').trim(), 10);
  if (Number.isFinite(fromEnv) && fromEnv >= 1 && fromEnv <= 65535) return fromEnv;
  return 443;
}

/** Client-facing TCP (public / demux port). */
function getClientFacingPort() {
  return getPublicPort();
}

function assertSniDemux(sni, publicPort) {
  require('./portPlan').assertSniConflict(
    'naive',
    sni,
    publicPort != null ? publicPort : getPublicPort(),
  );
}

function getSni() {
  return getSetting(SNI_KEY, '').trim();
}

function getSniStored() {
  return getSetting(SNI_KEY, '') || null;
}

function getProbeResistanceDomain() {
  return getSetting(PROBE_KEY, '').trim();
}

function isFqdn(host) {
  const s = String(host || '').trim().toLowerCase();
  if (!s || s === 'localhost') return false;
  const portPlan = require('./portPlan');
  if (portPlan.isIpLiteral(s)) return false;
  return s.includes('.');
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

function naiveHostDir() {
  return path.join(config.WG_PATH, NAIVE_REL);
}

function caddyfilePath() {
  return path.join(naiveHostDir(), CADDYFILE_NAME);
}

function ensureNaiveDir() {
  fs.mkdirSync(naiveHostDir(), { recursive: true });
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
    'nginx',
  ]);
  const name = (r.ok ? r.stdout : '').trim();
  if (name) return name;
  return `${process.env.COMPOSE_PROJECT_NAME || 'amnezia-wg-easy'}_certbot_conf`;
}

async function ensureNaiveImage() {
  const inspect = await runCmd('docker', ['image', 'inspect', IMAGE_NAME]);
  if (inspect.ok) return;

  const dockerfilePath = path.join(DOCKERFILE_FOLDER, 'Dockerfile');
  if (!fs.existsSync(dockerfilePath)) {
    throw new Error('amnezia-naive image missing; run deploy.sh');
  }
  const dockerfile = fs.readFileSync(dockerfilePath, 'utf8');
  await new Promise((resolve, reject) => {
    const child = spawn('docker', ['build', '-t', IMAGE_NAME, '-'], {
      stdio: ['pipe', 'ignore', 'pipe'],
    });
    let err = '';
    const timer = setTimeout(() => {
      try { child.kill('SIGKILL'); } catch (_) { /* ignore */ }
      reject(new Error('docker build amnezia-naive timed out'));
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

/**
 * Basic-auth username for forward_proxy (client name, sanitized).
 * @param {{ id: string, name?: string }} client
 */
function basicAuthUser(client) {
  const raw = String(client.name || client.id || '').trim();
  const safe = raw.replace(/[\s\r\n\t#"]/g, '_').slice(0, 64);
  return safe || String(client.id);
}

/**
 * Ensure every client has a stable naive_password; return enabled clients for Caddyfile.
 * @returns {Array<{ id: string, name: string, naive_password: string, enabled: number }>}
 */
function ensureClientPasswords() {
  const db = getDb();
  const rows = db.clients.getAll();
  const out = [];
  for (const row of rows) {
    let pwd = row.naive_password;
    if (!pwd) {
      pwd = crypto.randomBytes(16).toString('base64url');
      db.clients.setNaivePassword(row.id, pwd);
      row.naive_password = pwd;
    }
    if (row.enabled) {
      out.push({
        id: row.id,
        name: row.name,
        naive_password: pwd,
        enabled: row.enabled,
      });
    }
  }
  return out;
}

/**
 * @param {{ port: number, sni: string, probeDomain?: string, clients: Array<{ name: string, naive_password: string, id: string }> }} opts
 */
function buildCaddyfileObject(opts) {
  const sni = String(opts.sni || '').trim().toLowerCase();
  const port = opts.port || INTERNAL_PORT;
  const certBase = `/etc/letsencrypt/live/${sni}`;
  const lines = [
    '{',
    '  order forward_proxy before file_server',
    '}',
    '',
    `:${port}, ${sni} {`,
    `  tls ${certBase}/fullchain.pem ${certBase}/privkey.pem`,
    '  forward_proxy {',
  ];
  for (const c of opts.clients || []) {
    const user = basicAuthUser(c);
    const pass = String(c.naive_password || '');
    if (!user || !pass) continue;
    lines.push(`    basic_auth ${user} ${pass}`);
  }
  lines.push('    hide_ip');
  lines.push('    hide_via');
  const probe = String(opts.probeDomain || '').trim();
  if (probe) {
    lines.push(`    probe_resistance ${probe}`);
  }
  lines.push('  }');
  lines.push('  file_server {');
  lines.push('    root /var/www/html');
  lines.push('  }');
  lines.push('}');
  lines.push('');
  return lines.join('\n');
}

function writeCaddyfile(text) {
  ensureNaiveDir();
  const p = caddyfilePath();
  fs.writeFileSync(p, text.endsWith('\n') ? text : `${text}\n`, 'utf8');
  return p;
}

/**
 * Client Naive JSON for share links / Amnezia export.
 * @param {{ listen?: string, proxy: string }} params
 */
function buildClientJson({ listen, proxy }) {
  return {
    listen: listen || 'socks://127.0.0.1:1080',
    proxy,
  };
}

/**
 * Build naive+json:// share link (base64 JSON).
 */
function buildNaiveShareUrl(clientJson) {
  const payload = Buffer.from(JSON.stringify(clientJson), 'utf8').toString('base64');
  return `naive+json://${payload}`;
}

/**
 * Public TCP address for client proxy URL (not TLS SNI hostname).
 */
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
 * @param {{ id: string, name: string, naive_password?: string, enabled?: number }} client
 * @param {{ baseUrl?: string }} [opts]
 */
function getClientNaivePayload(client, opts = {}) {
  if (!client || !client.naive_password) return null;
  const host = getPublicHost();
  const port = getClientFacingPort();
  const sni = getSni();
  if (!sni) return null;

  const user = basicAuthUser(client);
  const pass = client.naive_password;
  const hostPart = host.includes(':') && !host.startsWith('[') ? `[${host}]` : host;
  const portPart = port === 443 ? '' : `:${port}`;
  const proxy = `https://${encodeURIComponent(user)}:${encodeURIComponent(pass)}@${hostPart}${portPart}`;

  const clientJson = buildClientJson({ proxy });
  const shareUrl = buildNaiveShareUrl(clientJson);

  const base = (opts.baseUrl || '').replace(/\/+$/, '');
  const subPrefix = String(
    opts.subPublicPrefix != null ? opts.subPublicPrefix : (require('../config').SUB_PUBLIC_PREFIX || '/sub'),
  ).replace(/\/+$/, '') || '/sub';
  const subPath = `${subPrefix}/${encodeURIComponent(client.name)}`;
  const subUrl = base ? `${base}${subPath}` : subPath;

  return {
    shareUrl,
    subUrl,
    subPath,
    clientJson,
    port,
    sni,
    host,
    user,
  };
}

const AMNEZIA_NAIVE_SUBNET = '10.8.2.0';

/**
 * Amnezia `.vpn` naive container block.
 */
function buildAmneziaNaiveContainer(client) {
  const payload = getClientNaivePayload(client);
  if (!payload) return null;
  return {
    container: 'amnezia-naive',
    naive: {
      last_config: `${JSON.stringify(payload.clientJson, null, 4)}\n`,
      port: String(payload.port),
      subnet_address: AMNEZIA_NAIVE_SUBNET,
      transport_proto: 'tcp',
    },
  };
}

async function probeListenInsideContainer(port) {
  const p = String(port);
  const ss = await runCmd('docker', [
    'exec', CONTAINER_NAME, 'sh', '-c',
    `(ss -ltn 2>/dev/null || netstat -ltn 2>/dev/null) | grep -q ":${p} "`,
  ], { timeout: 8_000 });
  if (ss.ok) return { ok: true, via: 'ss', out: 'listening' };

  const nc = await runCmd('docker', [
    'exec', CONTAINER_NAME, 'nc', '-z', '-w', '2', '127.0.0.1', p,
  ], { timeout: 8_000 });
  if (nc.ok) return { ok: true, via: 'nc', out: 'connected' };

  const out = (ss.stderr || ss.stdout || nc.stderr || nc.stdout || 'not listening')
    .trim()
    .slice(0, 160);
  return { ok: false, via: 'ss/nc', out: out || 'not listening' };
}

async function runSmoke() {
  const containerUp = await dockerContainerRunning();
  let versionOk = false;
  let versionOut = '';
  let dial = { ok: false, via: 'skip', out: 'container down' };
  const port = getPort();
  if (containerUp) {
    const ver = await runCmd('docker', ['exec', CONTAINER_NAME, 'caddy', 'version'], { timeout: 10_000 });
    versionOk = ver.ok;
    versionOut = (ver.stdout || ver.stderr || '').trim().slice(0, 120);
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

function normalizePort(raw, fallback = INTERNAL_PORT) {
  const n = parseInt(String(raw == null ? '' : raw).trim(), 10);
  if (!Number.isFinite(n) || n < 1 || n > 65535) return fallback;
  return n;
}

async function removeNaiveContainer() {
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
  return parts[0] === '1' && parts[1] === 'naive';
}

async function ensureNaiveContainer() {
  await ensureNaiveImage();
  const volume = await resolveAwgVolumeName();
  const certbotVol = await resolveCertbotVolumeName();
  const portPlan = require('./portPlan');
  const mode = portPlan.modeForService('naive') || 'direct';
  const publicPort = getPublicPort();
  const port = getPort();

  const network = await portPlan.resolveNginxNetwork();
  if (mode === 'demux' && !network) {
    throw new Error('nginx compose network not found; is nginx running?');
  }

  const running = await dockerContainerRunning();
  if (running && await containerManagedByUs()) {
    const labelMode = await runCmd('docker', [
      'inspect', '-f', '{{index .Config.Labels "amnezia.port_mode"}}', CONTAINER_NAME,
    ]);
    const curMode = (labelMode.ok ? labelMode.stdout : '').trim();
    if (curMode === mode) {
      return { reused: true };
    }
  }

  if ((await runCmd('docker', ['inspect', CONTAINER_NAME])).ok) {
    await removeNaiveContainer();
  }

  const runArgs = [
    'run', '-d',
    '--log-driver', 'none',
    '--restart', 'unless-stopped',
    '--name', CONTAINER_NAME,
    '--label', 'amnezia.managed=1',
    '--label', 'amnezia.service=naive',
    '--label', `amnezia.port_mode=${mode}`,
    '--label', `amnezia.listen_port=${port}`,
    '--label', `amnezia.public_port=${publicPort}`,
    '-v', `${volume}:/opt/amnezia/awg:rw`,
    '-v', `${certbotVol}:/etc/letsencrypt:ro`,
  ];
  if (mode === 'demux') {
    runArgs.push('--network', network);
  } else {
    if (network) runArgs.push('--network', network);
    runArgs.push('-p', `${publicPort}:${port}/tcp`);
  }
  runArgs.push(IMAGE_NAME);

  const run = await runCmd('docker', runArgs, { timeout: 60_000 });
  if (!run.ok) {
    throw new Error(run.stderr.trim() || 'docker run amnezia-naive failed');
  }
  return { reused: false };
}

async function reloadNaiveConfig() {
  const up = await dockerContainerRunning();
  if (!up) return;
  await runCmd('docker', ['restart', CONTAINER_NAME], { timeout: 60_000 });
}

/**
 * Rewrite Caddyfile from DB and reload container when Naive is desired/running.
 */
async function syncClientsFromDb() {
  if (getDesired() !== true && phase !== 'running' && phase !== 'degraded') {
    return { skipped: true };
  }
  const sni = getSni();
  if (!sni) {
    throw new Error('Naive SNI (FQDN) is required');
  }
  const clients = ensureClientPasswords();
  const text = buildCaddyfileObject({
    port: getPort(),
    sni,
    probeDomain: getProbeResistanceDomain(),
    clients,
  });
  writeCaddyfile(text);

  if (await dockerContainerRunning()) {
    const validate = await runCmd('docker', [
      'exec', CONTAINER_NAME, 'caddy', 'validate', '--config', '/opt/amnezia/awg/naive/Caddyfile', '--adapter', 'caddyfile',
    ], { timeout: 15_000 });
    if (!validate.ok) {
      throw new Error((validate.stderr || validate.stdout || 'caddy validate failed').trim().slice(0, 300));
    }
    await reloadNaiveConfig();
  }
  return { ok: true, clients: clients.length };
}

function isAmneziaNaiveAvailable() {
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
    sni: getSni() || null,
    sniStored: getSniStored(),
    probeResistanceDomain: getProbeResistanceDomain() || null,
    port: getPort(),
    publicPort: getClientFacingPort(),
    mode: plan.modes.naive || null,
    demuxPeers: plan.demuxPeers.naive || [],
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
    console.error('Amnezia Naive: saveConfig after toggle failed:', err.message);
  }
}

async function forceCleanup() {
  await removeNaiveContainer();
  lastSmoke = null;
  setPhase('off');
}

async function enableInternal(opts = {}) {
  setPhase('installing');
  setDesired(true);
  const deadline = Date.now() + ENABLE_TIMEOUT_MS;
  try {
    const sni = (opts.sni != null ? String(opts.sni).trim() : '') || getSni();
    if (!sni || !isFqdn(sni)) {
      throw Object.assign(new Error('Naive SNI must be a valid FQDN'), {
        status: 400,
        code: 'NAIVE_BAD_SNI',
      });
    }

    const publicPort = opts.publicPort != null
      ? parseInt(String(opts.publicPort).trim(), 10)
      : getPublicPort();
    if (!Number.isFinite(publicPort) || publicPort < 1 || publicPort > 65535) {
      throw Object.assign(new Error('Invalid Naive public port (1–65535)'), {
        status: 400,
        code: 'NAIVE_BAD_PUBLIC_PORT',
      });
    }
    setSetting(PUBLIC_PORT_KEY, String(publicPort));
    assertSniDemux(sni, publicPort);

    const probeDomain = opts.probeResistanceDomain != null
      ? String(opts.probeResistanceDomain).trim()
      : getProbeResistanceDomain();
    if (probeDomain) {
      setSetting(PROBE_KEY, probeDomain);
    }

    const portPlan = require('./portPlan');
    const tentativeMode = (() => {
      const panelPub = parseInt(String(config.PANEL_HTTPS_PORT || '10123'), 10);
      if (panelPub === publicPort) return 'demux';
      return 'direct';
    })();

    const addressRaw = opts.address != null ? String(opts.address).trim() : '';
    const address = addressRaw || getAddress() || getPublicHost();
    if (!address) {
      throw Object.assign(new Error('Naive address is required'), { status: 400, code: 'NAIVE_BAD_ADDRESS' });
    }

    setSetting(SNI_KEY, sni);
    setSetting(ADDRESS_KEY, address);

    if (tentativeMode === 'direct') {
      await portPlan.assertHostPortsAvailable([publicPort], { allowNginx: true });
    }

    ensureClientPasswords();
    const text = buildCaddyfileObject({
      port: getPort(),
      sni,
      probeDomain: probeDomain || getProbeResistanceDomain(),
      clients: ensureClientPasswords(),
    });
    writeCaddyfile(text);

    await ensureNaiveContainer();
    try {
      await portPlan.applyPlan();
    } catch (planErr) {
      // eslint-disable-next-line no-console
      console.error('Naive enable: portPlan.applyPlan failed:', planErr && planErr.message);
      setPhase('degraded', planErr);
    }
    await ensureNaiveContainer();
    try {
      await portPlan.applyPlan();
    } catch (planErr) {
      // eslint-disable-next-line no-console
      console.error('Naive enable: portPlan retry failed:', planErr && planErr.message);
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
          `Naive did not become ready in time (listen=${smoke.dial && smoke.dial.out}; versionOk=${smoke.versionOk})`,
        ),
        { code: 'NAIVE_TIMEOUT', status: 504 },
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
    const err = new Error('Amnezia Naive operation already in progress');
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
    getDb().clients.setNaivePassword(row.id, crypto.randomBytes(16).toString('base64url'));
  }
  ensureClientPasswords();
  if (getDesired() === true || phase === 'running' || phase === 'degraded') {
    await syncClientsFromDb();
  } else {
    const sni = getSni();
    if (sni) {
      writeCaddyfile(buildCaddyfileObject({
        port: getPort(),
        sni,
        probeDomain: getProbeResistanceDomain(),
        clients: ensureClientPasswords(),
      }));
    }
  }
  await regenerateClientConfigs();
  return getStatus();
}

function resetCredentials() {
  return withJob(resetCredentialsInternal);
}

/**
 * @param {string} name
 */
function findEnabledClientByName(name) {
  if (!name) return null;
  const rows = getDb().clients.getAll();
  const row = rows.find((c) => c.name === name);
  if (!row || !row.enabled) return null;
  if (!row.naive_password) {
    const pwd = crypto.randomBytes(16).toString('base64url');
    getDb().clients.setNaivePassword(row.id, pwd);
    row.naive_password = pwd;
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
      setPhase('degraded', new Error('amnezia-naive container not running'));
      await syncClientsFromDb();
      await ensureNaiveContainer();
    } else {
      await ensureNaiveContainer();
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

async function bootAmneziaNaive() {
  startReconcileTimer();
  await reconcile();
  return getStatus();
}

function stopAmneziaNaive() {
  stopReconcileTimer();
}

module.exports = {
  CONTAINER_NAME,
  IMAGE_NAME,
  INTERNAL_PORT,
  enable,
  disable,
  forceCleanup: forceCleanupApi,
  resetCredentials,
  getStatus,
  isAmneziaNaiveAvailable,
  syncClientsFromDb,
  ensureClientPasswords,
  getClientNaivePayload,
  buildAmneziaNaiveContainer,
  buildNaiveShareUrl,
  buildClientJson,
  buildCaddyfileObject,
  basicAuthUser,
  normalizePort,
  getPublicHost,
  getClientFacingPort,
  findEnabledClientByName,
  bootAmneziaNaive,
  stopAmneziaNaive,
  regenerateClientConfigs,
  ensureNaiveContainer,
  probeListenInsideContainer,
  assertSniDemux,
};
