'use strict';

/**
 * Amnezia Mieru orchestration: mita Docker container (amnezia-mieru).
 * Direct TCP/UDP publish (-p public:listen); no SNI demux.
 * Desired state in app_settings; per-client password on clients.mieru_password.
 */

const { execFile } = require('node:child_process');
const { promisify } = require('node:util');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const config = require('../config');

const execFileAsync = promisify(execFile);

const CONTAINER_NAME = 'amnezia-mieru';
const IMAGE_NAME = 'amnezia-mieru';
const DOCKERFILE_FOLDER = '/opt/amnezia/mieru';
const PANEL_CONTAINER = 'amnezia-awg';
const MIERU_REL = 'mieru';
const SERVER_JSON = 'server.json';

const DESIRED_KEY = 'amnezia_mieru_desired';
const PORT_KEY = 'amnezia_mieru_port';
const PUBLIC_PORT_KEY = 'amnezia_mieru_public_port';
const PROTOCOL_KEY = 'amnezia_mieru_protocol';
const ADDRESS_KEY = 'amnezia_mieru_address';

const DEFAULT_PROTOCOL = 'TCP';
const PROTOCOLS = Object.freeze(['TCP', 'UDP']);
const DEFAULT_INTERNAL_PORT = 35000;
const DEFAULT_PUBLIC_PORT = 3080;
const CLOCK_SKEW_WARN_SEC = 30;

const ENABLE_TIMEOUT_MS = 180_000;
const RECONCILE_INTERVAL_MS = 30_000;

/** @type {'off'|'installing'|'running'|'degraded'|'removing'|'error'} */
let phase = 'off';
let lastError = null;
let lastSmoke = null;
let lastClockWarning = null;
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
  const fromDb = getSetting(PORT_KEY, '');
  if (fromDb && /^\d+$/.test(fromDb)) return parseInt(fromDb, 10);
  const fromEnv = parseInt(String(process.env.MIERU_PORT || '').trim(), 10);
  if (Number.isFinite(fromEnv) && fromEnv >= 1 && fromEnv <= 65535) return fromEnv;
  return DEFAULT_INTERNAL_PORT;
}

function getPublicPort() {
  const fromDb = getSetting(PUBLIC_PORT_KEY, '');
  if (fromDb && /^\d+$/.test(fromDb)) return parseInt(fromDb, 10);
  const fromEnv = parseInt(String(process.env.MIERU_PUBLIC_PORT || '').trim(), 10);
  if (Number.isFinite(fromEnv) && fromEnv >= 1 && fromEnv <= 65535) return fromEnv;
  return DEFAULT_PUBLIC_PORT;
}

/** Client-facing port (host publish). */
function getClientFacingPort() {
  return getPublicPort();
}

function getProtocol() {
  const p = (getSetting(PROTOCOL_KEY, DEFAULT_PROTOCOL) || DEFAULT_PROTOCOL).toUpperCase();
  return PROTOCOLS.includes(p) ? p : DEFAULT_PROTOCOL;
}

function excludedPortsForAlloc() {
  return [
    config.PANEL_HTTPS_PORT,
    getPublicPort(),
    80,
    443,
    8443,
  ];
}

/**
 * Internal listen port (20000–50000); never the public publish port.
 */
function resolveListenPort(preferred) {
  const { allocateInternalPort, needsInternalRealloc } = require('./internalPort');
  const publicPort = getPublicPort();
  const raw = preferred != null ? preferred : getPort();
  if (!needsInternalRealloc(raw) && parseInt(String(raw), 10) !== publicPort) {
    return parseInt(String(raw), 10);
  }
  return allocateInternalPort(excludedPortsForAlloc().concat([publicPort]), null);
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

function mieruHostDir() {
  return path.join(config.WG_PATH, MIERU_REL);
}

function serverJsonPath() {
  return path.join(mieruHostDir(), SERVER_JSON);
}

function ensureMieruDir() {
  fs.mkdirSync(mieruHostDir(), { recursive: true });
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

async function ensureMieruImage() {
  const inspect = await runCmd('docker', ['image', 'inspect', IMAGE_NAME]);
  if (inspect.ok) return;

  const dockerfilePath = path.join(DOCKERFILE_FOLDER, 'Dockerfile');
  if (!fs.existsSync(dockerfilePath)) {
    throw new Error('amnezia-mieru image missing; run deploy.sh');
  }
  const startPath = path.join(DOCKERFILE_FOLDER, 'start.sh');
  if (!fs.existsSync(startPath)) {
    throw new Error('amnezia-mieru start.sh missing; run deploy.sh');
  }
  const build = await runCmd('docker', ['build', '-t', IMAGE_NAME, DOCKERFILE_FOLDER], {
    timeout: 600_000,
  });
  if (!build.ok) {
    throw new Error((build.stderr || build.stdout || 'docker build amnezia-mieru failed').trim().slice(0, 400));
  }
}

/** Slug username from client display name (mita user name). */
function clientUsername(name) {
  const base = String(name || 'user')
    .normalize('NFKD')
    .replace(/[\u0300-\u036f]/g, '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 32);
  return base || 'user';
}

function randomPassword(len = 16) {
  return crypto.randomBytes(Math.ceil(len * 0.75)).toString('base64url').slice(0, len);
}

function setMieruPassword(id, password) {
  const now = Math.floor(Date.now() / 1000);
  getDb().prepare('UPDATE clients SET mieru_password = ?, updated_at = ? WHERE id = ?')
    .run(password || null, now, id);
}

/**
 * Ensure every client has mieru_password; return enabled clients with stable usernames.
 * @returns {Array<{ id: string, name: string, username: string, mieru_password: string, enabled: number }>}
 */
function ensureClientPasswords() {
  const db = getDb();
  const rows = db.clients.getAll();
  const enabled = [];
  for (const row of rows) {
    let password = row.mieru_password;
    if (!password) {
      password = randomPassword(16);
      setMieruPassword(row.id, password);
      row.mieru_password = password;
    }
    if (row.enabled) {
      enabled.push({
        id: row.id,
        name: row.name,
        mieru_password: password,
        enabled: row.enabled,
      });
    }
  }

  const seen = new Set();
  return enabled.map((c) => {
    let username = clientUsername(c.name);
    if (seen.has(username)) {
      username = `${username}-${String(c.id).slice(0, 6)}`.slice(0, 32);
    }
    seen.add(username);
    return { ...c, username };
  });
}

function buildServerConfigObject({ port, protocol }) {
  const users = ensureClientPasswords();
  return {
    port,
    protocol,
    loggingLevel: 'INFO',
    users: users.map((c) => ({
      name: c.username,
      password: c.mieru_password,
    })),
  };
}

function writeServerJson(obj) {
  ensureMieruDir();
  const p = serverJsonPath();
  fs.writeFileSync(p, `${JSON.stringify(obj, null, 2)}\n`, 'utf8');
  return p;
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
 * Build mierus:// share link.
 * @param {{ username: string, password: string, host: string, port: number, protocol: string }} p
 */
function buildMieruUrl({ username, password, host, port, protocol }) {
  const params = new URLSearchParams();
  params.set('port', String(Number(port)));
  params.set('protocol', protocol || DEFAULT_PROTOCOL);
  const userinfo = `${encodeURIComponent(username)}:${encodeURIComponent(password)}`;
  return `mierus://${userinfo}@${host}?${params.toString()}`;
}

/**
 * Client-facing Mieru payload for one panel client.
 * @param {{ id: string, name: string, mieru_password?: string, enabled?: number }} client
 */
function getClientMieruPayload(client) {
  if (!client || !client.enabled) return null;
  let password = client.mieru_password;
  if (!password) {
    const row = getDb().clients.getById(client.id);
    password = row && row.mieru_password;
  }
  if (!password) return null;

  const username = clientUsername(client.name);
  const host = getPublicHost();
  const port = getClientFacingPort();
  const protocol = getProtocol();
  const mieruUrl = buildMieruUrl({ username, password, host, port, protocol });

  return {
    username,
    password,
    host,
    port,
    protocol,
    mieruUrl,
  };
}

/**
 * Probe TCP listen inside container namespace (panel must not dial 127.0.0.1 on host).
 */
async function probeListenInsideContainer(port) {
  const p = String(port);
  const nc = await runCmd('docker', [
    'exec', CONTAINER_NAME, 'nc', '-z', '-w', '2', '127.0.0.1', p,
  ], { timeout: 8_000 });
  if (nc.ok) return { ok: true, via: 'nc', out: 'connected' };

  const bash = await runCmd('docker', [
    'exec', CONTAINER_NAME, 'sh', '-c', `echo >/dev/tcp/127.0.0.1/${p}`,
  ], { timeout: 8_000 });
  if (bash.ok) return { ok: true, via: 'sh', out: 'connected' };

  const out = (nc.stderr || nc.stdout || bash.stderr || bash.stdout || 'not listening')
    .trim()
    .slice(0, 160);
  return { ok: false, via: 'nc/sh', out: out || 'not listening' };
}

async function runSmoke() {
  const containerUp = await dockerContainerRunning();
  let statusOk = false;
  let statusOut = '';
  let dial = { ok: false, via: 'skip', out: 'container down' };
  const port = getPort();
  if (containerUp) {
    const st = await runCmd('docker', ['exec', CONTAINER_NAME, 'mita', 'status'], { timeout: 10_000 });
    statusOk = st.ok && /RUNNING/i.test(`${st.stdout}\n${st.stderr}`);
    statusOut = (st.stdout || st.stderr || '').trim().slice(0, 120);
    dial = await probeListenInsideContainer(port);
  }
  const ok = containerUp && statusOk && dial.ok;
  lastSmoke = {
    ok,
    containerUp,
    statusOk,
    statusOut,
    dial,
    port,
    at: Date.now(),
  };
  return lastSmoke;
}

/**
 * Mieru auth uses time-based keys — warn when NTP is off or clocks diverge.
 */
async function detectClockWarning() {
  const panelTs = Math.floor(Date.now() / 1000);
  let skewSeconds = 0;
  let ntpSynced = null;

  const timedate = await runCmd('timedatectl', ['show', '-p', 'NTPSynchronized', '--value']);
  if (timedate.ok) {
    const v = timedate.stdout.trim().toLowerCase();
    if (v === 'yes' || v === 'no') ntpSynced = v === 'yes';
  }

  if (await dockerContainerRunning()) {
    const r = await runCmd('docker', ['exec', CONTAINER_NAME, 'date', '+%s'], { timeout: 5_000 });
    if (r.ok) {
      const containerTs = parseInt(r.stdout.trim(), 10);
      if (Number.isFinite(containerTs)) {
        skewSeconds = Math.abs(panelTs - containerTs);
      }
    }
  }

  if (ntpSynced === false) {
    return {
      warning: true,
      message: 'NTP is not synchronized; mieru requires accurate system time',
      skewSeconds,
      ntpSynced: false,
    };
  }
  if (skewSeconds > CLOCK_SKEW_WARN_SEC) {
    return {
      warning: true,
      message: `Clock skew ${skewSeconds}s between panel and mieru container; enable NTP`,
      skewSeconds,
      ntpSynced,
    };
  }
  return { warning: false, message: null, skewSeconds, ntpSynced };
}

async function removeMieruContainer() {
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
  return parts[0] === '1' && parts[1] === 'mieru';
}

async function inspectContainerListenPort() {
  const r = await runCmd('docker', [
    'inspect', '-f',
    '{{range .Config.Env}}{{println .}}{{end}}',
    CONTAINER_NAME,
  ]);
  if (!r.ok) return null;
  const line = r.stdout.split(/\r?\n/).find((l) => l.startsWith('MIERU_SERVER_PORT='));
  if (!line) return null;
  const n = parseInt(line.slice('MIERU_SERVER_PORT='.length), 10);
  return Number.isFinite(n) ? n : null;
}

async function inspectPublishedPublicPort() {
  const r = await runCmd('docker', [
    'inspect', '-f', '{{json .HostConfig.PortBindings}}', CONTAINER_NAME,
  ]);
  if (!r.ok) return null;
  try {
    const bindings = JSON.parse(r.stdout.trim() || '{}');
    const proto = getProtocol().toLowerCase();
    const key = `${getPort()}/${proto}`;
    const altKey = `${getPort()}/tcp`;
    const entry = bindings[key] || bindings[altKey];
    if (!entry || !entry[0] || !entry[0].HostPort) return null;
    return parseInt(entry[0].HostPort, 10);
  } catch {
    return null;
  }
}

/**
 * Direct mode: publish publicPort → internal listenPort on host.
 */
async function ensureMieruContainer() {
  await ensureMieruImage();
  const volume = await resolveAwgVolumeName();
  const portPlan = require('./portPlan');
  const publicPort = getPublicPort();
  const port = resolveListenPort(getPort());
  if (String(port) !== String(getPort())) {
    setSetting(PORT_KEY, String(port));
  }

  const network = await portPlan.resolveNginxNetwork();
  const proto = getProtocol().toLowerCase();

  const running = await dockerContainerRunning();
  if (running && await containerManagedByUs()) {
    const envPort = await inspectContainerListenPort();
    const pub = await inspectPublishedPublicPort();
    const labelMode = await runCmd('docker', [
      'inspect', '-f', '{{index .Config.Labels "amnezia.port_mode"}}', CONTAINER_NAME,
    ]);
    const curMode = (labelMode.ok ? labelMode.stdout : '').trim();
    if (envPort === port && pub === publicPort && curMode === 'direct') {
      return { reused: true };
    }
  }

  if ((await runCmd('docker', ['inspect', CONTAINER_NAME])).ok) {
    await removeMieruContainer();
  }

  const runArgs = [
    'run', '-d',
    '--log-driver', 'none',
    '--restart', 'unless-stopped',
    '--name', CONTAINER_NAME,
    '--label', 'amnezia.managed=1',
    '--label', 'amnezia.service=mieru',
    '--label', 'amnezia.port_mode=direct',
    '--label', `amnezia.listen_port=${port}`,
    '--label', `amnezia.public_port=${publicPort}`,
    '-e', `MIERU_SERVER_PORT=${port}`,
    '-v', `${volume}:/opt/amnezia/awg:rw`,
    '-p', `${publicPort}:${port}/${proto}`,
  ];
  if (network) runArgs.push('--network', network);
  runArgs.push(IMAGE_NAME);

  const run = await runCmd('docker', runArgs, { timeout: 60_000 });
  if (!run.ok) {
    throw new Error(run.stderr.trim() || 'docker run amnezia-mieru failed');
  }
  return { reused: false };
}

async function reloadMieruConfig() {
  const up = await dockerContainerRunning();
  if (!up) return;
  await runCmd('docker', ['restart', CONTAINER_NAME], { timeout: 60_000 });
}

/**
 * Rewrite server.json users[] from DB and reload container when Mieru is desired/running.
 */
async function syncClientsFromDb() {
  if (getDesired() !== true && phase !== 'running' && phase !== 'degraded') {
    return { skipped: true };
  }
  const port = getPort();
  const protocol = getProtocol();
  const obj = buildServerConfigObject({ port, protocol });
  writeServerJson(obj);

  if (await dockerContainerRunning()) {
    await reloadMieruConfig();
  }
  return { ok: true, users: obj.users.length };
}

function isAmneziaMieruAvailable() {
  return phase === 'running' && lastSmoke && lastSmoke.ok === true;
}

function getStatus() {
  const desired = getDesired();
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
    clockWarning: lastClockWarning,
    container: CONTAINER_NAME,
    address: getPublicHost(),
    addressStored: getAddress() || null,
    port: getPort(),
    publicPort: getClientFacingPort(),
    protocol: getProtocol(),
    protocols: PROTOCOLS,
    mode: 'direct',
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
    console.error('Amnezia Mieru: saveConfig after toggle failed:', err.message);
  }
}

async function forceCleanup() {
  await removeMieruContainer();
  lastSmoke = null;
  setPhase('off');
}

async function enableInternal(opts = {}) {
  setPhase('installing');
  setDesired(true);
  const deadline = Date.now() + ENABLE_TIMEOUT_MS;
  try {
    const publicPort = opts.publicPort != null
      ? parseInt(String(opts.publicPort).trim(), 10)
      : getPublicPort();
    if (!Number.isFinite(publicPort) || publicPort < 1 || publicPort > 65535) {
      throw Object.assign(new Error('Invalid Mieru public port (1–65535)'), {
        status: 400,
        code: 'MIERU_BAD_PUBLIC_PORT',
      });
    }
    setSetting(PUBLIC_PORT_KEY, String(publicPort));

    let protocol = opts.protocol != null ? String(opts.protocol).trim().toUpperCase() : getProtocol();
    if (!PROTOCOLS.includes(protocol)) protocol = DEFAULT_PROTOCOL;
    setSetting(PROTOCOL_KEY, protocol);

    if (opts.port != null && String(opts.port).trim() !== '') {
      const requested = parseInt(String(opts.port).trim(), 10);
      if (!Number.isFinite(requested) || requested < 1 || requested > 65535) {
        throw Object.assign(new Error('Invalid Mieru listen port (1–65535)'), {
          status: 400,
          code: 'MIERU_BAD_PORT',
        });
      }
    }

    const port = resolveListenPort(
      opts.port != null && String(opts.port).trim() !== '' ? opts.port : getPort(),
    );

    const addressRaw = opts.address != null ? String(opts.address).trim() : '';
    const address = addressRaw || getAddress() || getPublicHost();
    if (!address) {
      throw Object.assign(new Error('Mieru address is required'), { status: 400, code: 'MIERU_BAD_ADDRESS' });
    }

    setSetting(PORT_KEY, String(port));
    setSetting(ADDRESS_KEY, address);

    await require('./portPlan').assertHostPortsAvailable([publicPort], { allowNginx: true });

    ensureClientPasswords();
    const obj = buildServerConfigObject({ port, protocol });
    writeServerJson(obj);

    await ensureMieruContainer();
    try {
      await require('./portPlan').applyPlan();
    } catch (planErr) {
      // eslint-disable-next-line no-console
      console.error('Mieru enable: portPlan.applyPlan failed:', planErr && planErr.message);
      setPhase('degraded', planErr);
    }
    await ensureMieruContainer();

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
          `Mieru did not become ready in time (listen=${smoke.dial && smoke.dial.out}; statusOk=${smoke.statusOk})`,
        ),
        { code: 'MIERU_TIMEOUT', status: 504 },
      );
    }

    lastClockWarning = await detectClockWarning();
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
    const err = new Error('Amnezia Mieru operation already in progress');
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
    const listenPort = resolveListenPort(getPort());
    if (String(listenPort) !== String(getPort())) {
      setSetting(PORT_KEY, String(listenPort));
      await syncClientsFromDb();
    }
    if (!(await dockerContainerRunning())) {
      setPhase('degraded', new Error('amnezia-mieru container not running'));
      await syncClientsFromDb();
      await ensureMieruContainer();
    } else {
      await ensureMieruContainer();
    }
    try {
      await require('./portPlan').applyPlan();
    } catch (planErr) {
      // eslint-disable-next-line no-console
      console.error('Mieru reconcile: portPlan.applyPlan failed:', planErr && planErr.message);
    }
    lastClockWarning = await detectClockWarning();
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

async function bootAmneziaMieru() {
  startReconcileTimer();
  await reconcile();
  return getStatus();
}

function stopAmneziaMieru() {
  stopReconcileTimer();
}

module.exports = {
  CONTAINER_NAME,
  IMAGE_NAME,
  DEFAULT_PROTOCOL,
  PROTOCOLS,
  enable,
  disable,
  forceCleanup: forceCleanupApi,
  getStatus,
  isAmneziaMieruAvailable,
  syncClientsFromDb,
  getClientMieruPayload,
  buildMieruUrl,
  bootAmneziaMieru,
  stopAmneziaMieru,
  ensureMieruContainer,
  ensureClientPasswords,
  clientUsername,
  randomPassword,
  probeListenInsideContainer,
  detectClockWarning,
};
