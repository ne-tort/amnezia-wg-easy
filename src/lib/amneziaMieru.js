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
const TCP_ENABLED_KEY = 'amnezia_mieru_tcp_enabled';
const UDP_ENABLED_KEY = 'amnezia_mieru_udp_enabled';
const TCP_PUBLIC_PORT_KEY = 'amnezia_mieru_tcp_public_port';
const UDP_PUBLIC_PORT_KEY = 'amnezia_mieru_udp_public_port';
const TCP_PORT_KEY = 'amnezia_mieru_tcp_port';
const UDP_PORT_KEY = 'amnezia_mieru_udp_port';
const MTU_KEY = 'amnezia_mieru_mtu';
const LOGGING_LEVEL_KEY = 'amnezia_mieru_logging_level';
const MULTIPLEXING_KEY = 'amnezia_mieru_multiplexing';
const HANDSHAKE_MODE_KEY = 'amnezia_mieru_handshake_mode';

const DEFAULT_PROTOCOL = 'TCP';
const PROTOCOLS = Object.freeze(['TCP', 'UDP']);
const LOGGING_LEVELS = Object.freeze(['ERROR', 'WARN', 'INFO', 'DEBUG']);
const MULTIPLEXING_LEVELS = Object.freeze(['OFF', 'LOW', 'MIDDLE', 'HIGH']);
const HANDSHAKE_MODES = Object.freeze(['HANDSHAKE_STANDARD', 'HANDSHAKE_NO_WAIT']);
const DEFAULT_MULTIPLEXING = 'LOW';
const DEFAULT_HANDSHAKE_MODE = 'HANDSHAKE_STANDARD';
const MTU_MIN = 1280;
const MTU_MAX = 1400;
const DEFAULT_INTERNAL_PORT = 35000;
const DEFAULT_PUBLIC_PORT = 3080;
const CLOCK_SKEW_WARN_SEC = 30;

const {
  DOCKER_RESTART_POLICY,
  RECONCILE_INTERVAL_MS,
  ENABLE_TIMEOUT_MS,
  observeSidecarHealth,
} = require('./sidecarOrchestrator');

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

function getTcpPublicPort() {
  const fromDb = getSetting(TCP_PUBLIC_PORT_KEY, '');
  if (fromDb && /^\d+$/.test(fromDb)) return parseInt(fromDb, 10);
  return getPublicPort();
}

function getUdpPublicPort() {
  const fromDb = getSetting(UDP_PUBLIC_PORT_KEY, '');
  if (fromDb && /^\d+$/.test(fromDb)) return parseInt(fromDb, 10);
  const fromEnv = parseInt(String(process.env.MIERU_UDP_PUBLIC_PORT || process.env.MIERU_PUBLIC_PORT || '').trim(), 10);
  if (Number.isFinite(fromEnv) && fromEnv >= 1 && fromEnv <= 65535) return fromEnv;
  return getPublicPort();
}

/** Primary client-facing port (host publish). */
function getClientFacingPort() {
  if (isTcpEnabled()) return getTcpPublicPort();
  if (isUdpEnabled()) return getUdpPublicPort();
  return getPublicPort();
}

function getProtocol() {
  const p = (getSetting(PROTOCOL_KEY, DEFAULT_PROTOCOL) || DEFAULT_PROTOCOL).toUpperCase();
  return PROTOCOLS.includes(p) ? p : DEFAULT_PROTOCOL;
}

function truthySetting(key, fallback = false) {
  const raw = getSetting(key, '');
  if (raw === '1' || raw === 'true' || raw === 'yes' || raw === 'on') return true;
  if (raw === '0' || raw === 'false' || raw === 'no' || raw === 'off') return false;
  return fallback;
}

function isTcpEnabled() {
  const explicit = getSetting(TCP_ENABLED_KEY, '');
  if (explicit !== '') return truthySetting(TCP_ENABLED_KEY, false);
  return getProtocol() === 'TCP';
}

function isUdpEnabled() {
  const explicit = getSetting(UDP_ENABLED_KEY, '');
  if (explicit !== '') return truthySetting(UDP_ENABLED_KEY, false);
  return getProtocol() === 'UDP';
}

function getLoggingLevel() {
  const lvl = (getSetting(LOGGING_LEVEL_KEY, 'INFO') || 'INFO').toUpperCase();
  return LOGGING_LEVELS.includes(lvl) ? lvl : 'INFO';
}

function getMtu() {
  const raw = getSetting(MTU_KEY, '');
  if (!raw || !/^\d+$/.test(raw)) return null;
  const n = parseInt(raw, 10);
  if (n < MTU_MIN || n > MTU_MAX) return null;
  return n;
}

function getMultiplexing() {
  const m = (getSetting(MULTIPLEXING_KEY, DEFAULT_MULTIPLEXING) || DEFAULT_MULTIPLEXING).toUpperCase();
  return MULTIPLEXING_LEVELS.includes(m) ? m : DEFAULT_MULTIPLEXING;
}

function getHandshakeMode() {
  const m = (getSetting(HANDSHAKE_MODE_KEY, DEFAULT_HANDSHAKE_MODE) || DEFAULT_HANDSHAKE_MODE).toUpperCase();
  return HANDSHAKE_MODES.includes(m) ? m : DEFAULT_HANDSHAKE_MODE;
}

function getTcpListenPort() {
  const fromDb = getSetting(TCP_PORT_KEY, '');
  if (fromDb && /^\d+$/.test(fromDb)) return parseInt(fromDb, 10);
  return getPort();
}

function getUdpListenPort() {
  const fromDb = getSetting(UDP_PORT_KEY, '');
  if (fromDb && /^\d+$/.test(fromDb)) return parseInt(fromDb, 10);
  if (isUdpEnabled() && !isTcpEnabled()) return getPort();
  return DEFAULT_INTERNAL_PORT + 1;
}

function excludedPortsForAlloc() {
  const ports = [
    config.PANEL_HTTPS_PORT,
    getPublicPort(),
    getTcpPublicPort(),
    getUdpPublicPort(),
    80,
    443,
    8443,
  ];
  if (isTcpEnabled()) ports.push(getTcpListenPort());
  if (isUdpEnabled()) ports.push(getUdpListenPort());
  return [...new Set(ports.filter((p) => Number.isFinite(p) && p > 0))];
}

/**
 * Internal listen port (20000–50000); never the public publish port.
 */
function resolveListenPort(preferred, { publicPort, exclude = [] } = {}) {
  const { allocateInternalPort, needsInternalRealloc } = require('./internalPort');
  const pub = publicPort != null ? publicPort : getPublicPort();
  const raw = preferred != null ? preferred : getPort();
  const n = parseInt(String(raw), 10);
  if (Number.isFinite(n) && !needsInternalRealloc(n) && n !== pub && !exclude.includes(n)) {
    return n;
  }
  return allocateInternalPort(excludedPortsForAlloc().concat([pub, ...exclude]), null);
}

function resolveTcpListenPort(preferred) {
  const exclude = isUdpEnabled() ? [getUdpListenPort()] : [];
  const pub = getTcpPublicPort();
  const raw = preferred != null ? preferred : getTcpListenPort();
  const { allocateInternalPort, needsInternalRealloc } = require('./internalPort');
  const n = parseInt(String(raw), 10);
  if (Number.isFinite(n) && !needsInternalRealloc(n) && n !== pub && !exclude.includes(n)) {
    return n;
  }
  return allocateInternalPort(excludedPortsForAlloc().concat([pub, ...exclude]), null);
}

function resolveUdpListenPort(preferred) {
  const exclude = isTcpEnabled() ? [getTcpListenPort()] : [];
  const pub = getUdpPublicPort();
  const raw = preferred != null ? preferred : (
    isUdpEnabled() && !isTcpEnabled() ? getPort() : getUdpListenPort()
  );
  const { allocateInternalPort, needsInternalRealloc } = require('./internalPort');
  const n = parseInt(String(raw), 10);
  if (Number.isFinite(n) && !needsInternalRealloc(n) && n !== pub && !exclude.includes(n)) {
    return n;
  }
  return allocateInternalPort(excludedPortsForAlloc().concat([pub, ...exclude]), null);
}

function buildPortBindings({ tcpListen, udpListen } = {}) {
  const bindings = [];
  if (isTcpEnabled()) {
    bindings.push({ port: tcpListen != null ? tcpListen : getTcpListenPort(), protocol: 'TCP' });
  }
  if (isUdpEnabled()) {
    bindings.push({ port: udpListen != null ? udpListen : getUdpListenPort(), protocol: 'UDP' });
  }
  return bindings;
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
  getDb().clients.setMieruPassword(id, password);
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

function buildServerConfigObject({ portBindings, loggingLevel, mtu } = {}) {
  const users = ensureClientPasswords();
  const obj = {
    portBindings: portBindings || buildPortBindings(),
    loggingLevel: loggingLevel || getLoggingLevel(),
    users: users.map((c) => ({
      name: c.username,
      password: c.mieru_password,
    })),
    advancedSettings: {
      userHintIsMandatory: true,
    },
  };
  const mtuVal = mtu != null ? mtu : getMtu();
  if (mtuVal) obj.mtu = mtuVal;
  return obj;
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
 * @param {{ username: string, password: string, host: string, port: number, protocol: string, mtu?: number|null, multiplexing?: string, handshakeMode?: string }} p
 */
function buildMieruUrl({
  username, password, host, port, protocol, mtu, multiplexing, handshakeMode,
}) {
  const params = new URLSearchParams();
  params.set('port', String(Number(port)));
  params.set('protocol', protocol || DEFAULT_PROTOCOL);
  const proto = String(protocol || DEFAULT_PROTOCOL).toUpperCase();
  const mtuVal = mtu != null ? mtu : (proto === 'UDP' ? getMtu() : null);
  if (mtuVal != null) params.set('mtu', String(mtuVal));
  const mux = multiplexing != null ? multiplexing : getMultiplexing();
  if (mux && mux !== 'OFF') params.set('multiplexing', mux);
  const hs = handshakeMode != null ? handshakeMode : getHandshakeMode();
  if (hs === 'HANDSHAKE_NO_WAIT') params.set('handshake-mode', hs);
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
  const mieruUrls = [];
  if (isTcpEnabled()) {
    mieruUrls.push(buildMieruUrl({
      username, password, host, port: getTcpPublicPort(), protocol: 'TCP',
    }));
  }
  if (isUdpEnabled()) {
    mieruUrls.push(buildMieruUrl({
      username, password, host, port: getUdpPublicPort(), protocol: 'UDP',
    }));
  }
  if (!mieruUrls.length) return null;

  const primary = mieruUrls[0];
  return {
    username,
    password,
    host,
    port: getClientFacingPort(),
    protocol: isTcpEnabled() ? 'TCP' : 'UDP',
    mieruUrl: primary,
    mieruUrls,
    tcpEnabled: isTcpEnabled(),
    udpEnabled: isUdpEnabled(),
    tcpPublicPort: isTcpEnabled() ? getTcpPublicPort() : null,
    udpPublicPort: isUdpEnabled() ? getUdpPublicPort() : null,
    mtu: getMtu(),
    multiplexing: getMultiplexing(),
    handshakeMode: getHandshakeMode(),
  };
}

const AMNEZIA_MIERU_SUBNET = '10.8.3.0';

function buildAmneziaMieruContainer(client) {
  const payload = getClientMieruPayload(client);
  if (!payload) return null;
  return {
    container: 'amnezia-mieru',
    mieru: {
      mieru_url: payload.mieruUrl,
      port: String(payload.port),
      subnet_address: AMNEZIA_MIERU_SUBNET,
      transport_proto: String(payload.protocol || 'TCP').toLowerCase(),
      mtu: payload.mtu != null ? String(payload.mtu) : '',
      multiplexing: payload.multiplexing || DEFAULT_MULTIPLEXING,
      handshake_mode: payload.handshakeMode || DEFAULT_HANDSHAKE_MODE,
    },
  };
}

function findEnabledClientByName(name) {
  if (!name) return null;
  const rows = getDb().clients.getAll();
  const row = rows.find((c) => c.name === name);
  if (!row || !row.enabled) return null;
  if (!row.mieru_password) {
    const pwd = randomPassword();
    getDb().clients.setMieruPassword(row.id, pwd);
    row.mieru_password = pwd;
  }
  return row;
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

async function probeUdpListenInsideContainer(port) {
  const p = String(port);
  const nc = await runCmd('docker', [
    'exec', CONTAINER_NAME, 'nc', '-z', '-u', '-w', '2', '127.0.0.1', p,
  ], { timeout: 8_000 });
  if (nc.ok) return { ok: true, via: 'nc-udp', out: 'connected' };
  const out = (nc.stderr || nc.stdout || 'not listening').trim().slice(0, 160);
  return { ok: false, via: 'nc-udp', out: out || 'not listening' };
}

async function runSmoke() {
  const containerUp = await dockerContainerRunning();
  let statusOk = false;
  let statusOut = '';
  const probes = [];
  if (containerUp) {
    const st = await runCmd('docker', ['exec', CONTAINER_NAME, 'mita', 'status'], { timeout: 10_000 });
    statusOk = st.ok && /RUNNING/i.test(`${st.stdout}\n${st.stderr}`);
    statusOut = (st.stdout || st.stderr || '').trim().slice(0, 120);
    if (isTcpEnabled()) {
      probes.push({
        proto: 'tcp',
        port: getTcpListenPort(),
        dial: await probeListenInsideContainer(getTcpListenPort()),
      });
    }
    if (isUdpEnabled()) {
      probes.push({
        proto: 'udp',
        port: getUdpListenPort(),
        dial: await probeUdpListenInsideContainer(getUdpListenPort()),
      });
    }
  }
  const dialOk = probes.length > 0 && probes.every((p) => p.dial && p.dial.ok);
  const ok = containerUp && statusOk && dialOk;
  lastSmoke = {
    ok,
    containerUp,
    statusOk,
    statusOut,
    probes,
    dial: probes[0] ? probes[0].dial : { ok: false, via: 'skip', out: 'container down' },
    port: getPort(),
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

async function inspectPublishedBindings() {
  const r = await runCmd('docker', [
    'inspect', '-f', '{{json .HostConfig.PortBindings}}', CONTAINER_NAME,
  ]);
  if (!r.ok) return { tcp: null, udp: null };
  try {
    const bindings = JSON.parse(r.stdout.trim() || '{}');
    const out = { tcp: null, udp: null };
    for (const [key, entry] of Object.entries(bindings)) {
      if (!entry || !entry[0] || !entry[0].HostPort) continue;
      const hostPort = parseInt(entry[0].HostPort, 10);
      if (key.endsWith('/tcp')) out.tcp = hostPort;
      if (key.endsWith('/udp')) out.udp = hostPort;
    }
    return out;
  } catch {
    return { tcp: null, udp: null };
  }
}

function bindingsMatchPublished({ tcpPublic, udpPublic, published }) {
  if (isTcpEnabled()) {
    if (published.tcp !== tcpPublic) return false;
  } else if (published.tcp != null) return false;
  if (isUdpEnabled()) {
    if (published.udp !== udpPublic) return false;
  } else if (published.udp != null) return false;
  return true;
}

/**
 * Direct mode: publish publicPort → internal listenPort on host for each enabled protocol.
 */
async function ensureMieruContainer() {
  await ensureMieruImage();
  const volume = await resolveAwgVolumeName();
  const portPlan = require('./portPlan');
  const tcpPublic = getTcpPublicPort();
  const udpPublic = getUdpPublicPort();
  const tcpListen = isTcpEnabled() ? resolveTcpListenPort(getTcpListenPort()) : null;
  const udpListen = isUdpEnabled() ? resolveUdpListenPort(getUdpListenPort()) : null;
  if (isTcpEnabled() && String(tcpListen) !== String(getTcpListenPort())) {
    setSetting(TCP_PORT_KEY, String(tcpListen));
    setSetting(PORT_KEY, String(tcpListen));
  }
  if (isUdpEnabled() && String(udpListen) !== String(getUdpListenPort())) {
    setSetting(UDP_PORT_KEY, String(udpListen));
    if (!isTcpEnabled()) setSetting(PORT_KEY, String(udpListen));
  }

  const network = await portPlan.resolveNginxNetwork();

  const running = await dockerContainerRunning();
  if (running && await containerManagedByUs()) {
    const pub = await inspectPublishedBindings();
    const labelMode = await runCmd('docker', [
      'inspect', '-f', '{{index .Config.Labels "amnezia.port_mode"}}', CONTAINER_NAME,
    ]);
    const curMode = (labelMode.ok ? labelMode.stdout : '').trim();
    const pubOk = bindingsMatchPublished({
      tcpPublic, udpPublic, published: pub,
    });
    if (pubOk && curMode === 'direct') {
      return { reused: true };
    }
  }

  if ((await runCmd('docker', ['inspect', CONTAINER_NAME])).ok) {
    await removeMieruContainer();
  }

  const runArgs = [
    'run', '-d',
    '--log-driver', 'none',
    '--restart', DOCKER_RESTART_POLICY,
    '--name', CONTAINER_NAME,
    '--label', 'amnezia.managed=1',
    '--label', 'amnezia.service=mieru',
    '--label', 'amnezia.port_mode=direct',
  ];
  if (isTcpEnabled()) {
    runArgs.push('--label', `amnezia.listen_port=${tcpListen}`);
    runArgs.push('--label', `amnezia.public_port=${tcpPublic}`);
    runArgs.push('-p', `${tcpPublic}:${tcpListen}/tcp`);
  }
  if (isUdpEnabled()) {
    runArgs.push('--label', `amnezia.udp_listen_port=${udpListen}`);
    runArgs.push('--label', `amnezia.udp_public_port=${udpPublic}`);
    runArgs.push('-p', `${udpPublic}:${udpListen}/udp`);
  }
  const primaryListen = isTcpEnabled() ? tcpListen : udpListen;
  runArgs.push('-e', `MIERU_SERVER_PORT=${primaryListen}`);
  runArgs.push('-v', `${volume}:/opt/amnezia/awg:rw`);
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
  const tcpListen = isTcpEnabled() ? resolveTcpListenPort(getTcpListenPort()) : null;
  const udpListen = isUdpEnabled() ? resolveUdpListenPort(getUdpListenPort()) : null;
  const portBindings = buildPortBindings({ tcpListen, udpListen });
  const obj = buildServerConfigObject({ portBindings });
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
    tcpEnabled: isTcpEnabled(),
    udpEnabled: isUdpEnabled(),
    tcpPublicPort: isTcpEnabled() ? getTcpPublicPort() : null,
    udpPublicPort: isUdpEnabled() ? getUdpPublicPort() : null,
    mtu: getMtu(),
    loggingLevel: getLoggingLevel(),
    multiplexing: getMultiplexing(),
    handshakeMode: getHandshakeMode(),
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
    let tcpOn = opts.enableTcp !== false && opts.enableTcp !== '0';
    let udpOn = opts.enableUdp === true || opts.enableUdp === '1' || opts.enableUdp === 1;
    if (opts.protocol != null && String(opts.protocol).trim() !== '') {
      const p = String(opts.protocol).trim().toUpperCase();
      if (p === 'TCP') { tcpOn = true; udpOn = false; }
      else if (p === 'UDP') { tcpOn = false; udpOn = true; }
    } else if (opts.enableTcp == null && opts.enableUdp == null) {
      tcpOn = isTcpEnabled() || !isUdpEnabled();
      udpOn = isUdpEnabled();
    }
    if (!tcpOn && !udpOn) {
      throw Object.assign(new Error('Enable at least one of TCP or UDP'), {
        status: 400,
        code: 'MIERU_NO_PROTOCOL',
      });
    }

    const legacyPublic = opts.publicPort != null
      ? parseInt(String(opts.publicPort).trim(), 10)
      : null;
    const tcpPublicPort = opts.tcpPublicPort != null
      ? parseInt(String(opts.tcpPublicPort).trim(), 10)
      : (legacyPublic != null && Number.isFinite(legacyPublic) ? legacyPublic : getTcpPublicPort());
    const udpPublicPort = opts.udpPublicPort != null
      ? parseInt(String(opts.udpPublicPort).trim(), 10)
      : (legacyPublic != null && Number.isFinite(legacyPublic) ? legacyPublic : getUdpPublicPort());

    if (tcpOn && (!Number.isFinite(tcpPublicPort) || tcpPublicPort < 1 || tcpPublicPort > 65535)) {
      throw Object.assign(new Error('Invalid Mieru TCP public port (1–65535)'), {
        status: 400,
        code: 'MIERU_BAD_TCP_PUBLIC_PORT',
      });
    }
    if (udpOn && (!Number.isFinite(udpPublicPort) || udpPublicPort < 1 || udpPublicPort > 65535)) {
      throw Object.assign(new Error('Invalid Mieru UDP public port (1–65535)'), {
        status: 400,
        code: 'MIERU_BAD_UDP_PUBLIC_PORT',
      });
    }

    setSetting(TCP_ENABLED_KEY, tcpOn ? '1' : '0');
    setSetting(UDP_ENABLED_KEY, udpOn ? '1' : '0');
    if (tcpOn) setSetting(TCP_PUBLIC_PORT_KEY, String(tcpPublicPort));
    if (udpOn) setSetting(UDP_PUBLIC_PORT_KEY, String(udpPublicPort));
    setSetting(PUBLIC_PORT_KEY, String(tcpOn ? tcpPublicPort : udpPublicPort));
    setSetting(PROTOCOL_KEY, tcpOn && udpOn ? 'TCP' : (tcpOn ? 'TCP' : 'UDP'));

    if (opts.port != null && String(opts.port).trim() !== '') {
      const requested = parseInt(String(opts.port).trim(), 10);
      if (!Number.isFinite(requested) || requested < 1 || requested > 65535) {
        throw Object.assign(new Error('Invalid Mieru listen port (1–65535)'), {
          status: 400,
          code: 'MIERU_BAD_PORT',
        });
      }
    }

    let loggingLevel = opts.loggingLevel != null
      ? String(opts.loggingLevel).trim().toUpperCase()
      : getLoggingLevel();
    if (!LOGGING_LEVELS.includes(loggingLevel)) loggingLevel = 'INFO';
    setSetting(LOGGING_LEVEL_KEY, loggingLevel);

    let mtu = null;
    if (opts.mtu != null && String(opts.mtu).trim() !== '') {
      mtu = parseInt(String(opts.mtu).trim(), 10);
      if (!Number.isFinite(mtu) || mtu < MTU_MIN || mtu > MTU_MAX) {
        throw Object.assign(new Error(`Invalid Mieru MTU (${MTU_MIN}–${MTU_MAX})`), {
          status: 400,
          code: 'MIERU_BAD_MTU',
        });
      }
      setSetting(MTU_KEY, String(mtu));
    } else {
      setSetting(MTU_KEY, '');
    }

    let multiplexing = opts.multiplexing != null
      ? String(opts.multiplexing).trim().toUpperCase()
      : getMultiplexing();
    if (!MULTIPLEXING_LEVELS.includes(multiplexing)) multiplexing = DEFAULT_MULTIPLEXING;
    setSetting(MULTIPLEXING_KEY, multiplexing);

    let handshakeMode = opts.handshakeMode != null
      ? String(opts.handshakeMode).trim().toUpperCase()
      : (opts.handshakeNoWait === true || opts.handshakeNoWait === '1' || opts.handshakeNoWait === 'true'
        ? 'HANDSHAKE_NO_WAIT'
        : getHandshakeMode());
    if (!HANDSHAKE_MODES.includes(handshakeMode)) handshakeMode = DEFAULT_HANDSHAKE_MODE;
    setSetting(HANDSHAKE_MODE_KEY, handshakeMode);

    const addressRaw = opts.address != null ? String(opts.address).trim() : '';
    const address = addressRaw || getAddress() || getPublicHost();
    if (!address) {
      throw Object.assign(new Error('Mieru address is required'), { status: 400, code: 'MIERU_BAD_ADDRESS' });
    }
    setSetting(ADDRESS_KEY, address);

    const portPlan = require('./portPlan');
    const tcpPorts = tcpOn ? [tcpPublicPort] : [];
    const udpPorts = udpOn ? [udpPublicPort] : [];
    if (tcpPorts.length) await portPlan.assertHostPortsAvailable(tcpPorts, { allowNginx: true });
    if (udpPorts.length) await portPlan.assertHostUdpPortsAvailable(udpPorts, { allowSidecar: true });

    const listenPreferred = opts.port != null && String(opts.port).trim() !== '' ? opts.port : null;
    const tcpListen = tcpOn
      ? resolveTcpListenPort(listenPreferred != null ? listenPreferred : getTcpListenPort())
      : null;
    const udpListen = udpOn
      ? resolveUdpListenPort(listenPreferred != null && !tcpOn ? listenPreferred : getUdpListenPort())
      : null;
    if (tcpOn) {
      setSetting(TCP_PORT_KEY, String(tcpListen));
      setSetting(PORT_KEY, String(tcpListen));
    }
    if (udpOn) {
      setSetting(UDP_PORT_KEY, String(udpListen));
      if (!tcpOn) setSetting(PORT_KEY, String(udpListen));
    }

    ensureClientPasswords();
    const portBindings = buildPortBindings({ tcpListen, udpListen });
    const obj = buildServerConfigObject({ portBindings, loggingLevel, mtu });
    writeServerJson(obj);

    await ensureMieruContainer();
    try {
      await portPlan.applyPlan();
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
      const dialOut = smoke.probes && smoke.probes.length
        ? smoke.probes.map((p) => `${p.proto}=${p.dial && p.dial.out}`).join('; ')
        : (smoke.dial && smoke.dial.out);
      throw Object.assign(
        new Error(
          `Mieru did not become ready in time (listen=${dialOut}; statusOk=${smoke.statusOk})`,
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
    if (isTcpEnabled() && !getSetting(TCP_PUBLIC_PORT_KEY, '')) {
      setSetting(TCP_PUBLIC_PORT_KEY, String(getTcpPublicPort()));
    }
    if (isUdpEnabled() && !getSetting(UDP_PUBLIC_PORT_KEY, '')) {
      setSetting(UDP_PUBLIC_PORT_KEY, String(getUdpPublicPort()));
    }
    if (isTcpEnabled()) {
      const tcpListen = resolveTcpListenPort(getTcpListenPort());
      if (String(tcpListen) !== String(getTcpListenPort())) {
        setSetting(TCP_PORT_KEY, String(tcpListen));
        setSetting(PORT_KEY, String(tcpListen));
      }
    }
    if (isUdpEnabled()) {
      const udpListen = resolveUdpListenPort(getUdpListenPort());
      if (String(udpListen) !== String(getUdpListenPort())) {
        setSetting(UDP_PORT_KEY, String(udpListen));
        if (!isTcpEnabled()) setSetting(PORT_KEY, String(udpListen));
      }
    }
    lastClockWarning = await detectClockWarning();
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
  buildAmneziaMieruContainer,
  findEnabledClientByName,
  buildServerConfigObject,
  buildPortBindings,
  isTcpEnabled,
  isUdpEnabled,
  bootAmneziaMieru,
  stopAmneziaMieru,
  ensureMieruContainer,
  ensureClientPasswords,
  clientUsername,
  randomPassword,
  probeListenInsideContainer,
  detectClockWarning,
};
