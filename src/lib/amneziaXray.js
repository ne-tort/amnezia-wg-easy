'use strict';

/**
 * Amnezia Xray orchestration: VLESS + REALITY Docker container (amnezia-xray).
 * Desired state and Reality keys live in app_settings; per-client UUID on clients.xray_uuid.
 */

const { spawn, execFile } = require('node:child_process');
const { promisify } = require('node:util');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const config = require('../config');

const execFileAsync = promisify(execFile);

const CONTAINER_NAME = 'amnezia-xray';
const IMAGE_NAME = 'amnezia-xray';
const DOCKERFILE_FOLDER = '/opt/amnezia/xray';
const PANEL_CONTAINER = 'amnezia-awg';
const XRAY_REL = 'xray';
const SERVER_JSON = 'server.json';
/** Loopback Stats API inside amnezia-xray (not published to host). */
const XRAY_API_PORT = 10085;

const DESIRED_KEY = 'amnezia_xray_desired';
const SNI_KEY = 'amnezia_xray_sni';
const FP_KEY = 'amnezia_xray_fingerprint';
const FLOW_KEY = 'amnezia_xray_flow';
const PORT_KEY = 'amnezia_xray_port';
const PUBLIC_PORT_KEY = 'amnezia_xray_public_port';
const ADDRESS_KEY = 'amnezia_xray_address';
const PRIV_KEY = 'amnezia_xray_private_key';
const PUB_KEY = 'amnezia_xray_public_key';
const SHORT_ID_KEY = 'amnezia_xray_short_id';

const DEFAULT_SNI = 'www.gov.uk';
const DEFAULT_FP = 'chrome';
const DEFAULT_FLOW = 'xtls-rprx-vision';
const FINGERPRINTS = Object.freeze([
  'chrome', 'firefox', 'safari', 'ios', 'android', 'edge', 'random',
]);
const FLOWS = Object.freeze([
  'xtls-rprx-vision',
  'xtls-rprx-vision-udp443',
  '',
]);

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
  const fromDb = getSetting(PORT_KEY, '');
  if (fromDb && /^\d+$/.test(fromDb)) return parseInt(fromDb, 10);
  return config.XRAY_PORT;
}

function getPublicPort() {
  const fromDb = getSetting(PUBLIC_PORT_KEY, '');
  if (fromDb && /^\d+$/.test(fromDb)) return parseInt(fromDb, 10);
  const fromEnv = parseInt(String(process.env.XRAY_PUBLIC_PORT || '').trim(), 10);
  if (Number.isFinite(fromEnv) && fromEnv >= 1 && fromEnv <= 65535) return fromEnv;
  return 443;
}

/** Client-facing TCP (public / demux port). */
function getClientFacingPort() {
  return getPublicPort();
}

function excludedPortsForAlloc() {
  const list = [
    config.PANEL_HTTPS_PORT,
    getPublicPort(),
    getSetting('amnezia_mtproto_public_port', '') || 443,
    getSetting('amnezia_mtproto_port', ''),
    80,
    8443,
  ];
  return list;
}

/**
 * Resolve listen port: demux → high internal; direct → public (or preferred).
 */
function resolveListenPort(preferred, { mode } = {}) {
  const portPlan = require('./portPlan');
  const m = mode || portPlan.modeForService('xray') || 'direct';
  const publicPort = getPublicPort();
  if (m === 'direct') {
    const raw = preferred != null ? parseInt(String(preferred), 10) : getPort();
    if (Number.isFinite(raw) && raw >= 1 && raw <= 65535
      && raw !== 80 && raw !== 8443) {
      return raw;
    }
    return publicPort;
  }
  // demux: never listen on the shared public port inside the container
  const { allocateInternalPort, needsInternalRealloc } = require('./internalPort');
  const raw = preferred != null ? preferred : getPort();
  if (!needsInternalRealloc(raw) && parseInt(String(raw), 10) !== publicPort) {
    const n = parseInt(String(raw), 10);
    const mt = parseInt(getSetting('amnezia_mtproto_port', ''), 10);
    if (Number.isFinite(mt) && mt === n) {
      return allocateInternalPort(excludedPortsForAlloc().concat([n, publicPort]), null);
    }
    return n;
  }
  return allocateInternalPort(excludedPortsForAlloc().concat([publicPort]), null);
}

function resolveInternalListenPort(preferred) {
  return resolveListenPort(preferred);
}

function assertSniNotMtproto(sni, publicPort) {
  require('./portPlan').assertSniConflict('xray', sni, publicPort != null ? publicPort : getPublicPort());
}

function getSni() {
  const stored = getSetting(SNI_KEY, '');
  if (stored) return stored;
  try {
    // eslint-disable-next-line global-require
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

function getFingerprint() {
  const fp = getSetting(FP_KEY, DEFAULT_FP) || DEFAULT_FP;
  return FINGERPRINTS.includes(fp) ? fp : DEFAULT_FP;
}

function getFlow() {
  const flow = getSetting(FLOW_KEY, DEFAULT_FLOW);
  if (flow === '' || FLOWS.includes(flow)) return flow;
  return DEFAULT_FLOW;
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

function xrayHostDir() {
  return path.join(config.WG_PATH, XRAY_REL);
}

function serverJsonPath() {
  return path.join(xrayHostDir(), SERVER_JSON);
}

function ensureXrayDir() {
  fs.mkdirSync(xrayHostDir(), { recursive: true });
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

async function ensureXrayImage() {
  const inspect = await runCmd('docker', ['image', 'inspect', IMAGE_NAME]);
  if (inspect.ok) return;

  const dockerfilePath = path.join(DOCKERFILE_FOLDER, 'Dockerfile');
  if (!fs.existsSync(dockerfilePath)) {
    throw new Error('amnezia-xray image missing; run deploy.sh');
  }
  const dockerfile = fs.readFileSync(dockerfilePath, 'utf8');
  await new Promise((resolve, reject) => {
    const child = spawn('docker', ['build', '-t', IMAGE_NAME, '-'], {
      stdio: ['pipe', 'ignore', 'pipe'],
    });
    let err = '';
    const timer = setTimeout(() => {
      try { child.kill('SIGKILL'); } catch (_) { /* ignore */ }
      reject(new Error('docker build amnezia-xray timed out'));
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
 * Parse `xray x25519` output into private/public keys.
 * @param {string} text
 * @returns {{ privateKey: string, publicKey: string }}
 */
function parseX25519Output(text) {
  const lines = String(text || '').split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
  let privateKey = '';
  let publicKey = '';
  for (const line of lines) {
    const m = line.match(/^(?:Private(?:\s*key)?|Password)\s*:\s*(.+)$/i);
    const n = line.match(/^(?:Public(?:\s*key)?)\s*:\s*(.+)$/i);
    if (m) privateKey = m[1].trim();
    if (n) publicKey = n[1].trim();
  }
  if (!privateKey || !publicKey) {
    // Older two-line "Private key: … / Public key: …" already covered; last resort split
    if (lines.length >= 2) {
      const a = lines[0].split(':').slice(1).join(':').trim();
      const b = lines[1].split(':').slice(1).join(':').trim();
      if (a && b) {
        privateKey = privateKey || a;
        publicKey = publicKey || b;
      }
    }
  }
  if (!privateKey || !publicKey) {
    throw new Error('failed to parse xray x25519 output');
  }
  return { privateKey, publicKey };
}

async function generateRealityKeysIfMissing() {
  let privateKey = getSetting(PRIV_KEY, '');
  let publicKey = getSetting(PUB_KEY, '');
  let shortId = getSetting(SHORT_ID_KEY, '');

  if (!shortId) {
    shortId = crypto.randomBytes(8).toString('hex');
    setSetting(SHORT_ID_KEY, shortId);
  }

  if (privateKey && publicKey) {
    return { privateKey, publicKey, shortId };
  }

  await ensureXrayImage();
  const r = await runCmd('docker', ['run', '--rm', '--entrypoint', 'xray', IMAGE_NAME, 'x25519'], {
    timeout: 60_000,
  });
  if (!r.ok) {
    throw new Error(r.stderr.trim() || 'xray x25519 failed');
  }
  const parsed = parseX25519Output(r.stdout + '\n' + r.stderr);
  setSetting(PRIV_KEY, parsed.privateKey);
  setSetting(PUB_KEY, parsed.publicKey);
  return { privateKey: parsed.privateKey, publicKey: parsed.publicKey, shortId };
}

/**
 * Ensure every active client has a stable xray_uuid; return enabled clients for inbound.
 * @returns {Array<{ id: string, name: string, xray_uuid: string, enabled: number }>}
 */
function ensureClientUuids() {
  const db = getDb();
  const rows = db.clients.getAll();
  const out = [];
  for (const row of rows) {
    let uuid = row.xray_uuid;
    if (!uuid) {
      uuid = crypto.randomUUID();
      db.clients.setXrayUuid(row.id, uuid);
      row.xray_uuid = uuid;
    }
    if (row.enabled) {
      out.push({
        id: row.id,
        name: row.name,
        xray_uuid: uuid,
        enabled: row.enabled,
      });
    }
  }
  return out;
}

/**
 * Build server.json clients[] entries from DB.
 * @param {string} flow
 */
function buildInboundClients(flow) {
  const enabled = ensureClientUuids();
  return enabled.map((c) => {
    /** @type {Record<string, string>} */
    const entry = { id: c.xray_uuid, email: c.name };
    if (flow) entry.flow = flow;
    return entry;
  });
}

function buildServerConfigObject({ port, sni, privateKey, shortId, flow }) {
  return {
    log: { loglevel: 'error' },
    stats: {},
    api: {
      tag: 'api',
      services: ['StatsService'],
    },
    policy: {
      levels: {
        '0': {
          statsUserUplink: true,
          statsUserDownlink: true,
          // Presence for panel online indicator (idle VLESS sessions).
          statsUserOnline: true,
        },
      },
      system: {
        statsInboundUplink: true,
        statsInboundDownlink: true,
      },
    },
    inbounds: [
      {
        tag: 'vless-reality',
        listen: '0.0.0.0',
        port,
        protocol: 'vless',
        settings: {
          clients: buildInboundClients(flow),
          decryption: 'none',
        },
        streamSettings: {
          network: 'tcp',
          security: 'reality',
          realitySettings: {
            dest: `${sni}:443`,
            serverNames: [sni],
            privateKey,
            shortIds: [shortId],
          },
        },
      },
      {
        tag: 'api',
        listen: '127.0.0.1',
        port: XRAY_API_PORT,
        protocol: 'dokodemo-door',
        settings: { address: '127.0.0.1' },
      },
    ],
    outbounds: [{ protocol: 'freedom', tag: 'direct' }],
    routing: {
      rules: [
        {
          type: 'field',
          inboundTag: ['api'],
          outboundTag: 'api',
        },
      ],
    },
  };
}

function writeServerJson(obj) {
  ensureXrayDir();
  const p = serverJsonPath();
  fs.writeFileSync(p, `${JSON.stringify(obj, null, 2)}\n`, 'utf8');
  return p;
}

/**
 * Client Xray JSON for Amnezia `.vpn` / Preview / subscription.
 * Must match amnezia-client `server_scripts/xray/template.json` +
 * `serialization::inbounds::GenerateInboundEntry()` (SOCKS 127.0.0.1:10808):
 * Amnezia XrayProtocol starts this JSON as-is, then tun2socks → socks5://127.0.0.1:10808.
 * spiderX left empty (Xray default "/"); omit spiderX from vless://.
 */
function buildClientJson({ uuid, host, port, sni, publicKey, shortId, fingerprint, flow, remark }) {
  // Field order matches amnezia-client server_scripts/xray/template.json
  /** @type {Record<string, unknown>} */
  const user = { id: uuid };
  if (flow) user.flow = flow;
  user.encryption = 'none';

  /** @type {Record<string, unknown>} */
  const outbound = {
    protocol: 'vless',
    settings: {
      vnext: [
        {
          address: host,
          port,
          users: [user],
        },
      ],
    },
    streamSettings: {
      network: 'tcp',
      security: 'reality',
      realitySettings: {
        fingerprint,
        serverName: sni,
        publicKey,
        shortId,
        spiderX: '',
      },
    },
  };
  // Amnezia template has no outbound tag; keep optional remark only for non-Amnezia preview.
  if (remark) outbound.tag = remark;

  return {
    log: { loglevel: 'error' },
    inbounds: [
      {
        listen: '127.0.0.1',
        port: 10808,
        protocol: 'socks',
        settings: { udp: true },
      },
    ],
    outbounds: [outbound],
  };
}

/**
 * Build vless:// share link (Amnezia / Qv2ray style).
 */
function buildVlessUrl({
  uuid, host, port, sni, publicKey, shortId, fingerprint, flow, remark,
}) {
  const params = new URLSearchParams();
  params.set('encryption', 'none');
  params.set('security', 'reality');
  params.set('type', 'tcp');
  if (flow) params.set('flow', flow);
  if (sni) params.set('sni', sni);
  if (fingerprint) params.set('fp', fingerprint);
  if (publicKey) params.set('pbk', publicKey);
  if (shortId) params.set('sid', shortId);
  // Intentionally omit spiderX (empty = Xray default "/"; Amnezia Serialize skips empty).
  let url = `vless://${uuid}@${host}:${Number(port)}?${params.toString()}`;
  if (remark) url += `#${encodeURIComponent(remark)}`;
  return url;
}

/**
 * Public TCP address for vless:// (not Reality SNI).
 * Stored address → WG_HOST → 127.0.0.1.
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
 * Client-facing endpoints for one panel client.
 * @param {{ id: string, name: string, xray_uuid?: string, enabled?: number }} client
 * @param {{ baseUrl?: string }} [opts]
 */
function getClientXrayPayload(client, opts = {}) {
  if (!client || !client.xray_uuid) return null;
  const host = getPublicHost();
  const port = getClientFacingPort();
  const sni = getSni();
  const fingerprint = getFingerprint();
  const flow = getFlow();
  const publicKey = getSetting(PUB_KEY, '');
  const shortId = getSetting(SHORT_ID_KEY, '');
  if (!publicKey || !shortId) return null;

  const clientJson = buildClientJson({
    uuid: client.xray_uuid,
    host,
    port,
    sni,
    publicKey,
    shortId,
    fingerprint,
    flow,
    remark: client.name,
  });
  const vlessUrl = buildVlessUrl({
    uuid: client.xray_uuid,
    host,
    port,
    sni,
    publicKey,
    shortId,
    fingerprint,
    flow,
    remark: client.name,
  });

  const base = (opts.baseUrl || '').replace(/\/+$/, '');
  const subPrefix = String(
    opts.subPublicPrefix != null ? opts.subPublicPrefix : (require('../config').SUB_PUBLIC_PREFIX || '/sub'),
  ).replace(/\/+$/, '') || '/sub';
  const subPath = `${subPrefix}/${encodeURIComponent(client.name)}`;
  const subUrl = base ? `${base}${subPath}` : subPath;

  return {
    uuid: client.xray_uuid,
    vlessUrl,
    subUrl,
    subPath,
    clientJson,
    port,
    sni,
    fingerprint,
    flow,
    publicKey,
    shortId,
    host,
  };
}

/** Default subnet_address in official Amnezia Xray connection .vpn exports. */
const AMNEZIA_XRAY_SUBNET = '10.8.1.0';

/**
 * Amnezia `.vpn` xray container block.
 * Matches official ExportController::generateConnectionConfig for amnezia-xray:
 *   { container, xray: { last_config, port, subnet_address, transport_proto } }
 * last_config = pretty-printed template.json (SOCKS 10808 + VLESS Reality outbound).
 */
function buildAmneziaXrayContainer(client) {
  const payload = getClientXrayPayload(client);
  if (!payload) return null;
  const last = payload.clientJson;
  // Amnezia template has no outbound tag — strip before embedding in .vpn
  const forVpn = JSON.parse(JSON.stringify(last));
  if (forVpn.outbounds && forVpn.outbounds[0] && forVpn.outbounds[0].tag) {
    delete forVpn.outbounds[0].tag;
  }
  // Official client stores last_config as indented template JSON (4 spaces).
  return {
    container: 'amnezia-xray',
    xray: {
      last_config: `${JSON.stringify(forVpn, null, 4)}\n`,
      port: String(payload.port),
      subnet_address: AMNEZIA_XRAY_SUBNET,
      transport_proto: 'tcp',
    },
  };
}

/**
 * Probe that Xray accepts TCP inside its container namespace.
 * Do NOT dial 127.0.0.1 from the panel — published -p ports bind on the Docker
 * host, not in amnezia-awg, so ECONNREFUSED there is expected.
 */
async function probeListenInsideContainer(port) {
  const p = String(port);
  // netcat-openbsd is in the amnezia-xray image
  const nc = await runCmd('docker', [
    'exec', CONTAINER_NAME, 'nc', '-z', '-w', '2', '127.0.0.1', p,
  ], { timeout: 8_000 });
  if (nc.ok) return { ok: true, via: 'nc', out: 'connected' };

  const bash = await runCmd('docker', [
    'exec', CONTAINER_NAME, 'bash', '-c', `echo >/dev/tcp/127.0.0.1/${p}`,
  ], { timeout: 8_000 });
  if (bash.ok) return { ok: true, via: 'bash', out: 'connected' };

  const out = (nc.stderr || nc.stdout || bash.stderr || bash.stdout || 'not listening')
    .trim()
    .slice(0, 160);
  return { ok: false, via: 'nc/bash', out: out || 'not listening' };
}

async function runSmoke() {
  const containerUp = await dockerContainerRunning();
  let versionOk = false;
  let versionOut = '';
  let dial = { ok: false, via: 'skip', out: 'container down' };
  const port = getPort();
  if (containerUp) {
    const ver = await runCmd('docker', ['exec', CONTAINER_NAME, 'xray', 'version'], { timeout: 10_000 });
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

/**
 * Parse `xray api statsquery` stdout into Map(email → { uplink, downlink }).
 * Accepts JSON or protobuf-ish text.
 * @param {string} raw
 * @returns {Map<string, { uplink: number, downlink: number }>}
 */
function parseStatsQueryOutput(raw) {
  const out = new Map();
  const text = String(raw || '');

  const apply = (name, value) => {
    const m = String(name).match(/^user>>>(.+)>>>traffic>>>(uplink|downlink)$/);
    if (!m) return;
    const email = m[1];
    const kind = m[2];
    const n = Number(value) || 0;
    const cur = out.get(email) || { uplink: 0, downlink: 0 };
    if (kind === 'uplink') cur.uplink = n;
    else cur.downlink = n;
    out.set(email, cur);
  };

  try {
    const json = JSON.parse(text);
    const list = (json && (json.stat || json.Stat || json.stats)) || [];
    if (Array.isArray(list)) {
      for (const s of list) {
        apply(s.name || s.Name || '', s.value != null ? s.value : s.Value);
      }
      if (out.size) return out;
    }
  } catch {
    /* fall through to regex */
  }

  const re = /user>>>(.+?)>>>traffic>>>(uplink|downlink)["'\s,}:]+(?:value|Value)["'\s:=]+"?(\d+)/g;
  let match;
  while ((match = re.exec(text)) !== null) {
    apply(`user>>>${match[1]}>>>traffic>>>${match[2]}`, match[3]);
  }
  // Alternate: name on one line, value on next / "name":"...","value":"123"
  if (!out.size) {
    const re2 = /"name"\s*:\s*"([^"]+)"\s*,\s*"value"\s*:\s*"?(\d+)"?/gi;
    while ((match = re2.exec(text)) !== null) {
      apply(match[1], match[2]);
    }
  }
  return out;
}

/**
 * Parse online-user stats (`user>>>email>>>online` with value > 0).
 * OnlineMap may be absent from QueryStats on some builds — empty Set is fine.
 * @param {string} raw
 * @returns {Set<string>} client emails currently online
 */
function parseOnlineStatsOutput(raw) {
  const out = new Set();
  const text = String(raw || '');

  const apply = (name, value) => {
    const m = String(name).match(/^user>>>(.+)>>>online$/);
    if (!m) return;
    const n = Number(value);
    if (Number.isFinite(n) && n > 0) out.add(m[1]);
  };

  try {
    const json = JSON.parse(text);
    const list = (json && (json.stat || json.Stat || json.stats)) || [];
    if (Array.isArray(list)) {
      for (const s of list) {
        apply(s.name || s.Name || '', s.value != null ? s.value : s.Value);
      }
      if (out.size) return out;
    }
    // Single-stat shape from `xray api statsonline`
    const one = json && (json.stat || json.Stat);
    if (one && !Array.isArray(one)) {
      apply(one.name || one.Name || '', one.value != null ? one.value : one.Value);
      if (out.size) return out;
    }
  } catch {
    /* fall through */
  }

  const re = /user>>>(.+?)>>>online["'\s,}:]+(?:value|Value)["'\s:=]+"?(\d+)/g;
  let match;
  while ((match = re.exec(text)) !== null) {
    apply(`user>>>${match[1]}>>>online`, match[2]);
  }
  return out;
}

/**
 * Query per-user traffic from running amnezia-xray (by inbound email = client name).
 * @returns {Promise<Map<string, { uplink: number, downlink: number }>>}
 */
async function queryUserTrafficStats() {
  if (!(await dockerContainerRunning())) return new Map();
  const r = await runCmd('docker', [
    'exec', CONTAINER_NAME,
    'xray', 'api', 'statsquery',
    '--server', `127.0.0.1:${XRAY_API_PORT}`,
    '-pattern', 'user>>>',
  ], { timeout: 15_000 });
  if (!r.ok) {
    // Retry with -json if present on this build
    const r2 = await runCmd('docker', [
      'exec', CONTAINER_NAME,
      'xray', 'api', 'statsquery',
      '--server', `127.0.0.1:${XRAY_API_PORT}`,
      '-pattern', 'user>>>',
      '-json',
    ], { timeout: 15_000 });
    if (!r2.ok) return new Map();
    return parseStatsQueryOutput(`${r2.stdout || ''}\n${r2.stderr || ''}`);
  }
  return parseStatsQueryOutput(`${r.stdout || ''}\n${r.stderr || ''}`);
}

/**
 * Best-effort set of currently online Xray user emails (client names).
 * Relies on statsUserOnline; returns empty Set if API/build does not expose it.
 * @returns {Promise<Set<string>>}
 */
async function queryOnlineUserEmails() {
  if (!(await dockerContainerRunning())) return new Set();
  const attempts = [
    ['exec', CONTAINER_NAME, 'xray', 'api', 'statsquery',
      '--server', `127.0.0.1:${XRAY_API_PORT}`, '-pattern', '>>>online'],
    ['exec', CONTAINER_NAME, 'xray', 'api', 'statsquery',
      '--server', `127.0.0.1:${XRAY_API_PORT}`, '-pattern', '>>>online', '-json'],
  ];
  for (const args of attempts) {
    // eslint-disable-next-line no-await-in-loop
    const r = await runCmd('docker', args, { timeout: 15_000 });
    if (!r.ok) continue;
    const set = parseOnlineStatsOutput(`${r.stdout || ''}\n${r.stderr || ''}`);
    if (set.size) return set;
  }
  return new Set();
}

function normalizePort(raw, fallback = config.XRAY_PORT) {
  const n = parseInt(String(raw == null ? '' : raw).trim(), 10);
  if (!Number.isFinite(n) || n < 1 || n > 65535) return fallback;
  return n;
}

async function removeXrayContainer() {
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
  return parts[0] === '1' && parts[1] === 'xray';
}

async function inspectContainerPortEnv() {
  const r = await runCmd('docker', [
    'inspect', '-f',
    '{{range .Config.Env}}{{println .}}{{end}}',
    CONTAINER_NAME,
  ]);
  if (!r.ok) return null;
  const line = r.stdout.split(/\r?\n/).find((l) => l.startsWith('XRAY_SERVER_PORT='));
  if (!line) return null;
  const n = parseInt(line.slice('XRAY_SERVER_PORT='.length), 10);
  return Number.isFinite(n) ? n : null;
}

async function ensureXrayContainer() {
  await ensureXrayImage();
  const volume = await resolveAwgVolumeName();
  const portPlan = require('./portPlan');
  const mode = portPlan.modeForService('xray') || 'direct';
  const publicPort = getPublicPort();
  const port = resolveListenPort(getPort(), { mode });
  if (String(port) !== String(getPort())) {
    setSetting(PORT_KEY, String(port));
  }

  const network = await portPlan.resolveNginxNetwork();
  if (mode === 'demux' && !network) {
    throw new Error('nginx compose network not found; is nginx running?');
  }

  const running = await dockerContainerRunning();
  if (running && await containerManagedByUs()) {
    const envPort = await inspectContainerPortEnv();
    const labelMode = await runCmd('docker', [
      'inspect', '-f', '{{index .Config.Labels "amnezia.port_mode"}}', CONTAINER_NAME,
    ]);
    const curMode = (labelMode.ok ? labelMode.stdout : '').trim();
    if (envPort === port && curMode === mode) {
      return { reused: true };
    }
  }

  if ((await runCmd('docker', ['inspect', CONTAINER_NAME])).ok) {
    await removeXrayContainer();
  }

  const runArgs = [
    'run', '-d',
    '--log-driver', 'none',
    '--restart', 'unless-stopped',
    '--cap-add=NET_ADMIN',
    '--name', CONTAINER_NAME,
    '--label', 'amnezia.managed=1',
    '--label', 'amnezia.service=xray',
    '--label', `amnezia.port_mode=${mode}`,
    '--label', `amnezia.listen_port=${port}`,
    '--label', `amnezia.public_port=${publicPort}`,
    '-e', `XRAY_SERVER_PORT=${port}`,
    '-v', `${volume}:/opt/amnezia/awg:rw`,
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
    throw new Error(run.stderr.trim() || 'docker run amnezia-xray failed');
  }
  return { reused: false };
}

async function reloadXrayConfig() {
  const up = await dockerContainerRunning();
  if (!up) return;
  // Restart so start.sh re-reads server.json (xray has no hot reload in our entrypoint)
  await runCmd('docker', ['restart', CONTAINER_NAME], { timeout: 60_000 });
}

/**
 * Rewrite server.json from DB and reload container when Xray is desired/running.
 */
async function syncClientsFromDb() {
  if (getDesired() !== true && phase !== 'running' && phase !== 'degraded') {
    return { skipped: true };
  }
  const keys = await generateRealityKeysIfMissing();
  const port = getPort();
  const sni = getSni();
  const flow = getFlow();
  const obj = buildServerConfigObject({
    port,
    sni,
    privateKey: keys.privateKey,
    shortId: keys.shortId,
    flow,
  });
  writeServerJson(obj);

  if (await dockerContainerRunning()) {
    const test = await runCmd('docker', [
      'exec', CONTAINER_NAME, 'xray', '-test', '-config', '/opt/amnezia/awg/xray/server.json',
    ], { timeout: 15_000 });
    if (!test.ok) {
      throw new Error((test.stderr || test.stdout || 'xray -test failed').trim().slice(0, 300));
    }
    await reloadXrayConfig();
  }
  return { ok: true, clients: obj.inbounds[0].settings.clients.length };
}

function isAmneziaXrayAvailable() {
  return phase === 'running';
}

function getStatus() {
  const desired = getDesired();
  const portPlan = require('./portPlan');
  const plan = portPlan.computePlan();
  return {
    desired: desired === true,
    desiredSet: desired !== null,
    phase,
    available: phase === 'running',
    lastError,
    smoke: lastSmoke,
    container: CONTAINER_NAME,
    address: getPublicHost(),
    addressStored: getAddress() || null,
    sni: getSni(),
    sniStored: getSniStored(),
    fingerprint: getFingerprint(),
    flow: getFlow(),
    port: getPort(),
    publicPort: getClientFacingPort(),
    mode: plan.modes.xray || null,
    demuxPeers: plan.demuxPeers.xray || [],
    publicKey: getSetting(PUB_KEY, '') || null,
    shortId: getSetting(SHORT_ID_KEY, '') || null,
    updatedAt,
    busy: Boolean(activeJob),
    fingerprints: FINGERPRINTS,
    flows: FLOWS,
  };
}

async function regenerateClientConfigs() {
  try {
    const WireGuard = require('./WireGuard');
    await WireGuard.saveConfig();
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Amnezia Xray: saveConfig after toggle failed:', err.message);
  }
}

/**
 * forceCleanup removes only the Docker container / runtime smoke state.
 * Persisted app_settings (keys, address, sni, fp, flow, port) and clients.xray_uuid are kept.
 */
async function forceCleanup() {
  await removeXrayContainer();
  lastSmoke = null;
  setPhase('off');
}

async function enableInternal(opts = {}) {
  setPhase('installing');
  setDesired(true);
  const deadline = Date.now() + ENABLE_TIMEOUT_MS;
  try {
    const sni = (opts.sni != null ? String(opts.sni).trim() : '') || getSni() || DEFAULT_SNI;
    let fingerprint = opts.fingerprint != null ? String(opts.fingerprint).trim() : getFingerprint();
    if (!FINGERPRINTS.includes(fingerprint)) fingerprint = DEFAULT_FP;
    let flow = opts.flow != null ? String(opts.flow) : getFlow();
    if (flow !== '' && !FLOWS.includes(flow)) flow = DEFAULT_FLOW;

    const publicPort = opts.publicPort != null
      ? parseInt(String(opts.publicPort).trim(), 10)
      : getPublicPort();
    if (!Number.isFinite(publicPort) || publicPort < 1 || publicPort > 65535) {
      throw Object.assign(new Error('Invalid Xray public port (1–65535)'), {
        status: 400,
        code: 'XRAY_BAD_PUBLIC_PORT',
      });
    }
    setSetting(PUBLIC_PORT_KEY, String(publicPort));
    assertSniNotMtproto(sni, publicPort);

    if (opts.port != null && String(opts.port).trim() !== '') {
      const requested = parseInt(String(opts.port).trim(), 10);
      if (!Number.isFinite(requested) || requested < 1 || requested > 65535) {
        throw Object.assign(new Error('Invalid Xray listen port (1–65535)'), {
          status: 400,
          code: 'XRAY_BAD_PORT',
        });
      }
    }

    const portPlan = require('./portPlan');
    // Tentative listen for plan computation
    const tentativeMode = (() => {
      const mtDesired = getSetting('amnezia_mtproto_desired', '');
      const mtOn = mtDesired === '1' || mtDesired === 'true';
      const mtPub = parseInt(getSetting('amnezia_mtproto_public_port', '') || '443', 10);
      if (mtOn && mtPub === publicPort) return 'demux';
      const panelPub = parseInt(String(config.PANEL_HTTPS_PORT || '10123'), 10);
      if (panelPub === publicPort) return 'demux';
      return 'direct';
    })();

    const port = resolveListenPort(
      opts.port != null && String(opts.port).trim() !== '' ? opts.port : getPort(),
      { mode: tentativeMode },
    );
    const addressRaw = opts.address != null ? String(opts.address).trim() : '';
    const address = addressRaw || getAddress() || getPublicHost();
    if (!address) {
      throw Object.assign(new Error('Xray address is required'), { status: 400, code: 'XRAY_BAD_ADDRESS' });
    }

    setSetting(SNI_KEY, sni);
    setSetting(FP_KEY, fingerprint);
    setSetting(FLOW_KEY, flow);
    setSetting(PORT_KEY, String(port));
    setSetting(ADDRESS_KEY, address);

    if (tentativeMode === 'direct') {
      await portPlan.assertHostPortsAvailable([publicPort], { allowNginx: true });
    }

    const keys = await generateRealityKeysIfMissing();
    ensureClientUuids();
    const obj = buildServerConfigObject({
      port,
      sni,
      privateKey: keys.privateKey,
      shortId: keys.shortId,
      flow,
    });
    writeServerJson(obj);

    await ensureXrayContainer();
    await portPlan.applyPlan();
    try {
      const mt = require('./amneziaMtproto');
      if (mt.getStatus && mt.getStatus().desired && typeof mt.ensureMtprotoContainer === 'function') {
        await mt.ensureMtprotoContainer();
      }
    } catch { /* ignore */ }
    await ensureXrayContainer();
    try {
      await portPlan.applyPlan();
    } catch { /* ignore */ }

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
          `Xray did not become ready in time (listen=${smoke.dial && smoke.dial.out}; versionOk=${smoke.versionOk})`,
        ),
        { code: 'XRAY_TIMEOUT', status: 504 },
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
    const err = new Error('Amnezia Xray operation already in progress');
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

/**
 * Regenerate Reality keys + all client xray_uuid. Keeps address/sni/fp/flow/port.
 * Invalidates existing vless/sub links (intentionally).
 */
async function resetCredentialsInternal() {
  setSetting(PRIV_KEY, '');
  setSetting(PUB_KEY, '');
  setSetting(SHORT_ID_KEY, '');
  const rows = getDb().clients.getAll();
  for (const row of rows) {
    getDb().clients.setXrayUuid(row.id, crypto.randomUUID());
  }
  const keys = await generateRealityKeysIfMissing();
  ensureClientUuids();
  if (getDesired() === true || phase === 'running' || phase === 'degraded') {
    await syncClientsFromDb();
  } else {
    // Still rewrite server.json for next enable
    const obj = buildServerConfigObject({
      port: getPort(),
      sni: getSni(),
      privateKey: keys.privateKey,
      shortId: keys.shortId,
      flow: getFlow(),
    });
    writeServerJson(obj);
  }
  await regenerateClientConfigs();
  return getStatus();
}

function resetCredentials() {
  return withJob(resetCredentialsInternal);
}

/**
 * Lookup enabled client by exact name for public /sub/:name.
 * @param {string} name
 */
function findEnabledClientByName(name) {
  if (!name) return null;
  const rows = getDb().clients.getAll();
  const row = rows.find((c) => c.name === name);
  if (!row || !row.enabled) return null;
  if (!row.xray_uuid) {
    const uuid = crypto.randomUUID();
    getDb().clients.setXrayUuid(row.id, uuid);
    row.xray_uuid = uuid;
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
    const listenPort = resolveListenPort(getPort());
    if (String(listenPort) !== String(getPort())) {
      setSetting(PORT_KEY, String(listenPort));
      await syncClientsFromDb();
    }
    if (!(await dockerContainerRunning())) {
      setPhase('degraded', new Error('amnezia-xray container not running'));
      await syncClientsFromDb();
      await ensureXrayContainer();
    } else {
      // Mode drift (e.g. MTProto joined same public port) → recreate
      await ensureXrayContainer();
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

async function bootAmneziaXray() {
  startReconcileTimer();
  await reconcile();
  try {
    // eslint-disable-next-line global-require
    require('./sniFinder').bootSniFinder();
  } catch (err) {
    // eslint-disable-next-line no-console
    console.warn('SNI Finder boot:', err && err.message ? err.message : err);
  }
  return getStatus();
}

function stopAmneziaXray() {
  stopReconcileTimer();
}

module.exports = {
  CONTAINER_NAME,
  IMAGE_NAME,
  XRAY_API_PORT,
  DEFAULT_SNI,
  DEFAULT_FP,
  DEFAULT_FLOW,
  FINGERPRINTS,
  FLOWS,
  enable,
  disable,
  forceCleanup: forceCleanupApi,
  resetCredentials,
  getStatus,
  isAmneziaXrayAvailable,
  syncClientsFromDb,
  ensureClientUuids,
  getClientXrayPayload,
  buildAmneziaXrayContainer,
  buildVlessUrl,
  buildClientJson,
  buildServerConfigObject,
  parseX25519Output,
  parseStatsQueryOutput,
  parseOnlineStatsOutput,
  queryUserTrafficStats,
  queryOnlineUserEmails,
  probeListenInsideContainer,
  normalizePort,
  getPublicHost,
  getClientFacingPort,
  findEnabledClientByName,
  bootAmneziaXray,
  stopAmneziaXray,
  regenerateClientConfigs,
  ensureXrayContainer,
};
