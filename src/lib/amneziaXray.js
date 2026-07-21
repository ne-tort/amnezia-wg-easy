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
const SECURITY_KEY = 'amnezia_xray_security';
const NETWORK_KEY = 'amnezia_xray_network';
const CERT_SOURCE_KEY = 'amnezia_xray_cert_source';
const CERT_DOMAIN_KEY = 'amnezia_xray_cert_domain';
const SSL_CERT_ID_KEY = 'amnezia_xray_ssl_cert_id';
const WS_PATH_KEY = 'amnezia_xray_ws_path';
const WS_HOST_KEY = 'amnezia_xray_ws_host';
const GRPC_SERVICE_KEY = 'amnezia_xray_grpc_service_name';
const GRPC_MULTI_KEY = 'amnezia_xray_grpc_multi_mode';
const ALPN_KEY = 'amnezia_xray_tls_alpn';
const ALLOW_INSECURE_KEY = 'amnezia_xray_allow_insecure';
const TRANSPORT_JSON_KEY = 'amnezia_xray_transport_json';

const xrayVlessConfig = require('./xrayVlessConfig');
const xrayTransportSchema = require('./xrayTransportSchema');

const DEFAULT_SNI = 'www.sbb.ch';
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
  const m = mode || portPlan.inferTcpMode('xray', getPublicPort());
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
    return parseInt(String(raw), 10);
  }
  return allocateInternalPort(excludedPortsForAlloc().concat([publicPort]), null);
}

function resolveInternalListenPort(preferred) {
  return resolveListenPort(preferred);
}

function assertSniDemux(sni, publicPort) {
  require('./portPlan').assertSniConflict(
    'xray',
    sni,
    publicPort != null ? publicPort : getPublicPort(),
    { sslCertId: getSetting(SSL_CERT_ID_KEY, '') },
  );
}

function getSni() {
  const raw = getDb().appSettings.get(SNI_KEY);
  if (raw === '') return '';
  if (raw != null && String(raw).trim()) return String(raw).trim();
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

function getSecurity() {
  return xrayVlessConfig.normalizeSecurity(getSetting(SECURITY_KEY, 'reality'));
}

function getNetwork() {
  return xrayVlessConfig.normalizeNetwork(getSetting(NETWORK_KEY, 'tcp'));
}

function getCertSource() {
  const tlsMaterial = require('./tlsMaterial');
  const s = getSetting(CERT_SOURCE_KEY, 'self_signed').trim().toLowerCase();
  return tlsMaterial.CERT_SOURCES.includes(s) ? s : 'self_signed';
}

function resolveCertDomain() {
  const override = getSetting(CERT_DOMAIN_KEY, '').trim().toLowerCase();
  if (override) return override;
  const sni = getSni();
  const source = getCertSource();
  if (source === 'panel') {
    const panel = require('./tlsMaterial').panelCertDomain();
    if (panel) return panel;
  }
  return sni;
}

function getWsPath() {
  return getSetting(WS_PATH_KEY, '/').trim() || '/';
}

function getWsHost() {
  return getSetting(WS_HOST_KEY, '').trim();
}

function getGrpcServiceName() {
  return getSetting(GRPC_SERVICE_KEY, '').trim();
}

function getGrpcMultiMode() {
  const raw = getSetting(GRPC_MULTI_KEY, '');
  return raw === '1' || raw === 'true' || raw === 'yes' || raw === 'on';
}

function getTlsAlpn() {
  const raw = getSetting(ALPN_KEY, '').trim();
  return raw ? raw.split(',').map((s) => s.trim()).filter(Boolean) : [];
}

function getAllowInsecure() {
  const raw = getSetting(ALLOW_INSECURE_KEY, '');
  if (raw === '1' || raw === 'true' || raw === 'yes' || raw === 'on') return true;
  if (raw === '0' || raw === 'false' || raw === 'no' || raw === 'off') return false;
  return getSecurity() === 'tls' && getCertSource() === 'self_signed';
}

function migrateLegacyTransportSettings(network) {
  /** @type {Record<string, unknown>} */
  const legacy = {};
  const wsPath = getWsPath();
  const wsHost = getWsHost();
  const grpcService = getGrpcServiceName();
  if (network === 'ws') {
    if (wsPath && wsPath !== '/') legacy.wsPath = wsPath;
    if (wsHost) legacy.wsHost = wsHost;
  }
  if (network === 'grpc') {
    if (grpcService) legacy.grpcServiceName = grpcService;
    if (getGrpcMultiMode()) legacy.grpcMultiMode = true;
  }
  return legacy;
}

function getTransportSettingsRaw() {
  const raw = getSetting(TRANSPORT_JSON_KEY, '');
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw);
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) return parsed;
  } catch {
    /* ignore */
  }
  return null;
}

function getTransportSettings() {
  const network = getNetwork();
  const stored = getTransportSettingsRaw();
  if (stored) {
    return xrayTransportSchema.sanitizeTransportSettings(network, stored);
  }
  return xrayTransportSchema.sanitizeTransportSettings(network, migrateLegacyTransportSettings(network));
}

function setTransportSettings(network, settings) {
  const sanitized = xrayTransportSchema.sanitizeTransportSettings(network, settings || {});
  setSetting(TRANSPORT_JSON_KEY, Object.keys(sanitized).length ? JSON.stringify(sanitized) : '');
  // Keep legacy keys in sync for ws/grpc
  if (network === 'ws') {
    setSetting(WS_PATH_KEY, String(sanitized.wsPath || '/').trim() || '/');
    setSetting(WS_HOST_KEY, sanitized.wsHost != null ? String(sanitized.wsHost).trim() : '');
  }
  if (network === 'grpc') {
    setSetting(GRPC_SERVICE_KEY, sanitized.grpcServiceName != null ? String(sanitized.grpcServiceName).trim() : '');
    setSetting(GRPC_MULTI_KEY, sanitized.grpcMultiMode === true ? '1' : '0');
  }
}

function mergeStreamOpts(overrides = {}) {
  const network = xrayVlessConfig.normalizeNetwork(
    overrides.network != null ? overrides.network : getNetwork(),
  );
  const security = xrayVlessConfig.normalizeSecurity(
    overrides.security != null ? overrides.security : getSecurity(),
  );
  const sni = overrides.sni != null ? String(overrides.sni) : getSni();
  const transportRaw = overrides.transportSettings != null
    ? overrides.transportSettings
    : getTransportSettings();
  const inherited = xrayTransportSchema.inheritTransportFields(
    { sni, certDomain: overrides.certDomain },
    network,
    transportRaw,
  );
  let flow = overrides.flow != null ? String(overrides.flow) : getFlow();
  if (!xrayTransportSchema.flowSupported(network)) flow = '';
  return {
    security,
    network,
    sni,
    fingerprint: overrides.fingerprint != null ? overrides.fingerprint : getFingerprint(),
    flow,
    alpn: overrides.alpn != null ? overrides.alpn : getTlsAlpn(),
    allowInsecure: overrides.allowInsecure != null ? overrides.allowInsecure : getAllowInsecure(),
    ...inherited,
    ...overrides,
    security,
    network,
    sni,
    flow,
  };
}

function clientStreamOpts() {
  return mergeStreamOpts({});
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
  let needBuild = !inspect.ok;
  if (!needBuild) {
    const ver = await runCmd('docker', [
      'run', '--rm', '--entrypoint', 'xray', IMAGE_NAME, 'version',
    ], { timeout: 30_000 });
    const text = `${ver.stdout || ''} ${ver.stderr || ''}`;
    // Hy2 inbound requires Xray >= 26.3.27
    if (!/Xray\s+26\./i.test(text) && !/26\.\d+\.\d+/.test(text)) {
      needBuild = true;
      await runCmd('docker', ['rmi', '-f', IMAGE_NAME], { timeout: 60_000 });
    }
  }
  if (!needBuild) return;

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

function buildServerConfigObject(opts = {}) {
  const merged = mergeStreamOpts(opts);
  const security = merged.security;
  const network = merged.network;
  const port = opts.port;
  const sni = merged.sni || getSni();
  const flow = merged.flow;
  const clients = ensureClientUuids();
  const includeVless = opts.includeVless !== false && getDesired() === true;

  /** @type {Array<Record<string, unknown>>} */
  const inbounds = [];

  if (includeVless) {
    /** @type {Record<string, unknown>} */
    const inboundOpts = {
      ...merged,
      port,
      sni,
      security,
      network,
      flow,
      clients,
    };

    if (security === 'reality') {
      inboundOpts.privateKey = opts.privateKey;
      inboundOpts.shortId = opts.shortId;
    } else if (security === 'tls') {
      const certDomain = opts.certDomain || resolveCertDomain();
      const paths = require('./tlsMaterial').certPathsForDomain(certDomain);
      inboundOpts.tlsCert = paths.cert;
      inboundOpts.tlsKey = paths.key;
    }

    inbounds.push(xrayVlessConfig.buildServerInbound(inboundOpts));
  }

  if (opts.hysteriaInbound) {
    inbounds.push(opts.hysteriaInbound);
  } else {
    try {
      const hyInbound = buildSharedHysteriaInboundIfNeeded();
      if (hyInbound) inbounds.push(hyInbound);
    } catch (err) {
      // eslint-disable-next-line no-console
      console.warn('Xray hy inbound skip:', err && err.message ? err.message : err);
    }
  }

  inbounds.push({
    tag: 'api',
    listen: '127.0.0.1',
    port: XRAY_API_PORT,
    protocol: 'dokodemo-door',
    settings: { address: '127.0.0.1' },
  });

  if (!inbounds.some((i) => i.tag !== 'api')) {
    throw new Error('Xray config has no proxy inbounds');
  }

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
          statsUserOnline: true,
        },
      },
      system: {
        statsInboundUplink: true,
        statsInboundDownlink: true,
      },
    },
    inbounds,
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

/** Internal UDP listen for Hy2 inbound inside amnezia-xray. */
const HYSTERIA_XRAY_LISTEN_PORT = 34443;

function isHysteriaXrayCoreDesired() {
  try {
    const hy = require('./amneziaHysteria');
    return typeof hy.isXrayCoreDesired === 'function' && hy.isXrayCoreDesired();
  } catch {
    return false;
  }
}

function buildSharedHysteriaInboundIfNeeded() {
  if (!isHysteriaXrayCoreDesired()) return null;
  const hy = require('./amneziaHysteria');
  return hy.buildXrayInboundConfig({ listenPort: HYSTERIA_XRAY_LISTEN_PORT });
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
function buildClientJson(opts) {
  return xrayVlessConfig.buildClientJson(opts);
}

function buildVlessUrl(opts) {
  return xrayVlessConfig.buildVlessUrl(opts);
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
  const stream = clientStreamOpts();
  const publicKey = getSetting(PUB_KEY, '');
  const shortId = getSetting(SHORT_ID_KEY, '');
  if (stream.security === 'reality' && (!publicKey || !shortId)) return null;

  const baseOpts = {
    uuid: client.xray_uuid,
    host,
    port,
    remark: client.name,
    publicKey,
    shortId,
    ...stream,
  };

  const clientJson = buildClientJson(baseOpts);
  const vlessUrl = buildVlessUrl(baseOpts);

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
    sni: stream.sni,
    fingerprint: stream.fingerprint,
    flow: stream.flow,
    security: stream.security,
    network: stream.network,
    publicKey: stream.security === 'reality' ? publicKey : null,
    shortId: stream.security === 'reality' ? shortId : null,
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
      transport_proto: xrayTransportSchema.mapTransportProto(payload.network),
    },
  };
}

/**
 * Probe that Xray accepts connections inside its container namespace.
 * Do NOT dial 127.0.0.1 from the panel — published -p ports bind on the Docker
 * host, not in amnezia-awg, so ECONNREFUSED there is expected.
 */
async function probeListenInsideContainer(port) {
  const p = String(port);
  const needsUdp = xrayTransportSchema.isUdpTransport(getNetwork());
  if (needsUdp) {
    // UDP: confirm the process is listening (ss/netstat); nc -u is unreliable for bind-only.
    const ss = await runCmd('docker', [
      'exec', CONTAINER_NAME, 'sh', '-c',
      `ss -uln 2>/dev/null | grep -E '[:.]${p}\\s' || netstat -uln 2>/dev/null | grep -E '[:.]${p}\\s'`,
    ], { timeout: 8_000 });
    if (ss.ok && String(ss.stdout || '').trim()) {
      return { ok: true, via: 'ss-udp', out: 'listening' };
    }
    // Fallback: xray process up + config test already passed at start
    const ps = await runCmd('docker', [
      'exec', CONTAINER_NAME, 'sh', '-c', 'pgrep -x xray >/dev/null && echo up',
    ], { timeout: 8_000 });
    if (ps.ok && String(ps.stdout || '').includes('up')) {
      return { ok: true, via: 'pgrep', out: 'xray running (udp)' };
    }
    return { ok: false, via: 'ss-udp', out: (ss.stderr || ss.stdout || 'udp not listening').trim().slice(0, 160) };
  }

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
  const networkName = getNetwork();
  const vlessDesired = getDesired() === true;
  const needsUdpTransport = vlessDesired && xrayTransportSchema.isUdpTransport(networkName);
  const hyXray = isHysteriaXrayCoreDesired();
  let mode = portPlan.inferTcpMode('xray', getPublicPort());
  // UDP transports (mKCP / hysteria) cannot share TCP SNI demux — force direct publish.
  if (needsUdpTransport && mode === 'demux') {
    mode = 'direct';
  }
  const publicPort = getPublicPort();
  const port = resolveListenPort(getPort(), { mode });
  if (vlessDesired && String(port) !== String(getPort())) {
    setSetting(PORT_KEY, String(port));
  }

  let hyPublicPort = 0;
  if (hyXray) {
    try {
      hyPublicPort = require('./amneziaHysteria').getPublicPort();
    } catch {
      hyPublicPort = 443;
    }
  }

  const dockerNet = await portPlan.resolveNginxNetwork();
  if (mode === 'demux' && vlessDesired && !dockerNet) {
    throw new Error('nginx compose network not found; is nginx running?');
  }

  const wantHyUdp = hyXray ? `hyudp=${hyPublicPort}:${HYSTERIA_XRAY_LISTEN_PORT}` : '';
  const wantVlessProto = needsUdpTransport ? 'udp' : 'tcp';
  const wantVlessPub = (vlessDesired && mode !== 'demux')
    ? `${publicPort}:${port}/${wantVlessProto}`
    : (vlessDesired ? 'demux' : 'none');
  const wantFingerprint = `${wantVlessPub}|${wantHyUdp}|mode=${mode}`;

  const running = await dockerContainerRunning();
  if (running && await containerManagedByUs()) {
    const labelFp = await runCmd('docker', [
      'inspect', '-f', '{{index .Config.Labels "amnezia.publish_fp"}}', CONTAINER_NAME,
    ]);
    const curFp = (labelFp.ok ? labelFp.stdout : '').trim();
    if (curFp === wantFingerprint) {
      return { reused: true };
    }
  }

  if ((await runCmd('docker', ['inspect', CONTAINER_NAME])).ok) {
    await removeXrayContainer();
  }

  const needCertMount = getSecurity() === 'tls' || hyXray;
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
    '--label', `amnezia.transport_proto=${wantVlessProto}`,
    '--label', `amnezia.publish_fp=${wantFingerprint}`,
    '-e', `XRAY_SERVER_PORT=${port}`,
    '-e', `XRAY_TRANSPORT_PROTO=${wantVlessProto}`,
    '-v', `${volume}:/opt/amnezia/awg:rw`,
  ];
  if (needCertMount) {
    const certVolume = await resolveCertbotVolumeName();
    runArgs.push('-v', `${certVolume}:/etc/letsencrypt:ro`);
  }
  if (dockerNet) runArgs.push('--network', dockerNet);
  if (vlessDesired && mode !== 'demux') {
    runArgs.push('-p', `${publicPort}:${port}/${wantVlessProto}`);
  }
  if (hyXray && hyPublicPort) {
    runArgs.push('-p', `${hyPublicPort}:${HYSTERIA_XRAY_LISTEN_PORT}/udp`);
    runArgs.push('-e', `XRAY_HYSTERIA_PORT=${HYSTERIA_XRAY_LISTEN_PORT}`);
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
  const hyNeedsXray = isHysteriaXrayCoreDesired();
  if (getDesired() !== true && !hyNeedsXray && phase !== 'running' && phase !== 'degraded') {
    return { skipped: true };
  }
  const keys = (getDesired() === true && getSecurity() === 'reality')
    ? await generateRealityKeysIfMissing()
    : null;
  const port = getPort();
  const sni = getSni();
  const flow = getFlow();
  const obj = buildServerConfigObject({
    port,
    sni,
    privateKey: keys && keys.privateKey,
    shortId: keys && keys.shortId,
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
  const inbound = obj.inbounds.find((i) => i.protocol === 'vless');
  const clientCount = inbound && inbound.settings && inbound.settings.clients
    ? inbound.settings.clients.length
    : 0;
  return { ok: true, clients: clientCount };
}

function isAmneziaXrayAvailable() {
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
    fingerprint: getFingerprint(),
    flow: getFlow(),
    security: getSecurity(),
    network: getNetwork(),
    transports: xrayTransportSchema.TRANSPORTS,
    transportSettings: getTransportSettings(),
    transportFields: xrayTransportSchema.getFieldsForUi(getNetwork()),
    allowedSecurities: xrayTransportSchema.allowedSecurities(getNetwork()),
    allowedCertTypes: xrayTransportSchema.allowedCertTypes(getSecurity(), getNetwork()),
    certSource: getCertSource(),
    certDomain: resolveCertDomain(),
    sslCertId: getSetting(SSL_CERT_ID_KEY, '') || null,
    wsPath: getWsPath(),
    wsHost: getWsHost() || null,
    grpcServiceName: getGrpcServiceName() || null,
    grpcMultiMode: getGrpcMultiMode(),
    tlsAlpn: getTlsAlpn(),
    allowInsecure: getAllowInsecure(),
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
    const sidecarValidate = require('./sidecarValidate');
    const validation = sidecarValidate.validateXray(opts);
    if (!validation.ok) {
      const msg = Object.values(validation.fieldErrors || {}).join('; ') || 'Invalid Xray settings';
      throw Object.assign(new Error(msg), {
        status: 400,
        code: validation.code || 'XRAY_VALIDATION',
        fieldErrors: validation.fieldErrors,
      });
    }
    const { resolveOptsSslCert } = require('./sidecarAutoCert');
    opts = await resolveOptsSslCert(opts, 'xray');
    if (validation.sni && !opts.sni) opts.sni = validation.sni;

    const security = xrayVlessConfig.normalizeSecurity(
      opts.security != null ? opts.security : getSecurity(),
    );
    const network = xrayVlessConfig.normalizeNetwork(
      opts.network != null ? opts.network : getNetwork(),
    );
    const sslManager = require('./sslManager');
    const sslCertId = String(opts.sslCertId || opts.ssl_cert_id || '').trim()
      || getSetting(SSL_CERT_ID_KEY, '');
    let inventoryCert = null;
    if (sslCertId && (security === 'reality' || security === 'tls')) {
      inventoryCert = sslManager.requireSidecarCert(
        sslCertId,
        security === 'reality' ? 'xray_reality' : 'xray_tls',
      );
    }

    let certSource = opts.certSource != null
      ? String(opts.certSource).trim().toLowerCase()
      : getCertSource();
    let certDomainOverride = opts.certDomain != null ? String(opts.certDomain).trim().toLowerCase() : '';
    const tlsMaterial = require('./tlsMaterial');
    const emailOpt = opts.email != null ? opts.email : (opts.certbotEmail != null ? opts.certbotEmail : null);
    if (emailOpt) tlsMaterial.setCertbotEmail(emailOpt);

    let sni = tlsMaterial.normalizeHostname(
      opts.sni != null ? String(opts.sni) : (getSniStored() || ''),
    );
    if (inventoryCert) {
      sni = tlsMaterial.normalizeHostname(inventoryCert.sni || inventoryCert.domain || sni);
      if (inventoryCert.type === 'self_signed') certSource = 'self_signed';
      else if (inventoryCert.type === 'lets_encrypt' || inventoryCert.type === 'lets_encrypt_ip') certSource = 'issue_le';
      else if (inventoryCert.type === 'manual') certSource = 'manual_path';
      else if (inventoryCert.type === 'reality') certSource = 'reality';
      certDomainOverride = inventoryCert.storage_key || inventoryCert.domain || certDomainOverride;
    }
    if (security === 'none') {
      sni = '';
    } else if (security === 'reality') {
      sni = sni || getSni() || DEFAULT_SNI;
    } else if (security === 'tls') {
      if (certSource === 'issue_le') {
        sni = sni || tlsMaterial.normalizeHostname(opts.sni || '');
      } else {
        sni = sni || '';
      }
    }

    let fingerprint = opts.fingerprint != null ? String(opts.fingerprint).trim() : getFingerprint();
    if (!FINGERPRINTS.includes(fingerprint)) fingerprint = DEFAULT_FP;
    let flow = opts.flow != null ? String(opts.flow) : getFlow();
    if (flow !== '' && !FLOWS.includes(flow)) flow = DEFAULT_FLOW;
    if (!xrayTransportSchema.flowSupported(network)) flow = '';

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
    if (security !== 'none' && sni) {
      assertSniDemux(sni, publicPort);
    }

    if (security === 'reality' || (security === 'tls' && certSource === 'issue_le' && sni)) {
      const { domainHasPublicDns } = require('./sniFinder');
      if (sni && !(await domainHasPublicDns(sni))) {
        throw Object.assign(
          new Error(
            `SNI «${sni}» не резолвится в публичном DNS (нужен реальный hostname, не CDN-SAN)`,
          ),
          { status: 400, code: 'XRAY_SNI_NO_DNS' },
        );
      }
    }

    setSetting(SECURITY_KEY, security);
    setSetting(NETWORK_KEY, network);
    setSetting(CERT_SOURCE_KEY, certSource);
    setSetting(CERT_DOMAIN_KEY, certDomainOverride);
        if (inventoryCert) {
      setSetting(SSL_CERT_ID_KEY, inventoryCert.id);
    } else if (security === 'none') {
      setSetting(SSL_CERT_ID_KEY, '');
    }

    const transportRaw = opts.transportSettings != null ? opts.transportSettings : null;
    if (opts.transportSettings != null || opts.network != null) {
      const ts = transportRaw != null ? transportRaw : getTransportSettings();
      const transportCheckEarly = xrayTransportSchema.validateTransportSettings(network, ts);
      if (!transportCheckEarly.ok) {
        const msg = Object.values(transportCheckEarly.fieldErrors || {}).join('; ') || 'Invalid transport settings';
        throw Object.assign(new Error(msg), {
          status: 400,
          code: 'XRAY_TRANSPORT_VALIDATION',
          fieldErrors: transportCheckEarly.fieldErrors,
        });
      }
      setTransportSettings(network, ts);
    } else {
      if (opts.wsPath != null) setSetting(WS_PATH_KEY, String(opts.wsPath).trim() || '/');
      if (opts.wsHost != null) setSetting(WS_HOST_KEY, String(opts.wsHost).trim());
      if (opts.grpcServiceName != null) setSetting(GRPC_SERVICE_KEY, String(opts.grpcServiceName).trim());
      if (opts.grpcMultiMode != null) {
        setSetting(GRPC_MULTI_KEY, (opts.grpcMultiMode === true || opts.grpcMultiMode === '1') ? '1' : '0');
      }
    }
    const transportCheck = xrayTransportSchema.validateTransportSettings(
      network,
      getTransportSettings(),
    );
    if (!transportCheck.ok) {
      const msg = Object.values(transportCheck.fieldErrors || {}).join('; ') || 'Invalid transport settings';
      throw Object.assign(new Error(msg), {
        status: 400,
        code: 'XRAY_TRANSPORT_VALIDATION',
        fieldErrors: transportCheck.fieldErrors,
      });
    }
    if (!xrayTransportSchema.allowedSecurities(network).includes(security)) {
      throw Object.assign(new Error(`Security «${security}» is not allowed for transport «${network}»`), {
        status: 400,
        code: 'XRAY_TRANSPORT_SECURITY',
      });
    }
    if (opts.alpn != null) {
      const alpnVal = Array.isArray(opts.alpn) ? opts.alpn.join(',') : String(opts.alpn).trim();
      setSetting(ALPN_KEY, alpnVal);
    }
    let allowInsecure = opts.allowInsecure != null
      ? (opts.allowInsecure === true || opts.allowInsecure === '1' || opts.allowInsecure === 'true')
      : getAllowInsecure();
    if (security === 'tls' && certSource === 'self_signed' && opts.allowInsecure == null) {
      allowInsecure = true;
    }
    if (security === 'tls' && certSource === 'issue_le') {
      allowInsecure = false;
    }
    setSetting(ALLOW_INSECURE_KEY, allowInsecure ? '1' : '0');

    if (security === 'tls') {
      if (inventoryCert) {
        const key = inventoryCert.storage_key || inventoryCert.domain;
        if (!(await tlsMaterial.certExistsInVolume(key))) {
          throw Object.assign(new Error(`Certificate files missing for ${key}`), {
            status: 400,
            code: 'XRAY_CERT_MISSING',
          });
        }
        setSetting(CERT_DOMAIN_KEY, key);
      } else {
        if (certSource === 'panel') {
          tlsMaterial.assertPanelCertReuseAllowed('xray', publicPort);
        }
        let certDomain = certDomainOverride;
        if (!certDomain) {
          if (certSource === 'panel') {
            certDomain = tlsMaterial.panelCertDomain() || sni || 'localhost';
          } else if (certSource === 'issue_le') {
            certDomain = sni;
          } else {
            certDomain = sni || 'xray.local';
          }
        }
        await tlsMaterial.resolveCertMaterial({
          certSource,
          domain: certDomain,
          certPem: opts.certPem,
          keyPem: opts.keyPem,
          certPath: opts.certPath,
          keyPath: opts.keyPath,
          email: emailOpt || tlsMaterial.getCertbotEmail(),
          issueIfMissing: certSource === 'issue_le',
        });
      }
    }

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
    // Demux when panel or mirror stub already owns this public TCP port.
    const tentativeMode = portPlan.inferTcpMode('xray', publicPort);

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

    const keys = security === 'reality'
      ? (inventoryCert && inventoryCert.type === 'reality'
        ? (() => {
          setSetting(PRIV_KEY, inventoryCert.reality_private_key);
          setSetting(PUB_KEY, inventoryCert.reality_public_key);
          setSetting(SHORT_ID_KEY, inventoryCert.reality_short_id);
          return {
            privateKey: inventoryCert.reality_private_key,
            publicKey: inventoryCert.reality_public_key,
            shortId: inventoryCert.reality_short_id,
          };
        })()
        : await generateRealityKeysIfMissing())
      : null;
    ensureClientUuids();
    let obj;
    try {
      obj = buildServerConfigObject({
        port,
        sni,
        privateKey: keys && keys.privateKey,
        shortId: keys && keys.shortId,
        flow,
        security,
        network,
      });
      writeServerJson(obj);
    } catch (buildErr) {
      throw Object.assign(
        new Error(buildErr && buildErr.message ? buildErr.message : 'Failed to build Xray server config'),
        { status: 400, code: 'XRAY_CONFIG_BUILD' },
      );
    }

    await ensureXrayContainer();
    try {
      await portPlan.applyPlan();
    } catch (planErr) {
      // nginx name Conflict / compose glitch must not wipe a started Xray container
      // eslint-disable-next-line no-console
      console.error('Xray enable: portPlan.applyPlan failed:', planErr && planErr.message);
      setPhase('degraded', planErr);
    }
    await ensureXrayContainer();
    try {
      await portPlan.applyPlan();
    } catch (planErr) {
      // eslint-disable-next-line no-console
      console.error('Xray enable: portPlan retry failed:', planErr && planErr.message);
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
          `Xray did not become ready in time (listen=${smoke.dial && smoke.dial.out}; versionOk=${smoke.versionOk})`,
        ),
        { code: 'XRAY_TIMEOUT', status: 504 },
      );
    }

    setPhase('running');
    await regenerateClientConfigs();
    return getStatus();
  } catch (err) {
    try {
      await forceCleanup();
    } catch (cleanupErr) {
      // eslint-disable-next-line no-console
      console.error('Xray enable: forceCleanup failed:', cleanupErr && cleanupErr.message);
    }
    setDesired(false);
    try {
      await require('./portPlan').applyPlan();
    } catch (planErr) {
      // eslint-disable-next-line no-console
      console.error('Xray enable: portPlan after failure failed:', planErr && planErr.message);
    }
    setPhase('error', err);
    try {
      await regenerateClientConfigs();
    } catch (regErr) {
      // eslint-disable-next-line no-console
      console.error('Xray enable: regenerateClientConfigs failed:', regErr && regErr.message);
    }
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
  try {
    require('./xrayTransportProfileBank').ensureBankSeeded();
  } catch (err) {
    // eslint-disable-next-line no-console
    console.warn('Xray transport profile bank seed:', err && err.message ? err.message : err);
  }
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
  reloadXrayConfig,
};
