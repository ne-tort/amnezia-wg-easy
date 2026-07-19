'use strict';

/**
 * Amnezia MTProto (Telemt) orchestration: Fake-TLS proxy behind nginx SNI demux.
 * Shared tg:// link (not per-AWG-client). Persistence in app_settings.
 */

const { spawn, execFile } = require('node:child_process');
const { promisify } = require('node:util');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const net = require('node:net');
const config = require('../config');

const execFileAsync = promisify(execFile);

const CONTAINER_NAME = 'amnezia-mtproto';
const IMAGE_NAME = 'amnezia-mtproto';
const DOCKERFILE_FOLDER = '/opt/amnezia/mtproto';
const PANEL_CONTAINER = 'amnezia-awg';
const MT_REL = 'mtproto';
const CONFIG_TOML = 'config.toml';

const DESIRED_KEY = 'amnezia_mtproto_desired';
const SECRET_KEY = 'amnezia_mtproto_secret';
const SNI_KEY = 'amnezia_mtproto_sni';
const PORT_KEY = 'amnezia_mtproto_port';
const PUBLIC_PORT_KEY = 'amnezia_mtproto_public_port';
const ADDRESS_KEY = 'amnezia_mtproto_address';

const DEFAULT_SNI = 'www.ns.nl';
const USER_NAME = 'amnezia';

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

function mtHostDir() {
  return path.join(config.WG_PATH, MT_REL);
}

function configTomlPath() {
  return path.join(mtHostDir(), CONFIG_TOML);
}

function ensureMtDir() {
  fs.mkdirSync(mtHostDir(), { recursive: true });
}

function getPort() {
  const fromDb = getSetting(PORT_KEY, '');
  if (fromDb && /^\d+$/.test(fromDb)) return parseInt(fromDb, 10);
  return 0;
}

function getPublicPort() {
  const fromDb = getSetting(PUBLIC_PORT_KEY, '');
  if (fromDb && /^\d+$/.test(fromDb)) return parseInt(fromDb, 10);
  const fromEnv = parseInt(String(process.env.MTPROTO_PUBLIC_PORT || '').trim(), 10);
  if (Number.isFinite(fromEnv) && fromEnv >= 1 && fromEnv <= 65535) return fromEnv;
  return 443;
}

function getClientFacingPort() {
  return getPublicPort();
}

function getSni() {
  const stored = getSetting(SNI_KEY, '');
  if (stored) return stored;
  try {
    const xraySni = getDb().appSettings.get('amnezia_xray_sni') || '';
    // eslint-disable-next-line global-require
    const picked = require('./sniFinder').pickAlternateSni(xraySni);
    if (picked) return picked;
  } catch { /* optional */ }
  return DEFAULT_SNI;
}

function getSniStored() {
  return getSetting(SNI_KEY, '') || null;
}

function getAddress() {
  return getSetting(ADDRESS_KEY, '').trim();
}

function getPublicHost() {
  const stored = getAddress();
  if (stored) return stored;
  const wg = (config.WG_HOST || '').trim();
  if (wg) return wg;
  return '127.0.0.1';
}

function generateSecret() {
  return crypto.randomBytes(16).toString('hex');
}

function getOrCreateSecret() {
  let secret = getSetting(SECRET_KEY, '').trim().toLowerCase();
  if (/^[0-9a-f]{32}$/.test(secret)) return secret;
  secret = generateSecret();
  setSetting(SECRET_KEY, secret);
  return secret;
}

function domainToHex(domain) {
  return Buffer.from(String(domain), 'utf8').toString('hex');
}

/**
 * Fake-TLS ee secret: ee + 32hex + domain hex
 */
function buildEeSecret(rawSecret, sni) {
  return `ee${rawSecret}${domainToHex(sni)}`;
}

function buildTgProxyLink({ host, port, eeSecret }) {
  const q = new URLSearchParams({
    server: host,
    port: String(port),
    secret: eeSecret,
  });
  return `tg://proxy?${q.toString()}`;
}

function buildTmeProxyLink({ host, port, eeSecret }) {
  const q = new URLSearchParams({
    server: host,
    port: String(port),
    secret: eeSecret,
  });
  return `https://t.me/proxy?${q.toString()}`;
}

function buildConfigToml({
  port, sni, secret, publicHost, publicPort,
}) {
  // Telemt TOML — Fake-TLS only, mask to tls_domain.
  // Direct DC (use_middle_proxy=false): ME often gives check/ping then dies;
  // C→telemt→DC is more stable for full sync on typical VPS.
  const lines = [
    '[general]',
    'use_middle_proxy = false',
    'fast_mode = true',
    'prefer_ipv6 = false',
    'log_level = "normal"',
  ];
  lines.push(
    '',
    '[general.modes]',
    'classic = false',
    'secure = false',
    'tls = true',
    '',
    '[general.links]',
    'show = "*"',
    `public_host = ${JSON.stringify(publicHost)}`,
    `public_port = ${Number(publicPort)}`,
    '',
    '[server]',
    `port = ${Number(port)}`,
    '',
    '[server.api]',
    'enabled = false',
    '',
    '[[server.listeners]]',
    'ip = "0.0.0.0"',
    '',
    '[timeouts]',
    'client_handshake = 60',
    '',
    '[censorship]',
    `tls_domain = ${JSON.stringify(sni)}`,
    'mask = true',
    'tls_emulation = true',
    'tls_front_dir = "tlsfront"',
    '',
    '[access]',
    'ignore_time_skew = true',
    '',
    '[access.users]',
    `${USER_NAME} = ${JSON.stringify(secret)}`,
    '',
  );
  return lines.join('\n');
}

function writeConfigToml(opts) {
  ensureMtDir();
  fs.writeFileSync(configTomlPath(), buildConfigToml(opts), 'utf8');
}

function assertSniNotXray(sni, publicPort) {
  require('./portPlan').assertSniConflict(
    'mtproto',
    sni,
    publicPort != null ? publicPort : getPublicPort(),
  );
}

/** Fake-TLS + tls_emulation require the mask domain to resolve on public DNS. */
async function assertSniHasPublicDns(sni) {
  const d = String(sni || '').trim().toLowerCase();
  if (!d) {
    throw Object.assign(new Error('MTProto SNI is required'), {
      status: 400,
      code: 'MTPROTO_BAD_SNI',
    });
  }
  const { domainHasPublicDns } = require('./sniFinder');
  if (!(await domainHasPublicDns(d))) {
    throw Object.assign(
      new Error(
        `SNI «${d}» не резолвится в публичном DNS — Telemt Fake-TLS нужен реальный сайт (не CDN-SAN вроде secondary.cloudflare.com)`,
      ),
      { status: 400, code: 'MTPROTO_SNI_NO_DNS' },
    );
  }
}

function excludedPortsForAlloc() {
  return [
    config.PANEL_HTTPS_PORT,
    getPublicPort(),
    getSetting('amnezia_xray_public_port', '') || 443,
    getSetting('amnezia_xray_port', ''),
    80,
    8443,
  ];
}

function resolveListenPort(preferred, { mode } = {}) {
  const portPlan = require('./portPlan');
  const m = mode || portPlan.modeForService('mtproto') || 'direct';
  const publicPort = getPublicPort();
  if (m === 'direct') {
    const raw = preferred != null ? parseInt(String(preferred), 10) : getPort();
    if (Number.isFinite(raw) && raw >= 1 && raw <= 65535 && raw !== 80 && raw !== 8443) {
      return raw;
    }
    return publicPort;
  }
  const { allocateInternalPort, needsInternalRealloc } = require('./internalPort');
  const raw = preferred != null ? preferred : getPort();
  if (raw && !needsInternalRealloc(raw) && parseInt(String(raw), 10) !== publicPort) {
    const n = parseInt(String(raw), 10);
    const xr = parseInt(getSetting('amnezia_xray_port', ''), 10);
    if (Number.isFinite(xr) && xr === n) {
      return allocateInternalPort(excludedPortsForAlloc().concat([n, publicPort]), null);
    }
    return n;
  }
  return allocateInternalPort(excludedPortsForAlloc().concat([publicPort]), null);
}

function resolveInternalListenPort(preferred) {
  return resolveListenPort(preferred);
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

async function ensureMtprotoImage() {
  const inspect = await runCmd('docker', ['image', 'inspect', IMAGE_NAME]);
  if (inspect.ok) return;

  const dockerfilePath = path.join(DOCKERFILE_FOLDER, 'Dockerfile');
  const startPath = path.join(DOCKERFILE_FOLDER, 'start.sh');
  if (!fs.existsSync(dockerfilePath)) {
    throw new Error('amnezia-mtproto image missing; run deploy.sh');
  }
  await new Promise((resolve, reject) => {
    const child = spawn('docker', ['build', '-t', IMAGE_NAME, DOCKERFILE_FOLDER], {
      stdio: ['ignore', 'ignore', 'pipe'],
    });
    let err = '';
    const timer = setTimeout(() => {
      try { child.kill('SIGKILL'); } catch (_) { /* ignore */ }
      reject(new Error('docker build amnezia-mtproto timed out'));
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
  });
  // Ensure start.sh present for in-image rebuild path
  if (fs.existsSync(startPath)) { /* ok */ }
}

async function containerManagedByUs() {
  const r = await runCmd('docker', [
    'inspect', '-f', '{{index .Config.Labels "amnezia.managed"}} {{index .Config.Labels "amnezia.service"}}',
    CONTAINER_NAME,
  ]);
  if (!r.ok) return false;
  const parts = r.stdout.trim().split(/\s+/);
  return parts[0] === '1' && parts[1] === 'mtproto';
}

async function inspectContainerPortLabel() {
  const r = await runCmd('docker', [
    'inspect', '-f', '{{index .Config.Labels "amnezia.listen_port"}}',
    CONTAINER_NAME,
  ]);
  if (!r.ok) return null;
  const n = parseInt(r.stdout.trim(), 10);
  return Number.isFinite(n) ? n : null;
}

async function removeMtprotoContainer() {
  await runCmd('docker', ['stop', CONTAINER_NAME]);
  await runCmd('docker', ['rm', '-fv', CONTAINER_NAME]);
}

async function ensureMtprotoContainer() {
  await ensureMtprotoImage();
  const volume = await resolveAwgVolumeName();
  const portPlan = require('./portPlan');
  const mode = portPlan.modeForService('mtproto') || 'direct';
  const publicPort = getPublicPort();
  const port = resolveListenPort(getPort() || null, { mode });
  if (String(port) !== String(getPort())) {
    setSetting(PORT_KEY, String(port));
  }

  const network = await portPlan.resolveNginxNetwork();
  if (mode === 'demux' && !network) {
    throw new Error('nginx compose network not found; is nginx running?');
  }

  if (await dockerContainerRunning() && await containerManagedByUs()) {
    const labeled = await inspectContainerPortLabel();
    const labelMode = await runCmd('docker', [
      'inspect', '-f', '{{index .Config.Labels "amnezia.port_mode"}}', CONTAINER_NAME,
    ]);
    const curMode = (labelMode.ok ? labelMode.stdout : '').trim();
    if (labeled === port && curMode === mode) {
      return { reused: true };
    }
  }

  if ((await runCmd('docker', ['inspect', CONTAINER_NAME])).ok) {
    await removeMtprotoContainer();
  }

  const runArgs = [
    'run', '-d',
    '--log-driver', 'none',
    '--restart', 'unless-stopped',
    '--name', CONTAINER_NAME,
    '--label', 'amnezia.managed=1',
    '--label', 'amnezia.service=mtproto',
    '--label', `amnezia.listen_port=${port}`,
    '--label', `amnezia.port_mode=${mode}`,
    '--label', `amnezia.public_port=${publicPort}`,
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
    throw new Error(run.stderr.trim() || 'docker run amnezia-mtproto failed');
  }
  return { reused: false };
}

async function probeListenInsideContainer(port) {
  const p = String(port);
  const nc = await runCmd('docker', [
    'exec', CONTAINER_NAME, 'nc', '-z', '-w', '2', '127.0.0.1', p,
  ], { timeout: 8_000 });
  if (nc.ok) return { ok: true, via: 'nc', out: 'connected' };
  const out = (nc.stderr || nc.stdout || 'not listening').trim().slice(0, 160);
  return { ok: false, via: 'nc', out: out || 'not listening' };
}

async function runSmoke() {
  const containerUp = await dockerContainerRunning();
  const port = getPort();
  const dial = containerUp
    ? await probeListenInsideContainer(port)
    : { ok: false, via: 'skip', out: 'container down' };
  const ok = containerUp && dial.ok;
  lastSmoke = { ok, containerUp, dial, at: Date.now() };
  return lastSmoke;
}

function getProxyLinks() {
  const secret = getSetting(SECRET_KEY, '').trim().toLowerCase();
  const sni = getSni();
  if (!/^[0-9a-f]{32}$/.test(secret) || !sni) return null;
  const host = getPublicHost();
  const port = getClientFacingPort();
  const eeSecret = buildEeSecret(secret, sni);
  return {
    tg: buildTgProxyLink({ host, port, eeSecret }),
    tme: buildTmeProxyLink({ host, port, eeSecret }),
    eeSecret,
    host,
    port,
    sni,
  };
}

function isAmneziaMtprotoAvailable() {
  return phase === 'running' && lastSmoke && lastSmoke.ok === true;
}

function getStatus() {
  const desiredOn = getDesired();
  const links = getProxyLinks();
  const portPlan = require('./portPlan');
  const plan = portPlan.computePlan();
  const smokeOk = !!(lastSmoke && lastSmoke.ok === true);
  const healthy = phase === 'running' && smokeOk;
  return {
    desired: desiredOn === true,
    desiredSet: desiredOn !== null,
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
    port: getPort() || null,
    publicPort: getClientFacingPort(),
    mode: plan.modes.mtproto || null,
    demuxPeers: plan.demuxPeers.mtproto || [],
    link: links ? links.tg : null,
    linkTme: links ? links.tme : null,
    updatedAt,
    busy: Boolean(activeJob),
  };
}

async function forceCleanup() {
  await removeMtprotoContainer();
  lastSmoke = null;
  setPhase('off');
}

async function enableInternal(opts = {}) {
  setPhase('installing');
  setDesired(true);
  const deadline = Date.now() + ENABLE_TIMEOUT_MS;
  try {
    const sni = (opts.sni != null ? String(opts.sni).trim() : '') || getSni() || DEFAULT_SNI;
    const publicPort = opts.publicPort != null
      ? parseInt(String(opts.publicPort).trim(), 10)
      : getPublicPort();
    if (!Number.isFinite(publicPort) || publicPort < 1 || publicPort > 65535) {
      throw Object.assign(new Error('Invalid MTProto public port (1-65535)'), {
        status: 400,
        code: 'MTPROTO_BAD_PUBLIC_PORT',
      });
    }
    setSetting(PUBLIC_PORT_KEY, String(publicPort));
    assertSniNotXray(sni, publicPort);
    await assertSniHasPublicDns(sni);
    if (opts.port != null && String(opts.port).trim() !== '') {
      const requested = parseInt(String(opts.port).trim(), 10);
      if (!Number.isFinite(requested) || requested < 1 || requested > 65535) {
        throw Object.assign(new Error('Invalid MTProto listen port (1-65535)'), {
          status: 400,
          code: 'MTPROTO_BAD_PORT',
        });
      }
    }
    const tentativeMode = (() => {
      const xDesired = getSetting('amnezia_xray_desired', '');
      const xOn = xDesired === '1' || xDesired === 'true';
      const xPub = parseInt(getSetting('amnezia_xray_public_port', '') || '443', 10);
      if (xOn && xPub === publicPort) return 'demux';
      const panelPub = parseInt(String(config.PANEL_HTTPS_PORT || '10123'), 10);
      if (panelPub === publicPort) return 'demux';
      return 'direct';
    })();
    const port = resolveListenPort(
      opts.port != null && String(opts.port).trim() !== '' ? opts.port : getPort() || null,
      { mode: tentativeMode },
    );
    const addressRaw = opts.address != null ? String(opts.address).trim() : '';
    const address = addressRaw || getAddress() || getPublicHost();
    if (!address) {
      throw Object.assign(new Error('MTProto address is required'), {
        status: 400,
        code: 'MTPROTO_BAD_ADDRESS',
      });
    }

    const portPlan = require('./portPlan');
    if (tentativeMode === 'direct') {
      await portPlan.assertHostPortsAvailable([publicPort], { allowNginx: true });
    }
    const secret = getOrCreateSecret();
    setSetting(SNI_KEY, sni);
    setSetting(PORT_KEY, String(port));
    setSetting(ADDRESS_KEY, address);

    writeConfigToml({
      port,
      sni,
      secret,
      publicHost: address,
      publicPort,
    });

    await ensureMtprotoContainer();
    try {
      await portPlan.applyPlan();
    } catch (planErr) {
      // eslint-disable-next-line no-console
      console.error('MTProto enable: portPlan.applyPlan failed:', planErr && planErr.message);
      setPhase('degraded', planErr);
    }
    try {
      const xray = require('./amneziaXray');
      if (xray.getStatus && xray.getStatus().desired && typeof xray.ensureXrayContainer === 'function') {
        await xray.ensureXrayContainer();
      }
    } catch { /* ignore */ }
    await ensureMtprotoContainer();
    // nginx demux may have been applied after peer release — refresh once more
    try {
      await portPlan.applyPlan();
    } catch (planErr) {
      // eslint-disable-next-line no-console
      console.error('MTProto enable: portPlan retry failed:', planErr && planErr.message);
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
        new Error(`MTProto did not become ready (listen=${smoke.dial && smoke.dial.out})`),
        { code: 'MTPROTO_TIMEOUT', status: 504 },
      );
    }

    setPhase('running');
    return getStatus();
  } catch (err) {
    await forceCleanup();
    setDesired(false);
    try {
      await require('./portPlan').applyPlan();
    } catch { /* ignore */ }
    setPhase('error', err);
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
    } catch { /* ignore */ }
    setPhase('off');
    return getStatus();
  } catch (err) {
    setPhase('error', err);
    throw err;
  }
}

function withJob(fn) {
  if (activeJob) {
    const err = new Error('Amnezia MTProto operation already in progress');
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
    return getStatus();
  });
}

async function resetSecretInternal() {
  setSetting(SECRET_KEY, generateSecret());
  if (getDesired() === true || phase === 'running' || phase === 'degraded') {
    const secret = getOrCreateSecret();
    const port = getPort();
    const sni = getSni();
    writeConfigToml({
      port,
      sni,
      secret,
      publicHost: getPublicHost(),
      publicPort: getClientFacingPort(),
    });
    if (await dockerContainerRunning()) {
      await runCmd('docker', ['restart', CONTAINER_NAME], { timeout: 60_000 });
    }
  }
  return getStatus();
}

function resetSecret() {
  return withJob(resetSecretInternal);
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
    const listenPort = resolveListenPort(getPort() || null);
    if (String(listenPort) !== String(getPort())) {
      setSetting(PORT_KEY, String(listenPort));
    }
    const secret = getOrCreateSecret();
    const sni = getSni();
    writeConfigToml({
      port: getPort(),
      sni,
      secret,
      publicHost: getPublicHost(),
      publicPort: getClientFacingPort(),
    });
    if (!(await dockerContainerRunning())) {
      setPhase('degraded', new Error('amnezia-mtproto container not running'));
      await ensureMtprotoContainer();
    } else {
      await ensureMtprotoContainer();
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

async function bootAmneziaMtproto() {
  startReconcileTimer();
  await reconcile();
  return getStatus();
}

function stopAmneziaMtproto() {
  stopReconcileTimer();
}

module.exports = {
  CONTAINER_NAME,
  IMAGE_NAME,
  DEFAULT_SNI,
  enable,
  disable,
  forceCleanup: forceCleanupApi,
  resetSecret,
  getStatus,
  isAmneziaMtprotoAvailable,
  getProxyLinks,
  buildEeSecret,
  buildTgProxyLink,
  buildTmeProxyLink,
  buildConfigToml,
  domainToHex,
  bootAmneziaMtproto,
  stopAmneziaMtproto,
  getClientFacingPort,
  getPublicHost,
  ensureMtprotoContainer,
};
