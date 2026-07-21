'use strict';

/**
 * Amnezia DNS orchestration: Unbound container (docker) + dnsmasq in-panel.
 * Desired state lives in app_settings.amnezia_dns_desired (not env).
 */

const { spawn, execFile } = require('node:child_process');
const { promisify } = require('node:util');
const fs = require('node:fs');
const path = require('node:path');
const config = require('../config');

const execFileAsync = promisify(execFile);

const DNSMASQ_CONF_BASE = '/etc/dnsmasq-amnezia.conf';
const DNSMASQ_CONF_RUNTIME = '/tmp/dnsmasq-amnezia.conf';
const AMNEZIA_DNS_UPSTREAM = '172.29.172.254';
const AMNEZIA_DNS_NET_SUBNET = '172.29.172.0/24';
const CONTAINER_NAME = 'amnezia-dns';
/** Same image/container tag as Amnezia client (`docker build -t amnezia-dns`). */
const IMAGE_NAME = 'amnezia-dns';
const NETWORK_NAME = 'amnezia-dns-net';
/** Dockerfile path inside panel image (mirrors client /opt/amnezia/amnezia-dns). */
const DOCKERFILE_FOLDER = '/opt/amnezia/amnezia-dns';
const DESIRED_KEY = 'amnezia_dns_desired';
const PROFILE_KEY = 'amnezia_dns_profile';
const PANEL_CONTAINER = 'amnezia-awg';
const FORWARD_RECORDS_REL = path.join('amnezia-dns', 'forward-records.conf');
const ENABLE_TIMEOUT_MS = 90_000;
const SMOKE_DOMAIN = 'cloudflare.com';
const RECONCILE_INTERVAL_MS = 30_000;

/** @type {import('node:child_process').ChildProcess|null} */
let dnsmasqChild = null;

/** @type {'off'|'installing'|'running'|'degraded'|'removing'|'error'} */
let phase = 'off';
let lastError = null;
let lastSmoke = null;
let updatedAt = Date.now();
/** @type {Promise<any>|null} */
let activeJob = null;
let reconcileTimer = null;

function vpnGateway() {
  try {
    const dbMod = require('./db');
    const primary = dbMod.vpnPools.getPrimary();
    if (primary && primary.gateway) return primary.gateway;
  } catch {
    /* */
  }
  const addr = config.WG_DEFAULT_ADDRESS || '10.8.0.x';
  return addr.replace(/x$/, '1');
}

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

function getStoredProfileId() {
  const raw = getDb().appSettings.get(PROFILE_KEY);
  if (raw === null || raw === undefined || raw === '') return null;
  return String(raw);
}

function setStoredProfileId(id) {
  getDb().appSettings.set(PROFILE_KEY, id == null ? '' : String(id));
}

function dnsProfiles() {
  return require('./dnsProfilesBank');
}

function forwardRecordsHostPath() {
  return path.join(config.WG_PATH, FORWARD_RECORDS_REL);
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

function writeDnsmasqConf(gateway) {
  const base = fs.readFileSync(DNSMASQ_CONF_BASE, 'utf8');
  const lines = base
    .split('\n')
    .filter((line) => !line.trimStart().startsWith('listen-address='));
  const head = [
    '# Runtime: listen on VPN gateway and localhost (written by amneziaDns)',
    `listen-address=${gateway}`,
    'listen-address=127.0.0.1',
    '',
  ].join('\n');
  fs.writeFileSync(DNSMASQ_CONF_RUNTIME, head + lines.join('\n'), 'utf8');
  return DNSMASQ_CONF_RUNTIME;
}

function isDnsmasqAlive() {
  return Boolean(dnsmasqChild && dnsmasqChild.pid && !dnsmasqChild.killed);
}

/**
 * Start dnsmasq forwarding to Unbound. Does not check desired/env — caller decides.
 */
function startDnsmasq() {
  if (isDnsmasqAlive()) return dnsmasqChild;
  const gateway = vpnGateway();
  let confPath = DNSMASQ_CONF_BASE;
  try {
    confPath = writeDnsmasqConf(gateway);
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Amnezia DNS: could not write runtime config:', err.message);
  }
  try {
    dnsmasqChild = spawn('dnsmasq', ['-C', confPath, '-k'], {
      stdio: 'ignore',
      detached: false,
    });
    dnsmasqChild.on('error', (err) => {
      // eslint-disable-next-line no-console
      console.error('Amnezia DNS (dnsmasq) error:', err.message);
    });
    dnsmasqChild.on('exit', (code, signal) => {
      if (code !== null && code !== 0) {
        // eslint-disable-next-line no-console
        console.error('Amnezia DNS (dnsmasq) exited:', code, signal);
      }
      dnsmasqChild = null;
      if (getDesired() && phase === 'running') {
        setPhase('degraded', 'dnsmasq exited');
      }
    });
    return dnsmasqChild;
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Amnezia DNS (dnsmasq) start failed:', err.message);
    return null;
  }
}

function stopDnsmasq() {
  if (dnsmasqChild) {
    try {
      dnsmasqChild.kill('SIGTERM');
    } catch (_) { /* ignore */ }
    dnsmasqChild = null;
  }
}

async function dockerContainerRunning() {
  const r = await runCmd('docker', ['inspect', '-f', '{{.State.Running}}', CONTAINER_NAME]);
  if (!r.ok) return false;
  return r.stdout.trim() === 'true';
}

async function findDnsNetwork() {
  // Prefer exact Amnezia-client name; fall back to legacy compose-prefixed nets.
  const nets = await runCmd('docker', ['network', 'ls', '--format', '{{.Name}}']);
  if (!nets.ok) return null;
  const names = nets.stdout.split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
  if (names.includes(NETWORK_NAME)) return NETWORK_NAME;
  for (const name of names) {
    if (!name.includes('amnezia-dns')) continue;
    const inspect = await runCmd('docker', ['network', 'inspect', name, '-f', '{{range .IPAM.Config}}{{.Subnet}}{{end}}']);
    if (inspect.ok && inspect.stdout.includes('172.29.172.')) return name;
  }
  // Same as client prepare_host.sh
  const create = await runCmd('docker', [
    'network', 'create',
    '--driver', 'bridge',
    '--subnet', AMNEZIA_DNS_NET_SUBNET,
    '--opt', 'com.docker.network.bridge.name=amn0',
    NETWORK_NAME,
  ]);
  if (create.ok || /already exists/i.test(create.stderr)) return NETWORK_NAME;
  return null;
}

async function ensureDnsImage() {
  const inspect = await runCmd('docker', ['image', 'inspect', IMAGE_NAME]);
  if (inspect.ok) return;
  // Via docker.sock the host daemon cannot see container paths — feed Dockerfile on stdin
  // (same content as client; no COPY in context). Prefer deploy.sh pre-build for speed.
  const dockerfilePath = path.join(DOCKERFILE_FOLDER, 'Dockerfile');
  if (!fs.existsSync(dockerfilePath)) {
    throw new Error('amnezia-dns image missing; run deploy.sh');
  }
  const dockerfile = fs.readFileSync(dockerfilePath, 'utf8');
  await new Promise((resolve, reject) => {
    const child = spawn('docker', ['build', '-t', IMAGE_NAME, '-'], {
      stdio: ['pipe', 'ignore', 'pipe'],
    });
    let err = '';
    const timer = setTimeout(() => {
      try { child.kill('SIGKILL'); } catch (_) { /* ignore */ }
      reject(new Error('docker build amnezia-dns timed out'));
    }, 300_000);
    child.stderr.on('data', (d) => { err += String(d); });
    child.on('error', (e) => {
      clearTimeout(timer);
      reject(e);
    });
    child.on('close', (code) => {
      clearTimeout(timer);
      if (code === 0) resolve();
      else reject(new Error((err || `docker build failed (${code})`).trim().slice(0, 300)));
    });
    child.stdin.write(dockerfile);
    child.stdin.end();
  });
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

/**
 * Recreate Unbound with current forward-records.conf from the panel volume.
 * Always recreates so profile changes apply.
 */
async function ensureUnboundContainer() {
  await runCmd('docker', ['rm', '-f', CONTAINER_NAME]);
  await ensureDnsImage();

  const network = await findDnsNetwork();
  if (!network) throw new Error('amnezia-dns-net not found; redeploy (deploy.sh creates it)');

  const volume = await resolveAwgVolumeName();
  const fwdPath = forwardRecordsHostPath();
  if (!fs.existsSync(fwdPath)) {
    throw new Error('forward-records.conf missing; DNS profile was not written');
  }

  // Client-compatible run + mount panel volume so entrypoint can copy the profile conf.
  const run = await runCmd('docker', [
    'run', '-d',
    '--log-driver', 'none',
    '--restart', 'always',
    '--network', network,
    '--ip', AMNEZIA_DNS_UPSTREAM,
    '--name', CONTAINER_NAME,
    '--label', 'amnezia.managed=1',
    '--label', 'amnezia.service=dns',
    '-v', `${volume}:/opt/amnezia/awg:ro`,
    IMAGE_NAME,
  ], { timeout: 60_000 });

  if (!run.ok) {
    throw new Error(run.stderr.trim() || 'docker run amnezia-dns failed');
  }
}

async function removeUnboundContainer() {
  // Client remove_container.sh: stop + rm -fv (keep image for quick UI re-enable).
  await runCmd('docker', ['stop', CONTAINER_NAME]);
  await runCmd('docker', ['rm', '-fv', CONTAINER_NAME]);
}

async function smokeResolve(server, domain = SMOKE_DOMAIN) {
  // dig preferred (bind-tools in image); fallback to nslookup
  const dig = await runCmd('dig', [`@${server}`, domain, '+short', '+time=3', '+tries=1'], { timeout: 8_000 });
  if (dig.ok && dig.stdout.trim()) {
    return { ok: true, via: 'dig', out: dig.stdout.trim().split('\n')[0] };
  }
  const ns = await runCmd('nslookup', [domain, server], { timeout: 8_000 });
  if (ns.ok && /Address:\s*\d+\.\d+\.\d+\.\d+/i.test(ns.stdout + ns.stderr)) {
    return { ok: true, via: 'nslookup', out: 'ok' };
  }
  return {
    ok: false,
    via: 'dig/nslookup',
    out: (dig.stderr || ns.stderr || 'resolve failed').slice(0, 200),
  };
}

async function runSmoke() {
  const containerUp = await dockerContainerRunning();
  const dnsmasqUp = isDnsmasqAlive();
  const upstream = containerUp
    ? await smokeResolve(AMNEZIA_DNS_UPSTREAM)
    : { ok: false, via: 'skip', out: 'container down' };
  const local = dnsmasqUp
    ? await smokeResolve('127.0.0.1')
    : { ok: false, via: 'skip', out: 'dnsmasq down' };
  const ok = containerUp && dnsmasqUp && upstream.ok && local.ok;
  lastSmoke = {
    ok,
    containerUp,
    dnsmasqUp,
    upstream,
    local,
    at: Date.now(),
  };
  return lastSmoke;
}

/**
 * Runtime availability for client configs / .vpn export.
 */
function isAmneziaDnsAvailable() {
  return phase === 'running';
}

function getActiveProfileSummary() {
  const id = getStoredProfileId();
  if (!id) return { profileId: null, profile: null };
  try {
    const p = dnsProfiles().resolveProfile(id);
    return {
      profileId: p.id,
      profile: {
        id: p.id,
        name: p.name,
        description: p.description,
        forwardTls: p.forwardTls,
        servers: p.servers,
      },
    };
  } catch {
    return { profileId: id, profile: null };
  }
}

function getStatus() {
  const desired = getDesired();
  const { profileId, profile } = getActiveProfileSummary();
  return {
    desired: desired === true,
    desiredSet: desired !== null,
    phase,
    available: phase === 'running',
    lastError,
    smoke: lastSmoke,
    dnsmasqPid: dnsmasqChild && dnsmasqChild.pid ? dnsmasqChild.pid : null,
    container: CONTAINER_NAME,
    upstream: AMNEZIA_DNS_UPSTREAM,
    gateway: vpnGateway(),
    profileId,
    profile,
    updatedAt,
    busy: Boolean(activeJob),
  };
}

async function forceCleanup() {
  stopDnsmasq();
  await removeUnboundContainer();
  lastSmoke = null;
  setPhase('off');
}

async function regenerateClientConfigs() {
  try {
    const WireGuard = require('./WireGuard');
    await WireGuard.saveConfig();
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Amnezia DNS: saveConfig after toggle failed:', err.message);
  }
}

async function enableInternal(profileId) {
  setPhase('installing');
  setDesired(true);
  const deadline = Date.now() + ENABLE_TIMEOUT_MS;
  try {
    const bank = dnsProfiles();
    bank.ensureSeedBank();
    const profile = bank.resolveProfile(profileId != null ? profileId : getStoredProfileId());

    // Fresh smoke before install — refuse profiles the server cannot reach.
    const { probeProfile, invalidateProbeCache } = require('./dnsProfileProbe');
    invalidateProbeCache();
    const profileSmoke = await probeProfile(profile);
    if (!profileSmoke.ok) {
      throw Object.assign(
        new Error(`DNS profile unavailable: ${profile.name}`),
        { status: 503, code: 'DNS_PROFILE_UNREACHABLE' },
      );
    }

    setStoredProfileId(profile.id);
    bank.writeForwardRecordsFile(profile, forwardRecordsHostPath());

    await ensureUnboundContainer();
    // wait for Unbound to answer
    let upstreamOk = false;
    while (Date.now() < deadline) {
      if (await dockerContainerRunning()) {
        const s = await smokeResolve(AMNEZIA_DNS_UPSTREAM);
        if (s.ok) {
          upstreamOk = true;
          break;
        }
      }
      await new Promise((r) => setTimeout(r, 1500));
    }
    if (!upstreamOk) {
      throw Object.assign(
        new Error(`Unbound did not become ready in time (profile ${profile.id}: ${profile.name})`),
        { code: 'DNS_UPSTREAM_TIMEOUT', status: 504 },
      );
    }

    if (!startDnsmasq()) {
      throw Object.assign(new Error('failed to start dnsmasq'), { code: 'DNS_DNSMASQ_START' });
    }
    await new Promise((r) => setTimeout(r, 500));

    const smoke = await runSmoke();
    if (!smoke.ok) {
      throw Object.assign(
        new Error(`smoke failed: upstream=${smoke.upstream.out}; local=${smoke.local.out}`),
        { code: 'DNS_SMOKE_FAILED' },
      );
    }
    setPhase('running');
    await regenerateClientConfigs();
    return getStatus();
  } catch (err) {
    await forceCleanup();
    setDesired(false);
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
  const profileId = opts && opts.profileId != null ? opts.profileId : undefined;
  return withJob(() => enableInternal(profileId));
}

function displayPingMs(result) {
  if (!result || !result.ok) return null;
  if (result.pingMs != null) return result.pingMs;
  if (result.latencyMs != null) return result.latencyMs;
  return null;
}

async function listProfiles({ probe = true, forceProbe = false } = {}) {
  const bank = dnsProfiles();
  bank.ensureSeedBank();
  const catalog = bank.getProfilesCatalog();
  if (catalog.error || !probe) return catalog;

  const probeMod = require('./dnsProfileProbe');
  if (forceProbe) {
    await probeMod.probeProfiles(catalog.profiles, { force: true });
  } else {
    // Never block the UI: serve cache and refresh in the background when stale/missing.
    probeMod.refreshInBackground(catalog.profiles);
  }

  const snap = probeMod.getCache();
  const byId = snap.byId || {};
  catalog.profiles = catalog.profiles.map((p) => {
    const r = byId[p.id];
    if (!r) {
      return {
        ...p,
        available: true,
        probed: false,
        latencyMs: null,
        pingMs: null,
      };
    }
    return {
      ...p,
      available: r.ok === true,
      probed: true,
      latencyMs: r.ok ? r.latencyMs : null,
      pingMs: r.ok ? r.pingMs : null,
      displayMs: displayPingMs(r),
    };
  });

  catalog.profiles.sort((a, b) => {
    // Available first, not-yet-probed middle, known-down last; then by ping/latency.
    const aRank = a.available === false ? 2 : (a.probed ? 0 : 1);
    const bRank = b.available === false ? 2 : (b.probed ? 0 : 1);
    if (aRank !== bRank) return aRank - bRank;
    const am = a.displayMs != null ? a.displayMs : (a.pingMs != null ? a.pingMs : a.latencyMs);
    const bm = b.displayMs != null ? b.displayMs : (b.pingMs != null ? b.pingMs : b.latencyMs);
    if (am == null && bm == null) return Number(a.id) - Number(b.id);
    if (am == null) return 1;
    if (bm == null) return -1;
    if (am !== bm) return am - bm;
    return Number(a.id) - Number(b.id);
  });

  catalog.probedAt = snap.at;
  catalog.cache = {
    hit: snap.hit,
    fresh: snap.fresh,
    stale: snap.stale,
    probing: snap.probing,
    ageMs: snap.ageMs,
    ttlMs: snap.ttlMs,
  };
  catalog.availableCount = catalog.profiles.filter((p) => p.available !== false).length;
  return catalog;
}

function startDnsProfileProbes() {
  const probeMod = require('./dnsProfileProbe');
  probeMod.startProbeScheduler(() => {
    const bank = dnsProfiles();
    bank.ensureSeedBank();
    return bank.listProfiles();
  });
}

function disable() {
  return withJob(disableInternal);
}

function forceCleanupApi() {
  return withJob(async () => {
    setDesired(false);
    await forceCleanup();
    setPhase('off');
    await regenerateClientConfigs();
    return getStatus();
  });
}

/**
 * Migrate desired from legacy env on first boot; then reconcile stack to desired.
 */
async function migrateDesiredFromLegacyEnv() {
  if (getDesired() !== null) return;
  // Prefer live container (old always-on compose). Do not infer "on" from
  // WG_DEFAULT_DNS===gateway alone — that is just the client DNS address line.
  const containerUp = await dockerContainerRunning();
  if (containerUp) {
    setDesired(true);
    return;
  }
  const flag = (process.env.AMNEZIA_DNS_ENABLE || '').toLowerCase();
  if (['1', 'true', 'yes', 'on', 'enabled'].includes(flag)) {
    setDesired(true);
    return;
  }
  setDesired(false);
}

async function reconcile() {
  if (activeJob) return getStatus();
  const desired = getDesired();
  if (desired === null) return getStatus();

  if (!desired) {
    const up = await dockerContainerRunning();
    if (up || isDnsmasqAlive()) {
      await forceCleanup();
      setPhase('off');
      await regenerateClientConfigs();
    } else if (phase !== 'off' && phase !== 'error') {
      setPhase('off');
    }
    return getStatus();
  }

  // desired on
  try {
    const smoke = await runSmoke();
    if (smoke.ok) {
      if (!isDnsmasqAlive()) startDnsmasq();
      setPhase('running');
      return getStatus();
    }
    if (phase !== 'installing') {
      // eslint-disable-next-line no-console
      console.warn('Amnezia DNS: unhealthy, reinstalling…', JSON.stringify(smoke));
      await enableInternal();
    }
  } catch (err) {
    setPhase('degraded', err);
  }
  return getStatus();
}

async function bootAmneziaDns() {
  await migrateDesiredFromLegacyEnv();
  await reconcile();
  if (!reconcileTimer) {
    reconcileTimer = setInterval(() => {
      reconcile().catch((err) => {
        // eslint-disable-next-line no-console
        console.error('Amnezia DNS reconcile:', err.message);
      });
    }, RECONCILE_INTERVAL_MS);
    if (typeof reconcileTimer.unref === 'function') reconcileTimer.unref();
  }
}

/** @deprecated use startDnsmasq via enable/reconcile */
function startAmneziaDns() {
  if (getDesired()) return startDnsmasq();
  return null;
}

function stopAmneziaDns() {
  stopDnsmasq();
}

module.exports = {
  DESIRED_KEY,
  PROFILE_KEY,
  AMNEZIA_DNS_UPSTREAM,
  CONTAINER_NAME,
  IMAGE_NAME,
  NETWORK_NAME,
  isAmneziaDnsAvailable,
  getStatus,
  listProfiles,
  startDnsProfileProbes,
  enable,
  disable,
  forceCleanup: forceCleanupApi,
  reconcile,
  bootAmneziaDns,
  startAmneziaDns,
  stopAmneziaDns,
  startDnsmasq,
  stopDnsmasq,
  // test hooks
  _setPhaseForTests: (p, err) => setPhase(p, err),
  _setActiveJobForTests: (p) => { activeJob = p; },
  _getInternalStateForTests: () => ({ phase, lastError, dnsmasqChild, busy: Boolean(activeJob) }),
};
