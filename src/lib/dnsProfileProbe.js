'use strict';

/**
 * Server-side DNS profile smoke checks with a short TTL cache.
 * Probing runs in the background (boot + interval); API reads cache without waiting.
 */

const { execFile } = require('node:child_process');
const { promisify } = require('node:util');

const execFileAsync = promisify(execFile);

const PROBE_DOMAIN = 'example.com';
const DIG_TIMEOUT_MS = 4_000;
const PING_TIMEOUT_MS = 3_000;
/** Fresh results live this long before a background refresh is scheduled. */
const CACHE_TTL_MS = 5 * 60 * 1000;
const SCHEDULER_INTERVAL_MS = CACHE_TTL_MS;

/** @type {{ at: number, byId: Record<string, ProbeResult> } | null} */
let cache = null;
/** @type {Promise<Record<string, ProbeResult>>|null} */
let inflight = null;
/** @type {ReturnType<typeof setInterval>|null} */
let schedulerTimer = null;

/**
 * @typedef {{ ok: boolean, latencyMs: number|null, pingMs: number|null, error?: string }} ProbeResult
 */

function runCmd(bin, args, timeout) {
  return execFileAsync(bin, args, { timeout, maxBuffer: 256 * 1024 })
    .then(({ stdout, stderr }) => ({
      ok: true,
      stdout: String(stdout || ''),
      stderr: String(stderr || ''),
    }))
    .catch((err) => ({
      ok: false,
      stdout: String((err && err.stdout) || ''),
      stderr: String((err && err.stderr) || err.message || ''),
    }));
}

function parsePingMs(stdout) {
  const m = String(stdout).match(/time[=<]([\d.]+)\s*ms/i);
  if (!m) return null;
  const n = Number(m[1]);
  return Number.isFinite(n) ? Math.round(n) : null;
}

async function probeIcmp(address) {
  const started = Date.now();
  const r = await runCmd('ping', ['-c', '1', '-W', '2', address], PING_TIMEOUT_MS);
  if (!r.ok) return { ok: false, latencyMs: null };
  const fromOut = parsePingMs(r.stdout);
  return {
    ok: fromOut != null || /1 packets received|1 received/i.test(r.stdout),
    latencyMs: fromOut != null ? fromOut : Math.max(1, Date.now() - started),
  };
}

async function probeDnsQuery(server, forwardTls) {
  const args = [
    `@${server.address}`,
    PROBE_DOMAIN,
    '+short',
    '+time=2',
    '+tries=1',
  ];
  if (forwardTls) {
    args.push('+tls');
    if (server.tlsName) args.push(`+tls-hostname=${server.tlsName}`);
  }
  const started = Date.now();
  const r = await runCmd('dig', args, DIG_TIMEOUT_MS);
  const latencyMs = Math.max(1, Date.now() - started);
  const answer = (r.stdout || '').trim().split(/\r?\n/).find((line) => {
    const t = line.trim();
    return t && !t.startsWith(';') && (/^\d+\.\d+\.\d+\.\d+$/.test(t) || t.includes(':'));
  });
  if (r.ok && answer) return { ok: true, latencyMs };
  return {
    ok: false,
    latencyMs: null,
    error: (r.stderr || r.stdout || 'resolve failed').trim().slice(0, 120),
  };
}

/**
 * @param {{ id: string, forwardTls: boolean, servers: Array<{address:string,port?:number,tlsName?:string}> }} profile
 * @returns {Promise<ProbeResult>}
 */
async function probeProfile(profile) {
  const servers = Array.isArray(profile.servers) ? profile.servers : [];
  if (!servers.length) {
    return { ok: false, latencyMs: null, pingMs: null, error: 'no servers' };
  }

  let lastErr = 'unreachable';
  for (const server of servers) {
    const dns = await probeDnsQuery(server, profile.forwardTls === true);
    if (!dns.ok) {
      lastErr = dns.error || lastErr;
      continue;
    }
    const icmp = await probeIcmp(server.address);
    return {
      ok: true,
      latencyMs: dns.latencyMs,
      pingMs: icmp.ok ? icmp.latencyMs : null,
    };
  }

  return { ok: false, latencyMs: null, pingMs: null, error: lastErr };
}

function getCache() {
  if (!cache) {
    return {
      hit: false,
      stale: true,
      fresh: false,
      byId: {},
      at: null,
      ageMs: null,
      ttlMs: CACHE_TTL_MS,
      probing: Boolean(inflight),
    };
  }
  const ageMs = Date.now() - cache.at;
  const fresh = ageMs < CACHE_TTL_MS;
  return {
    hit: true,
    stale: !fresh,
    fresh,
    byId: cache.byId,
    at: cache.at,
    ageMs,
    ttlMs: CACHE_TTL_MS,
    probing: Boolean(inflight),
  };
}

async function runProbePass(profiles) {
  const list = Array.isArray(profiles) ? profiles : [];
  const settled = await Promise.all(
    list.map(async (p) => {
      try {
        return [String(p.id), await probeProfile(p)];
      } catch (err) {
        return [String(p.id), {
          ok: false,
          latencyMs: null,
          pingMs: null,
          error: err.message || 'probe failed',
        }];
      }
    }),
  );
  /** @type {Record<string, ProbeResult>} */
  const byId = {};
  for (const [id, result] of settled) byId[id] = result;
  cache = { at: Date.now(), byId };
  return byId;
}

/**
 * @param {Array<{ id: string, forwardTls: boolean, servers: any[] }>} profiles
 * @param {{ force?: boolean }} [opts]
 */
function probeProfiles(profiles, opts = {}) {
  const list = Array.isArray(profiles) ? profiles : [];
  if (!opts.force) {
    const snap = getCache();
    if (snap.fresh) return Promise.resolve(snap.byId);
  }
  if (inflight) return inflight;
  inflight = runProbePass(list).finally(() => {
    inflight = null;
  });
  return inflight;
}

/** Fire-and-forget refresh when cache is missing/stale. */
function refreshInBackground(profiles) {
  const snap = getCache();
  if (snap.fresh) return Promise.resolve(snap.byId);
  return probeProfiles(profiles, { force: !snap.hit }).catch((err) => {
    // eslint-disable-next-line no-console
    console.warn('DNS profile probe:', err && err.message ? err.message : err);
    return snap.byId;
  });
}

/**
 * @param {() => Array|{profiles: Array}|Promise<Array|{profiles: Array}>} loadProfiles
 */
function startProbeScheduler(loadProfiles) {
  if (schedulerTimer) return;

  const tick = () => {
    Promise.resolve()
      .then(() => loadProfiles())
      .then((raw) => {
        const list = Array.isArray(raw) ? raw : (raw && raw.profiles) || [];
        return probeProfiles(list, { force: true });
      })
      .catch((err) => {
        // eslint-disable-next-line no-console
        console.warn('DNS profile probe scheduler:', err && err.message ? err.message : err);
      });
  };

  tick();
  schedulerTimer = setInterval(tick, SCHEDULER_INTERVAL_MS);
  if (typeof schedulerTimer.unref === 'function') schedulerTimer.unref();
}

function stopProbeScheduler() {
  if (schedulerTimer) {
    clearInterval(schedulerTimer);
    schedulerTimer = null;
  }
}

function invalidateProbeCache() {
  cache = null;
}

module.exports = {
  PROBE_DOMAIN,
  CACHE_TTL_MS,
  probeProfile,
  probeProfiles,
  getCache,
  refreshInBackground,
  startProbeScheduler,
  stopProbeScheduler,
  invalidateProbeCache,
};
