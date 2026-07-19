'use strict';

/**
 * Reality SNI Finder for the panel.
 * Algorithm inspired by Reality-SNI-Finder / RealiTLScanner (clean-room Node implementation;
 * no GPL source vendored). Scans a public /24 for TLS:443, extracts CN/SAN, verifies h2.
 */

const fs = require('node:fs');
const path = require('node:path');
const net = require('node:net');
const tls = require('node:tls');
const dns = require('node:dns').promises;
const http = require('node:http');
const https = require('node:https');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');
const { WG_PATH } = require('../config');

const execFileAsync = promisify(execFile);

const CACHE_REL = path.join('xray', 'sni-cache.json');
const BANK_VOL_REL = path.join('xray', 'sni-bank.json');
const BANK_SEED = path.join(__dirname, '..', '..', 'config', 'sni-bank.seed.json');
const BANK_SEED_IN_IMAGE = path.join(__dirname, '..', 'config', 'sni-bank.seed.json');
const CACHE_TTL_MS = 24 * 60 * 60 * 1000;
const MAX_HOSTS = 256; // /24 hard cap
const TOP_N = 30;
const PROBE_CONCURRENCY = 48;
const VERIFY_CONCURRENCY = 32;
const CONNECT_TIMEOUT_MS = 3000;
const JOB_TIMEOUT_MS = 5 * 60 * 1000;
const EMPTY_MSG = 'Nothing found';

const GENERIC_SAN = new Set([
  'sni.cloudflaressl.com',
  'ssl.cloudflare.com',
  'akamai.net',
  'cloudfront.net',
  'edgekey.net',
  'edgesuite.net',
]);

/** @typedef {{ domain: string, ip: string, latencyMs: number|null, score: number, tlsVersion?: string|null, alpn?: string|null }} SniCandidate */

/** @type {{
 *   phase: string,
 *   progress: { done: number, total: number, label?: string },
 *   error: { code: string, message: string } | null,
 *   result: object | null,
 *   startedAt: number | null,
 *   cancelRequested: boolean,
 *   promise: Promise<void> | null,
 * }} */
const job = {
  phase: 'idle',
  progress: { done: 0, total: 0 },
  error: null,
  result: null,
  startedAt: null,
  cancelRequested: false,
  promise: null,
};

function scanError(code, message, status = 400) {
  const err = new Error(message);
  err.code = code;
  err.status = status;
  return err;
}

function ipv4ToInt(ip) {
  const parts = String(ip).split('.').map((n) => Number(n));
  if (parts.length !== 4 || parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) {
    return null;
  }
  return (((parts[0] << 24) >>> 0) + (parts[1] << 16) + (parts[2] << 8) + parts[3]) >>> 0;
}

function intToIpv4(n) {
  return [
    (n >>> 24) & 255,
    (n >>> 16) & 255,
    (n >>> 8) & 255,
    n & 255,
  ].join('.');
}

/**
 * True if IPv4 is globally routable (reject private / special-use).
 * @param {string} ip
 */
function isPublicIpv4(ip) {
  const n = ipv4ToInt(ip);
  if (n == null) return false;
  const parts = String(ip).split('.').map(Number);
  const a = parts[0];
  const b = parts[1];
  if (a === 0) return false; // this network
  if (a === 10) return false; // RFC1918
  if (a === 127) return false; // loopback
  if (a === 169 && b === 254) return false; // link-local
  if (a === 172 && b >= 16 && b <= 31) return false; // RFC1918
  if (a === 192 && b === 168) return false; // RFC1918
  if (a === 100 && b >= 64 && b <= 127) return false; // CGNAT
  if (a === 192 && b === 0 && parts[2] === 0) return false; // IETF protocol assignments / docs parts
  if (a === 192 && b === 0 && parts[2] === 2) return false; // TEST-NET-1
  if (a === 198 && (b === 51) && parts[2] === 100) return false; // TEST-NET-2
  if (a === 203 && b === 0 && parts[2] === 113) return false; // TEST-NET-3
  if (a >= 224) return false; // multicast / reserved
  if (a === 255) return false;
  return true;
}

/**
 * @param {string} cidr
 * @returns {{ network: string, prefix: number, first: number, last: number, count: number }}
 */
function parseCidr(cidr) {
  const raw = String(cidr || '').trim();
  const m = raw.match(/^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/);
  if (!m) throw scanError('CIDR_INVALID', `Invalid CIDR: ${raw}`);
  const ip = m[1];
  const prefix = Number(m[2]);
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > 32) {
    throw scanError('CIDR_INVALID', `Invalid CIDR prefix: ${raw}`);
  }
  const ipInt = ipv4ToInt(ip);
  if (ipInt == null) throw scanError('CIDR_INVALID', `Invalid CIDR IP: ${raw}`);
  if (prefix < 24) {
    throw scanError('CIDR_TOO_LARGE', `CIDR too large (max /24, got /${prefix})`);
  }
  const hostBits = 32 - prefix;
  const size = 2 ** hostBits;
  if (size > MAX_HOSTS) {
    throw scanError('CIDR_TOO_LARGE', `CIDR expands to ${size} hosts (max ${MAX_HOSTS})`);
  }
  const mask = hostBits === 32 ? 0 : (~((1 << hostBits) - 1)) >>> 0;
  const network = (ipInt & mask) >>> 0;
  const broadcast = (network + size - 1) >>> 0;
  // network + broadcast excluded for /24-style host scans when size > 2
  const first = size > 2 ? (network + 1) >>> 0 : network;
  const last = size > 2 ? (broadcast - 1) >>> 0 : broadcast;
  const count = last >= first ? (last - first + 1) : 0;
  if (count < 1 || count > MAX_HOSTS) {
    throw scanError('CIDR_TOO_LARGE', `CIDR host count ${count} out of range`);
  }
  // Every host in range must be public (reject private blocks entirely)
  for (let n = first; n <= last; n++) {
    const hip = intToIpv4(n);
    if (!isPublicIpv4(hip)) {
      throw scanError('CIDR_PRIVATE', `CIDR includes non-public address ${hip}`);
    }
  }
  return {
    network: intToIpv4(network),
    prefix,
    first,
    last,
    count,
    cidr: `${intToIpv4(network)}/${prefix}`,
  };
}

function expandCidrHosts(cidr) {
  const parsed = parseCidr(cidr);
  const hosts = [];
  for (let n = parsed.first; n <= parsed.last; n++) {
    hosts.push(intToIpv4(n));
  }
  return { hosts, meta: parsed };
}

function base24Cidr(ip) {
  if (!isPublicIpv4(ip)) {
    throw scanError('PUBLIC_IP_PRIVATE', `Reference IP is not public: ${ip}`);
  }
  const n = ipv4ToInt(ip);
  const network = (n & 0xffffff00) >>> 0;
  return `${intToIpv4(network)}/24`;
}

function isDomain(d) {
  const s = String(d || '').trim().toLowerCase();
  if (!s || s.length >= 253) return false;
  if (!s.includes('.')) return false;
  if (s.endsWith('.local') || s.endsWith('.lan') || s.endsWith('.internal')) return false;
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(s)) return false;
  return /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$/i.test(s);
}

function expandWildcard(d) {
  const s = String(d || '').trim().toLowerCase();
  if (s.startsWith('*.') && s.split('.').length >= 3) {
    const root = s.slice(2);
    return [root, `www.${root}`];
  }
  return [s];
}

function domainsFromCert(cn, sans, { includeGeneric = true } = {}) {
  const items = [];
  const pushName = (raw) => {
    const low = String(raw || '').trim().toLowerCase();
    if (!low) return;
    if (!includeGeneric && GENERIC_SAN.has(low)) return;
    for (const d of expandWildcard(low)) {
      if (isDomain(d)) items.push(d);
    }
  };
  if (cn) pushName(cn);
  for (const s of sans || []) pushName(s);
  const seen = new Set();
  const out = [];
  for (const i of items) {
    if (!seen.has(i)) {
      seen.add(i);
      out.push(i);
    }
  }
  return out;
}

function ipDistanceNorm(a, b) {
  const na = ipv4ToInt(a);
  const nb = ipv4ToInt(b);
  if (na == null || nb == null) return 1000;
  return (Math.abs(na - nb) / (2 ** 32)) * 1000;
}

function scoreCandidate(latencyMs, ip, refIp) {
  const lat = latencyMs == null ? 5000 : Number(latencyMs);
  return lat + 0.3 * ipDistanceNorm(ip, refIp);
}

function cachePath() {
  return path.join(WG_PATH, CACHE_REL);
}

function bankVolumePath() {
  return path.join(WG_PATH, BANK_VOL_REL);
}

function ensureCacheDir() {
  const dir = path.dirname(cachePath());
  fs.mkdirSync(dir, { recursive: true });
}

function readCache() {
  try {
    const raw = fs.readFileSync(cachePath(), 'utf8');
    const data = JSON.parse(raw);
    if (!data || typeof data !== 'object') return null;
    return data;
  } catch {
    return null;
  }
}

function writeCache(payload) {
  ensureCacheDir();
  fs.writeFileSync(cachePath(), `${JSON.stringify(payload, null, 2)}\n`, 'utf8');
}

/**
 * Normalize legacy `domains[]` cache into `entries[]`.
 * @param {object|null} cache
 */
function normalizeCache(cache) {
  if (!cache || typeof cache !== 'object') {
    return {
      refIp: null,
      cidr: null,
      scannedAt: null,
      expiresAt: null,
      entries: [],
    };
  }
  let entries = Array.isArray(cache.entries) ? cache.entries.slice() : [];
  if (!entries.length && Array.isArray(cache.domains)) {
    entries = cache.domains.map((d) => ({
      domain: String(d.domain || '').toLowerCase(),
      ip: d.ip || null,
      source: 'scan',
      alive: true,
      latencyMs: d.latencyMs != null ? d.latencyMs : null,
      score: d.score != null ? d.score : null,
      checkedAt: cache.scannedAt || Date.now(),
    })).filter((e) => e.domain);
  }
  entries = entries
    .map((e) => ({
      domain: String(e.domain || '').toLowerCase(),
      ip: e.ip || null,
      source: e.source === 'bank' ? 'bank' : 'scan',
      alive: e.alive !== false,
      latencyMs: e.latencyMs != null ? e.latencyMs : null,
      score: e.score != null ? e.score : null,
      checkedAt: e.checkedAt || null,
      tlsVersion: e.tlsVersion || null,
      alpn: e.alpn || null,
    }))
    .filter((e) => e.domain);
  return {
    refIp: cache.refIp || null,
    cidr: cache.cidr || null,
    scannedAt: cache.scannedAt || null,
    expiresAt: cache.expiresAt || null,
    entries,
  };
}

function loadBankDomains() {
  const paths = [bankVolumePath(), BANK_SEED_IN_IMAGE, BANK_SEED];
  for (const p of paths) {
    try {
      if (!fs.existsSync(p)) continue;
      const raw = JSON.parse(fs.readFileSync(p, 'utf8'));
      const list = Array.isArray(raw) ? raw : (raw && raw.domains);
      if (!Array.isArray(list)) continue;
      return [...new Set(list.map((d) => String(d || '').trim().toLowerCase()).filter(isDomain))];
    } catch {
      /* try next */
    }
  }
  return [];
}

/**
 * Merge scan results into cache entries (by domain). Does not wipe prior scan entries.
 * @param {Array<{domain:string,ip?:string,latencyMs?:number|null,score?:number,alpn?:string|null,tlsVersion?:string|null}>} found
 * @param {{ refIp: string, cidr: string }} meta
 */
function mergeScanResults(found, meta) {
  const cache = normalizeCache(readCache());
  const byDomain = new Map();
  for (const e of cache.entries) {
    byDomain.set(e.domain, { ...e });
  }
  const now = Date.now();
  for (const row of found) {
    const domain = String(row.domain || '').toLowerCase();
    if (!domain) continue;
    const prev = byDomain.get(domain) || {};
    byDomain.set(domain, {
      ...prev,
      domain,
      ip: row.ip || prev.ip || null,
      source: 'scan',
      alive: true,
      latencyMs: row.latencyMs != null ? row.latencyMs : (prev.latencyMs != null ? prev.latencyMs : null),
      score: row.score != null ? row.score : (prev.score != null ? prev.score : null),
      tlsVersion: row.tlsVersion || prev.tlsVersion || null,
      alpn: row.alpn || prev.alpn || null,
      checkedAt: now,
    });
  }
  const scannedAt = now;
  const payload = {
    refIp: meta.refIp,
    cidr: meta.cidr,
    scannedAt,
    expiresAt: scannedAt + CACHE_TTL_MS,
    entries: [...byDomain.values()],
  };
  writeCache(payload);
  return payload;
}

function getUnifiedList() {
  const cache = normalizeCache(readCache());
  const bankDomains = loadBankDomains();
  const scanMap = new Map();
  for (const e of cache.entries) {
    if (e.source === 'scan') scanMap.set(e.domain, e);
  }
  const bankMap = new Map();
  for (const e of cache.entries) {
    if (e.source === 'bank') bankMap.set(e.domain, e);
  }
  for (const d of bankDomains) {
    if (scanMap.has(d)) continue;
    if (!bankMap.has(d)) {
      bankMap.set(d, {
        domain: d,
        ip: null,
        source: 'bank',
        alive: true,
        latencyMs: null,
        score: null,
        checkedAt: null,
      });
    }
  }

  const scanAlive = [...scanMap.values()].filter((e) => e.alive !== false);
  const scanDead = [...scanMap.values()].filter((e) => e.alive === false);
  scanAlive.sort((a, b) => (a.score != null ? a.score : 1e9) - (b.score != null ? b.score : 1e9));

  const bankAlive = [...bankMap.values()].filter((e) => e.alive !== false);
  const bankDead = [...bankMap.values()].filter((e) => e.alive === false);
  const bankOrder = new Map(bankDomains.map((d, i) => [d, i]));
  bankAlive.sort((a, b) => (bankOrder.get(a.domain) ?? 999) - (bankOrder.get(b.domain) ?? 999));

  const entries = [...scanAlive, ...bankAlive, ...scanDead, ...bankDead];
  const scannedAliveCount = scanAlive.length;
  const bankCount = bankAlive.length + bankDead.length;
  const expiresAt = Number(cache.expiresAt) || 0;
  const stale = !cache.scannedAt || Date.now() >= expiresAt;
  return {
    hasCache: !!(cache.scannedAt || cache.entries.length || bankDomains.length),
    stale,
    expiresAt: cache.expiresAt || null,
    scannedAt: cache.scannedAt || null,
    refIp: cache.refIp || null,
    cidr: cache.cidr || null,
    entries,
    /** @deprecated prefer entries */
    domains: scanAlive.map((e) => ({
      domain: e.domain,
      ip: e.ip,
      latencyMs: e.latencyMs,
      score: e.score,
    })),
    scannedAliveCount,
    bankCount,
  };
}

function pickDefaultSni() {
  const { entries } = getUnifiedList();
  const scan = entries.find((e) => e.source === 'scan' && e.alive !== false);
  if (scan) return scan.domain;
  const bank = entries.find((e) => e.source === 'bank' && e.alive !== false);
  if (bank) return bank.domain;
  return null;
}

/**
 * Next SNI candidate different from exclude (for MTProto vs Xray demux).
 * @param {string|string[]} [exclude]
 */
function pickAlternateSni(exclude) {
  const blocked = new Set(
    (Array.isArray(exclude) ? exclude : [exclude])
      .map((s) => String(s || '').trim().toLowerCase())
      .filter(Boolean),
  );
  const { entries } = getUnifiedList();
  const pick = (src) => entries.find(
    (e) => e.source === src && e.alive !== false && !blocked.has(String(e.domain).toLowerCase()),
  );
  const scan = pick('scan');
  if (scan) return scan.domain;
  const bank = pick('bank');
  if (bank) return bank.domain;
  const any = entries.find((e) => e.alive !== false && !blocked.has(String(e.domain).toLowerCase()));
  if (any) return any.domain;
  return null;
}

function cacheStatus() {
  return getUnifiedList();
}

function finishEmpty(meta) {
  const unified = getUnifiedList();
  job.phase = 'done';
  job.error = null;
  job.result = {
    empty: true,
    message: EMPTY_MSG,
    refIp: meta.refIp,
    cidr: meta.cidr,
    entries: unified.entries,
    domains: unified.domains,
    scannedAt: unified.scannedAt,
    expiresAt: unified.expiresAt,
  };
  setProgress(1, 1, 'done');
}

function httpGetText(url, timeoutMs = 4000) {
  return new Promise((resolve, reject) => {
    const lib = url.startsWith('https') ? https : http;
    const req = lib.get(url, { timeout: timeoutMs }, (res) => {
      if (res.statusCode && res.statusCode >= 400) {
        res.resume();
        reject(new Error(`HTTP ${res.statusCode}`));
        return;
      }
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve(Buffer.concat(chunks).toString('utf8').trim()));
    });
    req.on('error', reject);
    req.on('timeout', () => {
      req.destroy();
      reject(new Error('timeout'));
    });
  });
}

async function detectPublicIpv4() {
  const attempts = [
    async () => {
      const ip = await httpGetText('https://api.ipify.org');
      if (ipv4ToInt(ip) != null) return ip;
      throw new Error('bad ipify');
    },
    async () => {
      const ip = await httpGetText('https://ifconfig.me/ip');
      if (ipv4ToInt(ip) != null) return ip;
      throw new Error('bad ifconfig.me');
    },
    async () => {
      try {
        const { stdout } = await execFileAsync('dig', [
          '+short', 'myip.opendns.com', '@resolver1.opendns.com',
        ], { timeout: 5000 });
        const ip = String(stdout || '').trim().split(/\s+/)[0];
        if (ipv4ToInt(ip) != null) return ip;
      } catch {
        /* optional dig */
      }
      throw new Error('dig failed');
    },
  ];
  for (const fn of attempts) {
    try {
      const ip = await fn();
      if (!isPublicIpv4(ip)) {
        throw scanError('PUBLIC_IP_PRIVATE', `Detected IP is not public: ${ip}`);
      }
      return ip;
    } catch (err) {
      if (err && err.code === 'PUBLIC_IP_PRIVATE') throw err;
    }
  }
  throw scanError('PUBLIC_IP_UNKNOWN', 'Cannot detect public IPv4 (check outbound HTTP/DNS)');
}

function extractSansFromPemText(text) {
  return [...String(text || '').matchAll(/DNS:([^,\s]+)/g)].map((m) => m[1].trim());
}

async function opensslSansFallback(ip) {
  try {
    const { stdout } = await execFileAsync(
      'bash',
      ['-lc', `echo | openssl s_client -connect ${ip}:443 -servername ${ip} -showcerts 2>/dev/null | openssl x509 -noout -text 2>/dev/null`],
      { timeout: 8000, maxBuffer: 2 * 1024 * 1024 },
    );
    return extractSansFromPemText(stdout);
  } catch {
    return [];
  }
}

/**
 * TLS probe without client SNI (camouflage discovery).
 * @param {string} ip
 * @param {number} timeoutMs
 */
function probeTlsNoSni(ip, timeoutMs = CONNECT_TIMEOUT_MS) {
  return new Promise((resolve) => {
    const started = Date.now();
    /** @type {import('net').Socket | null} */
    let raw = null;
    /** @type {import('tls').TLSSocket | null} */
    let secure = null;
    let settled = false;
    const finish = (result) => {
      if (settled) return;
      settled = true;
      try { if (secure) secure.destroy(); } catch { /* ignore */ }
      try { if (raw) raw.destroy(); } catch { /* ignore */ }
      resolve(result);
    };

    const timer = setTimeout(() => finish({
      ip, ok: false, latencyMs: null, alpn: null, tlsVersion: null, certCn: null, certSans: [],
    }), timeoutMs);

    try {
      raw = net.connect({ host: ip, port: 443 }, () => {
        secure = tls.connect({
          socket: raw,
          rejectUnauthorized: false,
          ALPNProtocols: ['h2', 'http/1.1'],
          minVersion: 'TLSv1.2',
          // Intentionally omit servername → probe without SNI
        }, () => {
          clearTimeout(timer);
          const latencyMs = Math.round((Date.now() - started) * 100) / 100;
          let certCn = null;
          let certSans = [];
          try {
            const cert = secure.getPeerCertificate();
            if (cert) {
              if (cert.subject && cert.subject.CN) certCn = String(cert.subject.CN);
              if (Array.isArray(cert.subjectaltname)) {
                // unlikely shape
              } else if (typeof cert.subjectaltname === 'string') {
                certSans = cert.subjectaltname
                  .split(',')
                  .map((p) => p.trim())
                  .filter((p) => p.toUpperCase().startsWith('DNS:'))
                  .map((p) => p.slice(4).trim());
              }
            }
          } catch { /* ignore */ }
          finish({
            ip,
            ok: true,
            latencyMs,
            alpn: secure.alpnProtocol || null,
            tlsVersion: secure.getProtocol ? secure.getProtocol() : null,
            certCn,
            certSans,
          });
        });
        secure.on('error', () => {
          clearTimeout(timer);
          finish({
            ip, ok: false, latencyMs: null, alpn: null, tlsVersion: null, certCn: null, certSans: [],
          });
        });
      });
      raw.setTimeout(timeoutMs);
      raw.on('timeout', () => {
        clearTimeout(timer);
        finish({
          ip, ok: false, latencyMs: null, alpn: null, tlsVersion: null, certCn: null, certSans: [],
        });
      });
      raw.on('error', () => {
        clearTimeout(timer);
        finish({
          ip, ok: false, latencyMs: null, alpn: null, tlsVersion: null, certCn: null, certSans: [],
        });
      });
    } catch {
      clearTimeout(timer);
      finish({
        ip, ok: false, latencyMs: null, alpn: null, tlsVersion: null, certCn: null, certSans: [],
      });
    }
  });
}

/**
 * Verify domain answers HTTP/2 / TLS1.3+h2 on the discovered IP (SNI = domain).
 */
function verifyHttp2OnIp(domain, ip, timeoutMs = 8000) {
  return new Promise((resolve) => {
    let settled = false;
    const done = (ok, meta = {}) => {
      if (settled) return;
      settled = true;
      try { sock.destroy(); } catch { /* ignore */ }
      resolve({ ok, ...meta });
    };
    /** @type {import('tls').TLSSocket} */
    let sock;
    const timer = setTimeout(() => done(false), timeoutMs);
    try {
      sock = tls.connect({
        host: ip,
        port: 443,
        servername: domain,
        rejectUnauthorized: false,
        ALPNProtocols: ['h2', 'http/1.1'],
        minVersion: 'TLSv1.2',
      }, () => {
        clearTimeout(timer);
        const alpn = sock.alpnProtocol || null;
        const ver = sock.getProtocol ? sock.getProtocol() : null;
        const h2 = alpn === 'h2';
        // Prefer TLS1.3 + h2 (RealiTLScanner-style); accept h2 on TLS1.2 as usable Reality dest.
        done(h2, { alpn, tlsVersion: ver });
      });
      sock.setTimeout(timeoutMs);
      sock.on('timeout', () => {
        clearTimeout(timer);
        done(false);
      });
      sock.on('error', () => {
        clearTimeout(timer);
        done(false);
      });
    } catch {
      clearTimeout(timer);
      done(false);
    }
  });
}

async function mapPool(items, concurrency, fn, shouldCancel) {
  const results = new Array(items.length);
  let next = 0;
  async function worker() {
    for (;;) {
      if (shouldCancel && shouldCancel()) throw scanError('SCAN_CANCELLED', 'Scan cancelled', 499);
      const i = next;
      next += 1;
      if (i >= items.length) return;
      results[i] = await fn(items[i], i);
    }
  }
  const n = Math.min(concurrency, Math.max(1, items.length));
  await Promise.all(Array.from({ length: n }, () => worker()));
  return results;
}

function setProgress(done, total, label) {
  job.progress = { done, total, label: label || job.progress.label };
}

function getScanStatus() {
  return {
    phase: job.phase,
    progress: { ...job.progress },
    error: job.error,
    result: job.result,
    startedAt: job.startedAt,
    busy: !['idle', 'done', 'error'].includes(job.phase),
  };
}

function cancelScan() {
  if (!['probing', 'verifying', 'detecting', 'starting'].includes(job.phase)) {
    return getScanStatus();
  }
  job.cancelRequested = true;
  return getScanStatus();
}

async function runScanInternal({ cidr, refIp, force }) {
  job.cancelRequested = false;
  job.error = null;
  job.result = null;
  job.startedAt = Date.now();
  job.phase = 'detecting';
  setProgress(0, 1, 'detecting');

  let resolvedRef = refIp ? String(refIp).trim() : '';
  if (resolvedRef) {
    if (ipv4ToInt(resolvedRef) == null) {
      throw scanError('CIDR_INVALID', `Invalid refIp: ${resolvedRef}`);
    }
    if (!isPublicIpv4(resolvedRef)) {
      throw scanError('PUBLIC_IP_PRIVATE', `Reference IP is not public: ${resolvedRef}`);
    }
  } else {
    resolvedRef = await detectPublicIpv4();
  }
  if (job.cancelRequested) throw scanError('SCAN_CANCELLED', 'Scan cancelled', 499);

  let targetCidr = cidr ? String(cidr).trim() : '';
  if (!targetCidr) targetCidr = base24Cidr(resolvedRef);
  const { hosts, meta } = expandCidrHosts(targetCidr);
  const scanMeta = { refIp: resolvedRef, cidr: meta.cidr };

  if (!force) {
    const cached = getUnifiedList();
    if (
      !cached.stale
      && cached.cidr === meta.cidr
      && cached.refIp === resolvedRef
      && cached.scannedAliveCount > 0
    ) {
      job.phase = 'done';
      job.result = {
        fromCache: true,
        empty: false,
        refIp: resolvedRef,
        cidr: meta.cidr,
        entries: cached.entries,
        domains: cached.domains,
        scannedAt: cached.scannedAt,
        expiresAt: cached.expiresAt,
      };
      setProgress(1, 1, 'cached');
      return;
    }
  }

  job.phase = 'probing';
  setProgress(0, hosts.length, 'probing');

  let probed = 0;
  const probes = await mapPool(hosts, PROBE_CONCURRENCY, async (ip) => {
    if (Date.now() - job.startedAt > JOB_TIMEOUT_MS) {
      throw scanError('SCAN_TIMEOUT', 'Scan timed out', 504);
    }
    let r = await probeTlsNoSni(ip);
    if (r.ok && (!r.certSans || !r.certSans.length)) {
      const sans = await opensslSansFallback(ip);
      if (sans.length) r = { ...r, certSans: sans };
    }
    probed += 1;
    setProgress(probed, hosts.length, 'probing');
    return r;
  }, () => job.cancelRequested);

  const okProbes = probes.filter((p) => p && p.ok);
  if (!okProbes.length) {
    // Soft empty: home ISP /24 often has no public :443
    finishEmpty(scanMeta);
    return;
  }

  /** @type {Array<{ ip: string, latencyMs: number|null, domain: string }>} */
  const candidates = [];
  for (const p of okProbes) {
    const domains = domainsFromCert(p.certCn, p.certSans, { includeGeneric: true });
    for (const domain of domains) {
      candidates.push({ ip: p.ip, latencyMs: p.latencyMs, domain });
    }
  }
  if (!candidates.length) {
    finishEmpty(scanMeta);
    return;
  }

  job.phase = 'verifying';
  setProgress(0, candidates.length, 'verifying');
  let verifiedCount = 0;
  const verified = [];
  await mapPool(candidates, VERIFY_CONCURRENCY, async (c) => {
    if (Date.now() - job.startedAt > JOB_TIMEOUT_MS) {
      throw scanError('SCAN_TIMEOUT', 'Scan timed out', 504);
    }
    const v = await verifyHttp2OnIp(c.domain, c.ip);
    verifiedCount += 1;
    setProgress(verifiedCount, candidates.length, 'verifying');
    if (v.ok) {
      verified.push({
        ...c,
        alpn: v.alpn || null,
        tlsVersion: v.tlsVersion || null,
      });
    }
    return v;
  }, () => job.cancelRequested);

  if (!verified.length) {
    finishEmpty(scanMeta);
    return;
  }

  const scored = verified.map((c) => ({
    domain: c.domain,
    ip: c.ip,
    latencyMs: c.latencyMs,
    score: Math.round(scoreCandidate(c.latencyMs, c.ip, resolvedRef) * 100) / 100,
    tlsVersion: c.tlsVersion || null,
    alpn: c.alpn || null,
  }));
  scored.sort((a, b) => a.score - b.score);

  const seen = new Set();
  const top = [];
  for (const row of scored) {
    if (seen.has(row.domain)) continue;
    seen.add(row.domain);
    top.push(row);
    if (top.length >= TOP_N) break;
  }

  const payload = mergeScanResults(top, scanMeta);
  const unified = getUnifiedList();
  job.phase = 'done';
  job.result = {
    fromCache: false,
    empty: false,
    refIp: payload.refIp,
    cidr: payload.cidr,
    scannedAt: payload.scannedAt,
    expiresAt: payload.expiresAt,
    entries: unified.entries,
    domains: unified.domains,
  };
  setProgress(1, 1, 'done');
}

function ensureBackgroundScan() {
  if (getScanStatus().busy) return false;
  const cached = getUnifiedList();
  if (!cached.stale && cached.scannedAliveCount > 0) return false;
  try {
    startScan({ force: false });
    return true;
  } catch {
    return false;
  }
}

async function recheckDomain(domain) {
  const d = String(domain || '').trim().toLowerCase();
  if (!isDomain(d)) throw scanError('CIDR_INVALID', `Invalid domain: ${domain}`);

  const unified = getUnifiedList();
  let entry = unified.entries.find((e) => e.domain === d);
  let source = (entry && entry.source) || (loadBankDomains().includes(d) ? 'bank' : 'scan');
  let ip = entry && entry.ip;

  if (!ip) {
    try {
      const r = await dns.lookup(d, { family: 4 });
      ip = r && r.address;
    } catch {
      ip = null;
    }
  }
  if (!ip || !isPublicIpv4(ip)) {
    // Still mark dead if we cannot reach a public A
    const cache = normalizeCache(readCache());
    const byDomain = new Map(cache.entries.map((e) => [e.domain, { ...e }]));
    const now = Date.now();
    byDomain.set(d, {
      ...(byDomain.get(d) || {}),
      domain: d,
      ip: ip || null,
      source,
      alive: false,
      checkedAt: now,
    });
    writeCache({
      ...cache,
      entries: [...byDomain.values()],
    });
    return getUnifiedList().entries.find((e) => e.domain === d);
  }

  const v = await verifyHttp2OnIp(d, ip);
  const cache = normalizeCache(readCache());
  const byDomain = new Map(cache.entries.map((e) => [e.domain, { ...e }]));
  const now = Date.now();
  byDomain.set(d, {
    ...(byDomain.get(d) || {}),
    domain: d,
    ip,
    source,
    alive: !!v.ok,
    alpn: v.alpn || null,
    tlsVersion: v.tlsVersion || null,
    checkedAt: now,
  });
  writeCache({
    ...cache,
    entries: [...byDomain.values()],
  });
  return getUnifiedList().entries.find((e) => e.domain === d);
}

function startScan(opts = {}) {
  if (job.promise || !['idle', 'done', 'error'].includes(job.phase)) {
    throw scanError('SCAN_BUSY', 'SNI scan already in progress', 409);
  }
  if (opts.refIp) {
    const ref = String(opts.refIp).trim();
    if (ipv4ToInt(ref) == null) {
      throw scanError('CIDR_INVALID', `Invalid refIp: ${ref}`);
    }
    if (!isPublicIpv4(ref)) {
      throw scanError('PUBLIC_IP_PRIVATE', `Reference IP is not public: ${ref}`);
    }
  }
  if (opts.cidr) {
    parseCidr(String(opts.cidr).trim());
  }
  job.phase = 'starting';
  job.error = null;
  job.result = null;
  job.promise = Promise.resolve()
    .then(() => runScanInternal({
      cidr: opts.cidr,
      refIp: opts.refIp,
      force: opts.force === true,
    }))
    .catch((err) => {
      job.phase = 'error';
      job.error = {
        code: (err && err.code) || 'SCAN_FAILED',
        message: (err && err.message) || 'Scan failed',
      };
      job.result = null;
    })
    .finally(() => {
      job.promise = null;
    });
  return getScanStatus();
}

async function getPublicIpPreview() {
  try {
    const ip = await detectPublicIpv4();
    return {
      ok: true,
      publicIp: ip,
      defaultCidr: base24Cidr(ip),
      error: null,
    };
  } catch (err) {
    return {
      ok: false,
      publicIp: null,
      defaultCidr: null,
      error: {
        code: (err && err.code) || 'PUBLIC_IP_UNKNOWN',
        message: (err && err.message) || 'Cannot detect public IP',
      },
    };
  }
}

async function getCacheWithPreview(opts = {}) {
  if (opts.ensureBg) {
    ensureBackgroundScan();
  }
  const unified = getUnifiedList();
  const preview = await getPublicIpPreview();
  return {
    ...unified,
    publicIp: preview.publicIp,
    defaultCidr: preview.defaultCidr,
    publicIpError: preview.error,
    defaultSni: pickDefaultSni(),
    scan: getScanStatus(),
  };
}

function bootSniFinder() {
  try {
    ensureBackgroundScan();
  } catch {
    /* ignore */
  }
}

module.exports = {
  CACHE_TTL_MS,
  MAX_HOSTS,
  TOP_N,
  EMPTY_MSG,
  isPublicIpv4,
  parseCidr,
  expandCidrHosts,
  base24Cidr,
  isDomain,
  expandWildcard,
  domainsFromCert,
  scoreCandidate,
  ipDistanceNorm,
  readCache,
  writeCache,
  normalizeCache,
  mergeScanResults,
  getUnifiedList,
  pickDefaultSni,
  pickAlternateSni,
  cacheStatus,
  cachePath,
  loadBankDomains,
  detectPublicIpv4,
  getPublicIpPreview,
  getCacheWithPreview,
  ensureBackgroundScan,
  bootSniFinder,
  recheckDomain,
  startScan,
  getScanStatus,
  cancelScan,
  scanError,
  // test hooks
  _job: job,
  probeTlsNoSni,
  verifyHttp2OnIp,
};
