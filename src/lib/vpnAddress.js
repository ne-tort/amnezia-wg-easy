'use strict';

/**
 * IPv4 VPN address pools: parse/normalize CIDR, containment, allocation.
 */

/**
 * @param {string} ip
 * @returns {number|null} unsigned 32-bit
 */
function ipv4ToInt(ip) {
  if (typeof ip !== 'string') return null;
  const parts = ip.trim().split('.');
  if (parts.length !== 4) return null;
  let n = 0;
  for (let i = 0; i < 4; i++) {
    const o = parseInt(parts[i], 10);
    if (!Number.isInteger(o) || o < 0 || o > 255) return null;
    n = (n << 8) | o;
  }
  return n >>> 0;
}

/**
 * @param {number} n unsigned 32-bit
 * @returns {string}
 */
function intToIpv4(n) {
  const x = n >>> 0;
  return `${(x >>> 24) & 255}.${(x >>> 16) & 255}.${(x >>> 8) & 255}.${x & 255}`;
}

/**
 * @param {string} cidr
 * @returns {{ network: number, prefixLen: number, mask: number, broadcast: number, networkIp: string, broadcastIp: string, cidr: string }|null}
 */
function parseCidr(cidr) {
  if (typeof cidr !== 'string') return null;
  const s = cidr.trim().replace(/\\/g, '/');
  const slash = s.indexOf('/');
  if (slash < 0) return null;
  const addr = s.slice(0, slash).trim();
  const len = parseInt(s.slice(slash + 1).trim(), 10);
  if (!Number.isInteger(len) || len < 0 || len > 32) return null;
  const ip = ipv4ToInt(addr);
  if (ip == null) return null;
  const mask = len === 0 ? 0 : (0xffffffff << (32 - len)) >>> 0;
  const network = (ip & mask) >>> 0;
  const broadcast = (network | (~mask >>> 0)) >>> 0;
  return {
    network,
    prefixLen: len,
    mask,
    broadcast,
    networkIp: intToIpv4(network),
    broadcastIp: intToIpv4(broadcast),
    cidr: `${intToIpv4(network)}/${len}`,
  };
}

/**
 * Normalize pool/user CIDR to canonical network/prefix. Prefix must be 8–30 for pools; 8–32 for user ranges.
 * @param {string} cidr
 * @param {{ minPrefix?: number, maxPrefix?: number }} [opts]
 * @returns {{ ok: true, cidr: string, parsed: object }|{ ok: false, message: string }}
 */
function normalizeCidr(cidr, opts = {}) {
  const minPrefix = opts.minPrefix != null ? opts.minPrefix : 8;
  const maxPrefix = opts.maxPrefix != null ? opts.maxPrefix : 32;
  const parsed = parseCidr(cidr);
  if (!parsed) return { ok: false, message: 'Invalid IPv4 CIDR' };
  if (parsed.prefixLen < minPrefix || parsed.prefixLen > maxPrefix) {
    return { ok: false, message: `CIDR prefix must be ${minPrefix}–${maxPrefix}` };
  }
  return { ok: true, cidr: parsed.cidr, parsed };
}

/** True if outer fully contains inner (equal OK). */
function cidrContains(outerCidr, innerCidr) {
  const outer = parseCidr(outerCidr);
  const inner = parseCidr(innerCidr);
  if (!outer || !inner) return false;
  if (outer.prefixLen > inner.prefixLen) return false;
  return (outer.network & outer.mask) === (inner.network & outer.mask);
}

/** True if two CIDRs share any IP. */
function cidrsOverlap(aCidr, bCidr) {
  const a = parseCidr(aCidr);
  const b = parseCidr(bCidr);
  if (!a || !b) return false;
  return a.network <= b.broadcast && b.network <= a.broadcast;
}

/**
 * @param {string} ip
 * @param {string} cidr
 */
function ipInCidr(ip, cidr) {
  const n = ipv4ToInt(ip);
  const c = parseCidr(cidr);
  if (n == null || !c) return false;
  return (n & c.mask) === c.network;
}

/**
 * Default gateway = network + 1 (e.g. 10.8.0.0/24 → 10.8.0.1).
 * @param {string} cidr
 * @returns {string|null}
 */
function defaultGatewayForCidr(cidr) {
  const p = parseCidr(cidr);
  if (!p) return null;
  if (p.prefixLen >= 31) return p.networkIp;
  return intToIpv4((p.network + 1) >>> 0);
}

/**
 * @param {string} cidr
 * @param {Set<string>|string[]} reservedGateways
 * @returns {string[]} usable host IPs in ascending order
 */
function enumerateUsableHosts(cidr, reservedGateways = []) {
  const p = parseCidr(cidr);
  if (!p) return [];
  const reserved = reservedGateways instanceof Set
    ? reservedGateways
    : new Set(reservedGateways);
  const out = [];
  if (p.prefixLen >= 31) {
    // /31 or /32: treat all addresses in range as candidates except reserved
    for (let i = p.network; i <= p.broadcast; i++) {
      const ip = intToIpv4(i >>> 0);
      if (!reserved.has(ip)) out.push(ip);
    }
    return out;
  }
  for (let i = p.network + 1; i < p.broadcast; i++) {
    const ip = intToIpv4(i >>> 0);
    if (reserved.has(ip)) continue;
    out.push(ip);
  }
  return out;
}

/**
 * Deterministic first free host across ranges (order preserved).
 * @param {{ ranges: string[], usedSet: Set<string>|string[], reservedGateways?: string[] }} opts
 * @returns {string|null}
 */
function allocateAddress({ ranges, usedSet, reservedGateways = [] }) {
  const used = usedSet instanceof Set ? usedSet : new Set(usedSet || []);
  const reserved = new Set(reservedGateways || []);
  const list = Array.isArray(ranges) ? ranges : [];
  for (const range of list) {
    const hosts = enumerateUsableHosts(range, reserved);
    for (const ip of hosts) {
      if (!used.has(ip)) return ip;
    }
  }
  return null;
}

/**
 * Each user CIDR must be subnet of at least one pool.
 * @param {string[]} userCidrs
 * @param {string[]} poolCidrs
 * @returns {{ ok: true, cidrs: string[] }|{ ok: false, message: string }}
 */
function validateAssignedCidrs(userCidrs, poolCidrs) {
  if (!Array.isArray(userCidrs)) return { ok: false, message: 'assigned_cidrs must be an array' };
  const pools = Array.isArray(poolCidrs) ? poolCidrs : [];
  if (!pools.length && userCidrs.length) {
    return { ok: false, message: 'No VPN address pools configured' };
  }
  const normalized = [];
  for (const raw of userCidrs) {
    const n = normalizeCidr(String(raw), { minPrefix: 8, maxPrefix: 32 });
    if (!n.ok) return { ok: false, message: n.message };
    const ok = pools.some((pool) => cidrContains(pool, n.cidr));
    if (!ok) {
      return { ok: false, message: `CIDR ${n.cidr} is outside configured VPN pools` };
    }
    if (!normalized.includes(n.cidr)) normalized.push(n.cidr);
  }
  return { ok: true, cidrs: normalized };
}

/**
 * Parse assigned_cidrs from DB (JSON array or comma-separated).
 * @param {string|null|undefined} raw
 * @returns {string[]}
 */
function parseAssignedCidrsField(raw) {
  if (raw == null || raw === '') return [];
  if (Array.isArray(raw)) return raw.map(String);
  const s = String(raw).trim();
  if (!s) return [];
  if (s.startsWith('[')) {
    try {
      const arr = JSON.parse(s);
      return Array.isArray(arr) ? arr.map(String) : [];
    } catch {
      return [];
    }
  }
  return s.split(',').map((x) => x.trim()).filter(Boolean);
}

function stringifyAssignedCidrs(cidrs) {
  return JSON.stringify(Array.isArray(cidrs) ? cidrs : []);
}

/**
 * Derive seed pool from WG_DEFAULT_ADDRESS template (e.g. 10.8.0.x → 10.8.0.0/24).
 * @param {string} [template]
 * @returns {{ cidr: string, gateway: string }}
 */
function seedPoolFromEnvTemplate(template) {
  const t = typeof template === 'string' && template.trim() ? template.trim() : '10.8.0.x';
  const base = t.replace(/x/gi, '0');
  const parts = base.split('.');
  let cidr;
  if (parts.length === 4 && parts.every((p) => /^\d{1,3}$/.test(p))) {
    const network = `${parseInt(parts[0], 10)}.${parseInt(parts[1], 10)}.${parseInt(parts[2], 10)}.0`;
    cidr = `${network}/24`;
  } else {
    cidr = '10.8.0.0/24';
  }
  const n = normalizeCidr(cidr, { minPrefix: 8, maxPrefix: 30 });
  const finalCidr = n.ok ? n.cidr : '10.8.0.0/24';
  return {
    cidr: finalCidr,
    gateway: defaultGatewayForCidr(finalCidr) || '10.8.0.1',
  };
}

/**
 * @param {string} ip
 * @param {string[]} poolCidrs
 */
function ipInAnyPool(ip, poolCidrs) {
  return (poolCidrs || []).some((c) => ipInCidr(ip, c));
}

module.exports = {
  ipv4ToInt,
  intToIpv4,
  parseCidr,
  normalizeCidr,
  cidrContains,
  cidrsOverlap,
  ipInCidr,
  ipInAnyPool,
  defaultGatewayForCidr,
  enumerateUsableHosts,
  allocateAddress,
  validateAssignedCidrs,
  parseAssignedCidrsField,
  stringifyAssignedCidrs,
  seedPoolFromEnvTemplate,
};
