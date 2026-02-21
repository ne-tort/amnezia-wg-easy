'use strict';

/**
 * Normalizes CIDR string: trim and replace backslash with forward slash.
 * @param {*} s - Raw value (string or other).
 * @returns {string} Normalized string or empty string.
 */
function normalizeCidr(s) {
  if (typeof s !== 'string') return '';
  return s.trim().replace(/\\/g, '/');
}

/**
 * Validates IPv4 CIDR (a.b.c.d/m, octets 0-255, prefix 0-32).
 * @param {string} s - CIDR string (should be normalized first).
 * @returns {{ ok: boolean, message?: string }}
 */
function validateCidr(s) {
  const n = normalizeCidr(s);
  if (!n) return { ok: false, message: 'destination_cidr is required' };
  const m = n.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$/);
  if (!m) return { ok: false, message: 'destination_cidr must be IPv4 CIDR (e.g. 10.8.0.0/24)' };
  const a = parseInt(m[1], 10);
  const b = parseInt(m[2], 10);
  const c = parseInt(m[3], 10);
  const d = parseInt(m[4], 10);
  const prefix = parseInt(m[5], 10);
  if (a > 255 || b > 255 || c > 255 || d > 255) return { ok: false, message: 'invalid IPv4 octets' };
  if (prefix > 32) return { ok: false, message: 'CIDR prefix must be 0-32' };
  return { ok: true };
}

/**
 * Normalizes port: trim; ANY/ALL -> null; replace : with - for range.
 * @param {*} s - Raw value.
 * @returns {string|null}
 */
function normalizePort(s) {
  if (s == null) return null;
  const t = typeof s === 'string' ? s.trim() : String(s).trim();
  if (!t || /^(any|all)$/i.test(t)) return null;
  return t.replace(':', '-');
}

/**
 * Validates port: empty/null ok; single 1-65535; range num-num (both 1-65535, first <= second).
 * @param {string|null} s - Port string (normalized).
 * @returns {{ ok: boolean, message?: string }}
 */
function validatePort(s) {
  if (s == null || s === '') return { ok: true };
  const num = (n) => {
    const v = parseInt(n, 10);
    return Number.isInteger(v) && v >= 1 && v <= 65535 ? v : null;
  };
  if (/^\d+$/.test(s)) {
    return num(s) != null ? { ok: true } : { ok: false, message: 'port must be 1-65535' };
  }
  const parts = s.split('-');
  if (parts.length !== 2) return { ok: false, message: 'port must be a number or range (e.g. 80-443)' };
  const low = num(parts[0].trim());
  const high = num(parts[1].trim());
  if (low == null || high == null) return { ok: false, message: 'port range values must be 1-65535' };
  if (low > high) return { ok: false, message: 'port range start must be <= end' };
  return { ok: true };
}

/**
 * Normalizes protocol: trim, lowercase; empty or any/all -> null.
 * @param {*} s - Raw value.
 * @returns {string|null}
 */
function normalizeProtocol(s) {
  if (s == null) return null;
  const t = typeof s === 'string' ? s.trim().toLowerCase() : String(s).trim().toLowerCase();
  if (!t || /^(any|all)$/.test(t)) return null;
  return t;
}

/**
 * Validates protocol: empty/null ok; only tcp or udp.
 * @param {string|null} s - Protocol string (normalized).
 * @returns {{ ok: boolean, message?: string }}
 */
function validateProtocol(s) {
  if (s == null || s === '') return { ok: true };
  if (s === 'tcp' || s === 'udp') return { ok: true };
  return { ok: false, message: 'protocol must be tcp, udp, or empty (any)' };
}

/**
 * Sanitizes a rule for use in nftables/firewalld. Normalizes fields and drops invalid ones
 * so that bad DB values never produce invalid commands.
 * @param {Object} r - Rule object { destination_cidr, port_range, protocol }.
 * @returns {{ destination_cidr: string, port_range: string|null, protocol: string|null }}
 */
function sanitizeRule(r) {
  const destRaw = r && r.destination_cidr != null ? r.destination_cidr : '';
  const portRaw = r && r.port_range != null ? r.port_range : null;
  const protoRaw = r && r.protocol != null ? r.protocol : null;

  const dest = normalizeCidr(destRaw);
  const port = normalizePort(portRaw);
  const proto = normalizeProtocol(protoRaw);

  const destination_cidr = validateCidr(dest).ok ? dest : '';
  const port_range = validatePort(port).ok ? port : null;
  const protocol = validateProtocol(proto).ok ? proto : null;

  return { destination_cidr, port_range, protocol };
}

module.exports = {
  normalizeCidr,
  validateCidr,
  normalizePort,
  validatePort,
  normalizeProtocol,
  validateProtocol,
  sanitizeRule,
};
