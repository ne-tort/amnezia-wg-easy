'use strict';

/**
 * Declarative VLESS/Xray transport schema for UI and validation.
 * Security × transport matrix aligned with Xray v25.8+ docs.
 */

const TRANSPORTS = Object.freeze([
  { id: 'tcp', label: 'RAW TCP', deprecated: false },
  { id: 'xhttp', label: 'XHTTP', deprecated: false },
  { id: 'grpc', label: 'gRPC', deprecated: true },
  { id: 'ws', label: 'WebSocket', deprecated: true },
  { id: 'httpupgrade', label: 'HTTPUpgrade', deprecated: true },
  { id: 'kcp', label: 'mKCP', deprecated: false },
  { id: 'hysteria', label: 'Hysteria', deprecated: false },
]);

const TRANSPORT_IDS = Object.freeze(TRANSPORTS.map((t) => t.id));

/** @type {Record<string, string[]>} */
const SECURITY_BY_TRANSPORT = Object.freeze({
  tcp: ['reality', 'tls', 'none'],
  xhttp: ['reality', 'tls', 'none'],
  grpc: ['reality', 'tls', 'none'],
  ws: ['tls', 'none'],
  httpupgrade: ['tls', 'none'],
  kcp: ['tls', 'none'],
  hysteria: ['tls'],
});

const KCP_HEADER_TYPES = Object.freeze([
  'none', 'srtp', 'utp', 'wechat-video', 'wechat-audio', 'dtls', 'wireguard',
]);

const XHTTP_MODES = Object.freeze(['auto', 'stream-one', 'stream-up', 'packet-up']);

const TCP_HEADER_TYPES = Object.freeze(['none', 'http']);

const SOCKOPT_FIELDS = Object.freeze([
  { key: 'tcpFastOpen', type: 'bool', optional: true, group: 'socket', label: 'TCP Fast Open' },
  { key: 'tcpCongestion', type: 'text', optional: true, group: 'socket', label: 'TCP congestion', placeholder: 'bbr' },
  { key: 'domainStrategy', type: 'select', optional: true, group: 'socket', label: 'Domain strategy',
    options: ['AsIs', 'UseIP', 'UseIPv4', 'UseIPv6'] },
  { key: 'acceptProxyProtocol', type: 'bool', optional: true, group: 'socket', label: 'Accept PROXY protocol (inbound)' },
]);

/** @type {Record<string, Array<Record<string, unknown>>>} */
const FIELDS = Object.freeze({
  tcp: Object.freeze([
    { key: 'headerType', type: 'select', optional: true, default: 'none', group: 'basic', label: 'Header type',
      options: TCP_HEADER_TYPES },
    { key: 'httpVersion', type: 'text', optional: true, group: 'httpHeader', label: 'HTTP version', default: '1.1',
      showIf: { headerType: 'http' } },
    { key: 'httpMethod', type: 'text', optional: true, group: 'httpHeader', label: 'HTTP method', default: 'GET',
      showIf: { headerType: 'http' } },
    { key: 'httpPath', type: 'text', optional: true, group: 'httpHeader', label: 'HTTP path (comma-separated)',
      default: '/', showIf: { headerType: 'http' } },
    { key: 'httpHost', type: 'text', optional: true, group: 'httpHeader', label: 'HTTP Host header',
      inheritFrom: 'sni', showIf: { headerType: 'http' } },
    ...SOCKOPT_FIELDS,
  ]),
  ws: Object.freeze([
    { key: 'wsPath', type: 'text', optional: true, default: '/', group: 'basic', label: 'Path' },
    { key: 'wsHost', type: 'text', optional: true, group: 'basic', label: 'Host', inheritFrom: 'sni' },
    { key: 'wsHeaders', type: 'json', optional: true, group: 'advanced', label: 'Extra headers (JSON map)' },
    { key: 'acceptProxyProtocol', type: 'bool', optional: true, group: 'advanced', label: 'Accept PROXY protocol (inbound)' },
  ]),
  grpc: Object.freeze([
    { key: 'grpcServiceName', type: 'text', optional: false, group: 'basic', label: 'Service name' },
    { key: 'grpcMultiMode', type: 'bool', optional: true, group: 'basic', label: 'Multi mode' },
    { key: 'grpcAuthority', type: 'text', optional: true, group: 'advanced', label: 'Authority', inheritFrom: 'sni' },
    { key: 'grpcIdleTimeout', type: 'number', optional: true, group: 'advanced', label: 'Idle timeout (seconds)' },
  ]),
  kcp: Object.freeze([
    { key: 'kcpMtu', type: 'number', optional: true, group: 'basic', label: 'MTU' },
    { key: 'kcpTti', type: 'number', optional: true, group: 'basic', label: 'TTI' },
    { key: 'kcpUplinkCapacity', type: 'number', optional: true, group: 'basic', label: 'Uplink capacity (MB)' },
    { key: 'kcpDownlinkCapacity', type: 'number', optional: true, group: 'basic', label: 'Downlink capacity (MB)' },
    { key: 'kcpReadBufferSize', type: 'number', optional: true, group: 'advanced', label: 'Read buffer (MB)' },
    { key: 'kcpWriteBufferSize', type: 'number', optional: true, group: 'advanced', label: 'Write buffer (MB)' },
    { key: 'kcpCongestion', type: 'bool', optional: true, group: 'advanced', label: 'Enable congestion' },
    { key: 'kcpSeed', type: 'text', optional: true, group: 'advanced', label: 'Seed' },
    { key: 'kcpHeaderType', type: 'select', optional: true, default: 'none', group: 'basic', label: 'Header type',
      options: KCP_HEADER_TYPES },
  ]),
  httpupgrade: Object.freeze([
    { key: 'httpupgradeHost', type: 'text', optional: true, group: 'basic', label: 'Host', inheritFrom: 'sni' },
    { key: 'httpupgradePath', type: 'text', optional: true, default: '/', group: 'basic', label: 'Path' },
    { key: 'httpupgradeHeaders', type: 'json', optional: true, group: 'advanced', label: 'Extra headers (JSON map)' },
  ]),
  xhttp: Object.freeze([
    { key: 'xhttpMode', type: 'select', optional: true, default: 'auto', group: 'basic', label: 'Mode',
      options: XHTTP_MODES },
    { key: 'xhttpHost', type: 'text', optional: true, group: 'basic', label: 'Host', inheritFrom: 'sni' },
    { key: 'xhttpPath', type: 'text', optional: true, default: '/', group: 'basic', label: 'Path' },
    { key: 'xhttpExtra', type: 'text', optional: true, group: 'advanced', label: 'Extra download path' },
    { key: 'xhttpHeaders', type: 'json', optional: true, group: 'advanced', label: 'Extra headers (JSON map)' },
    ...SOCKOPT_FIELDS,
  ]),
  hysteria: Object.freeze([
    { key: 'hysteriaUpMbps', type: 'number', optional: true, group: 'basic', label: 'Upload (Mbps)' },
    { key: 'hysteriaDownMbps', type: 'number', optional: true, group: 'basic', label: 'Download (Mbps)' },
  ]),
});

function isEmptyValue(v) {
  if (v === null || v === undefined) return true;
  if (typeof v === 'string') return v.trim() === '';
  if (typeof v === 'boolean') return false;
  if (typeof v === 'number') return false;
  if (Array.isArray(v)) return v.length === 0;
  if (typeof v === 'object') return Object.keys(v).length === 0;
  return false;
}

function allowedSecurities(network) {
  const n = String(network || 'tcp').trim().toLowerCase();
  return SECURITY_BY_TRANSPORT[n] || SECURITY_BY_TRANSPORT.tcp;
}

function supportsReality(network) {
  return allowedSecurities(network).includes('reality');
}

/**
 * @param {'reality'|'tls'|'none'} security
 * @param {string} network
 * @returns {string[]|null} null = no cert needed
 */
function allowedCertTypes(security, network) {
  const sec = String(security || 'reality').toLowerCase();
  if (sec === 'none') return null;
  if (sec === 'reality') {
    if (!supportsReality(network)) return [];
    return ['reality'];
  }
  return ['self_signed', 'lets_encrypt', 'lets_encrypt_ip', 'manual'];
}

function certFilterKey(security) {
  return String(security || 'reality').toLowerCase() === 'reality' ? 'xray_reality' : 'xray_tls';
}

/**
 * @param {{ sni?: string, certDomain?: string }} base
 * @param {string} network
 * @param {Record<string, unknown>} settings
 */
function inheritTransportFields(base, network, settings = {}) {
  const out = { ...(settings || {}) };
  const sni = String(base.sni || base.certDomain || '').trim();
  const fields = FIELDS[network] || [];
  for (const f of fields) {
    if (f.inheritFrom === 'sni' && isEmptyValue(out[f.key]) && sni) {
      out[f.key] = sni;
    }
  }
  // Legacy flat keys
  if (network === 'ws') {
    if (isEmptyValue(out.wsHost) && sni) out.wsHost = sni;
  }
  if (network === 'grpc' && isEmptyValue(out.grpcAuthority) && sni) {
    out.grpcAuthority = sni;
  }
  if (network === 'httpupgrade' && isEmptyValue(out.httpupgradeHost) && sni) {
    out.httpupgradeHost = sni;
  }
  if (network === 'xhttp' && isEmptyValue(out.xhttpHost) && sni) {
    out.xhttpHost = sni;
  }
  return out;
}

/**
 * Strip empty optional values before persist/export.
 * @param {string} network
 * @param {Record<string, unknown>} settings
 */
function sanitizeTransportSettings(network, settings = {}) {
  const out = {};
  const fields = FIELDS[network] || [];
  const fieldMap = new Map(fields.map((f) => [f.key, f]));
  for (const [key, val] of Object.entries(settings || {})) {
    const meta = fieldMap.get(key);
    if (meta && meta.optional === false && isEmptyValue(val)) continue;
    if (isEmptyValue(val)) continue;
    if (meta && meta.type === 'json' && typeof val === 'string') {
      try {
        const parsed = JSON.parse(val);
        if (!isEmptyValue(parsed)) out[key] = parsed;
      } catch {
        /* skip invalid json */
      }
      continue;
    }
    out[key] = val;
  }
  return out;
}

/**
 * Validate required transport fields.
 * @returns {{ ok: boolean, fieldErrors?: Record<string, string> }}
 */
function validateTransportSettings(network, settings = {}) {
  const fields = FIELDS[network] || [];
  /** @type {Record<string, string>} */
  const fieldErrors = {};
  for (const f of fields) {
    if (f.optional === false && isEmptyValue(settings[f.key])) {
      fieldErrors[f.key] = `${f.label || f.key} is required`;
    }
    if (f.type === 'json' && !isEmptyValue(settings[f.key]) && typeof settings[f.key] === 'string') {
      try {
        JSON.parse(settings[f.key]);
      } catch {
        fieldErrors[f.key] = 'Invalid JSON';
      }
    }
  }
  if (Object.keys(fieldErrors).length) {
    return { ok: false, fieldErrors };
  }
  return { ok: true };
}

function flowSupported(network) {
  const n = String(network || 'tcp').toLowerCase();
  return n === 'tcp' || n === 'xhttp';
}

function mapTransportProto(network) {
  const n = String(network || 'tcp').toLowerCase();
  if (n === 'kcp') return 'udp';
  return 'tcp';
}

function getFieldsForUi(network) {
  return FIELDS[network] || [];
}

module.exports = {
  TRANSPORTS,
  TRANSPORT_IDS,
  SECURITY_BY_TRANSPORT,
  FIELDS,
  KCP_HEADER_TYPES,
  XHTTP_MODES,
  TCP_HEADER_TYPES,
  allowedSecurities,
  supportsReality,
  allowedCertTypes,
  certFilterKey,
  inheritTransportFields,
  sanitizeTransportSettings,
  validateTransportSettings,
  flowSupported,
  mapTransportProto,
  getFieldsForUi,
  isEmptyValue,
};
