'use strict';

/**
 * Declarative VLESS/Xray transport schema for UI and validation.
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
const TCP_CONGESTION = Object.freeze(['bbr', 'cubic', 'reno', 'bbr2']);
const HTTP_VERSIONS = Object.freeze(['1.1', '2']);
const HTTP_METHODS = Object.freeze(['GET', 'POST', 'PUT', 'HEAD', 'OPTIONS']);
const DOMAIN_STRATEGIES = Object.freeze(['AsIs', 'UseIP', 'UseIPv4', 'UseIPv6']);

const SOCKOPT_FIELDS = Object.freeze([
  { key: 'tcpFastOpen', type: 'bool', optional: true, scope: 'shared', labelKey: 'xrayTfTcpFastOpen' },
  { key: 'tcpCongestion', type: 'select', optional: true, scope: 'shared', labelKey: 'xrayTfTcpCongestion',
    options: TCP_CONGESTION, default: 'bbr' },
  { key: 'domainStrategy', type: 'select', optional: true, scope: 'shared', labelKey: 'xrayTfDomainStrategy',
    options: DOMAIN_STRATEGIES },
  { key: 'acceptProxyProtocol', type: 'bool', optional: true, scope: 'shared', labelKey: 'xrayTfAcceptProxyProtocol' },
]);

/** @type {Record<string, Array<Record<string, unknown>>>} */
const FIELDS = Object.freeze({
  tcp: Object.freeze([
    { key: 'headerType', type: 'select', optional: true, default: 'none', scope: 'shared', labelKey: 'xrayTfHeaderType',
      options: TCP_HEADER_TYPES },
    { key: 'httpVersion', type: 'select', optional: true, scope: 'shared', labelKey: 'xrayTfHttpVersion',
      default: '1.1', options: HTTP_VERSIONS, showIf: { headerType: 'http' } },
    { key: 'httpMethod', type: 'select', optional: true, scope: 'shared', labelKey: 'xrayTfHttpMethod',
      default: 'GET', options: HTTP_METHODS, showIf: { headerType: 'http' } },
    { key: 'httpPath', type: 'text', optional: true, scope: 'shared', labelKey: 'xrayTfHttpPath',
      default: '/', showIf: { headerType: 'http' } },
    { key: 'httpHost', type: 'text', optional: true, scope: 'shared', labelKey: 'xrayTfHttpHost',
      inheritFrom: 'sni', showIf: { headerType: 'http' } },
    ...SOCKOPT_FIELDS,
  ]),
  ws: Object.freeze([
    { key: 'wsPath', type: 'text', optional: true, default: '/', scope: 'shared', labelKey: 'xrayTfWsPath' },
    { key: 'wsHost', type: 'text', optional: true, scope: 'shared', labelKey: 'xrayTfWsHost', inheritFrom: 'sni' },
    { key: 'wsHeaders', type: 'json', optional: true, scope: 'shared', labelKey: 'xrayTfWsHeaders' },
    { key: 'acceptProxyProtocol', type: 'bool', optional: true, scope: 'shared', labelKey: 'xrayTfAcceptProxyProtocol' },
  ]),
  grpc: Object.freeze([
    { key: 'grpcServiceName', type: 'text', optional: false, scope: 'shared', labelKey: 'xrayTfGrpcServiceName' },
    { key: 'grpcMultiMode', type: 'bool', optional: true, scope: 'shared', labelKey: 'xrayTfGrpcMultiMode' },
    { key: 'grpcAuthority', type: 'text', optional: true, scope: 'shared', labelKey: 'xrayTfGrpcAuthority', inheritFrom: 'sni' },
    { key: 'grpcIdleTimeout', type: 'number', optional: true, scope: 'shared', labelKey: 'xrayTfGrpcIdleTimeout' },
  ]),
  kcp: Object.freeze([
    { key: 'kcpMtu', type: 'number', optional: true, scope: 'shared', labelKey: 'xrayTfKcpMtu' },
    { key: 'kcpTti', type: 'number', optional: true, scope: 'shared', labelKey: 'xrayTfKcpTti' },
    { key: 'kcpUplinkCapacity', type: 'number', optional: true, scope: 'shared', labelKey: 'xrayTfKcpUplinkCapacity' },
    { key: 'kcpDownlinkCapacity', type: 'number', optional: true, scope: 'shared', labelKey: 'xrayTfKcpDownlinkCapacity' },
    { key: 'kcpReadBufferSize', type: 'number', optional: true, scope: 'shared', labelKey: 'xrayTfKcpReadBufferSize' },
    { key: 'kcpWriteBufferSize', type: 'number', optional: true, scope: 'shared', labelKey: 'xrayTfKcpWriteBufferSize' },
    { key: 'kcpCongestion', type: 'bool', optional: true, scope: 'shared', labelKey: 'xrayTfKcpCongestion' },
    // header/seed removed in Xray 26 (finalmask); do not expose in UI
  ]),
  httpupgrade: Object.freeze([
    { key: 'httpupgradeHost', type: 'text', optional: true, scope: 'shared', labelKey: 'xrayTfHttpupgradeHost', inheritFrom: 'sni' },
    { key: 'httpupgradePath', type: 'text', optional: true, default: '/', scope: 'shared', labelKey: 'xrayTfHttpupgradePath' },
    { key: 'httpupgradeHeaders', type: 'json', optional: true, scope: 'shared', labelKey: 'xrayTfHttpupgradeHeaders' },
  ]),
  xhttp: Object.freeze([
    { key: 'xhttpMode', type: 'select', optional: true, default: 'auto', scope: 'shared', labelKey: 'xrayTfXhttpMode',
      options: XHTTP_MODES },
    { key: 'xhttpHost', type: 'text', optional: true, scope: 'shared', labelKey: 'xrayTfXhttpHost', inheritFrom: 'sni' },
    { key: 'xhttpPath', type: 'text', optional: true, default: '/', scope: 'shared', labelKey: 'xrayTfXhttpPath' },
    { key: 'xhttpExtra', type: 'text', optional: true, scope: 'shared', labelKey: 'xrayTfXhttpExtra' },
    { key: 'xhttpHeaders', type: 'json', optional: true, scope: 'shared', labelKey: 'xrayTfXhttpHeaders' },
    ...SOCKOPT_FIELDS,
  ]),
  hysteria: Object.freeze([
    { key: 'hysteriaVersion', type: 'select', optional: true, default: '2', scope: 'shared', labelKey: 'xrayTfHysteriaVersion',
      options: Object.freeze(['2']) },
    { key: 'hysteriaAuth', type: 'text', optional: true, scope: 'shared', labelKey: 'xrayTfHysteriaAuth' },
    { key: 'hysteriaUdpIdleTimeout', type: 'number', optional: true, default: 60, scope: 'shared', labelKey: 'xrayTfHysteriaUdpIdleTimeout' },
    { key: 'hysteriaUpMbps', type: 'number', optional: true, scope: 'client', labelKey: 'xrayTfHysteriaUpMbps' },
    { key: 'hysteriaDownMbps', type: 'number', optional: true, scope: 'client', labelKey: 'xrayTfHysteriaDownMbps' },
    { key: 'hysteriaMasqueradeType', type: 'select', optional: true, default: '', scope: 'shared', labelKey: 'xrayTfHysteriaMasqueradeType',
      options: Object.freeze(['', 'proxy', 'string', 'file']) },
    { key: 'hysteriaMasqueradeUrl', type: 'text', optional: true, scope: 'shared', labelKey: 'xrayTfHysteriaMasqueradeUrl',
      showIf: { hysteriaMasqueradeType: 'proxy' } },
    { key: 'hysteriaMasqueradeContent', type: 'text', optional: true, scope: 'shared', labelKey: 'xrayTfHysteriaMasqueradeContent',
      showIf: { hysteriaMasqueradeType: 'string' } },
    { key: 'hysteriaMasqueradeDir', type: 'text', optional: true, default: '/var/www/html', scope: 'shared',
      labelKey: 'xrayTfHysteriaMasqueradeDir', showIf: { hysteriaMasqueradeType: 'file' } },
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

function inheritTransportFields(base, network, settings = {}) {
  const out = { ...(settings || {}) };
  const sni = String(base.sni || base.certDomain || '').trim();
  const fields = FIELDS[network] || [];
  for (const f of fields) {
    if (f.inheritFrom === 'sni' && isEmptyValue(out[f.key]) && sni) {
      out[f.key] = sni;
    }
  }
  if (network === 'ws' && isEmptyValue(out.wsHost) && sni) out.wsHost = sni;
  if (network === 'grpc' && isEmptyValue(out.grpcAuthority) && sni) out.grpcAuthority = sni;
  if (network === 'httpupgrade' && isEmptyValue(out.httpupgradeHost) && sni) out.httpupgradeHost = sni;
  if (network === 'xhttp' && isEmptyValue(out.xhttpHost) && sni) out.xhttpHost = sni;
  return out;
}

function sanitizeTransportSettings(network, settings = {}) {
  const out = {};
  const fields = FIELDS[network] || [];
  const fieldMap = new Map(fields.map((f) => [f.key, f]));
  for (const [key, val] of Object.entries(settings || {})) {
    const meta = fieldMap.get(key);
    if (meta && meta.optional === false && isEmptyValue(val)) continue;
    if (isEmptyValue(val)) continue;
    if (meta && meta.type === 'select' && meta.options && !meta.options.includes(val)) continue;
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

function validateTransportSettings(network, settings = {}) {
  const fields = FIELDS[network] || [];
  /** @type {Record<string, string>} */
  const fieldErrors = {};
  for (const f of fields) {
    if (f.optional === false && isEmptyValue(settings[f.key])) {
      fieldErrors[f.key] = `${f.labelKey || f.key} is required`;
    }
    if (f.type === 'json' && !isEmptyValue(settings[f.key]) && typeof settings[f.key] === 'string') {
      try {
        JSON.parse(settings[f.key]);
      } catch {
        fieldErrors[f.key] = 'Invalid JSON';
      }
    }
    if (f.type === 'select' && !isEmptyValue(settings[f.key]) && f.options && !f.options.includes(settings[f.key])) {
      fieldErrors[f.key] = 'Invalid value';
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
  if (n === 'kcp' || n === 'hysteria') return 'udp';
  return 'tcp';
}

/** Transports that listen on UDP (cannot use TCP SNI demux). */
function isUdpTransport(network) {
  return mapTransportProto(network) === 'udp';
}

/**
 * uTLS ClientHello fingerprint (fp) applies to Reality and TCP-TLS streams.
 * Not used for security=none, and not for QUIC/Hysteria (different stack).
 */
function fingerprintSupported(network, security) {
  const sec = String(security || '').toLowerCase();
  const net = String(network || 'tcp').toLowerCase();
  if (sec !== 'reality' && sec !== 'tls') return false;
  if (net === 'hysteria') return false;
  return true;
}

function getFieldsForUi(network) {
  return (FIELDS[network] || []).map((f) => ({ ...f }));
}

module.exports = {
  TRANSPORTS,
  TRANSPORT_IDS,
  SECURITY_BY_TRANSPORT,
  FIELDS,
  KCP_HEADER_TYPES,
  XHTTP_MODES,
  TCP_HEADER_TYPES,
  TCP_CONGESTION,
  HTTP_VERSIONS,
  HTTP_METHODS,
  DOMAIN_STRATEGIES,
  allowedSecurities,
  supportsReality,
  allowedCertTypes,
  certFilterKey,
  inheritTransportFields,
  sanitizeTransportSettings,
  validateTransportSettings,
  flowSupported,
  mapTransportProto,
  isUdpTransport,
  fingerprintSupported,
  getFieldsForUi,
  isEmptyValue,
};
