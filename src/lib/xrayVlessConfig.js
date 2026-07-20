'use strict';

/**
 * VLESS client/server config builders and vless:// serializer.
 * Aligns with amnezia-client core/serialization/vless.cpp where applicable.
 */

const SECURITY_MODES = Object.freeze(['reality', 'tls', 'none']);
const NETWORK_MODES = Object.freeze(['tcp', 'ws', 'grpc', 'kcp', 'http', 'quic']);

function normalizeSecurity(v) {
  const s = String(v || 'reality').trim().toLowerCase();
  return SECURITY_MODES.includes(s) ? s : 'reality';
}

function normalizeNetwork(v) {
  const n = String(v || 'tcp').trim().toLowerCase();
  return NETWORK_MODES.includes(n) ? n : 'tcp';
}

function buildStreamSettings(opts) {
  const security = normalizeSecurity(opts.security);
  const network = normalizeNetwork(opts.network);
  /** @type {Record<string, unknown>} */
  const stream = { network, security };

  if (security === 'reality') {
    stream.realitySettings = {
      fingerprint: opts.fingerprint || 'chrome',
      serverName: opts.sni || '',
      publicKey: opts.publicKey || '',
      shortId: opts.shortId || '',
      spiderX: opts.spiderX != null ? opts.spiderX : '',
    };
  } else if (security === 'tls') {
    stream.tlsSettings = {
      allowInsecure: opts.allowInsecure === true,
      fingerprint: opts.fingerprint || '',
      alpn: opts.alpn ? (Array.isArray(opts.alpn) ? opts.alpn : String(opts.alpn).split(',')) : undefined,
    };
    if (opts.sni) stream.tlsSettings.serverName = opts.sni;
    if (stream.tlsSettings.alpn == null) delete stream.tlsSettings.alpn;
    if (!stream.tlsSettings.fingerprint) delete stream.tlsSettings.fingerprint;
  }

  if (network === 'ws') {
    stream.wsSettings = {
      path: opts.wsPath || '/',
      headers: opts.wsHost ? { Host: opts.wsHost } : undefined,
    };
    if (!stream.wsSettings.headers) delete stream.wsSettings.headers;
  } else if (network === 'grpc') {
    stream.grpcSettings = {
      serviceName: opts.grpcServiceName || '',
      multiMode: opts.grpcMultiMode === true,
    };
  } else if (network === 'tcp' && security === 'none' && opts.headerType) {
    stream.tcpSettings = {
      header: { type: opts.headerType },
    };
  }

  return stream;
}

/**
 * Client JSON for Amnezia .vpn / subscription (SOCKS 10808 inbound).
 */
function buildClientJson(opts) {
  const security = normalizeSecurity(opts.security);
  const network = normalizeNetwork(opts.network);
  /** @type {Record<string, unknown>} */
  const user = { id: opts.uuid };
  if (opts.flow && (security === 'reality' || security === 'tls')) user.flow = opts.flow;
  user.encryption = 'none';

  /** @type {Record<string, unknown>} */
  const outbound = {
    protocol: 'vless',
    settings: {
      vnext: [{
        address: opts.host,
        port: Number(opts.port),
        users: [user],
      }],
    },
    streamSettings: buildStreamSettings(opts),
  };
  if (opts.remark) outbound.tag = opts.remark;

  return {
    log: { loglevel: 'error' },
    inbounds: [{
      listen: '127.0.0.1',
      port: 10808,
      protocol: 'socks',
      settings: { udp: true },
    }],
    outbounds: [outbound],
  };
}

/**
 * Build vless:// share link.
 */
function buildVlessUrl(opts) {
  const security = normalizeSecurity(opts.security);
  const network = normalizeNetwork(opts.network);
  const params = new URLSearchParams();
  params.set('encryption', 'none');
  params.set('security', security === 'tls' && opts.flow ? 'tls' : security);
  if (network !== 'tcp') params.set('type', network);
  if (opts.flow && security !== 'none') params.set('flow', opts.flow);
  if (opts.sni) params.set('sni', opts.sni);
  if (opts.fingerprint) params.set('fp', opts.fingerprint);
  if (security === 'reality') {
    if (opts.publicKey) params.set('pbk', opts.publicKey);
    if (opts.shortId) params.set('sid', opts.shortId);
  }
  if (security === 'tls') {
    if (opts.allowInsecure) params.set('allowInsecure', '1');
    if (opts.alpn) params.set('alpn', Array.isArray(opts.alpn) ? opts.alpn.join(',') : opts.alpn);
  }
  if (network === 'ws') {
    if (opts.wsPath) params.set('path', opts.wsPath);
    if (opts.wsHost) params.set('host', opts.wsHost);
  }
  if (network === 'grpc' && opts.grpcServiceName) {
    params.set('serviceName', opts.grpcServiceName);
  }
  let url = `vless://${opts.uuid}@${opts.host}:${Number(opts.port)}?${params.toString()}`;
  if (opts.remark) url += `#${encodeURIComponent(opts.remark)}`;
  return url;
}

/**
 * Server inbound for Xray server.json.
 */
function buildServerInbound(opts) {
  const security = normalizeSecurity(opts.security);
  const network = normalizeNetwork(opts.network);
  const tag = security === 'reality' ? 'vless-reality' : `vless-${security}-${network}`;

  /** @type {Array<Record<string, unknown>>} */
  const clients = (opts.clients || []).map((c) => {
    const entry = { id: c.xray_uuid || c.id, email: c.name || c.email || '' };
    if (opts.flow && security !== 'none') entry.flow = opts.flow;
    return entry;
  });

  /** @type {Record<string, unknown>} */
  const inbound = {
    tag,
    listen: '0.0.0.0',
    port: opts.port,
    protocol: 'vless',
    settings: { clients, decryption: 'none' },
    streamSettings: buildStreamSettings({
      security,
      network,
      sni: opts.sni,
      fingerprint: opts.fingerprint,
      publicKey: opts.publicKey,
      shortId: opts.shortId,
      wsPath: opts.wsPath,
      wsHost: opts.wsHost,
      grpcServiceName: opts.grpcServiceName,
      grpcMultiMode: opts.grpcMultiMode,
      allowInsecure: false,
      alpn: opts.alpn,
    }),
  };

  if (security === 'reality' && inbound.streamSettings.realitySettings) {
    const rs = inbound.streamSettings.realitySettings;
    rs.dest = `${opts.sni}:443`;
    rs.serverNames = [opts.sni];
    rs.privateKey = opts.privateKey;
    rs.shortIds = [opts.shortId];
    delete rs.publicKey;
  }

  if (security === 'tls' && opts.tlsCert && opts.tlsKey) {
    inbound.streamSettings.tlsSettings = {
      ...inbound.streamSettings.tlsSettings,
      certificates: [{ certificateFile: opts.tlsCert, keyFile: opts.tlsKey }],
    };
  }

  return inbound;
}

module.exports = {
  SECURITY_MODES,
  NETWORK_MODES,
  normalizeSecurity,
  normalizeNetwork,
  buildStreamSettings,
  buildClientJson,
  buildVlessUrl,
  buildServerInbound,
};
