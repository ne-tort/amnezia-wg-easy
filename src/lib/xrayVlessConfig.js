'use strict';

/**
 * VLESS client/server config builders and vless:// serializer.
 * Aligns with amnezia-client core/serialization/vless.cpp where applicable.
 */

const xrayTransportSchema = require('./xrayTransportSchema');

const SECURITY_MODES = Object.freeze(['reality', 'tls', 'none']);
const NETWORK_MODES = Object.freeze(xrayTransportSchema.TRANSPORT_IDS);

const NETWORK_ALIASES = Object.freeze({
  raw: 'tcp',
  tcp: 'tcp',
  splithttp: 'xhttp',
  xhttp: 'xhttp',
  websocket: 'ws',
  ws: 'ws',
  mkcp: 'kcp',
  kcp: 'kcp',
  httpupgrade: 'httpupgrade',
  grpc: 'grpc',
  hysteria: 'hysteria',
});

function normalizeSecurity(v) {
  const s = String(v || 'reality').trim().toLowerCase();
  return SECURITY_MODES.includes(s) ? s : 'reality';
}

function normalizeNetwork(v) {
  const raw = String(v || 'tcp').trim().toLowerCase();
  const n = NETWORK_ALIASES[raw] || raw;
  return NETWORK_MODES.includes(n) ? n : 'tcp';
}

function parseJsonMap(val) {
  if (val == null || val === '') return null;
  if (typeof val === 'object' && !Array.isArray(val)) return val;
  if (typeof val === 'string') {
    try {
      const parsed = JSON.parse(val);
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) return parsed;
    } catch {
      return null;
    }
  }
  return null;
}

function parseCommaList(val, fallback = []) {
  if (val == null || val === '') return fallback;
  if (Array.isArray(val)) return val.filter(Boolean);
  return String(val).split(',').map((s) => s.trim()).filter(Boolean);
}

function buildSockopt(opts) {
  /** @type {Record<string, unknown>} */
  const sock = {};
  if (opts.tcpFastOpen === true) sock.tcpFastOpen = true;
  if (opts.tcpCongestion) sock.tcpCongestion = String(opts.tcpCongestion).trim();
  if (opts.domainStrategy) sock.domainStrategy = String(opts.domainStrategy).trim();
  if (opts.acceptProxyProtocol === true) sock.acceptProxyProtocol = true;
  return Object.keys(sock).length ? sock : null;
}

function buildTcpSettings(opts) {
  const headerType = opts.headerType || opts.tcpHeaderType || 'none';
  if (headerType === 'http') {
    const paths = parseCommaList(opts.httpPath, ['/']);
    /** @type {Record<string, unknown>} */
    const request = {
      version: opts.httpVersion || '1.1',
      method: opts.httpMethod || 'GET',
      path: paths,
    };
    if (opts.httpHost) {
      request.headers = { Host: parseCommaList(opts.httpHost) };
    }
    return {
      acceptProxyProtocol: opts.acceptProxyProtocol === true || undefined,
      header: { type: 'http', request },
    };
  }
  if (headerType && headerType !== 'none') {
    return { header: { type: headerType } };
  }
  const sock = buildSockopt(opts);
  if (opts.acceptProxyProtocol === true) {
    return {
      acceptProxyProtocol: true,
      header: { type: 'none' },
    };
  }
  if (sock) return { header: { type: 'none' } };
  return null;
}

function buildWsSettings(opts) {
  const path = opts.wsPath || '/';
  const host = opts.wsHost || opts.sni || '';
  /** @type {Record<string, string>} */
  const headers = parseJsonMap(opts.wsHeaders) || {};
  if (host && !headers.Host) headers.Host = host;
  /** @type {Record<string, unknown>} */
  const ws = { path };
  if (Object.keys(headers).length) ws.headers = headers;
  if (opts.acceptProxyProtocol === true) ws.acceptProxyProtocol = true;
  return ws;
}

function buildGrpcSettings(opts) {
  const serviceName = opts.grpcServiceName || '';
  if (!serviceName) return null;
  /** @type {Record<string, unknown>} */
  const grpc = { serviceName };
  if (opts.grpcMultiMode === true) grpc.multiMode = true;
  if (opts.grpcAuthority) grpc.authority = opts.grpcAuthority;
  if (opts.grpcIdleTimeout != null && opts.grpcIdleTimeout !== '') {
    grpc.idle_timeout = Number(opts.grpcIdleTimeout);
  }
  return grpc;
}

function buildKcpSettings(opts) {
  /** @type {Record<string, unknown>} */
  const kcp = {};
  if (opts.kcpMtu != null && opts.kcpMtu !== '') kcp.mtu = Number(opts.kcpMtu);
  if (opts.kcpTti != null && opts.kcpTti !== '') kcp.tti = Number(opts.kcpTti);
  if (opts.kcpUplinkCapacity != null && opts.kcpUplinkCapacity !== '') {
    kcp.uplinkCapacity = Number(opts.kcpUplinkCapacity);
  }
  if (opts.kcpDownlinkCapacity != null && opts.kcpDownlinkCapacity !== '') {
    kcp.downlinkCapacity = Number(opts.kcpDownlinkCapacity);
  }
  if (opts.kcpReadBufferSize != null && opts.kcpReadBufferSize !== '') {
    kcp.readBufferSize = Number(opts.kcpReadBufferSize);
  }
  if (opts.kcpWriteBufferSize != null && opts.kcpWriteBufferSize !== '') {
    kcp.writeBufferSize = Number(opts.kcpWriteBufferSize);
  }
  if (opts.kcpCongestion === true) kcp.congestion = true;
  // Xray 26+: header/seed removed from kcpSettings (use finalmask). Emitting them
  // makes `xray -test` fail — never write them into server/client JSON.
  return kcp;
}

function buildHttpupgradeSettings(opts) {
  const path = opts.httpupgradePath || '/';
  const host = opts.httpupgradeHost || opts.sni || '';
  /** @type {Record<string, unknown>} */
  const hu = { path };
  if (host) hu.host = host;
  const headers = parseJsonMap(opts.httpupgradeHeaders);
  if (headers && Object.keys(headers).length) hu.headers = headers;
  return hu;
}

function buildXhttpSettings(opts) {
  /** @type {Record<string, unknown>} */
  const xhttp = {};
  if (opts.xhttpMode) xhttp.mode = opts.xhttpMode;
  if (opts.xhttpHost) xhttp.host = opts.xhttpHost;
  if (opts.xhttpPath) xhttp.path = opts.xhttpPath;
  if (opts.xhttpExtra) xhttp.extra = opts.xhttpExtra;
  const headers = parseJsonMap(opts.xhttpHeaders);
  if (headers && Object.keys(headers).length) xhttp.headers = headers;
  return Object.keys(xhttp).length ? xhttp : { path: '/' };
}

function buildHysteriaSettings(opts) {
  /** @type {Record<string, unknown>} */
  const h = {
    version: Number(opts.hysteriaVersion || 2) || 2,
  };
  if (opts.hysteriaAuth) h.auth = String(opts.hysteriaAuth);
  if (opts.hysteriaUdpIdleTimeout != null && opts.hysteriaUdpIdleTimeout !== '') {
    h.udpIdleTimeout = Number(opts.hysteriaUdpIdleTimeout);
  }
  if (opts.hysteriaUpMbps != null && opts.hysteriaUpMbps !== '') {
    h.up = `${opts.hysteriaUpMbps} Mbps`;
  }
  if (opts.hysteriaDownMbps != null && opts.hysteriaDownMbps !== '') {
    h.down = `${opts.hysteriaDownMbps} Mbps`;
  }
  const mType = String(opts.hysteriaMasqueradeType || '').trim();
  if (mType) {
    /** @type {Record<string, unknown>} */
    const masq = { type: mType };
    if (mType === 'proxy' && opts.hysteriaMasqueradeUrl) {
      masq.url = String(opts.hysteriaMasqueradeUrl);
      masq.rewriteHost = true;
    } else if (mType === 'string') {
      masq.content = String(opts.hysteriaMasqueradeContent || 'ok');
    } else if (mType === 'file') {
      masq.dir = String(opts.hysteriaMasqueradeDir || '/var/www/html');
    }
    h.masquerade = masq;
  }
  return h;
}

function normalizeAlpnList(alpn, { network, forClient } = {}) {
  let list = [];
  if (Array.isArray(alpn)) list = alpn.map((s) => String(s).trim()).filter(Boolean);
  else if (alpn != null && String(alpn).trim() !== '') {
    list = String(alpn).split(',').map((s) => s.trim()).filter(Boolean);
  }
  // Hysteria/QUIC requires h3; empty alpn [] breaks the TLS stack.
  if (network === 'hysteria' && !list.length) list = ['h3'];
  if (network === 'hysteria' && !list.includes('h3')) list = ['h3', ...list];
  return list.length ? list : undefined;
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
    // Server-side tlsSettings must NOT include allowInsecure (removed in Xray 26+;
    // that flag is client-only via pinnedPeerCertSha256 / URI allowInsecure).
    const alpn = normalizeAlpnList(opts.alpn, { network, forClient: opts.forClient === true });
    stream.tlsSettings = {};
    if (opts.forClient === true && opts.fingerprint) {
      stream.tlsSettings.fingerprint = opts.fingerprint;
    }
    if (alpn) stream.tlsSettings.alpn = alpn;
    if (opts.forClient === true && opts.allowInsecure === true) {
      stream.tlsSettings.allowInsecure = true;
    }
    if (opts.sni) stream.tlsSettings.serverName = opts.sni;
  }

  if (network === 'tcp') {
    const tcp = buildTcpSettings(opts);
    if (tcp) {
      stream.tcpSettings = tcp;
      stream.rawSettings = tcp;
    }
  } else if (network === 'ws') {
    stream.wsSettings = buildWsSettings(opts);
  } else if (network === 'grpc') {
    const grpc = buildGrpcSettings(opts);
    if (grpc) stream.grpcSettings = grpc;
  } else if (network === 'kcp') {
    stream.kcpSettings = buildKcpSettings(opts);
  } else if (network === 'httpupgrade') {
    stream.httpupgradeSettings = buildHttpupgradeSettings(opts);
  } else if (network === 'xhttp') {
    stream.xhttpSettings = buildXhttpSettings(opts);
  } else if (network === 'hysteria') {
    stream.hysteriaSettings = buildHysteriaSettings(opts);
  }

  const sock = buildSockopt(opts);
  if (sock) stream.sockopt = sock;

  return stream;
}

function effectiveFlow(opts) {
  const security = normalizeSecurity(opts.security);
  const network = normalizeNetwork(opts.network);
  if (security === 'none') return '';
  if (!xrayTransportSchema.flowSupported(network)) return '';
  return opts.flow || '';
}

/**
 * Client JSON for Amnezia .vpn / subscription (SOCKS 10808 inbound).
 */
function buildClientJson(opts) {
  const flow = effectiveFlow(opts);
  /** @type {Record<string, unknown>} */
  const user = { id: opts.uuid };
  if (flow) user.flow = flow;
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
    streamSettings: buildStreamSettings({ ...opts, forClient: true }),
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

function appendVlessTransportParams(params, network, opts) {
  if (network === 'ws') {
    if (opts.wsPath) params.set('path', opts.wsPath);
    if (opts.wsHost) params.set('host', opts.wsHost);
  } else if (network === 'grpc') {
    if (opts.grpcServiceName) params.set('serviceName', opts.grpcServiceName);
    if (opts.grpcMultiMode === true) params.set('mode', 'multi');
  } else if (network === 'httpupgrade') {
    if (opts.httpupgradePath) params.set('path', opts.httpupgradePath);
    if (opts.httpupgradeHost) params.set('host', opts.httpupgradeHost);
  } else if (network === 'xhttp') {
    if (opts.xhttpPath) params.set('path', opts.xhttpPath);
    if (opts.xhttpHost) params.set('host', opts.xhttpHost);
    if (opts.xhttpMode) params.set('mode', opts.xhttpMode);
    if (opts.xhttpExtra) params.set('extra', opts.xhttpExtra);
  } else if (network === 'hysteria') {
    // Required by Xray when hysteria transport is paired with non-hysteria proxy (VLESS).
    if (opts.hysteriaAuth) params.set('auth', opts.hysteriaAuth);
  } else if (network === 'tcp') {
    const ht = opts.headerType || opts.tcpHeaderType;
    if (ht && ht !== 'none') params.set('headerType', ht);
  }
}

/**
 * Build vless:// share link (including VLESS + hysteria transport).
 */
function buildVlessUrl(opts) {
  const security = normalizeSecurity(opts.security);
  const network = normalizeNetwork(opts.network);
  const flow = effectiveFlow(opts);
  const params = new URLSearchParams();
  params.set('encryption', 'none');
  params.set('security', security === 'tls' && flow ? 'tls' : security);
  if (network !== 'tcp') params.set('type', network);
  if (flow) params.set('flow', flow);
  if (opts.sni) params.set('sni', opts.sni);
  if (opts.fingerprint) params.set('fp', opts.fingerprint);
  if (security === 'reality') {
    if (opts.publicKey) params.set('pbk', opts.publicKey);
    if (opts.shortId) params.set('sid', opts.shortId);
  }
  if (security === 'tls') {
    if (opts.allowInsecure) params.set('allowInsecure', '1');
    const alpn = normalizeAlpnList(opts.alpn, { network, forClient: true });
    if (alpn) params.set('alpn', alpn.join(','));
  }
  appendVlessTransportParams(params, network, opts);
  let url = `vless://${opts.uuid}@${opts.host}:${Number(opts.port)}?${params.toString()}`;
  if (opts.remark) url += `#${encodeURIComponent(opts.remark)}`;
  return url;
}

/**
 * Server inbound for Xray server.json.
 * VLESS + network=hysteria requires hysteriaSettings.auth (Xray maintainers: not optional).
 */
function buildServerInbound(opts) {
  const security = normalizeSecurity(opts.security);
  const network = normalizeNetwork(opts.network);
  const tag = security === 'reality' ? 'vless-reality' : `vless-${security}-${network}`;
  const flow = effectiveFlow({ ...opts, security, network });

  if (network === 'hysteria' && !String(opts.hysteriaAuth || '').trim()) {
    throw new Error('hysteriaAuth is required for VLESS + hysteria transport');
  }

  /** @type {Array<Record<string, unknown>>} */
  const clients = (opts.clients || []).map((c) => {
    const entry = { id: c.xray_uuid || c.id, email: c.name || c.email || '' };
    if (flow) entry.flow = flow;
    return entry;
  });

  /** @type {Record<string, unknown>} */
  const inbound = {
    tag,
    listen: '0.0.0.0',
    port: opts.port,
    protocol: 'vless',
    settings: { clients, decryption: 'none' },
    streamSettings: buildStreamSettings(opts),
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
  NETWORK_ALIASES,
  normalizeSecurity,
  normalizeNetwork,
  buildStreamSettings,
  buildClientJson,
  buildVlessUrl,
  buildServerInbound,
  effectiveFlow,
  normalizeAlpnList,
};
