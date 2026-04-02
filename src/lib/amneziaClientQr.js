'use strict';

/**
 * AmneziaVPN QR payloads: same pipeline as ImportController + qrCodeUtils (Qt qCompress, QDataStream, magic 1984).
 * Ported from tools/amnezia_awg_ini_to_qr.py reference.
 */

const zlib = require('node:zlib');
const QRCode = require('qrcode');

const QR_MAGIC = 1984;
const CHUNK_PAYLOAD = 850;

const REQUIRED_JUNK = ['Jc', 'Jmin', 'Jmax', 'S1', 'S2', 'H1', 'H2', 'H3', 'H4'];
const OPTIONAL_JUNK = ['S3', 'S4', 'I1', 'I2', 'I3', 'I4', 'I5'];

const DNS_RE = /DNS = (\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b).*(\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b)/;

function parseIniWireguardStyle(text) {
  const cfg = {};
  for (const line of text.replace(/\r\n/g, '\n').split('\n')) {
    const t = line.trim();
    if (t.startsWith('[') && t.endsWith(']')) continue;
    const parts = t.split(' = ', 2);
    if (parts.length === 2) cfg[parts[0].trim()] = parts[1].trim();
  }
  return cfg;
}

function parseEndpoint(endpoint) {
  const ep = endpoint.trim();
  const defaultPort = 51820;
  if (ep.startsWith('[')) {
    const end = ep.indexOf(']');
    if (end === -1) throw new Error(`Invalid Endpoint (IPv6): ${endpoint}`);
    const hostInner = ep.slice(1, end);
    const rest = ep.slice(end + 1).trimStart();
    let port = defaultPort;
    if (rest.startsWith(':')) port = parseInt(rest.slice(1), 10);
    return { hostName: hostInner, port: port };
  }
  if (ep.includes(':')) {
    const i = ep.lastIndexOf(':');
    const host = ep.slice(0, i);
    const portS = ep.slice(i + 1);
    if (host && /^\d+$/.test(portS)) return { hostName: host, port: parseInt(portS, 10) };
  }
  if (ep) return { hostName: ep, port: defaultPort };
  throw new Error(`Invalid Endpoint: ${endpoint}`);
}

function compactJson(obj) {
  return JSON.stringify(obj);
}

/**
 * Qt qCompress: 4-byte big-endian uncompressed size + zlib payload.
 * @param {Buffer} raw
 * @param {number} level
 * @returns {Buffer}
 */
function qCompress(raw, level = 8) {
  const header = Buffer.allocUnsafe(4);
  header.writeUInt32BE(raw.length, 0);
  const compressed = zlib.deflateSync(raw, { level });
  return Buffer.concat([header, compressed]);
}

function packQdatastreamChunk(compressed, chunkIndex, totalChunks) {
  const start = chunkIndex * CHUNK_PAYLOAD;
  const payload = compressed.subarray(start, start + CHUNK_PAYLOAD);
  const buf = Buffer.allocUnsafe(2 + 1 + 1 + 4 + payload.length);
  buf.writeInt16BE(QR_MAGIC, 0);
  buf.writeUInt8(totalChunks, 2);
  buf.writeUInt8(chunkIndex, 3);
  buf.writeUInt32BE(payload.length, 4);
  payload.copy(buf, 8);
  return buf;
}

function b64url(data) {
  return data
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

function generateChunkPayloads(compressed) {
  const n = Math.max(1, Math.ceil(compressed.length / CHUNK_PAYLOAD));
  if (n > 255) {
    throw new Error('Compressed Amnezia QR data too large for chunk format (max 255 chunks)');
  }
  const out = [];
  for (let i = 0; i < n; i++) out.push(b64url(packQdatastreamChunk(compressed, i, n)));
  return out;
}

/**
 * Mirror ImportController::extractWireGuardConfig for AmneziaWG .ini text.
 * @param {string} iniText
 * @param {string} description
 * @returns {Record<string, unknown>}
 */
function buildAmneziaRoot(iniText, description) {
  const m = parseIniWireguardStyle(iniText);
  const requiredKeys = ['PrivateKey', 'Address', 'PublicKey', 'Endpoint'];
  const missing = requiredKeys.filter((k) => !m[k]);
  if (missing.length) throw new Error(`Missing required keys: ${missing.join(', ')}`);

  for (const k of REQUIRED_JUNK) {
    if (!m[k]) throw new Error(`Not an AmneziaWG ini: missing ${k} (required obfuscation field)`);
  }

  const { hostName, port: portNum } = parseEndpoint(m.Endpoint);
  const portStr = String(portNum);

  const normalizedIni = iniText.endsWith('\n') ? iniText : `${iniText}\n`;

  /** @type {Record<string, unknown>} */
  const last = {
    config: normalizedIni,
    hostName,
    port: portNum,
    client_priv_key: m.PrivateKey,
    client_ip: m.Address,
    server_pub_key: m.PublicKey,
  };

  if (m.PresharedKey) last.psk_key = m.PresharedKey;
  else if (m.PreSharedKey) last.psk_key = m.PreSharedKey;

  if (m.MTU) last.mtu = m.MTU;
  if (m.PersistentKeepalive) last.persistent_keep_alive = m.PersistentKeepalive;

  last.allowed_ips = m.AllowedIPs ? m.AllowedIPs.split(', ').filter(Boolean) : [];

  for (const k of REQUIRED_JUNK) last[k] = m[k];
  for (const k of OPTIONAL_JUNK) {
    if (m[k]) last[k] = m[k];
  }

  if (!m.MTU) last.mtu = '1280';

  let protocolVersion = '';
  const hasS3 = Boolean(m.S3);
  const hasS4 = Boolean(m.S4);
  const hasSpecial = [1, 2, 3, 4, 5].some((i) => m[`I${i}`]);
  if (hasS3 && hasS4) protocolVersion = '2';
  else if (hasSpecial && !hasS3 && !hasS4) protocolVersion = '1.5';

  const lastConfigStr = compactJson(last);

  /** @type {Record<string, unknown>} */
  const awgBlock = {
    last_config: lastConfigStr,
    isThirdPartyConfig: true,
    port: portStr,
    transport_proto: 'udp',
  };
  if (protocolVersion) awgBlock.protocol_version = protocolVersion;

  const containerEl = { container: 'amnezia-awg', awg: awgBlock };

  /** @type {Record<string, unknown>} */
  const root = {
    containers: [containerEl],
    defaultContainer: 'amnezia-awg',
    description,
    hostName,
  };

  const dnsM = iniText.match(DNS_RE);
  if (dnsM) {
    root.dns1 = dnsM[1];
    root.dns2 = dnsM[2];
  }

  return root;
}

const QR_OPTS = {
  type: 'svg',
  width: 512,
  errorCorrectionLevel: 'L',
};

/**
 * @param {string} iniText
 * @param {string} description
 * @returns {Promise<string[]>} One SVG string per QR chunk
 */
async function generateAmneziaClientQrSvgs(iniText, description) {
  const root = buildAmneziaRoot(iniText, description);
  const jsonBytes = Buffer.from(compactJson(root), 'utf8');
  const compressed = qCompress(jsonBytes, 8);
  const payloads = generateChunkPayloads(compressed);
  const svgs = [];
  for (const payload of payloads) {
    // eslint-disable-next-line no-await-in-loop
    const svg = await QRCode.toString(payload, QR_OPTS);
    svgs.push(svg);
  }
  return svgs;
}

module.exports = {
  QR_MAGIC,
  CHUNK_PAYLOAD,
  buildAmneziaRoot,
  generateAmneziaClientQrSvgs,
  qCompress,
  packQdatastreamChunk,
  generateChunkPayloads,
  parseIniWireguardStyle,
  parseEndpoint,
};
