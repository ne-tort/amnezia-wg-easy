'use strict';

/**
 * Fake-TLS (ee) MTProto probe without Telegram client.
 * Verifies the proxy recognizes the secret via ServerHello HMAC.
 */

const crypto = require('node:crypto');
const net = require('node:net');

const TIMEOUT_MS = 10_000;
const DIGEST_LEN = 32;
const DIGEST_POS = 11;
const TLS_VERS = Buffer.from([0x03, 0x03]);

function parseEeSecret(secretStr) {
  const s = String(secretStr || '').trim();
  let raw;
  if (/^[0-9a-fA-F]+$/.test(s) && s.length >= 34) {
    raw = Buffer.from(s, 'hex');
  } else {
    const b64 = s.replace(/-/g, '+').replace(/_/g, '/');
    const pad = '='.repeat((4 - (b64.length % 4)) % 4);
    raw = Buffer.from(b64 + pad, 'base64');
  }
  if (!raw.length || raw[0] !== 0xee) {
    throw new Error('Not a FakeTLS secret (expected 0xEE prefix)');
  }
  if (raw.length < 17) throw new Error('Secret too short');
  return { key: raw.subarray(1, 17), domain: raw.subarray(17).toString('ascii') };
}

function u16(n) {
  return Buffer.from([(n >> 8) & 0xff, n & 0xff]);
}

function buildSniExtension(domain) {
  const sni = Buffer.from(domain, 'ascii');
  const inner = Buffer.concat([Buffer.from([0x00]), u16(sni.length), sni]);
  const innerList = Buffer.concat([u16(inner.length), inner]);
  return Buffer.concat([Buffer.from([0x00, 0x00]), u16(innerList.length), innerList]);
}

function buildClientHello(domain, randomField) {
  const sessionId = crypto.randomBytes(32);
  const cipherSuites = Buffer.from(
    '130113021303c02bc02fc02cc030cca9cca8c013c014009c009d002f0035',
    'hex',
  );
  const sniExt = buildSniExtension(domain);
  const emsExt = Buffer.from([0x00, 0x17, 0x00, 0x00]);
  const renegExt = Buffer.from([0xff, 0x01, 0x00, 0x01, 0x00]);
  const supGrpExt = Buffer.from([0x00, 0x0a, 0x00, 0x08, 0x00, 0x06, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18]);
  const ecPfExt = Buffer.from([0x00, 0x0b, 0x00, 0x02, 0x01, 0x00]);
  const ticketExt = Buffer.from([0x00, 0x23, 0x00, 0x00]);
  const alpn = Buffer.from([0x02, 0x68, 0x32, 0x08, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31]);
  const alpnExt = Buffer.concat([Buffer.from([0x00, 0x10]), u16(alpn.length + 2), u16(alpn.length), alpn]);
  const statusExt = Buffer.from([0x00, 0x05, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00]);
  const sigAlgs = Buffer.from('040308040401050308050501080606010201', 'hex');
  const sigAlgsExt = Buffer.concat([
    Buffer.from([0x00, 0x0d]), u16(sigAlgs.length + 2), u16(sigAlgs.length), sigAlgs,
  ]);
  const sctExt = Buffer.from([0x00, 0x12, 0x00, 0x00]);
  const x25519Pub = crypto.randomBytes(32);
  const keyShareEntry = Buffer.concat([Buffer.from([0x00, 0x1d]), u16(x25519Pub.length), x25519Pub]);
  const keyShareList = Buffer.concat([u16(keyShareEntry.length), keyShareEntry]);
  const keyShareExt = Buffer.concat([Buffer.from([0x00, 0x33]), u16(keyShareList.length), keyShareList]);
  const pskKemExt = Buffer.from([0x00, 0x2d, 0x00, 0x02, 0x01, 0x01]);
  const supVerExt = Buffer.from([0x00, 0x2b, 0x00, 0x05, 0x04, 0x03, 0x04, 0x03, 0x03]);
  const compressCertExt = Buffer.from([0x00, 0x1b, 0x00, 0x03, 0x02, 0x00, 0x02]);

  let extensions = Buffer.concat([
    sniExt, emsExt, renegExt, supGrpExt, ecPfExt, ticketExt, alpnExt,
    statusExt, sigAlgsExt, sctExt, keyShareExt, pskKemExt, supVerExt, compressCertExt,
  ]);
  const currentTotal = 5 + 4 + 2 + 32 + 1 + 32 + 2 + cipherSuites.length + 2 + 2 + extensions.length;
  const padNeeded = Math.max(0, 517 - currentTotal - 4);
  extensions = Buffer.concat([
    extensions,
    Buffer.from([0x00, 0x15]),
    u16(padNeeded),
    Buffer.alloc(padNeeded),
  ]);

  const body = Buffer.concat([
    TLS_VERS, randomField,
    Buffer.from([sessionId.length]), sessionId,
    u16(cipherSuites.length), cipherSuites,
    Buffer.from([0x01, 0x00]),
    u16(extensions.length), extensions,
  ]);
  const hsLen = Buffer.alloc(3);
  hsLen.writeUIntBE(body.length, 0, 3);
  const handshake = Buffer.concat([Buffer.from([0x01]), hsLen, body]);
  return Buffer.concat([Buffer.from([0x16, 0x03, 0x01]), u16(handshake.length), handshake]);
}

function connectAndExchange(host, port, payload, timeoutMs) {
  return new Promise((resolve, reject) => {
    const socket = net.connect({ host, port });
    const chunks = [];
    let settled = false;
    const finish = (err, data) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try { socket.destroy(); } catch (_) { /* ignore */ }
      if (err) reject(err);
      else resolve(data);
    };
    const timer = setTimeout(() => finish(new Error('timeout')), timeoutMs);
    socket.once('connect', () => {
      socket.write(payload);
      // collect for a bit after first data
      let drainTimer = null;
      socket.on('data', (b) => {
        chunks.push(b);
        if (drainTimer) clearTimeout(drainTimer);
        drainTimer = setTimeout(() => finish(null, Buffer.concat(chunks)), 400);
      });
    });
    socket.once('error', (e) => finish(e));
    socket.once('end', () => finish(null, Buffer.concat(chunks)));
  });
}

/**
 * @param {{ host: string, port: number, eeSecret: string, timeoutMs?: number }} opts
 */
async function probeFakeTls({ host, port, eeSecret, timeoutMs = TIMEOUT_MS }) {
  const started = Date.now();
  let secretKey;
  let domain;
  try {
    ({ key: secretKey, domain } = parseEeSecret(eeSecret));
  } catch (e) {
    return { ok: false, code: 'INVALID_SECRET', message: e.message || String(e), ms: Date.now() - started };
  }

  const zeroRandom = Buffer.alloc(DIGEST_LEN);
  const helloZero = buildClientHello(domain, zeroRandom);
  const clientHmac = crypto.createHmac('sha256', secretKey).update(helloZero).digest();
  const ts = Buffer.alloc(4);
  ts.writeUInt32LE(Math.floor(Date.now() / 1000) >>> 0, 0);
  const xorMask = Buffer.concat([Buffer.alloc(DIGEST_LEN - 4), ts]);
  const randomField = Buffer.alloc(DIGEST_LEN);
  for (let i = 0; i < DIGEST_LEN; i += 1) randomField[i] = clientHmac[i] ^ xorMask[i];
  const realHello = Buffer.from(helloZero);
  randomField.copy(realHello, DIGEST_POS);

  let full;
  try {
    full = await connectAndExchange(host, port, realHello, timeoutMs);
  } catch (e) {
    return {
      ok: false,
      code: 'CONNECT_FAILED',
      message: e.message || String(e),
      ms: Date.now() - started,
    };
  }

  if (!full || full.length < 5) {
    return { ok: false, code: 'EMPTY_RESPONSE', message: 'No TLS response', ms: Date.now() - started };
  }
  if (full[0] !== 0x16) {
    return {
      ok: false,
      code: 'BAD_RECORD',
      message: `unexpected TLS record type 0x${full[0].toString(16)}`,
      ms: Date.now() - started,
    };
  }
  const recLen = full.readUInt16BE(3);
  const payload = full.subarray(5, 5 + recLen);
  if (payload.length < 4 || payload[0] !== 0x02) {
    return {
      ok: false,
      code: 'NOT_SERVER_HELLO',
      message: 'Server response is not a ServerHello (likely domain fronting)',
      ms: Date.now() - started,
    };
  }
  if (full.length < DIGEST_POS + DIGEST_LEN) {
    return { ok: false, code: 'SHORT_RESPONSE', message: 'Response too short', ms: Date.now() - started };
  }

  const serverDigest = full.subarray(DIGEST_POS, DIGEST_POS + DIGEST_LEN);
  const zeroed = Buffer.from(full);
  zeroed.fill(0, DIGEST_POS, DIGEST_POS + DIGEST_LEN);
  const expected = crypto
    .createHmac('sha256', secretKey)
    .update(Buffer.concat([randomField, zeroed]))
    .digest();

  if (crypto.timingSafeEqual(expected, serverDigest)) {
    return { ok: true, code: 'OK', message: 'FakeTLS HMAC verified', ms: Date.now() - started };
  }
  return {
    ok: false,
    code: 'HMAC_MISMATCH',
    message: 'Server digest mismatch — secret not recognized (domain fronting)',
    ms: Date.now() - started,
  };
}

module.exports = {
  parseEeSecret,
  probeFakeTls,
  buildClientHello,
  DIGEST_POS,
  DIGEST_LEN,
};
