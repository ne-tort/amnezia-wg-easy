'use strict';

const { I1: QUIC_I1 } = require('../config');

// * Obfuscation profiles: protocol mask (I1 signature) per profile id.
// Used when generating client config; profile is chosen in UI (default: quic).
const PROFILES = {
  quic: {
    id: 'quic',
    label: 'QUIC',
    i1: process.env.I1_QUIC || QUIC_I1,
  },
  dns: {
    id: 'dns',
    label: 'DNS',
    // Minimal DNS query: 12-byte header (ID=0, RD=1, QDCOUNT=1) + QNAME "com" + QTYPE A + QCLASS IN.
    i1: process.env.I1_DNS || '<b 0x00000100000100000000000003636f6d0000010001>',
  },
  sip: {
    id: 'sip',
    label: 'SIP',
    // TODO: replace with real SIP initial packet hex from Wireshark (filter: sip, copy as Hex Stream).
    i1: process.env.I1_SIP || (process.env.I1_QUIC || QUIC_I1),
  },
  stun: {
    id: 'stun',
    label: 'STUN',
    // RFC 5389: minimal STUN Binding Request — 20-byte header (type 0x0001, length 0, magic 0x2112A442, 12-byte transaction ID).
    i1: process.env.I1_STUN || '<b 0x000100002112a442544553545445535454455354>',
  },
  webrtc: {
    id: 'webrtc',
    label: 'WebRTC',
    // ICE uses STUN; same Binding Request format, different transaction ID so traffic looks like a distinct WebRTC/ICE flow.
    i1: process.env.I1_WEBRTC || '<b 0x000100002112a442000000000000000000000000>',
  },
  dtls: {
    id: 'dtls',
    label: 'DTLS',
    // RFC 6347: DTLS 1.2 record (type 22 Handshake, version 0xFEFD) + start of Handshake ClientHello header (type 01, length, msg_seq, fragment offset/length).
    i1: process.env.I1_DTLS || '<b 0x16fefd00000000000000000000001801000014000000000000000000>',
  },
};

const PROFILE_IDS = Object.keys(PROFILES);
const DEFAULT_PROFILE_ID = 'quic';

function getProfileI1(profileId) {
  const p = PROFILES[profileId];
  return p ? p.i1 : PROFILES[DEFAULT_PROFILE_ID].i1;
}

function getProfileIds() {
  return PROFILE_IDS;
}

function isKnownProfile(profileId) {
  return typeof profileId === 'string' && PROFILES[profileId] !== undefined;
}

module.exports = {
  PROFILES,
  PROFILE_IDS,
  DEFAULT_PROFILE_ID,
  getProfileI1,
  getProfileIds,
  isKnownProfile,
};
