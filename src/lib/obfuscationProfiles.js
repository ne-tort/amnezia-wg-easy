'use strict';

const { getI1ForProfile } = require('./signatures');

// * Profile ids in display order (must match Python run_all registry).
const PROFILE_IDS = ['dns', 'quic', 'stun', 'sip', 'webrtc', 'dtls'];
const DEFAULT_PROFILE_ID = 'dns';

function getProfileI1(profileId) {
  return getI1ForProfile(profileId);
}

function getProfileIds() {
  return PROFILE_IDS;
}

function isKnownProfile(profileId) {
  return typeof profileId === 'string' && PROFILE_IDS.includes(profileId);
}

module.exports = {
  PROFILE_IDS,
  DEFAULT_PROFILE_ID,
  getProfileI1,
  getProfileIds,
  isKnownProfile,
};
