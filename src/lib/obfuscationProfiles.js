'use strict';

const { getI1ForProfile, getProfileSignatures } = require('./signatures');
const { listProfilesMeta } = require('./siglabBridge');

let _profileIds = null;
let _defaultProfileId = 'dns';
let _meta = null;

function _ensureLoaded() {
  if (_profileIds !== null) return;
  _meta = listProfilesMeta();
  if (_meta && Array.isArray(_meta.profile_ids) && _meta.profile_ids.length) {
    _profileIds = _meta.profile_ids;
    _defaultProfileId = _meta.default_profile || (_profileIds.includes('dns') ? 'dns' : _profileIds[0]);
    return;
  }
  console.error('obfuscationProfiles: siglab list unavailable; profile list empty');
  _profileIds = [];
  _defaultProfileId = 'dns';
}

function getProfilesMeta() {
  _ensureLoaded();
  return _meta;
}

function getProfileIds() {
  _ensureLoaded();
  return _profileIds;
}

function getDefaultProfileId() {
  _ensureLoaded();
  return _defaultProfileId;
}

function getProfileI1(profileId) {
  return getI1ForProfile(profileId);
}

function isKnownProfile(profileId) {
  return typeof profileId === 'string' && getProfileIds().includes(profileId);
}

module.exports = {
  getProfileI1,
  getProfileSignatures,
  getProfileIds,
  getDefaultProfileId,
  getProfilesMeta,
  isKnownProfile,
};

Object.defineProperty(module.exports, 'PROFILE_IDS', {
  enumerable: true,
  get() {
    return getProfileIds();
  },
});

Object.defineProperty(module.exports, 'DEFAULT_PROFILE_ID', {
  enumerable: true,
  get() {
    return getDefaultProfileId();
  },
});
