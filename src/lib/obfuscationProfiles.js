'use strict';

const { execFileSync } = require('node:child_process');
const { getI1ForProfile, getProfileSignatures } = require('./signatures');

let _profileIds = null;
let _defaultProfileId = 'dns';

function _pythonKnownProfileIds() {
  const env = { ...process.env, PYTHONPATH: process.cwd() };
  const code = 'from python_signatures.library_api import known_profile_ids; import json; print(json.dumps(known_profile_ids()))';
  const bins = [];
  if (process.env.PYTHON) bins.push(process.env.PYTHON);
  bins.push('python3', 'python');
  const seen = new Set();
  for (const bin of bins) {
    if (!bin || seen.has(bin)) continue;
    seen.add(bin);
    try {
      const out = execFileSync(bin, ['-c', code], {
        encoding: 'utf8',
        env,
        cwd: process.cwd(),
        windowsHide: true,
        maxBuffer: 1024 * 1024,
      });
      const arr = JSON.parse(out.trim());
      if (Array.isArray(arr) && arr.length && arr.every((x) => typeof x === 'string')) {
        return arr;
      }
    } catch (_) {
      /* try next */
    }
  }
  throw new Error('known_profile_ids: need python3/python on PATH with PYTHONPATH=repo root');
}

function _ensureLoaded() {
  if (_profileIds !== null) return;
  try {
    _profileIds = _pythonKnownProfileIds();
  } catch (e) {
    console.error('obfuscationProfiles:', e.message);
    _profileIds = [];
  }
  _defaultProfileId = _profileIds.includes('dns') ? 'dns' : (_profileIds[0] || 'dns');
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
