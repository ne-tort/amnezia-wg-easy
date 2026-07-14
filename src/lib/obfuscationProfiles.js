'use strict';

/**
 * Thin catalog helpers over the static signature bank.
 */

const {
  loadBankSync,
  listProtocols,
  getDefaultProtocol,
  getProfilesCatalog: buildCatalog,
  getEntry,
  invalidateCache,
  BankError,
} = require('./signaturesBank');

function getProfilesCatalog() {
  try {
    return buildCatalog(loadBankSync());
  } catch (err) {
    const message = err instanceof BankError ? err.message : err.message;
    return {
      ok: false,
      error: message,
      profileIds: [],
      protocols: [],
      defaultProtocol: null,
      defaultProfile: null,
    };
  }
}

function getProfileIds() {
  try {
    return listProtocols(loadBankSync());
  } catch {
    return [];
  }
}

function getDefaultProfileId() {
  try {
    return getDefaultProtocol(loadBankSync()) || null;
  } catch {
    return null;
  }
}

function refreshCatalog() {
  invalidateCache();
  return getProfilesCatalog();
}

function isKnownProfile(profileId) {
  return typeof profileId === 'string' && getProfileIds().includes(profileId);
}

function getProfileSignatures(protocol, variant) {
  const slots = getEntry(protocol, variant, loadBankSync());
  if (!slots) {
    throw new BankError(`signature not found: ${protocol}#${variant}`, { status: 400 });
  }
  return slots;
}

module.exports = {
  getProfileSignatures,
  getProfileIds,
  getDefaultProfileId,
  getProfilesCatalog,
  refreshCatalog,
  isKnownProfile,
};

Object.defineProperty(module.exports, 'DEFAULT_PROFILE_ID', {
  enumerable: true,
  get() {
    return getDefaultProfileId() || 'dns';
  },
});
