'use strict';

const db = require('../db');

const FIREWALL_BACKEND = (process.env.FIREWALL_BACKEND || 'nftables').toLowerCase();
const BACKENDS = { nftables: true, firewalld: true };

/**
 * Builds a backend-agnostic rules descriptor from DB.
 * Order: global rules first, then profile rules; first match wins; default ACCEPT.
 * @returns {{ clients: Array<{ address: string, rule_profile_id: number|null }>, globalRules: Array<Object>, profileRules: Object }}
 */
function buildDescriptor() {
  const clients = db.clients.getEnabledForWireGuard();
  const globalRules = db.globalFirewallRules.getAll();
  const profileRules = {};
  const profileIds = [...new Set(clients.map((c) => c.rule_profile_id).filter(Boolean))];
  for (const pid of profileIds) {
    profileRules[pid] = db.ipRules.getByProfileId(pid);
  }
  return {
    clients: clients.map((c) => ({
      address: (c.address && c.address.trim()) || null,
      rule_profile_id: c.rule_profile_id ?? null,
    })),
    globalRules,
    profileRules,
  };
}

/**
 * Applies firewall rules from DB using the configured backend (nftables or firewalld).
 * @returns {boolean} true if applied, false if skipped or failed
 */
function applyFirewall() {
  const descriptor = buildDescriptor();
  const hasProfile = descriptor.clients.some((c) => c.rule_profile_id != null);
  const hasGlobal = descriptor.globalRules.length > 0;
  if (!hasProfile && !hasGlobal) {
    try {
      const backend = getBackend();
      if (backend.clear) backend.clear();
    } catch (_) {}
    return true;
  }

  try {
    const backend = getBackend();
    return backend.apply(descriptor);
  } catch (err) {
    if (process.env.NODE_ENV !== 'test') {
      const name = BACKENDS[FIREWALL_BACKEND] ? FIREWALL_BACKEND : 'nftables';
      console.error(`Firewall apply failed (${name}):`, err.message);
    }
    return false;
  }
}

function getBackend() {
  const name = BACKENDS[FIREWALL_BACKEND] ? FIREWALL_BACKEND : 'nftables';
  if (name === 'firewalld') {
    return require('./firewalld');
  }
  return require('./nftables');
}

module.exports = { applyFirewall, buildDescriptor, getBackend };
