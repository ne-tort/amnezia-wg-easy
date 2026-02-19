'use strict';

const { execSync } = require('node:child_process');

const TABLE = 'inet amnezia_wg';
const DISPATCH_CHAIN = 'forward_awg0';
const CHAIN_PREFIX = 'client_';

function nft(args) {
  execSync(`nft ${args}`, { stdio: ['pipe', 'pipe', 'pipe'] });
}

/**
 * Escapes a string for nft (avoid injection). CIDR/addresses and port ranges only.
 */
function escapeNft(s) {
  if (typeof s !== 'string') return '';
  return s.replace(/[^0-9a-fA-F.:\/\-\s]/g, '');
}

/**
 * Applies per-client firewall rules using nftables.
 * @param {Object} descriptor - { clients, globalRules, profileRules }
 * @returns {boolean}
 */
function apply(descriptor) {
  const { clients, globalRules, profileRules } = descriptor;
  try {
    nft(`delete table ${TABLE}`);
  } catch (_) {}
  nft(`add table ${TABLE}`);
  nft(`add chain ${TABLE} ${DISPATCH_CHAIN} '{ type filter hook forward priority -100; policy accept; }'`);
  nft(`add chain ${TABLE} ${DISPATCH_CHAIN}_dispatch`);
  nft(`add rule ${TABLE} ${DISPATCH_CHAIN} iifname "awg0" jump ${DISPATCH_CHAIN}_dispatch`);
  nft(`add rule ${TABLE} ${DISPATCH_CHAIN} accept`);

  clients.forEach((client, index) => {
    const chain = `${CHAIN_PREFIX}${index}`;
    nft(`add chain ${TABLE} ${chain}`);
    const profileRulesList = client.rule_profile_id ? (profileRules[client.rule_profile_id] || []) : [];
    const rules = [...globalRules, ...profileRulesList].sort((a, b) => (a.sort_order || 0) - (b.sort_order || 0));
    for (const r of rules) {
      const dest = r.destination_cidr ? escapeNft(r.destination_cidr).trim() : '';
      const proto = (r.protocol && escapeNft(r.protocol).toLowerCase()) || '';
      const dport = r.port_range ? escapeNft(r.port_range).trim() : '';
      const target = r.action === 'deny' ? 'drop' : 'accept';
      const parts = [];
      if (dest) parts.push(`ip daddr ${dest}`);
      if (proto === 'tcp' || proto === 'udp') {
        if (dport) parts.push(`${proto} dport ${dport}`);
      } else if (proto) {
        parts.push(`ip protocol ${proto}`);
      }
      if (parts.length) {
        nft(`add rule ${TABLE} ${chain} ${parts.join(' ')} ${target}`);
      } else {
        nft(`add rule ${TABLE} ${chain} ${target}`);
      }
    }
    nft(`add rule ${TABLE} ${chain} accept`);
  });

  clients.forEach((client, index) => {
    const addr = client.address;
    if (addr) {
      const safeAddr = escapeNft(addr).trim();
      if (safeAddr) nft(`add rule ${TABLE} ${DISPATCH_CHAIN}_dispatch ip saddr ${safeAddr} jump ${CHAIN_PREFIX}${index}`);
    }
  });
  nft(`add rule ${TABLE} ${DISPATCH_CHAIN}_dispatch accept`);

  return true;
}

/**
 * Removes our table (no per-client rules).
 */
function clear() {
  try {
    nft(`delete table ${TABLE}`);
  } catch (_) {}
}

module.exports = { apply, clear };
