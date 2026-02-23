'use strict';

const { execSync } = require('node:child_process');
const { sanitizeRule } = require('./validate');

const ZONE = 'amnezia_wg';

function fw(args) {
  execSync(`firewall-cmd ${args}`, { stdio: ['pipe', 'pipe', 'pipe'] });
}

function escape(s) {
  if (typeof s !== 'string') return '';
  return s.replace(/"/g, '\\"').replace(/[^0-9a-fA-F.:\/\-\s]/g, '');
}

/**
 * Applies per-client firewall rules using firewalld rich rules.
 * @param {Object} descriptor - { clients, globalRules, profileRules }
 * @returns {boolean}
 */
function apply(descriptor) {
  const { clients, globalRules, profileRules } = descriptor;
  try {
    const out = execSync(`firewall-cmd --permanent --zone=${ZONE} --list-rich-rules 2>/dev/null || true`, { encoding: 'utf8' });
    const lines = (out || '').trim().split('\n').filter(Boolean);
    for (const line of lines) {
      try {
        fw(`--permanent --zone=${ZONE} --remove-rich-rule="${line.replace(/"/g, '\\"')}"`);
      } catch (_) {}
    }
  } catch (_) {}

  try {
    fw(`--permanent --new-zone=${ZONE} 2>/dev/null || true`);
  } catch (_) {}
  try {
    fw(`--permanent --zone=${ZONE} --set-target=ACCEPT`);
  } catch (_) {}

  const bySortOrder = (a, b) => (a.sort_order ?? 0) - (b.sort_order ?? 0) || (a.id - b.id);
  for (const client of clients) {
    const src = client.address && client.address.trim();
    if (!src) continue;
    const safeSrc = escape(src).trim();
    if (!safeSrc) continue;
    const clientRulesList = (client.clientRules || []).slice().sort(bySortOrder);
    const profileRulesList = (client.rule_profile_id ? (profileRules[client.rule_profile_id] || []) : []).slice().sort(bySortOrder);
    const globalRulesSorted = globalRules.slice().sort(bySortOrder);
    const rules = [...clientRulesList, ...profileRulesList, ...globalRulesSorted];
    for (const r of rules) {
      const safe = sanitizeRule(r);
      const dest = safe.destination_cidr ? escape(safe.destination_cidr).trim() : '';
      const proto = (safe.protocol && escape(safe.protocol).toLowerCase()) || '';
      const dport = safe.port_range ? escape(safe.port_range).trim() : '';
      const target = r.action === 'deny' ? 'drop' : 'accept';

      if (dport && proto !== 'tcp' && proto !== 'udp') {
        // * Port set but protocol empty/other: add two rich-rules (tcp and udp) so port is enforced.
        let base = `rule family="ipv4" source address="${safeSrc}"`;
        if (dest) base += ` destination address="${dest}"`;
        try {
          fw(`--permanent --zone=${ZONE} --add-rich-rule="${base} tcp port="${dport}" ${target}"`);
        } catch (e) {
          if (process.env.NODE_ENV !== 'test') console.error('firewalld add-rich-rule:', e.message);
        }
        try {
          fw(`--permanent --zone=${ZONE} --add-rich-rule="${base} udp port="${dport}" ${target}"`);
        } catch (e) {
          if (process.env.NODE_ENV !== 'test') console.error('firewalld add-rich-rule:', e.message);
        }
      } else {
        let rule = `rule family="ipv4" source address="${safeSrc}"`;
        if (dest) rule += ` destination address="${dest}"`;
        if (proto === 'tcp' || proto === 'udp') {
          if (dport) rule += ` ${proto} port="${dport}"`;
        }
        rule += ` ${target}`;
        try {
          fw(`--permanent --zone=${ZONE} --add-rich-rule="${rule}"`);
        } catch (e) {
          if (process.env.NODE_ENV !== 'test') console.error('firewalld add-rich-rule:', e.message);
        }
      }
    }
  }

  try {
    fw('--reload');
  } catch (e) {
    if (process.env.NODE_ENV !== 'test') console.error('firewalld reload:', e.message);
    return false;
  }
  return true;
}

function clear() {
  try {
    fw(`--permanent --delete-zone=${ZONE}`);
    fw('--reload');
  } catch (_) {}
}

module.exports = { apply, clear };
