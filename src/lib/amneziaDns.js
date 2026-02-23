'use strict';

const { spawn } = require('node:child_process');
const fs = require('node:fs');
const config = require('../config');

const DNSMASQ_CONF_BASE = '/etc/dnsmasq-amnezia.conf';
const DNSMASQ_CONF_RUNTIME = '/tmp/dnsmasq-amnezia.conf';
const AMNEZIA_DNS_UPSTREAM = '172.29.172.254';

let dnsmasqChild = null;

/**
 * Returns true when Amnezia DNS (server DNS) is available: WG_DEFAULT_DNS equals VPN gateway and not disabled.
 * Used by API to expose serverCapabilities.amneziaDnsAvailable and by config build to choose DNS line.
 * @returns {boolean}
 */
function isAmneziaDnsAvailable() {
  const disabled = (process.env.AMNEZIA_DNS_ENABLE || '').toLowerCase();
  if (['0', 'false', 'no', 'off', 'disabled'].includes(disabled)) return false;
  const addr = config.WG_DEFAULT_ADDRESS || '10.8.0.x';
  const gateway = addr.replace(/x$/, '1');
  const dns = (config.WG_DEFAULT_DNS || '').trim();
  return Boolean(dns && dns === gateway);
}

/**
 * Writes runtime dnsmasq config with listen-address=gateway,127.0.0.1.
 * @param {string} gateway - e.g. 10.8.0.1
 * @returns {string} path to written config
 */
function writeDnsmasqConf(gateway) {
  const base = fs.readFileSync(DNSMASQ_CONF_BASE, 'utf8');
  const lines = base
    .split('\n')
    .filter((line) => !line.trimStart().startsWith('listen-address='));
  const head = [
    `# Runtime: listen on VPN gateway and localhost (written by amneziaDns)`,
    `listen-address=${gateway}`,
    'listen-address=127.0.0.1',
    '',
  ].join('\n');
  const body = lines.join('\n');
  fs.writeFileSync(DNSMASQ_CONF_RUNTIME, head + body, 'utf8');
  return DNSMASQ_CONF_RUNTIME;
}

/**
 * Starts dnsmasq for Amnezia DNS when WG_DEFAULT_DNS equals VPN gateway.
 * Must be called after WireGuard interface (awg0) is up so that the gateway address exists.
 * Forwards client DNS (10.8.0.1:53) to amnezia-dns container (Unbound) at 172.29.172.254.
 * @returns {import('node:child_process').ChildProcess|null} dnsmasq child or null if not started
 */
function startAmneziaDns() {
  if (dnsmasqChild) return dnsmasqChild;

  if (!isAmneziaDnsAvailable()) return null;

  const addr = config.WG_DEFAULT_ADDRESS || '10.8.0.x';
  const gateway = addr.replace(/x$/, '1');

  let confPath = DNSMASQ_CONF_BASE;
  try {
    confPath = writeDnsmasqConf(gateway);
  } catch (err) {
    if (process.env.NODE_ENV !== 'test') {
      // eslint-disable-next-line no-console
      console.error('Amnezia DNS: could not write runtime config, using base:', err.message);
    }
  }

  try {
    dnsmasqChild = spawn('dnsmasq', ['-C', confPath, '-k'], {
      stdio: 'ignore',
      detached: false,
    });
    dnsmasqChild.on('error', (err) => {
      if (process.env.NODE_ENV !== 'test') {
        // eslint-disable-next-line no-console
        console.error('Amnezia DNS (dnsmasq) error:', err.message);
      }
    });
    dnsmasqChild.on('exit', (code, signal) => {
      if (code !== null && code !== 0 && process.env.NODE_ENV !== 'test') {
        // eslint-disable-next-line no-console
        console.error('Amnezia DNS (dnsmasq) exited:', code, signal);
      }
      dnsmasqChild = null;
    });
    dnsmasqChild.unref();
    return dnsmasqChild;
  } catch (err) {
    if (process.env.NODE_ENV !== 'test') {
      // eslint-disable-next-line no-console
      console.error('Amnezia DNS (dnsmasq) start failed:', err.message);
    }
    return null;
  }
}

/**
 * Stops dnsmasq if it was started by startAmneziaDns.
 */
function stopAmneziaDns() {
  if (dnsmasqChild) {
    try {
      dnsmasqChild.kill('SIGTERM');
    } catch (_) {}
    dnsmasqChild = null;
  }
}

module.exports = { isAmneziaDnsAvailable, startAmneziaDns, stopAmneziaDns };
