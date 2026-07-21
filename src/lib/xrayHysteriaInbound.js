'use strict';

/**
 * Hysteria2 inbound for Xray-core (protocol: hysteria + network: hysteria).
 * Shared with VLESS in the same server.json / process.
 */

/**
 * @param {object} opts
 * @param {number} opts.port - UDP listen port inside container
 * @param {Array<{auth: string, email?: string}>} opts.users
 * @param {string} [opts.sni]
 * @param {string} [opts.tlsCert]
 * @param {string} [opts.tlsKey]
 * @param {string} [opts.auth] - shared auth fallback when users empty
 * @param {string} [opts.up]
 * @param {string} [opts.down]
 * @param {number} [opts.udpIdleTimeout]
 * @param {object} [opts.masquerade]
 * @param {string} [opts.salamanderPassword]
 */
function buildHysteriaInbound(opts = {}) {
  const port = Number(opts.port);
  if (!Number.isFinite(port) || port < 1) {
    throw new Error('Hysteria inbound port required');
  }

  const users = Array.isArray(opts.users) && opts.users.length
    ? opts.users.map((u) => ({
      auth: String(u.auth || ''),
      email: String(u.email || u.name || ''),
    })).filter((u) => u.auth)
    : (opts.auth ? [{ auth: String(opts.auth), email: 'default' }] : []);

  if (!users.length) {
    throw new Error('Hysteria inbound requires at least one user auth');
  }

  /** @type {Record<string, unknown>} */
  const hysteriaSettings = {
    version: 2,
  };
  if (opts.udpIdleTimeout != null) hysteriaSettings.udpIdleTimeout = Number(opts.udpIdleTimeout);
  if (opts.up) hysteriaSettings.up = String(opts.up);
  if (opts.down) hysteriaSettings.down = String(opts.down);
  if (opts.masquerade && typeof opts.masquerade === 'object') {
    hysteriaSettings.masquerade = opts.masquerade;
  }

  /** @type {Record<string, unknown>} */
  const streamSettings = {
    network: 'hysteria',
    security: 'tls',
    hysteriaSettings,
    tlsSettings: {
      alpn: ['h3'],
    },
  };
  if (opts.sni) streamSettings.tlsSettings.serverName = opts.sni;
  if (opts.tlsCert && opts.tlsKey) {
    streamSettings.tlsSettings.certificates = [{
      certificateFile: opts.tlsCert,
      keyFile: opts.tlsKey,
    }];
  }
  if (opts.salamanderPassword) {
    streamSettings.finalmask = {
      udp: [{
        type: 'salamander',
        settings: { password: String(opts.salamanderPassword) },
      }],
    };
  }

  return {
    tag: 'hysteria-in',
    listen: '0.0.0.0',
    port,
    protocol: 'hysteria',
    settings: {
      version: 2,
      users,
    },
    streamSettings,
  };
}

module.exports = {
  buildHysteriaInbound,
};
