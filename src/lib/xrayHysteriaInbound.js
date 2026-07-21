'use strict';

/**
 * Hysteria2 inbound for Xray-core (protocol: hysteria + network: hysteria).
 * Shared with VLESS in the same server.json / process.
 *
 * Obfuscation: Xray maps official Hy2 salamander/gecko to finalmask.
 * Gecko (Hy2 2.9.2+) = salamander + packetSize (Xray ≥ ~v26.5 / finalmask #6198).
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
 * @param {string} [opts.obfsType] - '' | salamander | gecko
 * @param {number|string} [opts.obfsGeckoMin]
 * @param {number|string} [opts.obfsGeckoMax]
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

  const obfsType = String(opts.obfsType || '').trim().toLowerCase();
  const password = String(
    opts.salamanderPassword
    || opts.obfsPassword
    || '',
  ).trim();
  if (password && (obfsType === 'salamander' || obfsType === 'gecko' || !obfsType)) {
    /** @type {Record<string, unknown>} */
    const settings = { password };
    if (obfsType === 'gecko') {
      const min = Number(opts.obfsGeckoMin != null ? opts.obfsGeckoMin : 512);
      const max = Number(opts.obfsGeckoMax != null ? opts.obfsGeckoMax : 1200);
      const lo = Number.isFinite(min) && min > 0 ? Math.floor(min) : 512;
      const hi = Number.isFinite(max) && max >= lo ? Math.min(2048, Math.floor(max)) : 1200;
      // Non-empty packetSize enables Gecko on top of Salamander (Xray finalmask docs).
      settings.packetSize = `${lo}-${hi}`;
    }
    streamSettings.finalmask = {
      udp: [{ type: 'salamander', settings }],
    };
  } else if (password) {
    streamSettings.finalmask = {
      udp: [{ type: 'salamander', settings: { password } }],
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
