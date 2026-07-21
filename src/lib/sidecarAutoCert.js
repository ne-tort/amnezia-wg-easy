'use strict';

/**
 * Resolve «Создать автоматически» sidecar SSL certificates.
 */

const SSL_CERT_AUTO = '__auto__';

function isAutoCertId(id) {
  return String(id || '').trim() === SSL_CERT_AUTO;
}

/**
 * @param {{ service: 'xray'|'hysteria', security?: string, sni?: string, address?: string, email?: string }} opts
 * @returns {Promise<{ id: string, sni?: string, type?: string }>}
 */
/** Neutral mDNS-style label for auto self-signed (no protocol brand in CN/SNI). */
const AUTO_SELF_SIGNED_HOST = 'server.local';

/**
 * Pick a demux-friendly cert CN/SNI. Bare IPs need a hostname for stream demux.
 */
function autoCertDomain(sni, address) {
  const tlsMaterial = require('./tlsMaterial');
  const portPlan = require('./portPlan');
  let domain = sni || tlsMaterial.normalizeHostname(address) || AUTO_SELF_SIGNED_HOST;
  if (portPlan.isIpLiteral(domain) || domain === 'localhost') {
    domain = AUTO_SELF_SIGNED_HOST;
  }
  return domain;
}

async function resolveAutoCert(opts = {}) {
  const sslManager = require('./sslManager');
  const tlsMaterial = require('./tlsMaterial');
  const service = String(opts.service || '').toLowerCase();
  const security = String(opts.security || 'reality').toLowerCase();
  const address = String(opts.address || '').trim();
  let sni = tlsMaterial.normalizeHostname(opts.sni || '');

  if (service === 'hysteria') {
    const domain = autoCertDomain(sni, address);
    const row = await sslManager.createSelfSigned({ domain, label: domain });
    return { id: row.id, sni: row.sni || row.domain, type: row.type };
  }

  if (service === 'xray' && security === 'tls') {
    const domain = autoCertDomain(sni, address);
    const row = await sslManager.createSelfSigned({ domain, label: domain });
    return { id: row.id, sni: row.sni || row.domain, type: row.type };
  }

  if (service === 'xray' && security === 'reality') {
    if (!sni) {
      throw Object.assign(new Error('SNI is required for auto Reality certificate'), {
        status: 400,
        code: 'XRAY_SNI_REQUIRED',
      });
    }
    const row = await sslManager.createReality({ sni, label: sni, reuse: true });
    return { id: row.id, sni: row.sni || row.domain, type: row.type };
  }

  throw Object.assign(new Error(`Auto certificate not supported for ${service}/${security}`), {
    status: 400,
    code: 'SSL_AUTO_UNSUPPORTED',
  });
}

/**
 * Replace __auto__ with a real certificate id before enable.
 * @param {Record<string, unknown>} opts
 * @param {'xray'|'hysteria'} service
 */
async function resolveOptsSslCert(opts, service) {
  const id = String(opts.sslCertId || opts.ssl_cert_id || '').trim();
  if (!isAutoCertId(id)) return opts;
  const resolved = await resolveAutoCert({
    service,
    security: opts.security,
    sni: opts.sni,
    address: opts.address,
    email: opts.email,
  });
  return {
    ...opts,
    sslCertId: resolved.id,
    sni: resolved.sni || opts.sni,
  };
}

module.exports = {
  SSL_CERT_AUTO,
  AUTO_SELF_SIGNED_HOST,
  isAutoCertId,
  resolveAutoCert,
  resolveOptsSslCert,
};
