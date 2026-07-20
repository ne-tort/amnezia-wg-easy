'use strict';

/**
 * Shared sidecar install validation: ports, SNI demux, cert reuse.
 * Returns { ok: true } or { ok: false, fieldErrors: Record<string,string>, code?: string }.
 */

const config = require('../config');
const portPlan = require('./portPlan');
const tlsMaterial = require('./tlsMaterial');

const PANEL_CERT_CONFLICT_MSG = 'Cannot reuse panel certificate on the same public port as panel HTTPS';

function errField(field, message, code) {
  return { ok: false, fieldErrors: { [field]: message }, code };
}

function mergeErrors(...parts) {
  /** @type {Record<string, string>} */
  const fieldErrors = {};
  let code;
  for (const p of parts) {
    if (!p || p.ok !== false) continue;
    Object.assign(fieldErrors, p.fieldErrors || {});
    if (p.code) code = p.code;
  }
  if (!Object.keys(fieldErrors).length) return { ok: true };
  return { ok: false, fieldErrors, code };
}

function panelHttpsPort() {
  return parseInt(String(config.PANEL_HTTPS_PORT || '443'), 10);
}

function validatePanelCertConflict(certSource, publicPort) {
  if (certSource !== 'panel') return { ok: true };
  const panelPort = panelHttpsPort();
  const pub = parseInt(String(publicPort), 10);
  if (Number.isFinite(panelPort) && pub === panelPort) {
    return errField('certSource', PANEL_CERT_CONFLICT_MSG, 'CERT_PORT_CONFLICT');
  }
  return { ok: true };
}

function validateManualCertFields(certSource, body = {}) {
  if (certSource === 'manual_pem') {
    const certPem = String(body.certPem || body.cert_pem || '').trim();
    const keyPem = String(body.keyPem || body.key_pem || '').trim();
    if (!certPem || !keyPem) {
      return errField('certSource', 'Certificate and private key PEM are required', 'CERT_PEM_MISSING');
    }
  }
  if (certSource === 'manual_path') {
    const certPath = String(body.certPath || body.cert_path || '').trim();
    const keyPath = String(body.keyPath || body.key_path || '').trim();
    if (!certPath || !keyPath) {
      return errField('certSource', 'Certificate and key file paths are required', 'CERT_PATH_MISSING');
    }
  }
  return { ok: true };
}

function validateMasqueradeUrl(url) {
  const raw = String(url || '').trim();
  if (!raw) return { ok: true };
  try {
    const u = new URL(raw);
    if (u.protocol !== 'https:') {
      return errField('masqueradeUrl', 'Masquerade URL must use https://', 'HYSTERIA_BAD_MASQUERADE');
    }
    if (!u.hostname) {
      return errField('masqueradeUrl', 'Masquerade URL must include a hostname', 'HYSTERIA_BAD_MASQUERADE');
    }
    return { ok: true };
  } catch {
    return errField('masqueradeUrl', 'Invalid masquerade URL', 'HYSTERIA_BAD_MASQUERADE');
  }
}

function validateMieru(body = {}) {
  const fieldErrors = {};
  const tcp = body.enableTcp !== false && body.enableTcp !== '0';
  const udp = body.enableUdp === true || body.enableUdp === '1' || body.enableUdp === 1;
  const legacyProto = String(body.protocol || '').toUpperCase();
  const tcpOn = tcp || legacyProto === 'TCP' || (!legacyProto && !udp);
  const udpOn = udp || legacyProto === 'UDP';
  if (!tcpOn && !udpOn) {
    fieldErrors.protocol = 'Enable at least one of TCP or UDP';
  }
  const tcpPort = parseInt(String(body.tcpPublicPort != null ? body.tcpPublicPort : body.publicPort || ''), 10);
  const udpPort = parseInt(String(body.udpPublicPort != null ? body.udpPublicPort : body.publicPort || ''), 10);
  if (tcpOn && (!Number.isFinite(tcpPort) || tcpPort < 1 || tcpPort > 65535)) {
    fieldErrors.tcpPublicPort = 'Invalid TCP port (1–65535)';
  }
  if (udpOn && (!Number.isFinite(udpPort) || udpPort < 1 || udpPort > 65535)) {
    fieldErrors.udpPublicPort = 'Invalid UDP port (1–65535)';
  }
  if (Object.keys(fieldErrors).length) return { ok: false, fieldErrors };
  return { ok: true, tcpOn, udpOn, tcpPort, udpPort };
}

function validateSniDemux(serviceId, sni, publicPort) {
  try {
    portPlan.assertSniConflict(serviceId, sni, publicPort);
    return { ok: true };
  } catch (err) {
    return errField('sni', err.message, err.code || 'SNI_CONFLICT');
  }
}

function validatePublicPortConflict(ports, { allowNginx = true } = {}) {
  const unique = [...new Set(ports.filter((p) => Number.isFinite(p)))];
  if (unique.length !== ports.filter((p) => Number.isFinite(p)).length) {
    return errField('publicPort', 'Public ports must differ between services', 'PORT_CONFLICT');
  }
  const panelPort = panelHttpsPort();
  for (const p of unique) {
    if (p === panelPort) {
      return errField('publicPort', `Port ${p} is used by panel HTTPS`, 'PORT_PANEL_CONFLICT');
    }
  }
  return { ok: true, ports: unique };
}

function validateNaive(body = {}) {
  const sni = tlsMaterial.normalizeHostname(body.sni || '');
  if (!sni || !tlsMaterial.isFqdn(sni)) {
    return errField('sni', 'Naive requires a real domain (FQDN)', 'NAIVE_BAD_SNI');
  }
  const publicPort = parseInt(String(body.publicPort != null ? body.publicPort : '443'), 10);
  if (!Number.isFinite(publicPort) || publicPort < 1 || publicPort > 65535) {
    return errField('publicPort', 'Invalid public port (1–65535)', 'NAIVE_BAD_PUBLIC_PORT');
  }
  const probe = String(body.probeResistanceDomain || body.probe_resistance_domain || '').trim();
  if (probe && probe.toLowerCase() === sni) {
    return errField('probeResistanceDomain', 'Probe resistance domain should differ from Naive SNI', 'NAIVE_PROBE_SNI');
  }
  return mergeErrors(
    { ok: true },
    validateSniDemux('naive', sni, publicPort),
    validatePublicPortConflict([publicPort]),
  );
}

function validateHysteria(body = {}) {
  const publicPort = parseInt(String(body.publicPort != null ? body.publicPort : '443'), 10);
  if (!Number.isFinite(publicPort) || publicPort < 1 || publicPort > 65535) {
    return errField('publicPort', 'Invalid UDP port (1–65535)', 'HYSTERIA_BAD_PUBLIC_PORT');
  }
  const certSource = String(body.certSource || body.cert_source || 'self_signed').trim().toLowerCase();
  const sni = tlsMaterial.normalizeHostname(body.sni || '');
  // SNI required only for Let's Encrypt; self_signed/panel may omit (bare IP)
  if (certSource === 'issue_le') {
    if (!sni || !tlsMaterial.isFqdn(sni)) {
      return errField('sni', 'Let\'s Encrypt requires a valid FQDN in SNI', 'HYSTERIA_BAD_SNI');
    }
  }
  if (certSource === 'panel') {
    const panel = tlsMaterial.panelCertDomain();
    if (!panel) {
      return errField('certSource', 'Panel certificate domain (PANEL_DOMAIN FQDN) is not configured', 'CERT_PANEL_DOMAIN_MISSING');
    }
  }
  const masq = body.masqueradeUrl != null ? body.masqueradeUrl : body.masquerade_url;
  // Hysteria is UDP — panel cert on same port as panel HTTPS is allowed
  return mergeErrors(
    { ok: true, publicPort, certSource },
    validateManualCertFields(certSource, body),
    validateMasqueradeUrl(masq),
  );
}

function validateXray(body = {}) {
  const security = String(body.security || 'reality').toLowerCase();
  const publicPort = parseInt(String(body.publicPort != null ? body.publicPort : '443'), 10);
  if (!Number.isFinite(publicPort) || publicPort < 1 || publicPort > 65535) {
    return errField('publicPort', 'Invalid public port (1–65535)', 'XRAY_BAD_PUBLIC_PORT');
  }
  const sni = tlsMaterial.normalizeHostname(body.sni || '');
  const certSource = String(body.certSource || body.cert_source || 'self_signed').trim().toLowerCase();

  if (security === 'reality' && !sni) {
    return errField('sni', 'SNI is required for Reality', 'XRAY_SNI_REQUIRED');
  }
  if (security === 'tls') {
    if (certSource === 'issue_le') {
      if (!sni || !tlsMaterial.isFqdn(sni)) {
        return errField('sni', 'Let\'s Encrypt requires a valid FQDN in SNI', 'XRAY_BAD_SNI');
      }
    }
    if (certSource === 'panel') {
      const panel = tlsMaterial.panelCertDomain();
      if (!panel) {
        return errField('certSource', 'Panel certificate domain (PANEL_DOMAIN FQDN) is not configured', 'CERT_PANEL_DOMAIN_MISSING');
      }
    }
  }

  const parts = [
    { ok: true, security, publicPort },
    security === 'tls' ? validatePanelCertConflict(certSource, publicPort) : { ok: true },
    security === 'tls' ? validateManualCertFields(certSource, body) : { ok: true },
  ];

  if (security === 'reality' || (security === 'tls' && sni)) {
    const demuxPort = panelHttpsPort();
    if (publicPort === demuxPort && sni) {
      parts.push(validateSniDemux('xray', sni, publicPort));
    }
  }

  return mergeErrors(...parts);
}

/**
 * @param {'mieru'|'hysteria'|'naive'|'xray'} service
 * @param {Record<string, unknown>} body
 */
function validateInstall(service, body = {}) {
  switch (service) {
    case 'mieru': return validateMieru(body);
    case 'hysteria': return validateHysteria(body);
    case 'naive': return validateNaive(body);
    case 'xray': return validateXray(body);
    default:
      return { ok: false, fieldErrors: { _form: `Unknown service ${service}` } };
  }
}

module.exports = {
  validateInstall,
  validateMieru,
  validateNaive,
  validateHysteria,
  validateXray,
  validateSniDemux,
  validatePublicPortConflict,
  validatePanelCertConflict,
  validateManualCertFields,
  validateMasqueradeUrl,
  mergeErrors,
  PANEL_CERT_CONFLICT_MSG,
};
