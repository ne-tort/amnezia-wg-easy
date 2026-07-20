'use strict';

/**
 * Shared sidecar install validation: ports, SNI demux, cert reuse.
 * Returns { ok: true } or { ok: false, fieldErrors: Record<string,string>, code?: string }.
 */

const config = require('../config');
const portPlan = require('./portPlan');
const tlsMaterial = require('./tlsMaterial');

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
  if (udpOn && (!Number.isFinite(udpPort) || udpPort < 1 || udpPort > 65535))  {
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
  const panelPort = parseInt(String(config.PANEL_HTTPS_PORT || '443'), 10);
  for (const p of unique) {
    if (p === panelPort) {
      return errField('publicPort', `Port ${p} is used by panel HTTPS`, 'PORT_PANEL_CONFLICT');
    }
  }
  return { ok: true, ports: unique };
}

function validateNaive(body = {}) {
  const sni = String(body.sni || '').trim().toLowerCase();
  if (!sni || !tlsMaterial.isFqdn(sni)) {
    return errField('sni', 'Naive SNI must be a valid FQDN', 'NAIVE_BAD_SNI');
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
  return { ok: true, publicPort };
}

function validateXray(body = {}) {
  const security = String(body.security || 'reality').toLowerCase();
  const publicPort = parseInt(String(body.publicPort != null ? body.publicPort : '443'), 10);
  if (!Number.isFinite(publicPort) || publicPort < 1 || publicPort > 65535) {
    return errField('publicPort', 'Invalid public port (1–65535)', 'XRAY_BAD_PUBLIC_PORT');
  }
  const sni = String(body.sni || '').trim();
  if (security === 'reality' && !sni) {
    return errField('sni', 'SNI is required for Reality', 'XRAY_SNI_REQUIRED');
  }
  if (security === 'tls' && body.certSource === 'panel') {
    try {
      tlsMaterial.assertPanelCertReuseAllowed('xray', publicPort);
    } catch (err) {
      return errField('publicPort', err.message, err.code);
    }
  }
  if (security === 'reality' || security === 'tls') {
    const demuxPort = parseInt(String(config.PANEL_HTTPS_PORT || '443'), 10);
    if (publicPort === demuxPort && sni) {
      return mergeErrors(validateSniDemux('xray', sni, publicPort));
    }
  }
  return { ok: true, security, publicPort };
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
  mergeErrors,
};
