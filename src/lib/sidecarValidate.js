'use strict';

/**
 * Shared sidecar install validation: ports, SNI demux, cert reuse.
 * Returns { ok: true } or { ok: false, fieldErrors: Record<string,string>, code?: string }.
 */

const config = require('../config');
const portPlan = require('./portPlan');
const tlsMaterial = require('./tlsMaterial');
const xrayTransportSchema = require('./xrayTransportSchema');
const { SSL_CERT_AUTO } = require('./sidecarAutoCert');

const PANEL_CERT_CONFLICT_MSG = 'Cannot reuse panel certificate on the same public port as panel HTTPS or mirror stub';

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

function mirrorHttpsPort() {
  try {
    const m = portPlan.mirrorPublicPort();
    return m != null ? m : null;
  } catch {
    return null;
  }
}

/** Ports where panel/mirror TLS terminate on nginx — panel cert reuse is forbidden. */
function nginxTlsExclusivePorts() {
  const ports = new Set();
  const panel = panelHttpsPort();
  if (Number.isFinite(panel)) ports.add(panel);
  const mirror = mirrorHttpsPort();
  if (mirror != null && Number.isFinite(mirror)) ports.add(mirror);
  return [...ports];
}

function validatePanelCertConflict(certSource, publicPort) {
  if (certSource !== 'panel') return { ok: true };
  const pub = parseInt(String(publicPort), 10);
  if (!Number.isFinite(pub)) return { ok: true };
  for (const p of nginxTlsExclusivePorts()) {
    if (pub === p) {
      return errField('certSource', PANEL_CERT_CONFLICT_MSG, 'CERT_PORT_CONFLICT');
    }
  }
  return { ok: true };
}

/**
 * TCP public ports that must not collide with exclusive nginx TLS publishes
 * (panel HTTPS and/or dedicated mirror stub). Demux-capable services may share
 * panel port when SNI is set — pass { allowPanelDemux: true }.
 */
function validateTcpHostPortConflict(ports, { allowPanelDemux = false } = {}) {
  const unique = [...new Set(ports.filter((p) => Number.isFinite(p)))];
  if (unique.length !== ports.filter((p) => Number.isFinite(p)).length) {
    return errField('publicPort', 'Public ports must differ between services', 'PORT_CONFLICT');
  }
  const panelPort = panelHttpsPort();
  const mirrorPort = mirrorHttpsPort();
  for (const p of unique) {
    if (!allowPanelDemux && p === panelPort) {
      return errField('publicPort', `Port ${p} is used by panel HTTPS`, 'PORT_PANEL_CONFLICT');
    }
    if (mirrorPort != null && p === mirrorPort) {
      return errField('publicPort', `Port ${p} is used by the mirror stub`, 'PORT_MIRROR_CONFLICT');
    }
  }
  return { ok: true, ports: unique };
}

function validatePublicPortConflict(ports, { allowNginx = true } = {}) {
  return validateTcpHostPortConflict(ports, { allowPanelDemux: false });
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
  if (tcpOn && Number.isFinite(tcpPort)) {
    const portCheck = validateTcpHostPortConflict([tcpPort], { allowPanelDemux: false });
    if (!portCheck.ok) {
      const msg = (portCheck.fieldErrors && (portCheck.fieldErrors.publicPort || portCheck.fieldErrors.tcpPublicPort))
        || 'TCP port conflicts with panel/mirror';
      fieldErrors.tcpPublicPort = msg;
    }
  }
  if (Object.keys(fieldErrors).length) return { ok: false, fieldErrors };
  return { ok: true, tcpOn, udpOn, tcpPort, udpPort };
}

function validateSniDemux(serviceId, sni, publicPort, opts = {}) {
  try {
    portPlan.assertSniConflict(serviceId, sni, publicPort, opts);
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

function validateSslCertId(body, filterKey) {
  const id = String(body.sslCertId || body.ssl_cert_id || '').trim();
  if (!id) {
    return errField('sslCertId', 'Certificate is required', 'SSL_CERT_REQUIRED');
  }
  if (id === SSL_CERT_AUTO) {
    return { ok: true, cert: null, auto: true };
  }
  const sslManager = require('./sslManager');
  const row = sslManager.getRaw(id);
  if (!row) {
    return errField('sslCertId', 'Certificate not found', 'SSL_NOT_FOUND');
  }
  const allowed = sslManager.SIDECAR_CERT_FILTERS[filterKey] || [];
  if (!allowed.includes(row.type)) {
    return errField('sslCertId', `Certificate type «${row.type}» is not allowed`, 'SSL_CERT_TYPE');
  }
  return { ok: true, cert: row };
}

function validateNaive(body = {}) {
  const publicPort = parseInt(String(body.publicPort != null ? body.publicPort : '443'), 10);
  if (!Number.isFinite(publicPort) || publicPort < 1 || publicPort > 65535) {
    return errField('publicPort', 'Invalid public port (1–65535)', 'NAIVE_BAD_PUBLIC_PORT');
  }
  const tcpOn = body.enableTcp != null
    ? (body.enableTcp === true || body.enableTcp === '1' || body.enableTcp === 'true')
    : (body.tcpEnabled != null
      ? (body.tcpEnabled === true || body.tcpEnabled === '1' || body.tcpEnabled === 'true')
      : true);
  const quicOn = body.enableQuic != null
    ? (body.enableQuic === true || body.enableQuic === '1' || body.enableQuic === 'true')
    : (body.quicEnabled != null
      ? (body.quicEnabled === true || body.quicEnabled === '1' || body.quicEnabled === 'true')
      : false);
  if (!tcpOn && !quicOn) {
    return errField('enableTcp', 'Enable TCP and/or QUIC', 'NAIVE_TRANSPORT_REQUIRED');
  }
  const certCheck = validateSslCertId(body, 'naive');
  if (!certCheck.ok) return certCheck;
  if (certCheck.auto) {
    return errField('sslCertId', 'Select a Let\'s Encrypt FQDN certificate', 'SSL_CERT_REQUIRED');
  }
  const sni = tlsMaterial.normalizeHostname(certCheck.cert.sni || certCheck.cert.domain || body.sni || '');
  if (!sni || !tlsMaterial.isFqdn(sni)) {
    return errField('sni', 'Naive requires a Let\'s Encrypt FQDN certificate', 'NAIVE_BAD_SNI');
  }
  const probe = String(body.probeResistanceDomain || body.probe_resistance_domain || '').trim();
  if (probe && probe.toLowerCase() === sni) {
    return errField('probeResistanceDomain', 'Probe resistance domain should differ from Naive SNI', 'NAIVE_PROBE_SNI');
  }
  const parts = [
    { ok: true, sni, sslCertId: certCheck.cert.id, tcpEnabled: tcpOn, quicEnabled: quicOn },
  ];
  if (tcpOn) {
    parts.push(validateSniDemux('naive', sni, publicPort, { sslCertId: certCheck.cert.id }));
  }
  if (certCheck.cert.is_panel) {
    parts.push(validatePanelCertConflict('panel', publicPort));
  }
  return mergeErrors(...parts);
}

function validateHysteria(body = {}) {
  const publicPort = parseInt(String(body.publicPort != null ? body.publicPort : '443'), 10);
  if (!Number.isFinite(publicPort) || publicPort < 1 || publicPort > 65535) {
    return errField('publicPort', 'Invalid UDP port (1–65535)', 'HYSTERIA_BAD_PUBLIC_PORT');
  }
  const sslId = String(body.sslCertId || body.ssl_cert_id || '').trim();
  const masq = body.masqueradeUrl != null ? body.masqueradeUrl : body.masquerade_url;
  const obfsType = String(body.obfsType != null ? body.obfsType : body.obfs_type || '').trim().toLowerCase();
  // Obfs password is auto-generated on enable when salamander/gecko is selected.
  void body.obfsPassword;
  void body.obfs_password;
  if (obfsType && obfsType !== 'salamander' && obfsType !== 'gecko' && obfsType !== '') {
    return errField('obfsType', 'Unsupported obfuscation type', 'HYSTERIA_BAD_OBFS');
  }
  if (sslId) {
    if (sslId === SSL_CERT_AUTO) {
      return mergeErrors(
        { ok: true, publicPort, sslCertId: SSL_CERT_AUTO, autoCert: true },
        validateMasqueradeUrl(masq),
      );
    }
    const certCheck = validateSslCertId(body, 'hysteria');
    if (!certCheck.ok) return certCheck;
    return mergeErrors(
      { ok: true, publicPort, sslCertId: certCheck.cert.id },
      validateMasqueradeUrl(masq),
    );
  }
  const certSource = String(body.certSource || body.cert_source || 'self_signed').trim().toLowerCase();
  const sni = tlsMaterial.normalizeHostname(body.sni || '');
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
  return mergeErrors(
    { ok: true, publicPort, certSource },
    validateManualCertFields(certSource, body),
    validateMasqueradeUrl(masq),
  );
}

function validateXray(body = {}) {
  const xrayVlessConfig = require('./xrayVlessConfig');
  const security = xrayVlessConfig.normalizeSecurity(body.security || 'reality');
  const network = xrayVlessConfig.normalizeNetwork(body.network || 'tcp');
  const publicPort = parseInt(String(body.publicPort != null ? body.publicPort : '443'), 10);
  if (!Number.isFinite(publicPort) || publicPort < 1 || publicPort > 65535) {
    return errField('publicPort', 'Invalid public port (1–65535)', 'XRAY_BAD_PUBLIC_PORT');
  }
  if (!xrayTransportSchema.allowedSecurities(network).includes(security)) {
    return errField('network', `Security «${security}» is not allowed for transport «${network}»`, 'XRAY_TRANSPORT_SECURITY');
  }
  const transportSettings = body.transportSettings != null ? body.transportSettings : body.transport_settings;
  if (transportSettings && typeof transportSettings === 'object') {
    const tv = xrayTransportSchema.validateTransportSettings(network, transportSettings);
    if (!tv.ok) return tv;
  }
  const sslId = String(body.sslCertId || body.ssl_cert_id || '').trim();
  const sni = tlsMaterial.normalizeHostname(body.sni || '');
  const parts = [{ ok: true, security, publicPort, network }];

  if (security === 'reality') {
    if (sslId) {
      if (sslId === SSL_CERT_AUTO) {
        if (!sni) return errField('sni', 'SNI is required for auto Reality certificate', 'XRAY_SNI_REQUIRED');
        const demuxPort = panelHttpsPort();
        if (publicPort === demuxPort) {
          parts.push(validateSniDemux('xray', sni, publicPort));
        }
        const merged = mergeErrors(...parts);
        if (!merged.ok) return merged;
        return { ok: true, sslCertId: SSL_CERT_AUTO, sni, autoCert: true, security, publicPort, network };
      }
      const certCheck = validateSslCertId(body, 'xray_reality');
      if (!certCheck.ok) return certCheck;
      const certSni = tlsMaterial.normalizeHostname(certCheck.cert.sni || certCheck.cert.domain || '');
      if (!certSni) return errField('sslCertId', 'Reality certificate has no SNI', 'XRAY_SNI_REQUIRED');
      const demuxPort = panelHttpsPort();
      if (publicPort === demuxPort) {
        parts.push(validateSniDemux('xray', certSni, publicPort));
      }
      return mergeErrors(...parts, { ok: true, sslCertId: certCheck.cert.id, sni: certSni });
    }
    if (!sni) return errField('sni', 'SNI is required for Reality', 'XRAY_SNI_REQUIRED');
    const demuxPort = panelHttpsPort();
    if (publicPort === demuxPort) {
      parts.push(validateSniDemux('xray', sni, publicPort));
    }
    return mergeErrors(...parts);
  }

  if (security === 'tls') {
    if (sslId) {
      if (sslId === SSL_CERT_AUTO) {
        return { ok: true, sslCertId: SSL_CERT_AUTO, autoCert: true, security, publicPort, network };
      }
      const certCheck = validateSslCertId(body, 'xray_tls');
      if (!certCheck.ok) return certCheck;
      if (certCheck.cert.is_panel) {
        const conflict = validatePanelCertConflict('panel', publicPort);
        if (!conflict.ok) return conflict;
      }
      const certSni = tlsMaterial.normalizeHostname(certCheck.cert.sni || certCheck.cert.domain || '');
      const demuxPort = panelHttpsPort();
      if (publicPort === demuxPort && certSni) {
        parts.push(validateSniDemux('xray', certSni, publicPort));
      }
      return mergeErrors(...parts, { ok: true, sslCertId: certCheck.cert.id });
    }
    const certSource = String(body.certSource || body.cert_source || 'self_signed').trim().toLowerCase();
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
    parts.push(validatePanelCertConflict(certSource, publicPort));
    parts.push(validateManualCertFields(certSource, body));
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
  let result;
  switch (service) {
    case 'mieru': result = validateMieru(body); break;
    case 'hysteria': result = validateHysteria(body); break;
    case 'naive': result = validateNaive(body); break;
    case 'xray': result = validateXray(body); break;
    default:
      return { ok: false, fieldErrors: { _form: `Unknown service ${service}` } };
  }
  if (!result.ok) return result;
  const occ = portPlan.validateOccupancyConflicts(service, body || {});
  if (!occ.ok) {
    return {
      ok: false,
      code: occ.code,
      fieldErrors: occ.fieldErrors,
      occupancy: { proposed: occ.proposed, existing: occ.existing },
    };
  }
  return {
    ...result,
    occupancy: { proposed: occ.proposed, existing: occ.existing },
  };
}

/**
 * Async follow-up: live host TCP/UDP bind checks (after sync validateInstall).
 */
async function validateInstallLive(service, body = {}) {
  const sync = validateInstall(service, body);
  if (!sync.ok) return sync;
  const proposed = (sync.occupancy && sync.occupancy.proposed)
    || portPlan.proposedClaimsForInstall(service, body);
  const udpPorts = proposed.filter((c) => c.proto === 'udp').map((c) => c.port);
  const tcpPorts = proposed.filter((c) => c.proto === 'tcp' && !c.demux).map((c) => c.port);
  try {
    if (udpPorts.length) {
      const owner = service === 'hysteria' ? 'hysteria'
        : (service === 'naive' ? 'naive'
          : (service === 'mieru' ? 'mieru'
            : (service === 'xray' ? 'xray' : 'any')));
      await portPlan.assertHostUdpPortsAvailable(udpPorts, { owner });
    }
    if (tcpPorts.length) {
      await portPlan.assertHostPortsAvailable(tcpPorts, { allowNginx: true });
    }
  } catch (err) {
    const field = (err && err.code === 'SNI_CONFLICT') ? 'sni' : 'publicPort';
    return {
      ok: false,
      code: (err && err.code) || 'HOST_PORT_BUSY',
      fieldErrors: (err && err.fieldErrors) || {
        [field]: (err && err.message) || 'Port is busy',
      },
    };
  }
  return sync;
}

module.exports = {
  validateInstall,
  validateInstallLive,
  validateMieru,
  validateNaive,
  validateHysteria,
  validateXray,
  validateSniDemux,
  validatePublicPortConflict,
  validateTcpHostPortConflict,
  validatePanelCertConflict,
  validateManualCertFields,
  validateMasqueradeUrl,
  validateSslCertId,
  mergeErrors,
  PANEL_CERT_CONFLICT_MSG,
};
