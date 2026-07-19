'use strict';

/**
 * Absolute origin for panel links shown to users (Xray /sub QR, etc.).
 * Nginx often forwards Host without the published HTTPS port ($host vs $http_host),
 * and inside the container TLS listens on 443 while the host maps PANEL_HTTPS_PORT→443.
 * Always prefer an explicit public port from env when the request omits one.
 *
 * @param {{
 *   requestUrl?: URL|{ protocol?: string, hostname?: string, port?: string },
 *   panelDomain?: string,
 *   panelHttpsPort?: string|number,
 *   wgHost?: string,
 * }} [opts]
 * @returns {string} e.g. https://work.example.com:10123  (no trailing slash)
 */
function buildPanelPublicBaseUrl(opts = {}) {
  const portRaw = opts.panelHttpsPort != null && String(opts.panelHttpsPort).trim() !== ''
    ? String(opts.panelHttpsPort).trim()
    : '10123';
  const port = /^\d+$/.test(portRaw) ? portRaw : '10123';

  let protocol = 'https:';
  let hostname = '';
  let requestPort = '';

  const req = opts.requestUrl;
  if (req && typeof req === 'object') {
    if (req.protocol) protocol = String(req.protocol);
    if (!protocol.endsWith(':')) protocol = `${protocol}:`;
    hostname = String(req.hostname || '').trim();
    requestPort = String(req.port || '').trim();
  }

  if (!hostname) {
    hostname = String(opts.panelDomain || opts.wgHost || '').trim();
  }
  if (!hostname) return '';

  // Trust explicit non-default port from the request Host header when present.
  if (requestPort && requestPort !== '443' && requestPort !== '80') {
    return `${protocol}//${hostname}:${requestPort}`;
  }

  if (port === '443' || port === '80') {
    return `${protocol}//${hostname}`;
  }
  return `${protocol}//${hostname}:${port}`;
}

module.exports = {
  buildPanelPublicBaseUrl,
  /**
   * Normalize a public path prefix (leading slash, no trailing slash).
   * @param {string} raw
   * @param {string} fallback
   */
  normalizePublicPrefix(raw, fallback = '/panel') {
    let p = String(raw == null ? '' : raw).trim();
    if (!p) p = fallback;
    if (!p.startsWith('/')) p = `/${p}`;
    p = p.replace(/\/+$/, '');
    return p || fallback;
  },
};
