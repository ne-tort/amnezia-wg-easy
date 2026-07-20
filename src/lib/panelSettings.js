'use strict';

/**
 * Panel admin settings: HTTPS port, UI path prefix, mirror host, panel TLS cert.
 * Persists to install .env (+ install.conf) so install.sh / deploy redeploy inherits values.
 */

const fs = require('node:fs');
const path = require('node:path');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');

const execFileAsync = promisify(execFile);

function httpError(status, message, code) {
  const err = new Error(message);
  err.status = status;
  if (code) err.code = code;
  return err;
}

function installDir() {
  return process.env.AWG_INSTALL_DIR || '/opt/amnezia-wg-easy';
}

function confDir() {
  return process.env.AWG_CONF_DIR || '/etc/amnezia-wg-easy';
}

function envPath() {
  return path.join(installDir(), '.env');
}

function installConfPath() {
  return path.join(confDir(), 'install.conf');
}

function runCmd(bin, args, { timeout = 60_000 } = {}) {
  return execFileAsync(bin, args, { timeout, maxBuffer: 2 * 1024 * 1024 })
    .then(({ stdout, stderr }) => ({
      ok: true,
      stdout: String(stdout || ''),
      stderr: String(stderr || ''),
    }))
    .catch((err) => ({
      ok: false,
      stdout: String((err && err.stdout) || ''),
      stderr: String((err && err.stderr) || err.message || ''),
      error: err,
    }));
}

function upsertKeyValueFile(filePath, key, value) {
  const k = String(key || '').trim();
  const v = String(value == null ? '' : value).trim();
  if (!k || !filePath) return false;
  try {
    let text = '';
    if (fs.existsSync(filePath)) {
      text = fs.readFileSync(filePath, 'utf8');
    }
    const re = new RegExp(`^${k.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}=.*$`, 'm');
    if (re.test(text)) {
      text = text.replace(re, `${k}=${v}`);
    } else {
      text = `${text.replace(/\s*$/, '')}\n${k}=${v}\n`;
    }
    const dir = path.dirname(filePath);
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(filePath, text, 'utf8');
    return true;
  } catch {
    return false;
  }
}

function readKeyFromFile(filePath, key) {
  try {
    if (!fs.existsSync(filePath)) return null;
    const text = fs.readFileSync(filePath, 'utf8');
    const re = new RegExp(`^${String(key).replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}=(.*)$`, 'm');
    const m = text.match(re);
    return m ? String(m[1] || '').trim() : null;
  } catch {
    return null;
  }
}

function readEnvKey(key, fallback = '') {
  const fromEnvFile = readKeyFromFile(envPath(), key);
  if (fromEnvFile != null && fromEnvFile !== '') return fromEnvFile;
  const fromProcess = process.env[key];
  if (fromProcess != null && String(fromProcess).trim() !== '') return String(fromProcess).trim();
  return fallback;
}

function persistEnvKeys(pairs) {
  const envFile = envPath();
  const confFile = installConfPath();
  for (const [key, value] of Object.entries(pairs)) {
    upsertKeyValueFile(envFile, key, value);
    upsertKeyValueFile(confFile, key, value);
    process.env[key] = String(value == null ? '' : value);
  }
}

function normalizePathPrefix(raw, fallback = '/panel') {
  let p = String(raw == null ? '' : raw).trim();
  if (!p || p === '/') p = fallback;
  if (!p.startsWith('/')) p = `/${p}`;
  p = p.replace(/\/+$/, '');
  return p || fallback;
}

function normalizeMirrorHost(raw) {
  let s = String(raw || '').trim().toLowerCase();
  if (!s) return '';
  s = s.replace(/^https?:\/\//i, '');
  s = s.split('/')[0].split('?')[0];
  if (s.includes(':') && !s.includes(']')) {
    const parts = s.split(':');
    if (parts.length === 2 && /^\d+$/.test(parts[1])) s = parts[0];
  }
  return s.replace(/\.$/, '');
}

function parsePort(raw) {
  const n = parseInt(String(raw == null ? '' : raw).trim(), 10);
  if (!Number.isInteger(n) || n < 1 || n > 65535) return null;
  return n;
}

function mutateRuntimeConfig({ panelHttpsPort, webuiPublicPrefix } = {}) {
  const config = require('../config');
  if (panelHttpsPort != null) {
    config.PANEL_HTTPS_PORT = String(panelHttpsPort);
  }
  if (webuiPublicPrefix != null) {
    config.WEBUI_PUBLIC_PREFIX = String(webuiPublicPrefix);
  }
}

async function openHostPorts() {
  const script = path.join(installDir(), 'scripts', 'open-ports.sh');
  if (!fs.existsSync(script)) {
    return { ok: false, skipped: true, reason: 'open-ports.sh missing' };
  }
  const r = await runCmd('bash', [script], { timeout: 60_000 });
  return { ok: r.ok, stdout: r.stdout, stderr: r.stderr };
}

/**
 * Recreate panel container so env (port/prefix) is picked up by config.js.
 * Scheduled after the HTTP response — this process will die.
 */
function schedulePanelRecreate() {
  const install = installDir();
  const composeYml = path.join(install, 'docker-compose.yml');
  const portsYml = path.join(install, 'docker-compose.ports.yml');
  const envFile = path.join(install, '.env');
  setTimeout(() => {
    (async () => {
      const args = ['compose'];
      if (fs.existsSync(envFile)) args.push('--env-file', envFile);
      args.push('-f', composeYml);
      if (fs.existsSync(portsYml)) args.push('-f', portsYml);
      args.push('up', '-d', '--no-deps', '--force-recreate', 'amnezia-wg-easy');
      const r = await runCmd('docker', args, { timeout: 180_000 });
      if (!r.ok) {
        console.error('panelSettings: panel recreate failed:', (r.stderr || r.stdout || '').slice(0, 400));
      }
    })().catch((err) => {
      console.error('panelSettings: panel recreate error:', err && err.message);
    });
  }, 800);
}

async function getSettings() {
  const config = require('../config');
  const sslManager = require('./sslManager');
  let panelCertId = '';
  try {
    const listed = await sslManager.list();
    const certs = (listed && listed.certs) || [];
    const panel = certs.find((c) => c && c.isPanel);
    if (panel) panelCertId = panel.id;
  } catch {
    /* inventory optional for GET */
  }

  const panelHttpsPort = parsePort(readEnvKey('PANEL_HTTPS_PORT', config.PANEL_HTTPS_PORT))
    || parsePort(config.PANEL_HTTPS_PORT)
    || 443;
  const webuiPublicPrefix = normalizePathPrefix(
    readEnvKey('WEBUI_PUBLIC_PREFIX', config.WEBUI_PUBLIC_PREFIX || '/panel'),
    '/panel',
  );
  const mirrorHost = normalizeMirrorHost(
    readEnvKey('NGINX_MIRROR_HOST', process.env.NGINX_MIRROR_HOST || ''),
  );
  const rootBehavior = readEnvKey('NGINX_ROOT_BEHAVIOR', process.env.NGINX_ROOT_BEHAVIOR || 'mirror') || 'mirror';

  return {
    panelHttpsPort,
    webuiPublicPrefix,
    mirrorHost,
    nginxRootBehavior: rootBehavior,
    sslCertId: panelCertId,
    panelDomain: String(config.PANEL_DOMAIN || process.env.PANEL_DOMAIN || '').trim(),
  };
}

/**
 * Apply panel settings from UI body.
 * @param {{ panelHttpsPort?: number|string, webuiPublicPrefix?: string, mirrorHost?: string, sslCertId?: string }} body
 */
async function applySettings(body = {}) {
  const current = await getSettings();
  const nextPort = body.panelHttpsPort != null
    ? parsePort(body.panelHttpsPort)
    : current.panelHttpsPort;
  if (nextPort == null) {
    throw httpError(400, 'Invalid panel HTTPS port', 'PANEL_BAD_PORT');
  }

  const nextPrefix = body.webuiPublicPrefix != null
    ? normalizePathPrefix(body.webuiPublicPrefix, '/panel')
    : current.webuiPublicPrefix;

  const nextMirror = body.mirrorHost != null
    ? normalizeMirrorHost(body.mirrorHost)
    : current.mirrorHost;

  const sslCertId = body.sslCertId != null
    ? String(body.sslCertId || '').trim()
    : current.sslCertId;

  const portChanged = Number(nextPort) !== Number(current.panelHttpsPort);
  const prefixChanged = nextPrefix !== current.webuiPublicPrefix;
  const mirrorChanged = nextMirror !== current.mirrorHost;
  const certChanged = sslCertId && sslCertId !== current.sslCertId;

  const envPairs = {
    PANEL_HTTPS_PORT: String(nextPort),
    WEBUI_PUBLIC_PREFIX: nextPrefix,
    NGINX_MIRROR_HOST: nextMirror,
  };
  if (nextMirror) {
    envPairs.NGINX_ROOT_BEHAVIOR = 'mirror';
  }
  persistEnvKeys(envPairs);
  mutateRuntimeConfig({
    panelHttpsPort: nextPort,
    webuiPublicPrefix: nextPrefix,
  });

  const sslManager = require('./sslManager');
  let assignedCert = null;
  if (certChanged && sslCertId) {
    assignedCert = await sslManager.assignPanel(sslCertId);
  }

  const portPlan = require('./portPlan');
  let planResult = null;
  if (portChanged || prefixChanged || mirrorChanged) {
    const plan = portPlan.computePlan();
    portPlan.writeStreamConfigs(plan);
    portPlan.writeComposePortsFile(plan);
    planResult = await portPlan.recreateNginxForPlan(plan);
  } else if (certChanged) {
    planResult = await portPlan.applyPlan();
  }

  let openPorts = null;
  if (portChanged) {
    openPorts = await openHostPorts();
  }

  const needsPanelRestart = portChanged || prefixChanged;
  if (needsPanelRestart) {
    schedulePanelRecreate();
  }

  const settings = await getSettings();
  return {
    success: true,
    settings,
    assignedCert,
    planResult,
    openPorts,
    restarted: needsPanelRestart,
    changes: {
      port: portChanged,
      prefix: prefixChanged,
      mirror: mirrorChanged,
      cert: !!certChanged,
    },
  };
}

module.exports = {
  getSettings,
  applySettings,
  normalizePathPrefix,
  normalizeMirrorHost,
  persistEnvKeys,
  readEnvKey,
};
