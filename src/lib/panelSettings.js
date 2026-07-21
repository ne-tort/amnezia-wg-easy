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
const PANEL_CONTAINER = 'amnezia-awg';

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
  p = p.replace(/\\/g, '/');
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

function normalizeMirrorPort(raw, panelPort) {
  if (raw == null || String(raw).trim() === '') return null;
  const n = parsePort(raw);
  if (n == null) return null;
  if (Number(panelPort) === n) return null;
  return n;
}

function mutateRuntimeConfig({ panelHttpsPort, webuiPublicPrefix, mirrorHttpsPort } = {}) {
  const config = require('../config');
  if (panelHttpsPort != null) {
    config.PANEL_HTTPS_PORT = String(panelHttpsPort);
  }
  if (webuiPublicPrefix != null) {
    config.WEBUI_PUBLIC_PREFIX = String(webuiPublicPrefix);
  }
  if (mirrorHttpsPort !== undefined) {
    config.NGINX_MIRROR_HTTPS_PORT = mirrorHttpsPort == null ? '' : String(mirrorHttpsPort);
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

async function recreatePanelContainer() {
  const install = installDir();
  const composeYml = path.join(install, 'docker-compose.yml');
  const portsYml = path.join(install, 'docker-compose.ports.yml');
  const envFile = path.join(install, '.env');
  const args = ['compose'];
  if (fs.existsSync(envFile)) args.push('--env-file', envFile);
  args.push('-f', composeYml);
  if (fs.existsSync(portsYml)) args.push('-f', portsYml);
  args.push('up', '-d', '--no-deps', '--force-recreate', 'amnezia-wg-easy');
  return runCmd('docker', args, { timeout: 180_000 });
}

async function waitForPanelReady({ timeoutMs = 90_000 } = {}) {
  const deadline = Date.now() + timeoutMs;
  const panelPort = parsePort(readEnvKey('PORT', '51821'), 51821) || 51821;
  while (Date.now() < deadline) {
    const st = await runCmd('docker', [
      'inspect', '-f', '{{.State.Running}}', PANEL_CONTAINER,
    ], { timeout: 10_000 });
    if (st.ok && st.stdout.trim() === 'true') {
      const probe = await runCmd('docker', [
        'exec', PANEL_CONTAINER,
        'wget', '-q', '-S', '-O', '/dev/null',
        `http://127.0.0.1:${panelPort}/api/session`,
      ], { timeout: 15_000 });
      const blob = `${probe.stdout || ''}\n${probe.stderr || ''}`;
      if (probe.ok || /HTTP\/1\.[01]\s+(200|401|403|302)/.test(blob)) {
        return true;
      }
    }
    await new Promise((r) => setTimeout(r, 1000));
  }
  return false;
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
  const mirrorPortRaw = readEnvKey('NGINX_MIRROR_HTTPS_PORT', config.NGINX_MIRROR_HTTPS_PORT || '');
  const mirrorHttpsPort = normalizeMirrorPort(mirrorPortRaw, panelHttpsPort);
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
    mirrorHttpsPort: mirrorHttpsPort == null ? '' : mirrorHttpsPort,
    webuiPublicPrefix,
    mirrorHost,
    nginxRootBehavior: rootBehavior,
    sslCertId: panelCertId,
    panelDomain: String(config.PANEL_DOMAIN || process.env.PANEL_DOMAIN || '').trim(),
  };
}

/**
 * Apply panel settings from UI body.
 * @param {{ panelHttpsPort?: number|string, mirrorHttpsPort?: number|string, webuiPublicPrefix?: string, mirrorHost?: string, sslCertId?: string }} body
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

  let nextMirrorPort = current.mirrorHttpsPort === '' ? null : current.mirrorHttpsPort;
  if (body.mirrorHttpsPort !== undefined) {
    const raw = String(body.mirrorHttpsPort == null ? '' : body.mirrorHttpsPort).trim();
    nextMirrorPort = raw === '' ? null : normalizeMirrorPort(raw, nextPort);
    if (raw !== '' && nextMirrorPort == null && parsePort(raw) == null) {
      throw httpError(400, 'Invalid mirror HTTPS port', 'MIRROR_BAD_PORT');
    }
  }

  const sslCertId = body.sslCertId != null
    ? String(body.sslCertId || '').trim()
    : current.sslCertId;

  const portChanged = Number(nextPort) !== Number(current.panelHttpsPort);
  const prefixChanged = nextPrefix !== current.webuiPublicPrefix;
  const mirrorChanged = nextMirror !== current.mirrorHost;
  const mirrorPortChanged = Number(nextMirrorPort || 0) !== Number(current.mirrorHttpsPort || 0);
  const certChanged = sslCertId && sslCertId !== current.sslCertId;

  const envPairs = {
    PANEL_HTTPS_PORT: String(nextPort),
    WEBUI_PUBLIC_PREFIX: nextPrefix,
    NGINX_MIRROR_HOST: nextMirror,
    NGINX_MIRROR_HTTPS_PORT: nextMirrorPort == null ? '' : String(nextMirrorPort),
  };
  if (nextMirror) {
    envPairs.NGINX_ROOT_BEHAVIOR = 'mirror';
  }
  persistEnvKeys(envPairs);
  mutateRuntimeConfig({
    panelHttpsPort: nextPort,
    webuiPublicPrefix: nextPrefix,
    mirrorHttpsPort: nextMirrorPort,
  });

  const sslManager = require('./sslManager');
  let assignedCert = null;
  if (certChanged && sslCertId) {
    assignedCert = await sslManager.assignPanel(sslCertId);
  }

  let panelReady = true;
  if (portChanged) {
    const panelRecreate = await recreatePanelContainer();
    if (!panelRecreate.ok) {
      throw httpError(500, (panelRecreate.stderr || panelRecreate.stdout || 'Panel recreate failed').slice(0, 300));
    }
    panelReady = await waitForPanelReady();
  }

  const portPlan = require('./portPlan');
  let planResult = null;
  if (portChanged || prefixChanged || mirrorChanged || mirrorPortChanged) {
    const plan = portPlan.computePlan();
    portPlan.writeStreamConfigs(plan);
    portPlan.writeComposePortsFile(plan);
    planResult = await portPlan.recreateNginxForPlan(plan);
  } else if (certChanged) {
    planResult = await portPlan.applyPlan();
  }

  let openPorts = null;
  if (portChanged || mirrorPortChanged) {
    openPorts = await openHostPorts();
  }

  const settings = await getSettings();
  return {
    success: true,
    settings,
    assignedCert,
    planResult,
    openPorts,
    panelReady,
    restarted: portChanged,
    changes: {
      port: portChanged,
      prefix: prefixChanged,
      mirror: mirrorChanged,
      mirrorPort: mirrorPortChanged,
      cert: !!certChanged,
    },
  };
}

module.exports = {
  getSettings,
  applySettings,
  normalizePathPrefix,
  normalizeMirrorHost,
  normalizeMirrorPort,
  persistEnvKeys,
  readEnvKey,
  waitForPanelReady,
};
