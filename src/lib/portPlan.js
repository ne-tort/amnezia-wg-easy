'use strict';

/**
 * Unified TCP port plan: shared public ports → nginx stream SNI demux;
 * exclusive ports → direct docker publish on sidecars.
 */

const fs = require('node:fs');
const path = require('node:path');
const { promisify } = require('node:util');
const { execFile } = require('node:child_process');
const config = require('../config');

const execFileAsync = promisify(execFile);

const NGINX_CONTAINER = 'nginx';
const PANEL_TLS_INTERNAL = 8443;
const MIRROR_TLS_INTERNAL = 8444;
const STREAM_DIR_REL = path.join('nginx', 'stream');
const COMPOSE_PORTS_NAME = 'docker-compose.ports.yml';

const NGINX_ENV_KEYS = [
  'PANEL_DOMAIN',
  'PANEL_PORT',
  'PORT',
  'PANEL_HTTPS_PORT',
  'NGINX_MIRROR_HTTPS_PORT',
  'WEBUI_PUBLIC_PREFIX',
  'SUB_PUBLIC_PREFIX',
  'NGINX_ROOT_BEHAVIOR',
  'NGINX_MIRROR_HOST',
  'NGINX_LOCAL_URL',
  'WG_HOST',
  'NGINX_CONFIG_PROFILE',
];

function runCmd(bin, args, { timeout = 30_000 } = {}) {
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

function getDb() {
  return require('./db');
}

function setting(key, fallback = '') {
  try {
    const raw = getDb().appSettings.get(key);
    if (raw === null || raw === undefined || raw === '') return fallback;
    return String(raw).trim();
  } catch {
    return fallback;
  }
}

function desired(key) {
  const raw = setting(key, '');
  return raw === '1' || raw === 'true' || raw === 'yes' || raw === 'on';
}

function parsePort(raw, fallback) {
  const n = parseInt(String(raw == null ? '' : raw).trim(), 10);
  if (Number.isFinite(n) && n >= 1 && n <= 65535) return n;
  return fallback;
}

function nginxDir() {
  return path.join(config.WG_PATH, 'nginx');
}

function streamDir() {
  return path.join(config.WG_PATH, STREAM_DIR_REL);
}

function composePortsPath() {
  return path.join(nginxDir(), COMPOSE_PORTS_NAME);
}

function panelPublicPort() {
  return parsePort(config.PANEL_HTTPS_PORT, 10123);
}

/** Host port for dedicated mirror stub; null when mirror shares panel port. */
function mirrorPublicPort() {
  const raw = String(process.env.NGINX_MIRROR_HTTPS_PORT || config.NGINX_MIRROR_HTTPS_PORT || '').trim();
  const m = parsePort(raw, 0);
  if (!m) return null;
  const panel = panelPublicPort();
  if (m === panel) return null;
  return m;
}

function mirrorExclusiveFromEnv() {
  const host = mirrorPublicPort();
  if (!host) return null;
  return { hostPort: host, containerPort: MIRROR_TLS_INTERNAL };
}

function installEnvPath() {
  return path.join(process.env.AWG_INSTALL_DIR || '/opt/amnezia-wg-easy', '.env');
}

function readInstallDotEnv() {
  const out = {};
  const envFile = installEnvPath();
  if (!fs.existsSync(envFile)) return out;
  try {
    const text = fs.readFileSync(envFile, 'utf8');
    for (const line of text.split(/\r?\n/)) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) continue;
      const idx = trimmed.indexOf('=');
      if (idx <= 0) continue;
      const key = trimmed.slice(0, idx).trim();
      out[key] = trimmed.slice(idx + 1).trim();
    }
  } catch {
    /* optional */
  }
  return out;
}

/** Refresh nginx container env from install .env (docker-run fallback after settings UI). */
function patchNginxEnvFromDotEnv(envArr) {
  const dot = readInstallDotEnv();
  const map = new Map();
  for (const entry of envArr || []) {
    const idx = String(entry).indexOf('=');
    if (idx <= 0) continue;
    map.set(entry.slice(0, idx), entry.slice(idx + 1));
  }
  for (const key of NGINX_ENV_KEYS) {
    if (key === 'PORT' && dot.PORT != null && dot.PORT !== '') {
      map.set('PANEL_PORT', dot.PORT);
      continue;
    }
    if (dot[key] != null && String(dot[key]).trim() !== '') {
      map.set(key, String(dot[key]).trim());
    }
  }
  if (!map.has('PANEL_PORT') && dot.PORT) {
    map.set('PANEL_PORT', String(dot.PORT).trim());
  }
  return [...map.entries()].map(([k, v]) => `${k}=${v}`);
}

function panelSni() {
  const domain = (config.PANEL_DOMAIN || '').trim();
  if (domain) return domain.toLowerCase();
  const wg = (config.WG_HOST || '').trim();
  if (wg) return wg.toLowerCase();
  return 'localhost';
}

/** True for IPv4 / IPv6 literals. */
function isIpLiteral(host) {
  const h = String(host || '').trim().toLowerCase().replace(/^\[|\]$/g, '');
  if (!h) return false;
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(h)) return true;
  if (h.includes(':')) return true; // IPv6
  return false;
}

/**
 * Panel gets a *named* SNI route only for an FQDN (not IP / localhost).
 * Bare-IP panel still shares demux via default (unknown/missing SNI → panel TLS).
 */
function panelCanJoinDemuxBySni(sni) {
  const s = String(sni || '').trim().toLowerCase();
  if (!s || s === 'localhost') return false;
  return !isIpLiteral(s);
}

function desiredBool(key, fallback = false) {
  const raw = setting(key, '');
  if (raw === '1' || raw === 'true' || raw === 'yes' || raw === 'on') return true;
  if (raw === '0' || raw === 'false' || raw === 'no' || raw === 'off') return false;
  return fallback;
}

function mieruTcpEnabled() {
  const explicit = setting('amnezia_mieru_tcp_enabled', '');
  if (explicit !== '') return desiredBool('amnezia_mieru_tcp_enabled', false);
  const proto = (setting('amnezia_mieru_protocol', 'TCP') || 'TCP').toUpperCase();
  return proto === 'TCP';
}

function mieruUdpEnabled() {
  const explicit = setting('amnezia_mieru_udp_enabled', '');
  if (explicit !== '') return desiredBool('amnezia_mieru_udp_enabled', false);
  const proto = (setting('amnezia_mieru_protocol', 'TCP') || 'TCP').toUpperCase();
  return proto === 'UDP';
}

/**
 * Collect candidate services for the plan (desired sidecars + always panel).
 */
function collectServices() {
  const services = [];

  services.push({
    id: 'panel',
    publicPort: panelPublicPort(),
    listenPort: PANEL_TLS_INTERNAL,
    sni: panelSni(),
    upstream: `127.0.0.1:${PANEL_TLS_INTERNAL}`,
    alwaysOn: true,
    canJoinDemux: panelCanJoinDemuxBySni(panelSni()),
  });

  if (desired('amnezia_xray_desired')) {
    const pub = parsePort(
      setting('amnezia_xray_public_port', '') || process.env.XRAY_PUBLIC_PORT || '443',
      443,
    );
    const listen = parsePort(setting('amnezia_xray_port', ''), 0);
    const sni = setting('amnezia_xray_sni', '');
    services.push({
      id: 'xray',
      publicPort: pub,
      listenPort: listen,
      sni: sni.toLowerCase(),
      upstream: listen ? `amnezia-xray:${listen}` : null,
      alwaysOn: false,
    });
  }

  if (desired('amnezia_naive_desired')) {
    const pub = parsePort(
      setting('amnezia_naive_public_port', '') || process.env.NAIVE_PUBLIC_PORT || '443',
      443,
    );
    const listen = 8443;
    const sni = setting('amnezia_naive_sni', '');
    services.push({
      id: 'naive',
      publicPort: pub,
      listenPort: listen,
      sni: sni.toLowerCase(),
      upstream: `amnezia-naive:${listen}`,
      alwaysOn: false,
    });
  }

  if (desired('amnezia_mieru_desired') && mieruTcpEnabled()) {
    const pub = parsePort(
      setting('amnezia_mieru_tcp_public_port', '')
      || setting('amnezia_mieru_public_port', '')
      || process.env.MIERU_PUBLIC_PORT || '3080',
      3080,
    );
    const listen = parsePort(
      setting('amnezia_mieru_tcp_port', '') || setting('amnezia_mieru_port', ''),
      0,
    );
    services.push({
      id: 'mieru-tcp',
      publicPort: pub,
      listenPort: listen,
      sni: '',
      upstream: listen ? `amnezia-mieru:${listen}` : null,
      alwaysOn: false,
    });
  }

  return services;
}

/**
 * UDP sidecars with direct host publish (no nginx demux).
 */
function collectUdpDirectServices() {
  const services = [];
  if (desired('amnezia_hysteria_desired')) {
    const pub = parsePort(
      setting('amnezia_hysteria_public_port', '') || process.env.HYSTERIA_PUBLIC_PORT || '443',
      443,
    );
    services.push({
      id: 'hysteria',
      publicPort: pub,
      listenPort: 443,
      protocol: 'udp',
    });
  }
  if (desired('amnezia_mieru_desired') && mieruUdpEnabled()) {
    const pub = parsePort(
      setting('amnezia_mieru_udp_public_port', '')
      || setting('amnezia_mieru_public_port', '')
      || process.env.MIERU_UDP_PUBLIC_PORT
      || process.env.MIERU_PUBLIC_PORT || '3080',
      3080,
    );
    const listen = parsePort(
      setting('amnezia_mieru_udp_port', '') || setting('amnezia_mieru_port', ''),
      0,
    );
    services.push({
      id: 'mieru-udp',
      publicPort: pub,
      listenPort: listen || 35001,
      protocol: 'udp',
    });
  }
  return services;
}

/**
 * @returns {{
 *   demuxPorts: { port: number, routes: { sni: string, upstream: string, service: string }[] }[],
 *   direct: { service: string, publicPort: number, listenPort: number }[],
 *   panelExclusive: { hostPort: number, containerPort: number } | null,
 *   modes: Record<string, 'demux'|'direct'|'panel'>,
 *   demuxPeers: Record<string, string[]>,
 *   conflicts: { code: string, message: string }[],
 * }}
 */
function computePlan(servicesInput) {
  const services = servicesInput || collectServices();
  const conflicts = [];
  const byPort = new Map();

  for (const s of services) {
    if (!s.publicPort) continue;
    if (!byPort.has(s.publicPort)) byPort.set(s.publicPort, []);
    byPort.get(s.publicPort).push(s);
  }

  const demuxPorts = [];
  const direct = [];
  const modes = {};
  const demuxPeers = {};
  let panelExclusive = null;

  for (const [port, group] of byPort.entries()) {
    // Sidecars = anything except panel (xray today; more services can join demux later).
    const sidecars = group.filter((s) => s.id !== 'panel');
    const panel = group.find((s) => s.id === 'panel');
    const panelSharesPort = !!(panel && panel.publicPort === port);
    const panelNamedSni = !!(
      panelSharesPort
      && panel.canJoinDemux !== false
      && panelCanJoinDemuxBySni(panel.sni)
    );
    // Demux when 2+ sidecars share a port, or any sidecar shares with the panel.
    const needDemux = sidecars.length >= 2
      || (sidecars.length >= 1 && panelSharesPort);

    if (needDemux) {
      const members = [...sidecars];
      if (panelSharesPort) members.push(panel);

      const routes = [];
      const snis = new Map();
      for (const m of members) {
        if (m.id === 'panel' && !panelNamedSni) {
          // Bare IP / no FQDN: no named SNI route — catch-all default handles panel TLS.
          continue;
        }
        if (!m.sni) {
          if (m.id !== 'panel') {
            conflicts.push({
              code: 'MISSING_SNI',
              message: `${m.id} needs SNI for demux on ${port}`,
            });
          }
          continue;
        }
        if (snis.has(m.sni)) {
          conflicts.push({
            code: 'SNI_CONFLICT',
            message: `SNI ${m.sni} shared by ${snis.get(m.sni)} and ${m.id} on port ${port}`,
          });
          continue;
        }
        snis.set(m.sni, m.id);
        if (m.id === 'panel') {
          routes.push({ sni: m.sni, upstream: m.upstream, service: 'panel' });
        } else if (m.upstream) {
          routes.push({ sni: m.sni, upstream: m.upstream, service: m.id });
        }
      }
      // Known SNI → xray/mt/(panel FQDN). Unknown/missing:
      //   bare-IP panel on this port → panel TLS (mirror + /panel);
      //   FQDN panel → :9 (stub/UI only via panel's known SNI).
      const defaultUpstream = (panelSharesPort && !panelNamedSni)
        ? `127.0.0.1:${PANEL_TLS_INTERNAL}`
        : '127.0.0.1:9';
      demuxPorts.push({ port, routes, defaultUpstream });

      const peerIds = members.map((m) => m.id);
      for (const m of members) {
        modes[m.id] = 'demux';
        demuxPeers[m.id] = peerIds.filter((id) => id !== m.id);
      }
    } else {
      for (const s of sidecars) {
        modes[s.id] = 'direct';
        demuxPeers[s.id] = [];
        if (s.listenPort) {
          direct.push({
            service: s.id,
            publicPort: s.publicPort,
            listenPort: s.listenPort,
          });
        }
      }
      if (panel && !modes.panel) {
        modes.panel = 'panel';
        panelExclusive = { hostPort: panel.publicPort, containerPort: PANEL_TLS_INTERNAL };
      }
    }
  }

  if (!modes.panel) {
    modes.panel = 'panel';
    // If panel public port is already a demux listen, do not double-publish
    const demuxOwnsPanelPort = demuxPorts.some((d) => d.port === panelPublicPort());
    if (!demuxOwnsPanelPort) {
      panelExclusive = { hostPort: panelPublicPort(), containerPort: PANEL_TLS_INTERNAL };
    }
  }

  const udpDirect = collectUdpDirectServices();
  const mirrorExclusive = mirrorExclusiveFromEnv();

  return {
    demuxPorts,
    direct,
    udpDirect,
    panelExclusive,
    mirrorExclusive,
    modes,
    demuxPeers,
    conflicts,
  };
}

function modeForService(serviceId, plan) {
  const p = plan || computePlan();
  return p.modes[serviceId] || null;
}

function isDemuxService(serviceId) {
  return modeForService(serviceId) === 'demux';
}

function writeStreamConfigs(plan) {
  const dir = streamDir();
  fs.mkdirSync(dir, { recursive: true });
  // Clear old generated stream servers
  for (const name of fs.readdirSync(dir)) {
    if (name.startsWith('demux-') && name.endsWith('.conf')) {
      fs.unlinkSync(path.join(dir, name));
    }
  }
  for (const name of fs.readdirSync(nginxDir())) {
    if (name.startsWith('stream-sni-') && name.endsWith('.map')) {
      fs.unlinkSync(path.join(nginxDir(), name));
    }
  }

  for (const block of plan.demuxPorts) {
    const mapName = `stream-sni-${block.port}.map`;
    const mapPath = path.join(nginxDir(), mapName);
    const lines = ['# generated by amnezia-wg-easy — do not edit'];
    const seen = new Set();
    for (const r of block.routes) {
      const sni = String(r.sni || '').trim().toLowerCase();
      const up = String(r.upstream || '').trim();
      if (!sni || !up || seen.has(sni)) continue;
      seen.add(sni);
      lines.push(`${sni} ${up};`);
    }
    lines.push('');
    fs.writeFileSync(mapPath, `${lines.join('\n')}`, 'utf8');

    const defaultUp = block.defaultUpstream || '127.0.0.1:9';
    // Variable proxy_pass (map → hostname:port) needs a resolver at runtime.
    // Without it nginx logs "no resolver defined to resolve amnezia-xray"
    // and resets the client TLS. Docker embedded DNS is 127.0.0.11.
    // Stream ssl_preread + proxy_pass is pure TCP passthrough (no TLS terminate,
    // no payload rewrite). Do NOT add proxy_protocol here — that prepends a
    // header and is only needed for real-IP logging, not for demux itself.
    const conf = [
      `map $ssl_preread_server_name $demux_backend_${block.port} {`,
      `    include /opt/amnezia/awg/nginx/${mapName};`,
      `    default ${defaultUp};`,
      '}',
      '',
      'server {',
      `    listen ${block.port};`,
      '    ssl_preread on;',
      '    resolver 127.0.0.11 valid=10s ipv6=off;',
      '    resolver_timeout 5s;',
      `    proxy_pass $demux_backend_${block.port};`,
      '    proxy_connect_timeout 5s;',
      '    proxy_timeout 1d;',
      '}',
      '',
    ].join('\n');
    fs.writeFileSync(path.join(dir, `demux-${block.port}.conf`), conf, 'utf8');
  }

  // Empty placeholder so include doesn't fail
  if (plan.demuxPorts.length === 0) {
    fs.writeFileSync(
      path.join(dir, 'empty.conf'),
      '# no demux ports — generated by amnezia-wg-easy\n',
      'utf8',
    );
  } else {
    const emptyPath = path.join(dir, 'empty.conf');
    if (fs.existsSync(emptyPath)) fs.unlinkSync(emptyPath);
  }
}

function writeComposePortsFile(plan) {
  fs.mkdirSync(nginxDir(), { recursive: true });
  const ports = [];
  if (plan.panelExclusive) {
    ports.push(`      - "${plan.panelExclusive.hostPort}:${plan.panelExclusive.containerPort}"`);
  }
  if (plan.mirrorExclusive) {
    ports.push(`      - "${plan.mirrorExclusive.hostPort}:${plan.mirrorExclusive.containerPort}"`);
  }
  for (const d of plan.demuxPorts) {
    ports.push(`      - "${d.port}:${d.port}"`);
  }
  const body = ports.length
    ? [
      '# generated by amnezia-wg-easy portPlan — do not edit by hand',
      'services:',
      '  nginx:',
      '    ports:',
      ...ports,
      '',
    ].join('\n')
    : [
      '# generated by amnezia-wg-easy portPlan — no extra nginx ports',
      'services: {}',
      '',
    ].join('\n');
  fs.writeFileSync(composePortsPath(), body, 'utf8');

  // Best-effort copy next to compose project if panel can see host install dir
  const installDir = process.env.AWG_INSTALL_DIR || '/opt/amnezia-wg-easy';
  try {
    if (fs.existsSync(path.join(installDir, 'docker-compose.yml'))) {
      fs.writeFileSync(path.join(installDir, COMPOSE_PORTS_NAME), body, 'utf8');
    }
  } catch {
    /* ignore */
  }
  return composePortsPath();
}

async function isHostUdpPortInUse(port) {
  const p = String(port);
  const ss = await runCmd('ss', ['-lnu'], { timeout: 5_000 });
  if (ss.ok) {
    const re = new RegExp(`[:.]${p}\\s`);
    if (re.test(ss.stdout)) return true;
  }
  const nt = await runCmd('netstat', ['-lnu'], { timeout: 5_000 });
  if (nt.ok) {
    const re = new RegExp(`[:.]${p}\\s`);
    if (re.test(nt.stdout)) return true;
  }
  return false;
}

/**
 * Assert host UDP ports for udpDirect sidecars are free or already ours.
 * @param {number[]} ports
 * @param {{ allowSidecar?: boolean }} opts
 */
async function assertHostUdpPortsAvailable(ports, opts = {}) {
  const allowSidecar = opts.allowSidecar !== false;
  const wgPort = parsePort(process.env.WG_PORT, 51820);
  for (const port of ports) {
    if (allowSidecar) {
      const hy = await runCmd('docker', [
        'inspect', '-f',
        '{{range $p, $conf := .NetworkSettings.Ports}}{{$p}} {{end}}',
        'amnezia-hysteria',
      ]);
      if (hy.ok && new RegExp(`${port}/udp`).test(hy.stdout)) continue;
      const mieru = await runCmd('docker', [
        'inspect', '-f',
        '{{range $p, $conf := .NetworkSettings.Ports}}{{$p}} {{end}}',
        'amnezia-mieru',
      ]);
      if (mieru.ok && new RegExp(`${port}/udp`).test(mieru.stdout)) continue;
    }
    if (port === wgPort) continue;
    if (await isHostUdpPortInUse(port)) {
      const err = new Error(`Host UDP ${port} is in use by another process`);
      err.status = 409;
      err.code = 'HOST_UDP_PORT_BUSY';
      throw err;
    }
  }
}

async function isHostTcpPortInUse(port) {
  const p = String(port);
  const ss = await runCmd('ss', ['-lnt'], { timeout: 5_000 });
  if (ss.ok) {
    const re = new RegExp(`[:.]${p}\\s`);
    if (re.test(ss.stdout)) return true;
  }
  const nt = await runCmd('netstat', ['-lnt'], { timeout: 5_000 });
  if (nt.ok) {
    const re = new RegExp(`[:.]${p}\\s`);
    if (re.test(nt.stdout)) return true;
  }
  return false;
}

/**
 * Host TCP ports published by nginx (what clients hit).
 */
async function nginxHostTcpPorts() {
  const r = await runCmd('docker', [
    'inspect', '-f',
    '{{range $p, $conf := .NetworkSettings.Ports}}{{range $conf}}{{.HostPort}} {{end}}{{end}}',
    NGINX_CONTAINER,
  ]);
  if (!r.ok) return [];
  const out = [];
  for (const part of r.stdout.trim().split(/\s+/)) {
    const n = parseInt(part, 10);
    if (Number.isFinite(n) && n > 0) out.push(n);
  }
  return [...new Set(out)].sort((a, b) => a - b);
}

/**
 * Container-side TCP ports published by nginx (Ports map keys).
 * Demux: 443/tcp; exclusive panel TLS: 8443/tcp — distinguishes 443→443 vs 443→8443.
 */
async function nginxContainerTcpPorts() {
  const r = await runCmd('docker', [
    'inspect', '-f',
    '{{range $p, $conf := .NetworkSettings.Ports}}{{$p}} {{end}}',
    NGINX_CONTAINER,
  ]);
  if (!r.ok) return [];
  const out = [];
  for (const part of r.stdout.trim().split(/\s+/)) {
    const m = /^(\d+)\/tcp$/.exec(part);
    if (m) out.push(parseInt(m[1], 10));
  }
  return out.sort((a, b) => a - b);
}

/** @deprecated use nginxHostTcpPorts — name historically meant host publishes */
async function nginxPublishedTcpPorts() {
  return nginxHostTcpPorts();
}

function desiredNginxHostPorts(plan) {
  const set = new Set([80]); // ACME always from base compose; may already exist
  if (plan.panelExclusive) set.add(plan.panelExclusive.hostPort);
  if (plan.mirrorExclusive) set.add(plan.mirrorExclusive.hostPort);
  for (const d of plan.demuxPorts) set.add(d.port);
  return [...set].sort((a, b) => a - b);
}

/**
 * Assert host ports needed for demux/direct are free or already ours.
 * @param {number[]} ports
 * @param {{ allowNginx?: boolean, allowSidecar?: boolean }} opts
 *   allowSidecar (default true): treat our sidecars' -p as OK (direct).
 *   Set false when nginx must bind demux ports (sidecars must already have released).
 */
async function assertHostPortsAvailable(ports, opts = {}) {
  const nginxPorts = opts.allowNginx ? await nginxPublishedTcpPorts() : [];
  const nginxSet = new Set(nginxPorts);
  const allowSidecar = opts.allowSidecar !== false;
  for (const port of ports) {
    if (nginxSet.has(port)) continue;
    if (allowSidecar) {
      const xray = await runCmd('docker', [
        'inspect', '-f',
        '{{range $p, $conf := .NetworkSettings.Ports}}{{$p}} {{end}}',
        'amnezia-xray',
      ]);
      if (xray.ok && new RegExp(`${port}/tcp`).test(xray.stdout)) continue;
      const naive = await runCmd('docker', [
        'inspect', '-f',
        '{{range $p, $conf := .NetworkSettings.Ports}}{{$p}} {{end}}',
        'amnezia-naive',
      ]);
      if (naive.ok && new RegExp(`${port}/tcp`).test(naive.stdout)) continue;
      const mieru = await runCmd('docker', [
        'inspect', '-f',
        '{{range $p, $conf := .NetworkSettings.Ports}}{{$p}} {{end}}',
        'amnezia-mieru',
      ]);
      if (mieru.ok && new RegExp(`${port}/tcp`).test(mieru.stdout)) continue;
    }

    if (await isHostTcpPortInUse(port)) {
      const err = new Error(`Host TCP ${port} is in use by another process`);
      err.status = 409;
      err.code = 'HOST_PORT_BUSY';
      throw err;
    }
  }
}

async function reloadNginx() {
  const test = await runCmd('docker', ['exec', NGINX_CONTAINER, 'nginx', '-t'], { timeout: 15_000 });
  if (!test.ok) {
    throw new Error(`nginx config invalid: ${(test.stderr || test.stdout || '').trim().slice(0, 400)}`);
  }
  const reload = await runCmd('docker', ['exec', NGINX_CONTAINER, 'nginx', '-s', 'reload'], {
    timeout: 15_000,
  });
  if (!reload.ok) {
    throw new Error((reload.stderr || 'nginx reload failed').trim().slice(0, 300));
  }
}

/**
 * Remove nginx and wait until the name is free (avoids "name already in use").
 */
async function removeNginxContainer({ attempts = 5 } = {}) {
  for (let i = 0; i < attempts; i += 1) {
    await runCmd('docker', ['rm', '-f', NGINX_CONTAINER], { timeout: 60_000 });
    const check = await runCmd('docker', ['inspect', NGINX_CONTAINER], { timeout: 10_000 });
    if (!check.ok) return true;
    await new Promise((r) => setTimeout(r, 250 * (i + 1)));
  }
  return false;
}

function buildNginxRunArgs(plan, info) {
  const image = (info.Config && info.Config.Image) || 'amnezia-wg-easy-nginx:local';
  const env = patchNginxEnvFromDotEnv((info.Config && info.Config.Env) || []);
  const restart = (info.HostConfig && info.HostConfig.RestartPolicy && info.HostConfig.RestartPolicy.Name)
    || 'unless-stopped';

  const networks = Object.keys((info.NetworkSettings && info.NetworkSettings.Networks) || {});
  const primaryNet = networks.find((n) => n !== 'bridge') || networks[0];

  const mounts = [];
  for (const m of info.Mounts || []) {
    if (m.Type === 'volume' && m.Name && m.Destination) {
      mounts.push(`${m.Name}:${m.Destination}${m.RW === false ? ':ro' : ''}`);
    } else if (m.Type === 'bind' && m.Source && m.Destination) {
      mounts.push(`${m.Source}:${m.Destination}${m.RW === false ? ':ro' : ''}`);
    }
  }

  const portArgs = [];
  const httpPort = parsePort(process.env.PANEL_HTTP_PORT, 80);
  portArgs.push('-p', `${httpPort}:80`);
  if (plan.panelExclusive) {
    portArgs.push('-p', `${plan.panelExclusive.hostPort}:${plan.panelExclusive.containerPort}`);
  }
  if (plan.mirrorExclusive) {
    portArgs.push('-p', `${plan.mirrorExclusive.hostPort}:${plan.mirrorExclusive.containerPort}`);
  }
  for (const d of plan.demuxPorts) {
    portArgs.push('-p', `${d.port}:${d.port}`);
  }

  const args = [
    'run', '-d',
    '--name', NGINX_CONTAINER,
    '--restart', restart,
    '--label', 'com.docker.compose.project=amnezia-wg-easy',
    '--label', 'com.docker.compose.service=nginx',
    '--label', 'com.docker.compose.container-number=1',
  ];
  if (primaryNet) args.push('--network', primaryNet);
  for (const e of env) {
    args.push('-e', e);
  }
  for (const m of mounts) {
    args.push('-v', m);
  }
  args.push(...portArgs, image);
  return args;
}

/**
 * Recreate nginx with updated publish ports.
 * Prefer `docker compose … --force-recreate nginx` so the container keeps compose labels
 * (raw `docker run --name nginx` orphans break the next deploy.sh).
 * Always free the name first; retry on Conflict.
 */
async function recreateNginxForPlan(plan) {
  writeComposePortsFile(plan);

  const installDir = process.env.AWG_INSTALL_DIR || '/opt/amnezia-wg-easy';
  const composeYml = path.join(installDir, 'docker-compose.yml');
  const portsYml = path.join(installDir, COMPOSE_PORTS_NAME);
  const envFile = path.join(installDir, '.env');

  // Snapshot before remove — docker-run fallback needs image/env/mounts.
  const inspectBefore = await runCmd('docker', ['inspect', NGINX_CONTAINER], { timeout: 15_000 });
  let snap = null;
  if (inspectBefore.ok) {
    try {
      snap = JSON.parse(inspectBefore.stdout)[0];
    } catch {
      snap = null;
    }
  }

  const composeAvailable = async () => {
    if (!fs.existsSync(composeYml) || !fs.existsSync(portsYml)) return false;
    const ver = await runCmd('docker', ['compose', 'version'], { timeout: 15_000 });
    return ver.ok;
  };

  if (await composeAvailable()) {
    const composeArgs = ['compose'];
    if (fs.existsSync(envFile)) {
      composeArgs.push('--env-file', envFile);
    }
    composeArgs.push(
      '-f', composeYml,
      '-f', portsYml,
      'up', '-d', '--no-deps', '--force-recreate', '--remove-orphans',
      'nginx',
    );

    for (let attempt = 0; attempt < 3; attempt += 1) {
      await removeNginxContainer();
      const viaCompose = await runCmd('docker', composeArgs, { timeout: 180_000 });
      if (viaCompose.ok) {
        return { ok: true, recreated: true, via: 'compose' };
      }
      const errText = `${viaCompose.stderr || ''} ${viaCompose.stdout || ''}`;
      if (!/already in use|Conflict/i.test(errText) && attempt >= 1) {
        // non-conflict failure: fall through to docker-run
        break;
      }
    }
  }

  if (!snap) {
    // Last resort defaults when nginx was already gone
    snap = {
      Config: {
        Image: 'amnezia-wg-easy-nginx:local',
        Env: [],
      },
      HostConfig: { RestartPolicy: { Name: 'unless-stopped' } },
      NetworkSettings: { Networks: {} },
      Mounts: [],
    };
    const img = await runCmd('docker', ['image', 'inspect', 'amnezia-wg-easy-nginx:local'], { timeout: 10_000 });
    if (!img.ok) {
      throw new Error(
        'nginx recreate failed: no running nginx to clone and image amnezia-wg-easy-nginx:local missing '
        + '(compose files/plugin unavailable inside panel)',
      );
    }
  }

  const runArgs = buildNginxRunArgs(plan, snap);
  let lastErr = '';
  for (let attempt = 0; attempt < 4; attempt += 1) {
    const freed = await removeNginxContainer();
    if (!freed) {
      lastErr = 'failed to free container name "nginx"';
      continue;
    }
    const run = await runCmd('docker', runArgs, { timeout: 90_000 });
    if (run.ok) {
      return { ok: true, recreated: true, via: 'docker-run' };
    }
    lastErr = (run.stderr || run.stdout || 'failed to recreate nginx').trim();
    if (!/already in use|Conflict/i.test(lastErr)) {
      throw new Error(lastErr.slice(0, 400));
    }
  }
  throw new Error(lastErr.slice(0, 400) || 'failed to recreate nginx (name conflict)');
}

function portsNeedRecreate(plan) {
  // Compare logical publish set (excluding ephemeral)
  return desiredNginxHostPorts(plan).filter((p) => p !== 80);
}

/** Serialize applyPlan — concurrent recreate causes nginx name Conflict. */
let applyPlanChain = Promise.resolve();

async function applyPlanUnlocked() {
  const plan = computePlan();
  writeStreamConfigs(plan);
  writeComposePortsFile(plan);

  // Sidecars must drop host -p before nginx can publish demux ports.
  await releaseSidecarsForDemux(plan);
  await ensureUdpDirectSidecars(plan);

  const demuxHostPorts = plan.demuxPorts.map((d) => d.port);
  await assertHostPortsAvailable(demuxHostPorts, { allowNginx: true, allowSidecar: false });

  const udpHostPorts = (plan.udpDirect || []).map((s) => s.publicPort);
  if (udpHostPorts.length) {
    await assertHostUdpPortsAvailable(udpHostPorts, { allowSidecar: true });
  }

  const inspect = await runCmd('docker', ['inspect', '-f', '{{.State.Running}}', NGINX_CONTAINER]);
  if (!inspect.ok) {
    return { ok: false, skipped: true, reason: 'nginx missing', plan };
  }
  // Recover stuck "Created" from a previous failed port bind
  if (inspect.stdout.trim() !== 'true') {
    const start = await runCmd('docker', ['start', NGINX_CONTAINER], { timeout: 60_000 });
    if (!start.ok) {
      try {
        await recreateNginxForPlan(plan);
        return { ok: true, plan, recreated: true, recovered: true };
      } catch (err) {
        return { ok: false, skipped: true, reason: err.message || 'nginx not running', plan };
      }
    }
  }

  const current = await nginxHostTcpPorts();
  const containerPorts = await nginxContainerTcpPorts();
  const want = portsNeedRecreate(plan);
  const wantSet = new Set(want);

  let needRecreate = false;
  for (const p of want) {
    if (!current.includes(p)) needRecreate = true;
  }
  // Extra demux ports published that we no longer want
  for (const p of current) {
    if (p === 80) continue;
    if (plan.panelExclusive && p === plan.panelExclusive.hostPort) continue;
    if (plan.demuxPorts.some((d) => d.port === p)) continue;
    // leftover demux/old 443
    if (!plan.panelExclusive || p !== plan.panelExclusive.hostPort) {
      if (!wantSet.has(p)) needRecreate = true;
    }
  }
  if (plan.panelExclusive && !current.includes(plan.panelExclusive.hostPort)) {
    needRecreate = true;
  }
  // Panel joined demux on its public port: must publish demux listen (443→443),
  // not the old exclusive mapping (host→8443). Host port alone is ambiguous when
  // PANEL_HTTPS_PORT===443 — detect leftover container 8443 instead.
  if (!plan.panelExclusive && plan.demuxPorts.some((d) => d.port === panelPublicPort())) {
    if (containerPorts.includes(PANEL_TLS_INTERNAL)) {
      needRecreate = true;
    }
  }

  if (needRecreate) {
    await recreateNginxForPlan(plan);
  } else {
    await reloadNginx();
  }
  return { ok: true, plan, recreated: needRecreate };
}

function applyPlan() {
  const run = applyPlanUnlocked;
  const next = applyPlanChain.then(run, run);
  applyPlanChain = next.then(() => undefined, () => undefined);
  return next;
}

/**
 * Recreate sidecar containers without host publish when they join a demux group.
 */
async function releaseSidecarsForDemux(plan) {
  const demuxServices = new Set();
  for (const d of plan.demuxPorts || []) {
    for (const r of d.routes || []) {
      if (r.service && r.service !== 'panel') demuxServices.add(r.service);
    }
  }
  if (!demuxServices.size) return;

  if (demuxServices.has('xray')) {
    try {
      const xray = require('./amneziaXray');
      if (typeof xray.ensureXrayContainer === 'function') {
        await xray.ensureXrayContainer();
      }
    } catch (err) {
      // eslint-disable-next-line no-console
      console.error('portPlan: ensure xray for demux failed:', err && err.message);
    }
  }
  if (demuxServices.has('naive')) {
    try {
      const naive = require('./amneziaNaive');
      if (typeof naive.ensureNaiveContainer === 'function') {
        await naive.ensureNaiveContainer();
      }
    } catch (err) {
      // eslint-disable-next-line no-console
      console.error('portPlan: ensure naive for demux failed:', err && err.message);
    }
  }
}

async function ensureUdpDirectSidecars(plan) {
  const ids = new Set((plan.udpDirect || []).map((s) => s.id));
  if (ids.has('hysteria')) {
    try {
      const hysteria = require('./amneziaHysteria');
      if (typeof hysteria.ensureHysteriaContainer === 'function') {
        await hysteria.ensureHysteriaContainer();
      }
    } catch (err) {
      // eslint-disable-next-line no-console
      console.error('portPlan: ensure hysteria for udpDirect failed:', err && err.message);
    }
  }
  if (ids.has('mieru-udp')) {
    try {
      const mieru = require('./amneziaMieru');
      if (typeof mieru.ensureMieruContainer === 'function') {
        await mieru.ensureMieruContainer();
      }
    } catch (err) {
      // eslint-disable-next-line no-console
      console.error('portPlan: ensure mieru for udpDirect failed:', err && err.message);
    }
  }
}

/** @deprecated use applyPlan — kept for callers */
async function syncStreamDemux() {
  return applyPlan();
}

async function resolveNginxNetwork() {
  const fromContainer = async (name) => {
    const r = await runCmd('docker', [
      'inspect', '-f',
      '{{range $k, $v := .NetworkSettings.Networks}}{{$k}}{{println}}{{end}}',
      name,
    ]);
    if (!r.ok) return null;
    const names = r.stdout.split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
    const preferred = names.find((n) => n !== 'bridge' && n !== 'host' && n !== 'none');
    return preferred || names[0] || null;
  };
  return (await fromContainer(NGINX_CONTAINER))
    || (await fromContainer('amnezia-awg'))
    || null;
}

/**
 * SNI conflict when another demux peer already uses the same SNI on the same public port.
 */
function assertSniConflict(serviceId, sni, publicPort) {
  const s = String(sni || '').trim().toLowerCase();
  if (!s) return;
  const pub = parsePort(publicPort, 0);
  if (!pub) return;

  for (const other of collectServices()) {
    if (other.id === serviceId) continue;
    if (other.publicPort !== pub) continue;
    if (other.sni && other.sni === s) {
      const err = new Error(
        `${serviceId} SNI must differ from ${other.id} SNI when sharing public port ${pub} (demux)`,
      );
      err.status = 400;
      err.code = 'SNI_CONFLICT';
      throw err;
    }
  }
}

function getStatusSummary() {
  const plan = computePlan();
  return {
    demuxPorts: plan.demuxPorts.map((d) => ({
      port: d.port,
      routes: d.routes,
      defaultUpstream: d.defaultUpstream,
    })),
    direct: plan.direct,
    udpDirect: plan.udpDirect || [],
    panelExclusive: plan.panelExclusive,
    modes: plan.modes,
    demuxPeers: plan.demuxPeers,
    conflicts: plan.conflicts,
  };
}

module.exports = {
  NGINX_CONTAINER,
  PANEL_TLS_INTERNAL,
  MIRROR_TLS_INTERNAL,
  COMPOSE_PORTS_NAME,
  computePlan,
  applyPlan,
  syncStreamDemux,
  modeForService,
  isDemuxService,
  assertSniConflict,
  assertHostPortsAvailable,
  assertHostUdpPortsAvailable,
  isHostTcpPortInUse,
  isHostUdpPortInUse,
  collectUdpDirectServices,
  resolveNginxNetwork,
  getStatusSummary,
  writeStreamConfigs,
  writeComposePortsFile,
  composePortsPath,
  panelPublicPort,
  mirrorPublicPort,
  panelSni,
  isIpLiteral,
  panelCanJoinDemuxBySni,
  parsePort,
  reloadNginx,
  recreateNginxForPlan,
  patchNginxEnvFromDotEnv,
};
