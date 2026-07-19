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
const STREAM_DIR_REL = path.join('nginx', 'stream');
const COMPOSE_PORTS_NAME = 'docker-compose.ports.yml';

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

  if (desired('amnezia_mtproto_desired')) {
    const pub = parsePort(
      setting('amnezia_mtproto_public_port', '') || process.env.MTPROTO_PUBLIC_PORT || '443',
      443,
    );
    const listen = parsePort(setting('amnezia_mtproto_port', ''), 0);
    const sni = setting('amnezia_mtproto_sni', '');
    services.push({
      id: 'mtproto',
      publicPort: pub,
      listenPort: listen,
      sni: sni.toLowerCase(),
      upstream: listen ? `amnezia-mtproto:${listen}` : null,
      alwaysOn: false,
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
    const sidecars = group.filter((s) => s.id === 'xray' || s.id === 'mtproto');
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

  return {
    demuxPorts,
    direct,
    panelExclusive,
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
    const conf = [
      `map $ssl_preread_server_name $demux_backend_${block.port} {`,
      `    include /opt/amnezia/awg/nginx/${mapName};`,
      `    default ${defaultUp};`,
      '}',
      '',
      'server {',
      `    listen ${block.port};`,
      '    ssl_preread on;',
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

async function nginxPublishedTcpPorts() {
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

function desiredNginxHostPorts(plan) {
  const set = new Set([80]); // ACME always from base compose; may already exist
  if (plan.panelExclusive) set.add(plan.panelExclusive.hostPort);
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
      const mt = await runCmd('docker', [
        'inspect', '-f',
        '{{range $p, $conf := .NetworkSettings.Ports}}{{$p}} {{end}}',
        'amnezia-mtproto',
      ]);
      if (mt.ok && new RegExp(`${port}/tcp`).test(mt.stdout)) continue;
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
 * Recreate nginx with updated -p list while preserving image/network/env/mounts.
 */
async function recreateNginxForPlan(plan) {
  const inspect = await runCmd('docker', ['inspect', NGINX_CONTAINER], { timeout: 15_000 });
  if (!inspect.ok) {
    return { ok: false, skipped: true, reason: 'nginx not found' };
  }
  let info;
  try {
    info = JSON.parse(inspect.stdout)[0];
  } catch {
    return { ok: false, skipped: true, reason: 'inspect parse failed' };
  }

  const image = info.Config && info.Config.Image;
  const env = (info.Config && info.Config.Env) || [];
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
  for (const d of plan.demuxPorts) {
    portArgs.push('-p', `${d.port}:${d.port}`);
  }

  await runCmd('docker', ['stop', NGINX_CONTAINER], { timeout: 60_000 });
  await runCmd('docker', ['rm', '-f', NGINX_CONTAINER], { timeout: 30_000 });

  const args = [
    'run', '-d',
    '--name', NGINX_CONTAINER,
    '--restart', restart,
  ];
  if (primaryNet) args.push('--network', primaryNet);
  for (const e of env) {
    args.push('-e', e);
  }
  for (const m of mounts) {
    args.push('-v', m);
  }
  args.push(...portArgs, image);

  const run = await runCmd('docker', args, { timeout: 90_000 });
  if (!run.ok) {
    throw new Error(run.stderr.trim() || 'failed to recreate nginx');
  }
  return { ok: true, recreated: true };
}

function portsNeedRecreate(plan) {
  // Compare logical publish set (excluding ephemeral)
  return desiredNginxHostPorts(plan).filter((p) => p !== 80);
}

async function applyPlan() {
  const plan = computePlan();
  writeStreamConfigs(plan);
  writeComposePortsFile(plan);

  // Sidecars must drop host -p before nginx can publish demux ports.
  await releaseSidecarsForDemux(plan);

  const demuxHostPorts = plan.demuxPorts.map((d) => d.port);
  await assertHostPortsAvailable(demuxHostPorts, { allowNginx: true, allowSidecar: false });

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

  const current = await nginxPublishedTcpPorts();
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
  if (!plan.panelExclusive && current.includes(panelPublicPort())
    && plan.demuxPorts.some((d) => d.port === panelPublicPort())) {
    // panel moved into demux — host still has old panel mapping style; recreate
    needRecreate = true;
  }

  if (needRecreate) {
    await recreateNginxForPlan(plan);
  } else {
    await reloadNginx();
  }
  return { ok: true, plan, recreated: needRecreate };
}

/**
 * Recreate Xray/MTProto containers without host publish when they join a demux group.
 */
async function releaseSidecarsForDemux(plan) {
  const demuxServices = new Set();
  for (const d of plan.demuxPorts || []) {
    for (const r of d.routes || []) {
      if (r.service === 'xray' || r.service === 'mtproto') demuxServices.add(r.service);
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
  if (demuxServices.has('mtproto')) {
    try {
      const mt = require('./amneziaMtproto');
      if (typeof mt.ensureMtprotoContainer === 'function') {
        await mt.ensureMtprotoContainer();
      }
    } catch (err) {
      // eslint-disable-next-line no-console
      console.error('portPlan: ensure mtproto for demux failed:', err && err.message);
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
 * SNI conflict only when both services share the same public port (demux).
 */
function assertSniConflict(serviceId, sni, publicPort) {
  const s = String(sni || '').trim().toLowerCase();
  if (!s) return;
  const pub = parsePort(publicPort, 0);
  if (!pub) return;

  if (serviceId === 'xray') {
    if (!desired('amnezia_mtproto_desired')) return;
    const mtPub = parsePort(
      setting('amnezia_mtproto_public_port', '') || process.env.MTPROTO_PUBLIC_PORT || '443',
      443,
    );
    if (mtPub !== pub) return;
    const mtSni = setting('amnezia_mtproto_sni', '').toLowerCase();
    if (mtSni && mtSni === s) {
      const err = new Error('Xray SNI must differ from MTProto SNI when sharing a public port (demux)');
      err.status = 400;
      err.code = 'XRAY_SNI_CONFLICT';
      throw err;
    }
  }
  if (serviceId === 'mtproto') {
    if (!desired('amnezia_xray_desired')) return;
    const xPub = parsePort(
      setting('amnezia_xray_public_port', '') || process.env.XRAY_PUBLIC_PORT || '443',
      443,
    );
    if (xPub !== pub) return;
    const xSni = setting('amnezia_xray_sni', '').toLowerCase();
    if (xSni && xSni === s) {
      const err = new Error('MTProto SNI must differ from Xray SNI when sharing a public port (demux)');
      err.status = 400;
      err.code = 'MTPROTO_SNI_CONFLICT';
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
    panelExclusive: plan.panelExclusive,
    modes: plan.modes,
    demuxPeers: plan.demuxPeers,
    conflicts: plan.conflicts,
  };
}

module.exports = {
  NGINX_CONTAINER,
  PANEL_TLS_INTERNAL,
  COMPOSE_PORTS_NAME,
  computePlan,
  applyPlan,
  syncStreamDemux,
  modeForService,
  isDemuxService,
  assertSniConflict,
  assertHostPortsAvailable,
  isHostTcpPortInUse,
  resolveNginxNetwork,
  getStatusSummary,
  writeStreamConfigs,
  writeComposePortsFile,
  composePortsPath,
  panelPublicPort,
  panelSni,
  isIpLiteral,
  panelCanJoinDemuxBySni,
  parsePort,
};
