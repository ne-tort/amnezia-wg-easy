'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const srcRoot = path.resolve(__dirname, '../../src');

function loadPortPlan(env = {}) {
  const settings = Object.create(null);
  const dbExports = {
    getDb() { return {}; },
    appSettings: {
      get(key) {
        return Object.prototype.hasOwnProperty.call(settings, key) ? settings[key] : null;
      },
      set(key, value) {
        settings[key] = value == null ? '' : String(value);
      },
    },
  };

  const dbFile = path.join(srcRoot, 'lib', 'db.js');
  const confFile = path.join(srcRoot, 'config.js');
  const planFile = path.join(srcRoot, 'lib', 'portPlan.js');

  delete require.cache[dbFile];
  delete require.cache[confFile];
  delete require.cache[planFile];

  require.cache[dbFile] = {
    id: dbFile, filename: dbFile, loaded: true, exports: dbExports,
  };

  for (const [k, v] of Object.entries(env)) {
    if (v == null) delete process.env[k];
    else process.env[k] = String(v);
  }
  process.env.WG_HOST = process.env.WG_HOST || 'vpn.example.com';
  process.env.PANEL_HTTPS_PORT = process.env.PANEL_HTTPS_PORT || '10123';

  // eslint-disable-next-line import/no-dynamic-require, global-require
  const portPlan = require(planFile);
  return { portPlan, settings };
}

const panel = (port = 10123, sni = 'vpn.example.com') => ({
  id: 'panel',
  publicPort: port,
  listenPort: 8443,
  sni,
  upstream: '127.0.0.1:8443',
  alwaysOn: true,
  canJoinDemux: !/^\d{1,3}(?:\.\d{1,3}){3}$/.test(sni) && !sni.includes(':') && sni !== 'localhost',
});

const xray = (publicPort, listenPort = 24443, sni = 'www.gov.uk') => ({
  id: 'xray',
  publicPort,
  listenPort,
  sni,
  upstream: `amnezia-xray:${listenPort}`,
  alwaysOn: false,
});

/** Generic future sidecar — keeps multi-peer demux architecture covered. */
const sidecar = (id, publicPort, listenPort = 25001, sni = 'cdn.cloudflare.com') => ({
  id,
  publicPort,
  listenPort,
  sni,
  upstream: `amnezia-${id}:${listenPort}`,
  alwaysOn: false,
});

test('computePlan: two sidecars on shared public port → demux', () => {
  const { portPlan } = loadPortPlan();
  const plan = portPlan.computePlan([
    panel(10123),
    xray(443),
    sidecar('future', 443),
  ]);
  assert.equal(plan.demuxPorts.length, 1);
  assert.equal(plan.demuxPorts[0].port, 443);
  assert.equal(plan.demuxPorts[0].routes.length, 2);
  assert.equal(plan.direct.length, 0);
  assert.equal(plan.modes.xray, 'demux');
  assert.equal(plan.modes.future, 'demux');
  assert.deepEqual(plan.demuxPeers.xray.sort(), ['future']);
  assert.deepEqual(plan.demuxPeers.future.sort(), ['xray']);
  assert.equal(plan.modes.panel, 'panel');
  assert.deepEqual(plan.panelExclusive, { hostPort: 10123, containerPort: 8443 });
  assert.equal(plan.conflicts.length, 0);
});

test('computePlan: distinct public ports → direct; no demux 443', () => {
  const { portPlan } = loadPortPlan();
  const plan = portPlan.computePlan([
    panel(10123),
    xray(443),
    sidecar('future', 8443, 25001, 'www.gov.uk'),
  ]);
  assert.equal(plan.demuxPorts.length, 0);
  assert.equal(plan.modes.xray, 'direct');
  assert.equal(plan.modes.future, 'direct');
  assert.deepEqual(plan.direct.map((d) => d.publicPort).sort(), [443, 8443]);
  assert.equal(plan.conflicts.length, 0);
});

test('computePlan: empty sidecars → no stream ports', () => {
  const { portPlan } = loadPortPlan();
  const plan = portPlan.computePlan([panel(10123)]);
  assert.equal(plan.demuxPorts.length, 0);
  assert.equal(plan.direct.length, 0);
  assert.equal(plan.modes.panel, 'panel');
  assert.deepEqual(plan.panelExclusive, { hostPort: 10123, containerPort: 8443 });
});

test('computePlan: panel joins demux when PANEL_HTTPS equals shared port', () => {
  const { portPlan } = loadPortPlan({ PANEL_HTTPS_PORT: '443' });
  const plan = portPlan.computePlan([
    panel(443, 'panel.example.com'),
    xray(443),
    sidecar('future', 443),
  ]);
  assert.equal(plan.demuxPorts.length, 1);
  assert.equal(plan.demuxPorts[0].port, 443);
  // FQDN panel: unknown SNI discarded; stub/UI only via panel SNI
  assert.equal(plan.demuxPorts[0].defaultUpstream, '127.0.0.1:9');
  const services = plan.demuxPorts[0].routes.map((r) => r.service).sort();
  assert.deepEqual(services, ['future', 'panel', 'xray']);
  assert.equal(plan.modes.panel, 'demux');
  assert.equal(plan.panelExclusive, null);
  assert.ok(plan.demuxPeers.panel.includes('xray'));
});

test('computePlan: bare-IP panel shares demux via catch-all (no named SNI)', () => {
  const { portPlan } = loadPortPlan({ PANEL_HTTPS_PORT: '443', PANEL_DOMAIN: '1.2.3.4' });
  const plan = portPlan.computePlan([
    panel(443, '1.2.3.4'),
    xray(443),
    sidecar('future', 443),
  ]);
  assert.equal(plan.demuxPorts.length, 1);
  assert.equal(plan.demuxPorts[0].defaultUpstream, '127.0.0.1:8443');
  assert.ok(!plan.demuxPorts[0].routes.some((r) => r.service === 'panel'));
  assert.equal(plan.conflicts.length, 0);
  assert.equal(plan.modes.panel, 'demux');
  assert.equal(plan.panelExclusive, null);
});

test('computePlan: panel+xray demux (single sidecar on panel port)', () => {
  const { portPlan } = loadPortPlan({ PANEL_HTTPS_PORT: '443' });
  const plan = portPlan.computePlan([
    panel(443, 'panel.example.com'),
    xray(443),
  ]);
  assert.equal(plan.demuxPorts.length, 1);
  assert.equal(plan.modes.xray, 'demux');
  assert.equal(plan.modes.panel, 'demux');
  assert.equal(plan.demuxPorts[0].defaultUpstream, '127.0.0.1:9');
});

test('computePlan: sidecar-only demux default is :9', () => {
  const { portPlan } = loadPortPlan();
  const plan = portPlan.computePlan([
    panel(10123),
    xray(443),
    sidecar('future', 443),
  ]);
  assert.equal(plan.demuxPorts[0].defaultUpstream, '127.0.0.1:9');
});

test('isIpLiteral / panelCanJoinDemuxBySni', () => {
  const { portPlan } = loadPortPlan();
  assert.equal(portPlan.isIpLiteral('1.2.3.4'), true);
  assert.equal(portPlan.isIpLiteral('panel.example.com'), false);
  assert.equal(portPlan.panelCanJoinDemuxBySni('panel.example.com'), true);
  assert.equal(portPlan.panelCanJoinDemuxBySni('31.56.211.60'), false);
});

test('computePlan: same SNI on shared port → SNI_CONFLICT', () => {
  const { portPlan } = loadPortPlan();
  const plan = portPlan.computePlan([
    panel(10123),
    xray(443, 24443, 'same.example'),
    sidecar('future', 443, 25001, 'same.example'),
  ]);
  assert.ok(plan.conflicts.some((c) => c.code === 'SNI_CONFLICT'));
});

test('assertSniConflict only when public ports match', () => {
  const { portPlan, settings } = loadPortPlan({
    PANEL_HTTPS_PORT: '443',
    PANEL_DOMAIN: 'panel.example.com',
  });
  settings.amnezia_xray_desired = '1';
  settings.amnezia_xray_sni = 'other.example';
  settings.amnezia_xray_public_port = '443';

  assert.throws(
    () => portPlan.assertSniConflict('xray', 'panel.example.com', 443),
    (err) => err && err.code === 'SNI_CONFLICT',
  );

  // Different public ports → same SNI as panel allowed
  assert.doesNotThrow(() => portPlan.assertSniConflict('xray', 'panel.example.com', 8443));
});

test('writeStreamConfigs: demux server includes Docker DNS resolver', () => {
  const fs = require('node:fs');
  const os = require('node:os');
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'portplan-'));
  const prev = process.env.WG_PATH;
  process.env.WG_PATH = tmp;
  try {
    const { portPlan } = loadPortPlan({ WG_PATH: tmp });
    const plan = portPlan.computePlan([
      panel(10123),
      xray(443),
      sidecar('future', 443),
    ]);
    portPlan.writeStreamConfigs(plan);
    const conf = fs.readFileSync(path.join(tmp, 'nginx', 'stream', 'demux-443.conf'), 'utf8');
    assert.match(conf, /resolver 127\.0\.0\.11 valid=10s ipv6=off;/);
    assert.match(conf, /proxy_pass \$demux_backend_443;/);
    assert.match(conf, /ssl_preread on;/);
    assert.doesNotMatch(conf, /proxy_protocol on;/);
    const map = fs.readFileSync(path.join(tmp, 'nginx', 'stream-sni-443.map'), 'utf8');
    assert.match(map, /amnezia-future:/);
    assert.match(map, /amnezia-xray:/);
  } finally {
    if (prev == null) delete process.env.WG_PATH;
    else process.env.WG_PATH = prev;
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('computePlan: mieru high port → direct TCP', () => {
  const { portPlan, settings } = loadPortPlan();
  settings.amnezia_mieru_desired = '1';
  settings.amnezia_mieru_tcp_enabled = '1';
  settings.amnezia_mieru_public_port = '3080';
  settings.amnezia_mieru_tcp_public_port = '3080';
  settings.amnezia_mieru_port = '35001';
  settings.amnezia_mieru_tcp_port = '35001';
  const plan = portPlan.computePlan();
  assert.equal(plan.modes['mieru-tcp'], 'direct');
  assert.ok(plan.direct.some((d) => d.service === 'mieru-tcp' && d.publicPort === 3080));
});

test('computePlan: mieru UDP → udpDirect', () => {
  const { portPlan, settings } = loadPortPlan();
  settings.amnezia_mieru_desired = '1';
  settings.amnezia_mieru_udp_enabled = '1';
  settings.amnezia_mieru_udp_public_port = '3081';
  settings.amnezia_mieru_udp_port = '35002';
  const plan = portPlan.computePlan();
  assert.ok(plan.udpDirect.some((d) => d.id === 'mieru-udp' && d.publicPort === 3081));
});

test('computePlan: naive + xray on 443 → demux', () => {
  const { portPlan, settings } = loadPortPlan({ PANEL_HTTPS_PORT: '443' });
  settings.amnezia_xray_desired = '1';
  settings.amnezia_xray_sni = 'www.gov.uk';
  settings.amnezia_xray_public_port = '443';
  settings.amnezia_naive_desired = '1';
  settings.amnezia_naive_sni = 'naive.example.com';
  settings.amnezia_naive_public_port = '443';
  const plan = portPlan.computePlan();
  assert.equal(plan.modes.naive, 'demux');
  assert.equal(plan.modes.xray, 'demux');
  const block = plan.demuxPorts.find((d) => d.port === 443);
  assert.ok(block);
  assert.ok(block.routes.some((r) => r.service === 'naive' && r.upstream === 'amnezia-naive:8443'));
});

test('computePlan: hysteria → udpDirect', () => {
  const { portPlan, settings } = loadPortPlan();
  settings.amnezia_hysteria_desired = '1';
  settings.amnezia_hysteria_public_port = '443';
  const plan = portPlan.computePlan();
  assert.ok(Array.isArray(plan.udpDirect));
  assert.ok(plan.udpDirect.some((u) => u.id === 'hysteria' && u.publicPort === 443 && u.protocol === 'udp'));
});

test('mirrorPublicPort: separate stub port when NGINX_MIRROR_HTTPS_PORT differs from panel', () => {
  const { portPlan } = loadPortPlan({
    PANEL_HTTPS_PORT: '4433',
    NGINX_MIRROR_HTTPS_PORT: '443',
  });
  assert.equal(portPlan.mirrorPublicPort(), 443);
  const plan = portPlan.computePlan([{
    id: 'panel',
    publicPort: 4433,
    listenPort: 8443,
    sni: 'panel.example.com',
    upstream: '127.0.0.1:8443',
    alwaysOn: true,
    canJoinDemux: true,
  }]);
  assert.deepEqual(plan.mirrorExclusive, { hostPort: 443, containerPort: 8444 });
  assert.deepEqual(plan.panelExclusive, { hostPort: 4433, containerPort: 8443 });
});

test('computePlan: mirror stub + xray direct on same port → demux with mirror default', () => {
  const { portPlan, settings } = loadPortPlan({
    PANEL_HTTPS_PORT: '4433',
    NGINX_MIRROR_HTTPS_PORT: '443',
  });
  settings.amnezia_xray_desired = '1';
  settings.amnezia_xray_public_port = '443';
  settings.amnezia_xray_port = '24443';
  settings.amnezia_xray_sni = 'vpn.example.com';

  const plan = portPlan.computePlan();
  assert.equal(plan.mirrorExclusive, null);
  assert.equal(plan.modes.xray, 'demux');
  assert.deepEqual(plan.direct, []);
  const demux = plan.demuxPorts.find((d) => d.port === 443);
  assert.ok(demux);
  assert.equal(demux.defaultUpstream, '127.0.0.1:8444');
  assert.ok(demux.routes.some((r) => r.service === 'xray' && r.sni === 'vpn.example.com'));
});
