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

const mtproto = (publicPort, listenPort = 25001, sni = 'cdn.cloudflare.com') => ({
  id: 'mtproto',
  publicPort,
  listenPort,
  sni,
  upstream: `amnezia-mtproto:${listenPort}`,
  alwaysOn: false,
});

test('computePlan: shared public port → demux', () => {
  const { portPlan } = loadPortPlan();
  const plan = portPlan.computePlan([
    panel(10123),
    xray(443),
    mtproto(443),
  ]);
  assert.equal(plan.demuxPorts.length, 1);
  assert.equal(plan.demuxPorts[0].port, 443);
  assert.equal(plan.demuxPorts[0].routes.length, 2);
  assert.equal(plan.direct.length, 0);
  assert.equal(plan.modes.xray, 'demux');
  assert.equal(plan.modes.mtproto, 'demux');
  assert.deepEqual(plan.demuxPeers.xray.sort(), ['mtproto']);
  assert.deepEqual(plan.demuxPeers.mtproto.sort(), ['xray']);
  assert.equal(plan.modes.panel, 'panel');
  assert.deepEqual(plan.panelExclusive, { hostPort: 10123, containerPort: 8443 });
  assert.equal(plan.conflicts.length, 0);
});

test('computePlan: distinct public ports → direct; no demux 443', () => {
  const { portPlan } = loadPortPlan();
  const plan = portPlan.computePlan([
    panel(10123),
    xray(443),
    mtproto(8443, 25001, 'www.gov.uk'),
  ]);
  assert.equal(plan.demuxPorts.length, 0);
  assert.equal(plan.modes.xray, 'direct');
  assert.equal(plan.modes.mtproto, 'direct');
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
    mtproto(443),
  ]);
  assert.equal(plan.demuxPorts.length, 1);
  assert.equal(plan.demuxPorts[0].port, 443);
  assert.equal(plan.demuxPorts[0].defaultUpstream, '127.0.0.1:8443');
  const services = plan.demuxPorts[0].routes.map((r) => r.service).sort();
  assert.deepEqual(services, ['mtproto', 'panel', 'xray']);
  assert.equal(plan.modes.panel, 'demux');
  assert.equal(plan.panelExclusive, null);
  assert.ok(plan.demuxPeers.panel.includes('xray'));
});

test('computePlan: bare-IP panel excluded from demux; default stays :9', () => {
  const { portPlan } = loadPortPlan({ PANEL_HTTPS_PORT: '443', PANEL_DOMAIN: '1.2.3.4' });
  const plan = portPlan.computePlan([
    panel(443, '1.2.3.4'),
    xray(443),
    mtproto(443),
  ]);
  assert.equal(plan.demuxPorts.length, 1);
  assert.equal(plan.demuxPorts[0].defaultUpstream, '127.0.0.1:9');
  assert.ok(!plan.demuxPorts[0].routes.some((r) => r.service === 'panel'));
  assert.ok(plan.conflicts.some((c) => c.code === 'PANEL_IP_ON_SHARED_PORT'));
  assert.notEqual(plan.modes.panel, 'demux');
});

test('computePlan: sidecar-only demux default is :9', () => {
  const { portPlan } = loadPortPlan();
  const plan = portPlan.computePlan([
    panel(10123),
    xray(443),
    mtproto(443),
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
    mtproto(443, 25001, 'same.example'),
  ]);
  assert.ok(plan.conflicts.some((c) => c.code === 'SNI_CONFLICT'));
});

test('assertSniConflict only when public ports match', () => {
  const { portPlan, settings } = loadPortPlan();
  settings.amnezia_xray_desired = '1';
  settings.amnezia_xray_sni = 'www.gov.uk';
  settings.amnezia_xray_public_port = '443';
  settings.amnezia_mtproto_desired = '1';
  settings.amnezia_mtproto_sni = 'www.gov.uk';
  settings.amnezia_mtproto_public_port = '443';

  assert.throws(
    () => portPlan.assertSniConflict('mtproto', 'www.gov.uk', 443),
    (err) => err && err.code === 'MTPROTO_SNI_CONFLICT',
  );

  // Different public ports → same SNI allowed
  assert.doesNotThrow(() => portPlan.assertSniConflict('mtproto', 'www.gov.uk', 8443));
});
