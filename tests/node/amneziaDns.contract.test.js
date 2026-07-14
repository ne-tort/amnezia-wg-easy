'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const Module = require('node:module');
const path = require('node:path');

const srcRoot = path.resolve(__dirname, '../../src');

function installRequireMock(map) {
  const original = Module.prototype.require;
  Module.prototype.require = function mockRequire(id) {
    if (Object.prototype.hasOwnProperty.call(map, id)) return map[id];
    return original.apply(this, arguments);
  };
  return () => {
    Module.prototype.require = original;
  };
}

function loadAmneziaDns() {
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
  const wgExports = {
    saveConfig: async () => undefined,
  };

  const dbFile = path.join(srcRoot, 'lib', 'db.js');
  const wgFile = path.join(srcRoot, 'lib', 'WireGuard.js');
  const dnsFile = path.join(srcRoot, 'lib', 'amneziaDns.js');
  const confFile = path.join(srcRoot, 'config.js');

  delete require.cache[dbFile];
  delete require.cache[wgFile];
  delete require.cache[dnsFile];
  delete require.cache[confFile];

  require.cache[dbFile] = {
    id: dbFile,
    filename: dbFile,
    loaded: true,
    exports: dbExports,
  };
  require.cache[wgFile] = {
    id: wgFile,
    filename: wgFile,
    loaded: true,
    exports: wgExports,
  };

  process.env.WG_DEFAULT_ADDRESS = '10.8.0.x';
  process.env.WG_DEFAULT_DNS = '1.1.1.1';

  // eslint-disable-next-line import/no-dynamic-require, global-require
  const amneziaDns = require(dnsFile);
  return { amneziaDns, settings };
}

function loadBuildAmneziaRoot() {
  const restore = installRequireMock({
    qrcode: {
      toDataURL: async () => 'data:image/png;base64,AA==',
      toBuffer: async () => Buffer.from('x'),
    },
  });
  const qrFile = path.join(srcRoot, 'lib', 'amneziaClientQr.js');
  delete require.cache[qrFile];
  try {
    // eslint-disable-next-line import/no-dynamic-require, global-require
    return require(qrFile).buildAmneziaRoot;
  } finally {
    restore();
  }
}

test('isAmneziaDnsAvailable follows running phase only', () => {
  const { amneziaDns } = loadAmneziaDns();
  amneziaDns._setPhaseForTests('off');
  assert.equal(amneziaDns.isAmneziaDnsAvailable(), false);
  amneziaDns._setPhaseForTests('installing');
  assert.equal(amneziaDns.isAmneziaDnsAvailable(), false);
  amneziaDns._setPhaseForTests('running');
  assert.equal(amneziaDns.isAmneziaDnsAvailable(), true);
  amneziaDns._setPhaseForTests('degraded');
  assert.equal(amneziaDns.isAmneziaDnsAvailable(), false);
  amneziaDns._setPhaseForTests('error');
  assert.equal(amneziaDns.isAmneziaDnsAvailable(), false);
});

test('getStatus reports phase and desired from app_settings', () => {
  const { amneziaDns, settings } = loadAmneziaDns();
  settings.amnezia_dns_desired = '1';
  amneziaDns._setPhaseForTests('running');
  const st = amneziaDns.getStatus();
  assert.equal(st.desired, true);
  assert.equal(st.phase, 'running');
  assert.equal(st.available, true);
  assert.equal(st.busy, false);
});

test('concurrent enable is rejected with 409', async () => {
  const { amneziaDns } = loadAmneziaDns();
  amneziaDns._setActiveJobForTests(Promise.resolve());
  const err = await amneziaDns.enable().catch((e) => e);
  assert.ok(err instanceof Error);
  assert.equal(err.status, 409);
  amneziaDns._setActiveJobForTests(null);
});

test('buildAmneziaRoot DNS_RE accepts single gateway IP', () => {
  const buildAmneziaRoot = loadBuildAmneziaRoot();
  const ini = `[Interface]
PrivateKey = aabb
Address = 10.8.0.2/32
DNS = 10.8.0.1
MTU = 1280
Jc = 4
Jmin = 10
Jmax = 50
S1 = 0
S2 = 0
H1 = 1
H2 = 2
H3 = 3
H4 = 4

[Peer]
PublicKey = ccdd
Endpoint = 1.2.3.4:51820
AllowedIPs = 0.0.0.0/0
`;
  const root = buildAmneziaRoot(ini, 't', { includeAmneziaDns: true });
  assert.equal(root.dns1, '10.8.0.1');
  assert.equal(root.dns2, undefined);
  assert.ok(root.containers.some((c) => c.container === 'amnezia-dns'));
});

test('buildAmneziaRoot omits amnezia-dns container when flag false', () => {
  const buildAmneziaRoot = loadBuildAmneziaRoot();
  const ini = `[Interface]
PrivateKey = aabb
Address = 10.8.0.2/32
DNS = 8.8.8.8, 8.8.4.4
Jc = 4
Jmin = 10
Jmax = 50
S1 = 0
S2 = 0
H1 = 1
H2 = 2
H3 = 3
H4 = 4

[Peer]
PublicKey = ccdd
Endpoint = 1.2.3.4:51820
AllowedIPs = 0.0.0.0/0
`;
  const root = buildAmneziaRoot(ini, 't', { includeAmneziaDns: false });
  assert.equal(root.dns1, '8.8.8.8');
  assert.equal(root.dns2, '8.8.4.4');
  assert.ok(!root.containers.some((c) => c.container === 'amnezia-dns'));
});

test('enable failure without docker ends in error phase and desired off', async () => {
  const { amneziaDns, settings } = loadAmneziaDns();
  amneziaDns._setPhaseForTests('off');
  const err = await amneziaDns.enable().catch((e) => e);
  assert.ok(err instanceof Error);
  assert.equal(amneziaDns.getStatus().phase, 'error');
  assert.equal(amneziaDns.isAmneziaDnsAvailable(), false);
  assert.equal(settings.amnezia_dns_desired, '0');
});
