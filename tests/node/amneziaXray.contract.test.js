'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const srcRoot = path.resolve(__dirname, '../../src');

function loadAmneziaXray() {
  const settings = Object.create(null);
  const clients = [];
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
    clients: {
      getAll() { return clients.slice(); },
      setXrayUuid(id, uuid) {
        const row = clients.find((c) => c.id === id);
        if (row) row.xray_uuid = uuid;
      },
      getById(id) { return clients.find((c) => c.id === id) || null; },
      getByName(name) { return clients.find((c) => c.name === name) || null; },
    },
  };
  const wgExports = { saveConfig: async () => undefined };

  const dbFile = path.join(srcRoot, 'lib', 'db.js');
  const wgFile = path.join(srcRoot, 'lib', 'WireGuard.js');
  const xrayFile = path.join(srcRoot, 'lib', 'amneziaXray.js');
  const confFile = path.join(srcRoot, 'config.js');

  delete require.cache[dbFile];
  delete require.cache[wgFile];
  delete require.cache[xrayFile];
  delete require.cache[confFile];

  require.cache[dbFile] = {
    id: dbFile, filename: dbFile, loaded: true, exports: dbExports,
  };
  require.cache[wgFile] = {
    id: wgFile, filename: wgFile, loaded: true, exports: wgExports,
  };

  process.env.WG_HOST = 'vpn.example.com';
  process.env.XRAY_PORT = '8443';

  // eslint-disable-next-line import/no-dynamic-require, global-require
  const amneziaXray = require(xrayFile);
  return { amneziaXray, settings, clients };
}

test('buildVlessUrl encodes Reality params', () => {
  const { amneziaXray } = loadAmneziaXray();
  const url = amneziaXray.buildVlessUrl({
    uuid: '11111111-1111-1111-1111-111111111111',
    host: 'vpn.example.com',
    port: 8443,
    sni: 'www.gov.uk',
    publicKey: 'pubKEY',
    shortId: 'abcd1234',
    fingerprint: 'chrome',
    flow: 'xtls-rprx-vision',
    remark: 'phone',
  });
  assert.match(url, /^vless:\/\/11111111-1111-1111-1111-111111111111@vpn\.example\.com:8443\?/);
  assert.match(url, /security=reality/);
  assert.match(url, /pbk=pubKEY/);
  assert.match(url, /sid=abcd1234/);
  assert.match(url, /sni=www\.gov\.uk/);
  assert.match(url, /fp=chrome/);
  assert.match(url, /flow=xtls-rprx-vision/);
  assert.match(url, /#phone$/);
});

test('buildVlessUrl omits empty flow', () => {
  const { amneziaXray } = loadAmneziaXray();
  const url = amneziaXray.buildVlessUrl({
    uuid: '11111111-1111-1111-1111-111111111111',
    host: 'h',
    port: 443,
    sni: 's',
    publicKey: 'p',
    shortId: 's1',
    fingerprint: 'chrome',
    flow: '',
    remark: '',
  });
  assert.equal(url.includes('flow='), false);
});

test('buildServerConfigObject lists enabled clients with email', () => {
  const { amneziaXray, settings, clients } = loadAmneziaXray();
  settings.amnezia_xray_desired = '1';
  clients.push(
    { id: 'a', name: 'Alice', enabled: 1, xray_uuid: 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa' },
    { id: 'b', name: 'Bob', enabled: 0, xray_uuid: 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb' },
  );
  const obj = amneziaXray.buildServerConfigObject({
    port: 8443,
    sni: 'www.example.com',
    privateKey: 'priv',
    shortId: 'deadbeef',
    flow: 'xtls-rprx-vision',
  });
  const list = obj.inbounds[0].settings.clients;
  assert.equal(list.length, 1);
  assert.equal(list[0].id, 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa');
  assert.equal(list[0].email, 'Alice');
  assert.equal(list[0].flow, 'xtls-rprx-vision');
  assert.equal(obj.inbounds[0].streamSettings.realitySettings.dest, 'www.example.com:443');
});

test('parseX25519Output accepts Private key / Public key lines', () => {
  const { amneziaXray } = loadAmneziaXray();
  const parsed = amneziaXray.parseX25519Output(
    'Private key: AAA\nPublic key: BBB\n',
  );
  assert.equal(parsed.privateKey, 'AAA');
  assert.equal(parsed.publicKey, 'BBB');
});

test('getStatus defaults and capabilities shape', () => {
  const { amneziaXray } = loadAmneziaXray();
  const st = amneziaXray.getStatus();
  assert.equal(st.desired, false);
  assert.equal(st.phase, 'off');
  assert.equal(st.port, 8443);
  assert.equal(st.sni, amneziaXray.DEFAULT_SNI);
  assert.ok(Array.isArray(st.fingerprints));
  assert.ok(st.fingerprints.includes('chrome'));
});

test('normalizePort clamps invalid values', () => {
  const { amneziaXray } = loadAmneziaXray();
  assert.equal(amneziaXray.normalizePort('9443'), 9443);
  assert.equal(amneziaXray.normalizePort('0', 8443), 8443);
  assert.equal(amneziaXray.normalizePort('99999', 8443), 8443);
  assert.equal(amneziaXray.normalizePort('', 8443), 8443);
});

test('getPublicHost prefers stored address over WG_HOST', () => {
  const { amneziaXray, settings } = loadAmneziaXray();
  assert.equal(amneziaXray.getPublicHost(), 'vpn.example.com');
  settings.amnezia_xray_address = '1.2.3.4';
  assert.equal(amneziaXray.getPublicHost(), '1.2.3.4');
});

test('buildVlessUrl omits spiderX; clientJson keeps empty spiderX', () => {
  const { amneziaXray } = loadAmneziaXray();
  const url = amneziaXray.buildVlessUrl({
    uuid: '11111111-1111-1111-1111-111111111111',
    host: 'h',
    port: 8443,
    sni: 'sni.example',
    publicKey: 'p',
    shortId: 's1',
    fingerprint: 'chrome',
    flow: 'xtls-rprx-vision',
  });
  assert.equal(url.includes('spiderX'), false);
  const json = amneziaXray.buildClientJson({
    uuid: '11111111-1111-1111-1111-111111111111',
    host: 'h',
    port: 8443,
    sni: 'sni.example',
    publicKey: 'p',
    shortId: 's1',
    fingerprint: 'chrome',
    flow: 'xtls-rprx-vision',
  });
  assert.equal(json.outbounds[0].streamSettings.realitySettings.spiderX, '');
});

test('disable-shaped settings: address and keys survive in app_settings map', () => {
  const { amneziaXray, settings } = loadAmneziaXray();
  settings.amnezia_xray_address = 'panel.example.com';
  settings.amnezia_xray_private_key = 'priv';
  settings.amnezia_xray_public_key = 'pub';
  settings.amnezia_xray_short_id = 'sid1234';
  settings.amnezia_xray_desired = '0';
  assert.equal(amneziaXray.getPublicHost(), 'panel.example.com');
  assert.equal(amneziaXray.getStatus().publicKey, 'pub');
  assert.equal(amneziaXray.getStatus().shortId, 'sid1234');
  assert.equal(amneziaXray.getStatus().desired, false);
});
