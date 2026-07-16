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
  const vless = obj.inbounds.find((i) => i.protocol === 'vless');
  assert.ok(vless);
  const list = vless.settings.clients;
  assert.equal(list.length, 1);
  assert.equal(list[0].id, 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa');
  assert.equal(list[0].email, 'Alice');
  assert.equal(list[0].flow, 'xtls-rprx-vision');
  assert.equal(vless.streamSettings.realitySettings.dest, 'www.example.com:443');
  assert.ok(obj.stats);
  assert.ok(obj.api && obj.api.services.includes('StatsService'));
  assert.equal(obj.policy.levels['0'].statsUserUplink, true);
  assert.equal(obj.policy.levels['0'].statsUserOnline, true);
  const apiIn = obj.inbounds.find((i) => i.tag === 'api');
  assert.ok(apiIn);
  assert.equal(apiIn.port, amneziaXray.XRAY_API_PORT);
});

test('parseStatsQueryOutput maps user email uplink/downlink', () => {
  const { amneziaXray } = loadAmneziaXray();
  const map = amneziaXray.parseStatsQueryOutput(JSON.stringify({
    stat: [
      { name: 'user>>>Alice>>>traffic>>>uplink', value: '100' },
      { name: 'user>>>Alice>>>traffic>>>downlink', value: '250' },
      { name: 'user>>>Bob>>>traffic>>>uplink', value: '10' },
    ],
  }));
  assert.equal(map.get('Alice').uplink, 100);
  assert.equal(map.get('Alice').downlink, 250);
  assert.equal(map.get('Bob').uplink, 10);
  assert.equal(map.get('Bob').downlink, 0);
});

test('parseOnlineStatsOutput collects online emails', () => {
  const { amneziaXray } = loadAmneziaXray();
  const set = amneziaXray.parseOnlineStatsOutput(JSON.stringify({
    stat: [
      { name: 'user>>>Alice>>>online', value: '2' },
      { name: 'user>>>Bob>>>online', value: '0' },
      { name: 'user>>>Carol>>>traffic>>>uplink', value: '9' },
    ],
  }));
  assert.equal(set.has('Alice'), true);
  assert.equal(set.has('Bob'), false);
  assert.equal(set.has('Carol'), false);
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
  assert.ok(Array.isArray(json.inbounds));
  assert.equal(json.inbounds[0].listen, '127.0.0.1');
  assert.equal(json.inbounds[0].port, 10808);
  assert.equal(json.inbounds[0].protocol, 'socks');
  assert.equal(json.inbounds[0].settings.udp, true);
  assert.equal(json.log.loglevel, 'error');
});

test('buildAmneziaXrayContainer matches official Amnezia connection .vpn shape', () => {
  const { amneziaXray, settings } = loadAmneziaXray();
  settings.amnezia_xray_desired = '1';
  settings.amnezia_xray_public_key = 'pub';
  settings.amnezia_xray_short_id = 'sid1234';
  settings.amnezia_xray_sni = 'www.example.com';
  settings.amnezia_xray_port = '443';
  settings.amnezia_xray_address = '1.2.3.4';
  const el = amneziaXray.buildAmneziaXrayContainer({
    name: 'alice',
    xray_uuid: '11111111-1111-1111-1111-111111111111',
  });
  assert.equal(el.container, 'amnezia-xray');
  assert.deepEqual(Object.keys(el.xray), ['last_config', 'port', 'subnet_address', 'transport_proto']);
  assert.equal(el.xray.port, '443');
  assert.equal(el.xray.subnet_address, '10.8.1.0');
  assert.equal(el.xray.transport_proto, 'tcp');
  assert.equal(el.xray.isThirdPartyConfig, undefined);
  assert.equal(el.xray.site, undefined);
  assert.ok(el.xray.last_config.includes('\n'), 'last_config must be pretty-printed like official export');
  const lc = JSON.parse(el.xray.last_config);
  assert.equal(lc.inbounds[0].port, 10808);
  assert.equal(lc.outbounds[0].settings.vnext[0].address, '1.2.3.4');
  assert.deepEqual(
    Object.keys(lc.outbounds[0].settings.vnext[0].users[0]),
    ['id', 'flow', 'encryption'],
  );
  assert.equal(lc.outbounds[0].tag, undefined);
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
