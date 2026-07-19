'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const srcRoot = path.resolve(__dirname, '../../src');

function loadMtproto() {
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
    clients: { getAll() { return []; } },
  };

  const dbFile = path.join(srcRoot, 'lib', 'db.js');
  const mtFile = path.join(srcRoot, 'lib', 'amneziaMtproto.js');
  const confFile = path.join(srcRoot, 'config.js');
  const xrayFile = path.join(srcRoot, 'lib', 'amneziaXray.js');

  delete require.cache[dbFile];
  delete require.cache[mtFile];
  delete require.cache[confFile];
  delete require.cache[xrayFile];

  require.cache[dbFile] = {
    id: dbFile, filename: dbFile, loaded: true, exports: dbExports,
  };
  require.cache[xrayFile] = {
    id: xrayFile,
    filename: xrayFile,
    loaded: true,
    exports: {
      getStatus: () => ({
        sniStored: settings.amnezia_xray_sni || null,
        sni: settings.amnezia_xray_sni || 'www.gov.uk',
      }),
    },
  };

  process.env.WG_HOST = 'vpn.example.com';
  process.env.DEMUX_PORT = '443';

  // eslint-disable-next-line import/no-dynamic-require, global-require
  const amneziaMtproto = require(mtFile);
  return { amneziaMtproto, settings };
}

test('buildEeSecret encodes domain hex', () => {
  const { amneziaMtproto } = loadMtproto();
  const ee = amneziaMtproto.buildEeSecret('1234567890abcdef1234567890abcdef', 'google.com');
  assert.equal(ee, `ee1234567890abcdef1234567890abcdef${Buffer.from('google.com').toString('hex')}`);
});

test('buildTgProxyLink uses demux port', () => {
  const { amneziaMtproto } = loadMtproto();
  const link = amneziaMtproto.buildTgProxyLink({
    host: '1.2.3.4',
    port: 443,
    eeSecret: 'eeabcd',
  });
  assert.match(link, /^tg:\/\/proxy\?/);
  assert.match(link, /server=1\.2\.3\.4/);
  assert.match(link, /port=443/);
  assert.match(link, /secret=eeabcd/);
});

test('getStatus exposes desired persistence keys', () => {
  const { amneziaMtproto, settings } = loadMtproto();
  settings.amnezia_mtproto_desired = '1';
  settings.amnezia_mtproto_sni = 'cdn.example';
  settings.amnezia_mtproto_secret = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
  settings.amnezia_mtproto_port = '25001';
  settings.amnezia_mtproto_address = 'vpn.example.com';
  const st = amneziaMtproto.getStatus();
  assert.equal(st.desired, true);
  assert.equal(st.sni, 'cdn.example');
  assert.equal(st.port, 25001);
  assert.equal(st.publicPort, 443);
  assert.match(st.link, /^tg:\/\/proxy\?/);
  // Without successful smoke, available/healthy stay false (no false-green).
  assert.equal(st.available, false);
  assert.equal(st.healthy, false);
});

test('buildConfigToml sets middle_proxy_nat_ip for IPv4 host', () => {
  const { amneziaMtproto } = loadMtproto();
  const toml = amneziaMtproto.buildConfigToml({
    port: 31179,
    sni: 'www.sbb.ch',
    secret: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    publicHost: '104.252.53.104',
    publicPort: 443,
  });
  assert.match(toml, /middle_proxy_nat_ip = "104\.252\.53\.104"/);
  assert.match(toml, /tls_domain = "www\.sbb\.ch"/);
  const tomlDom = amneziaMtproto.buildConfigToml({
    port: 31179,
    sni: 'www.sbb.ch',
    secret: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    publicHost: 'vpn.example.com',
    publicPort: 443,
  });
  assert.doesNotMatch(tomlDom, /middle_proxy_nat_ip/);
});

test('allocateInternalPort avoids demux and panel', () => {
  // eslint-disable-next-line import/no-dynamic-require, global-require
  const { allocateInternalPort, needsInternalRealloc } = require(path.join(srcRoot, 'lib', 'internalPort.js'));
  assert.equal(needsInternalRealloc(443), true);
  assert.equal(needsInternalRealloc(25001), false);
  const p = allocateInternalPort([10123, 25001], 25001);
  assert.notEqual(p, 25001);
  assert.ok(p >= 20000 && p <= 50000);
});
