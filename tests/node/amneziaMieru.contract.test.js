'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const srcRoot = path.resolve(__dirname, '../../src');

function loadAmneziaMieru(settingsInit = {}, clientsInit = []) {
  const settings = Object.assign(Object.create(null), settingsInit);
  const clients = clientsInit.slice();
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
      getById(id) { return clients.find((c) => c.id === id) || null; },
      setMieruPassword(id, password) {
        const row = clients.find((c) => c.id === id);
        if (row) row.mieru_password = password;
      },
    },
  };

  const dbFile = path.join(srcRoot, 'lib', 'db.js');
  const mieruFile = path.join(srcRoot, 'lib', 'amneziaMieru.js');
  const confFile = path.join(srcRoot, 'config.js');

  delete require.cache[dbFile];
  delete require.cache[mieruFile];
  delete require.cache[confFile];

  require.cache[dbFile] = {
    id: dbFile, filename: dbFile, loaded: true, exports: dbExports,
  };

  process.env.WG_HOST = 'vpn.example.com';

  // eslint-disable-next-line import/no-dynamic-require, global-require
  const mod = require(mieruFile);
  return { amneziaMieru: mod, settings, clients };
}

test('buildMieruUrl encodes credentials and port', () => {
  const { amneziaMieru } = loadAmneziaMieru();
  const url = amneziaMieru.buildMieruUrl({
    username: 'alice',
    password: 'p@ss:word',
    host: '1.2.3.4',
    port: 3080,
    protocol: 'TCP',
  });
  assert.match(url, /^mierus:\/\//);
  assert.match(url, /alice/);
  assert.match(url, /port=3080/);
  assert.match(url, /protocol=TCP/);
});

test('buildServerConfigObject writes portBindings array + loggingLevel + mtu', () => {
  const { amneziaMieru, settings, clients } = loadAmneziaMieru({
    amnezia_mieru_tcp_enabled: '1',
    amnezia_mieru_udp_enabled: '1',
    amnezia_mieru_tcp_port: '35000',
    amnezia_mieru_udp_port: '35001',
    amnezia_mieru_logging_level: 'DEBUG',
    amnezia_mieru_mtu: '1400',
  }, [{
    id: 'c1', name: 'Alice', enabled: 1, mieru_password: 'secret1234567890',
  }]);

  const obj = amneziaMieru.buildServerConfigObject({
    portBindings: [
      { port: 35000, protocol: 'TCP' },
      { port: 35001, protocol: 'UDP' },
    ],
    loggingLevel: settings.amnezia_mieru_logging_level,
    mtu: 1400,
  });

  assert.deepEqual(obj.portBindings, [
    { port: 35000, protocol: 'TCP' },
    { port: 35001, protocol: 'UDP' },
  ]);
  assert.equal(obj.loggingLevel, 'DEBUG');
  assert.equal(obj.mtu, 1400);
  assert.equal(obj.users.length, 1);
  assert.equal(obj.users[0].name, 'alice');
  assert.equal(obj.users[0].password, 'secret1234567890');
  assert.equal(!('port' in obj), true);
  assert.equal(!('protocol' in obj), true);
  assert.deepEqual(obj.advancedSettings, { userHintIsMandatory: true });
});

test('buildPortBindings respects legacy protocol=UDP only', () => {
  const { amneziaMieru } = loadAmneziaMieru({
    amnezia_mieru_protocol: 'UDP',
    amnezia_mieru_port: '35002',
  });
  const bindings = amneziaMieru.buildPortBindings();
  assert.deepEqual(bindings, [{ port: 35002, protocol: 'UDP' }]);
});

test('buildMieruUrl includes multiplexing and handshake-mode', () => {
  const { amneziaMieru } = loadAmneziaMieru({
    amnezia_mieru_multiplexing: 'MIDDLE',
    amnezia_mieru_handshake_mode: 'HANDSHAKE_NO_WAIT',
  });
  const url = amneziaMieru.buildMieruUrl({
    username: 'bob',
    password: 'pw12345678901234',
    host: '1.2.3.4',
    port: 3080,
    protocol: 'TCP',
  });
  assert.match(url, /multiplexing=MIDDLE/);
  assert.match(url, /handshake-mode=HANDSHAKE_NO_WAIT/);
});

test('buildMieruUrl includes mtu for UDP', () => {
  const { amneziaMieru } = loadAmneziaMieru({
    amnezia_mieru_mtu: '1400',
  });
  const url = amneziaMieru.buildMieruUrl({
    username: 'bob',
    password: 'pw12345678901234',
    host: 'vpn.example.com',
    port: 3081,
    protocol: 'UDP',
  });
  assert.match(url, /mtu=1400/);
  assert.match(url, /multiplexing=LOW/);
});

test('getClientMieruPayload returns mieruUrls for dual TCP+UDP', () => {
  const { amneziaMieru } = loadAmneziaMieru({
    amnezia_mieru_tcp_enabled: '1',
    amnezia_mieru_udp_enabled: '1',
    amnezia_mieru_tcp_public_port: '3080',
    amnezia_mieru_udp_public_port: '3081',
    amnezia_mieru_address: 'vpn.example.com',
  });

  const payload = amneziaMieru.getClientMieruPayload({
    id: 'c1',
    name: 'Bob',
    enabled: 1,
    mieru_password: 'pw12345678901234',
  });

  assert.ok(payload);
  assert.equal(payload.mieruUrls.length, 2);
  assert.match(payload.mieruUrls[0], /protocol=TCP/);
  assert.match(payload.mieruUrls[0], /port=3080/);
  assert.match(payload.mieruUrls[1], /protocol=UDP/);
  assert.match(payload.mieruUrls[1], /port=3081/);
  assert.equal(payload.mieruUrl, payload.mieruUrls[0]);
  assert.equal(payload.tcpEnabled, true);
  assert.equal(payload.udpEnabled, true);
});

test('getClientMieruPayload backward compat with legacy publicPort + protocol', () => {
  const { amneziaMieru } = loadAmneziaMieru({
    amnezia_mieru_protocol: 'TCP',
    amnezia_mieru_public_port: '4090',
    amnezia_mieru_address: '1.2.3.4',
  });

  const payload = amneziaMieru.getClientMieruPayload({
    id: 'c1',
    name: 'Carol',
    enabled: 1,
    mieru_password: 'pw12345678901234',
  });

  assert.ok(payload);
  assert.equal(payload.mieruUrls.length, 1);
  assert.match(payload.mieruUrl, /port=4090/);
  assert.match(payload.mieruUrl, /protocol=TCP/);
});

test('getStatus exposes tcp/udp flags and ports from settings', () => {
  const { amneziaMieru } = loadAmneziaMieru({
    amnezia_mieru_tcp_enabled: '1',
    amnezia_mieru_udp_enabled: '1',
    amnezia_mieru_tcp_public_port: '3080',
    amnezia_mieru_udp_public_port: '3081',
    amnezia_mieru_mtu: '1400',
    amnezia_mieru_logging_level: 'WARN',
  });

  const st = amneziaMieru.getStatus();
  assert.equal(st.tcpEnabled, true);
  assert.equal(st.udpEnabled, true);
  assert.equal(st.tcpPublicPort, 3080);
  assert.equal(st.udpPublicPort, 3081);
  assert.equal(st.mtu, 1400);
  assert.equal(st.loggingLevel, 'WARN');
});
