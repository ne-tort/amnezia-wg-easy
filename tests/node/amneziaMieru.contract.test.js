'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const srcRoot = path.resolve(__dirname, '../../src');

function loadAmneziaMieru() {
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
      getById(id) { return clients.find((c) => c.id === id) || null; },
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
  return require(mieruFile);
}

test('buildMieruUrl encodes credentials and port', () => {
  const amneziaMieru = loadAmneziaMieru();
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
