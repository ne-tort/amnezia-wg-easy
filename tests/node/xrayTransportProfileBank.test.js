'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const srcRoot = path.resolve(__dirname, '../../src');

function loadProfileBank(settingsInit = {}) {
  const settings = Object.assign(Object.create(null), settingsInit);
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
  const bankFile = path.join(srcRoot, 'lib', 'xrayTransportProfileBank.js');
  delete require.cache[dbFile];
  delete require.cache[bankFile];
  require.cache[dbFile] = { id: dbFile, filename: dbFile, loaded: true, exports: dbExports };
  // eslint-disable-next-line import/no-dynamic-require, global-require
  return { bank: require(bankFile), settings };
}

test('ensureBankSeeded loads tcp profiles from seed', () => {
  const { bank } = loadProfileBank();
  const profiles = bank.listProfiles('tcp');
  assert.ok(profiles.length >= 2);
  assert.ok(profiles.some((p) => p.id === 'tcp-plain'));
});

test('saveProfile persists to app_settings', () => {
  const { bank, settings } = loadProfileBank();
  bank.ensureBankSeeded();
  const saved = bank.saveProfile('tcp', { name: 'Custom TCP', settings: { headerType: 'none', tcpCongestion: 'cubic' } });
  assert.equal(saved.name, 'Custom TCP');
  assert.ok(settings[bank.BANK_KEY]);
  const parsed = JSON.parse(settings[bank.BANK_KEY]);
  assert.ok(parsed.tcp.some((p) => p.name === 'Custom TCP'));
});
