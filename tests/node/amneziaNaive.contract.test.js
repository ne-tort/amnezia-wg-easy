'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const srcRoot = path.resolve(__dirname, '../../src');

function loadAmneziaNaive() {
  const naiveFile = path.join(srcRoot, 'lib', 'amneziaNaive.js');
  delete require.cache[naiveFile];
  // eslint-disable-next-line import/no-dynamic-require, global-require
  return require(naiveFile);
}

test('buildCaddyfileObject includes encode, log exclude, volume www root', () => {
  const amneziaNaive = loadAmneziaNaive();
  const text = amneziaNaive.buildCaddyfileObject({
    port: 8443,
    sni: 'naive.example.com',
    probeDomain: 'decoy.example.com',
    clients: [{ name: 'Alice', naive_password: 'secret1234567890', id: 'c1' }],
  });
  assert.match(text, /log \{/);
  assert.match(text, /exclude http\.log\.error/);
  assert.match(text, /encode/);
  assert.match(text, new RegExp(`root ${amneziaNaive.NAIVE_WWW_CONTAINER.replace(/\//g, '\\/')}`));
  assert.match(text, /probe_resistance decoy\.example\.com/);
});
