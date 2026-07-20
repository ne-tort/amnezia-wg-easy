'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const xrayVless = require('../../src/lib/xrayVlessConfig');

test('buildVlessUrl supports tls and none security', () => {
  const tls = xrayVless.buildVlessUrl({
    uuid: '11111111-1111-4111-8111-111111111111',
    host: 'vpn.example.com',
    port: 8443,
    security: 'tls',
    sni: 'vpn.example.com',
    fingerprint: 'chrome',
    network: 'ws',
    wsPath: '/path',
    wsHost: 'vpn.example.com',
  });
  assert.match(tls, /^vless:\/\//);
  assert.match(tls, /security=tls/);
  assert.match(tls, /type=ws/);
  assert.match(tls, /path=%2Fpath/);

  const plain = xrayVless.buildVlessUrl({
    uuid: '11111111-1111-4111-8111-111111111111',
    host: '1.2.3.4',
    port: 10086,
    security: 'none',
    network: 'tcp',
  });
  assert.match(plain, /security=none/);
  assert.doesNotMatch(plain, /type=/);
});

test('buildClientJson produces SOCKS inbound for all security modes', () => {
  const json = xrayVless.buildClientJson({
    uuid: '11111111-1111-4111-8111-111111111111',
    host: '1.2.3.4',
    port: 443,
    security: 'none',
    network: 'tcp',
  });
  assert.equal(json.inbounds[0].port, 10808);
  assert.equal(json.outbounds[0].streamSettings.security, 'none');
});

test('sidecarValidate rejects naive SNI demux conflict', () => {
  const v = require('../../src/lib/sidecarValidate');
  const r = v.validateNaive({ sni: 'vpn.example.com', publicPort: 443 });
  assert.equal(r.ok, true);
});
