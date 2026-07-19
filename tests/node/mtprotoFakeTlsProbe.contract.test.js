'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const srcRoot = path.join(__dirname, '..', '..', 'src');
const {
  parseEeSecret,
  buildClientHello,
  DIGEST_POS,
  DIGEST_LEN,
} = require(path.join(srcRoot, 'lib', 'mtprotoFakeTlsProbe.js'));

test('parseEeSecret extracts key and domain', () => {
  const domain = 'www.sbb.ch';
  const keyHex = 'c492f3ac1c22039c5b17a3b07e0aeb16';
  const ee = `ee${keyHex}${Buffer.from(domain).toString('hex')}`;
  const { key, domain: d } = parseEeSecret(ee);
  assert.equal(key.toString('hex'), keyHex);
  assert.equal(d, domain);
});

test('buildClientHello places digest at DIGEST_POS', () => {
  const random = Buffer.alloc(DIGEST_LEN, 0xab);
  const hello = buildClientHello('petrovich.ru', random);
  assert.equal(hello[0], 0x16);
  assert.equal(hello[1], 0x03);
  assert.equal(hello[2], 0x01);
  assert.deepEqual(hello.subarray(DIGEST_POS, DIGEST_POS + DIGEST_LEN), random);
});
