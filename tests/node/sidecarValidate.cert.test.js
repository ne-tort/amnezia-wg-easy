'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

const sidecarValidate = require('../../src/lib/sidecarValidate');
const masqueradeBank = require('../../src/lib/masqueradeBank');
const config = require('../../src/config');

test('validatePanelCertConflict returns certSource field', () => {
  const panelPort = parseInt(String(config.PANEL_HTTPS_PORT || '443'), 10);
  const r = sidecarValidate.validatePanelCertConflict('panel', panelPort);
  assert.equal(r.ok, false);
  assert.ok(r.fieldErrors.certSource);
  assert.equal(r.code, 'CERT_PORT_CONFLICT');
});

test('validateXray tls panel on same port blocks certSource', () => {
  const panelPort = parseInt(String(config.PANEL_HTTPS_PORT || '443'), 10);
  const r = sidecarValidate.validateXray({
    security: 'tls',
    certSource: 'panel',
    publicPort: panelPort,
    sni: 'panel.example.com',
  });
  assert.equal(r.ok, false);
  assert.ok(r.fieldErrors.certSource);
});

test('validateXray tls self_signed passes without FQDN requirement in validate', () => {
  const r = sidecarValidate.validateXray({
    security: 'tls',
    certSource: 'self_signed',
    publicPort: 8443,
    sni: 'hysteria.local',
  });
  assert.equal(r.ok, true);
});

test('validateHysteria rejects bad masquerade URL', () => {
  const r = sidecarValidate.validateHysteria({
    sni: 'example.com',
    publicPort: 443,
    certSource: 'self_signed',
    masqueradeUrl: 'http://example.com/',
  });
  assert.equal(r.ok, false);
  assert.ok(r.fieldErrors.masqueradeUrl);
});

test('validateHysteria manual_pem requires PEM fields', () => {
  const r = sidecarValidate.validateHysteria({
    sni: 'test.local',
    publicPort: 443,
    certSource: 'manual_pem',
  });
  assert.equal(r.ok, false);
  assert.ok(r.fieldErrors.certSource);
});

test('masqueradeBank parseMasqueradeUrl requires https', () => {
  const bad = masqueradeBank.parseMasqueradeUrl('http://example.com/');
  assert.equal(bad.ok, false);
  const good = masqueradeBank.parseMasqueradeUrl('https://example.com/');
  assert.equal(good.ok, true);
  assert.equal(good.hostname, 'example.com');
});

test('masqueradeBank toMasqueradeUrl normalizes domain', () => {
  assert.equal(masqueradeBank.toMasqueradeUrl('www.example.com'), 'https://www.example.com/');
});

test('masqueradeBank loadMirrorBankDomains returns seed entries', () => {
  const domains = masqueradeBank.loadMirrorBankDomains();
  assert.ok(Array.isArray(domains));
  assert.ok(domains.length >= 1);
  assert.ok(domains.includes('www.sbb.ch'));
});
