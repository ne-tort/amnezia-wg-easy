'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

const sidecarValidate = require('../../src/lib/sidecarValidate');
const masqueradeBank = require('../../src/lib/masqueradeBank');
const tlsMaterial = require('../../src/lib/tlsMaterial');
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

test('validateXray tls self_signed allows empty SNI', () => {
  const r = sidecarValidate.validateXray({
    security: 'tls',
    certSource: 'self_signed',
    publicPort: 8443,
    sni: '',
  });
  assert.equal(r.ok, true);
});

test('validateXray tls issue_le requires FQDN SNI', () => {
  const r = sidecarValidate.validateXray({
    security: 'tls',
    certSource: 'issue_le',
    publicPort: 8443,
    sni: '',
  });
  assert.equal(r.ok, false);
  assert.ok(r.fieldErrors.sni);
});

test('validateHysteria panel cert on same port as panel HTTPS is allowed', () => {
  const panelPort = parseInt(String(config.PANEL_HTTPS_PORT || '443'), 10);
  const r = sidecarValidate.validateHysteria({
    publicPort: panelPort,
    certSource: 'panel',
    sni: '',
  });
  // May fail only if panel domain missing — not for port conflict
  if (!r.ok) {
    assert.ok(!r.fieldErrors.certSource || r.code !== 'CERT_PORT_CONFLICT');
    assert.notEqual(r.code, 'CERT_PORT_CONFLICT');
  } else {
    assert.equal(r.ok, true);
  }
});

test('validateHysteria self_signed allows empty SNI', () => {
  const r = sidecarValidate.validateHysteria({
    publicPort: 443,
    certSource: 'self_signed',
    sni: '',
  });
  assert.equal(r.ok, true);
});

test('validateHysteria issue_le requires FQDN SNI', () => {
  const r = sidecarValidate.validateHysteria({
    publicPort: 443,
    certSource: 'issue_le',
    sni: '',
  });
  assert.equal(r.ok, false);
  assert.ok(r.fieldErrors.sni);
});

test('tlsMaterial.parseOpensslEnddate parses notAfter line', () => {
  const ms = tlsMaterial.parseOpensslEnddate('notAfter=Oct 18 15:12:24 2026 GMT');
  assert.ok(Number.isFinite(ms));
  assert.ok(ms > Date.UTC(2026, 9, 18));
  assert.equal(tlsMaterial.parseOpensslEnddate('garbage'), null);
});

test('tlsMaterial.normalizeHostname strips scheme path and port', () => {
  assert.equal(tlsMaterial.normalizeHostname('https://Naive.Example.com:8443/path'), 'naive.example.com');
  assert.equal(tlsMaterial.normalizeHostname('http://FOO.BAR/'), 'foo.bar');
  assert.equal(tlsMaterial.normalizeHostname('  Example.COM.  '), 'example.com');
});

test('tlsMaterial.getCertbotEmail returns env fallback shape', () => {
  const prev = process.env.CERTBOT_EMAIL;
  process.env.CERTBOT_EMAIL = 'le-test@example.com';
  try {
    const em = tlsMaterial.getCertbotEmail();
    assert.ok(typeof em === 'string');
    if (em) assert.ok(em.includes('@'));
  } finally {
    if (prev == null) delete process.env.CERTBOT_EMAIL;
    else process.env.CERTBOT_EMAIL = prev;
  }
});

test('validateNaive normalizes https URL SNI to hostname', () => {
  const r = sidecarValidate.validateNaive({
    sni: 'https://Naive.Example.com:8443/path',
    publicPort: 18444,
  });
  // May fail on port/SNI demux conflict; must not fail SNI parse
  if (!r.ok) {
    assert.equal(r.fieldErrors.sni, undefined, JSON.stringify(r.fieldErrors));
  } else {
    assert.equal(r.ok, true);
  }
});

test('validateNaive rejects IP as SNI', () => {
  const r = sidecarValidate.validateNaive({
    sni: '1.2.3.4',
    publicPort: 8444,
  });
  assert.equal(r.ok, false);
  assert.ok(r.fieldErrors.sni);
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
