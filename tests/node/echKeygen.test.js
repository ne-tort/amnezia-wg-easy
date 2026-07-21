'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const echKeygen = require('../../src/lib/echKeygen');

const SAMPLE_PEM = `-----BEGIN ECH CONFIGS-----
AEn+DQBFAAAgACBgNHkpHTB1k63TZXk8tbRzjUyF41hp9tsf9puhnH59FQAMAAEA
AQABAAIAAQADAA5jbG91ZGZsYXJlLmNvbQAA
-----END ECH CONFIGS-----
-----BEGIN ECH KEYS-----
ACCms+MhBf39QHjGqwYPPTUubV+PNfJs+6DEwc843WuRQwBJ/g0ARQAAIAAgYDR5
KR0wdZOt02V5PLW0c41MheNYafbbH/aboZx+fRUADAABAAEAAQACAAEAAwAOY2xv
dWRmbGFyZS5jb20AAA==
-----END ECH KEYS-----
`;

test('extractConfigListBase64 parses ECH CONFIGS block', () => {
  const b64 = echKeygen.extractConfigListBase64(SAMPLE_PEM);
  assert.ok(b64);
  assert.match(b64, /^AEn\+/);
  assert.equal(b64.includes('\n'), false);
});

test('extractConfigListFromLog parses hysteria server log', () => {
  const log = 'INFO ECH enabled, set the following config list on clients (tls.ech) {"configList": "AEz+DQBIAAAg"}';
  assert.equal(echKeygen.extractConfigListFromLog(log), 'AEz+DQBIAAAg');
});

test('ensureEchMaterial reuses valid existing ech.pem', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ech-'));
  const pemPath = path.join(dir, 'ech.pem');
  fs.writeFileSync(pemPath, SAMPLE_PEM, 'utf8');
  const settings = Object.create(null);
  const res = await echKeygen.ensureEchMaterial({
    enabled: true,
    outPath: pemPath,
    excludeSni: 'real.example.com',
    getSetting: (k, fb = '') => (Object.prototype.hasOwnProperty.call(settings, k) ? settings[k] : fb),
    setSetting: (k, v) => { settings[k] = String(v); },
  });
  assert.equal(res.reused, true);
  assert.ok(res.configList);
  assert.equal(settings[echKeygen.ECH_CONFIG_LIST_KEY], res.configList);
  fs.rmSync(dir, { recursive: true, force: true });
});
