'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const { buildPanelPublicBaseUrl } = require(
  path.resolve(__dirname, '../../src/lib/panelPublicUrl.js')
);

test('buildPanelPublicBaseUrl appends PANEL_HTTPS_PORT when Host has no port', () => {
  const url = buildPanelPublicBaseUrl({
    requestUrl: new URL('https://work.ai-qwerty.ru/api/wireguard/client/x/xray'),
    panelDomain: 'work.ai-qwerty.ru',
    panelHttpsPort: '10123',
  });
  assert.equal(url, 'https://work.ai-qwerty.ru:10123');
});

test('buildPanelPublicBaseUrl keeps explicit request port', () => {
  const url = buildPanelPublicBaseUrl({
    requestUrl: new URL('https://work.ai-qwerty.ru:10123/api/x'),
    panelHttpsPort: '10123',
  });
  assert.equal(url, 'https://work.ai-qwerty.ru:10123');
});

test('buildPanelPublicBaseUrl omits suffix for 443', () => {
  const url = buildPanelPublicBaseUrl({
    requestUrl: new URL('https://vpn.example.com/'),
    panelHttpsPort: '443',
  });
  assert.equal(url, 'https://vpn.example.com');
});

test('buildPanelPublicBaseUrl falls back to PANEL_DOMAIN + port', () => {
  const url = buildPanelPublicBaseUrl({
    panelDomain: 'panel.example.com',
    panelHttpsPort: '8443',
    wgHost: '1.2.3.4',
  });
  assert.equal(url, 'https://panel.example.com:8443');
});
