'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

const panelSettings = require('../../src/lib/panelSettings');

test('normalizePathPrefix defaults and strips trailing slash', () => {
  assert.equal(panelSettings.normalizePathPrefix(''), '/panel');
  assert.equal(panelSettings.normalizePathPrefix('/'), '/panel');
  assert.equal(panelSettings.normalizePathPrefix('admin'), '/admin');
  assert.equal(panelSettings.normalizePathPrefix('/ui/'), '/ui');
});

test('normalizeMirrorHost strips scheme and path', () => {
  assert.equal(panelSettings.normalizeMirrorHost('https://www.Example.com/path'), 'www.example.com');
  assert.equal(panelSettings.normalizeMirrorHost('WWW.GOV.UK:443'), 'www.gov.uk');
  assert.equal(panelSettings.normalizeMirrorHost(''), '');
});
