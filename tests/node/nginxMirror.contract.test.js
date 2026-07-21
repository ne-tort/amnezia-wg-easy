'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const entryPath = path.join(__dirname, '../../nginx/entrypoint.sh');

test('entrypoint rewrites mirror Location www↔apex and cookies', () => {
  const src = fs.readFileSync(entryPath, 'utf8');
  assert.match(src, /mirror_host_variants\(\)/);
  assert.match(src, /mirror_proxy_directives\(\)/);
  assert.match(src, /proxy_redirect https:\/\/\$\{vh\}\/ \/;/);
  assert.match(src, /proxy_redirect http:\/\/\$\{vh\}\/ \/;/);
  assert.match(src, /proxy_cookie_domain \$\{vh\} \\\$host;/);
  assert.match(src, /www\.\*/);
  assert.match(src, /root_block_entry_mirror/);
  assert.match(src, /root_block_exit_mirror/);
  // Both profiles must use shared directives (no bare proxy_pass without redirect).
  assert.match(src, /root_block_entry_mirror\(\)[\s\S]*mirror_proxy_directives/);
  assert.match(src, /root_block_exit_mirror\(\)[\s\S]*mirror_proxy_directives/);
});

test('entrypoint never redirects strangers to WEBUI_PUBLIC_PREFIX', () => {
  const src = fs.readFileSync(entryPath, 'utf8');
  // Split ports / missing mirror → stealth 444, not 302 to /panel
  assert.match(src, /root_block_entry_stealth\(\)/);
  assert.match(src, /return 444;/);
  assert.doesNotMatch(src, /location = \/ \{\s*\n\s*return 302/);
  assert.doesNotMatch(src, /return 302 https:\/\/\$\{PANEL_HTTPS_REDIRECT_HOST\}\$\{pf\}\//);
  // When ports are split, panel catch-all must be stealth (not mirror or panel redirect)
  assert.match(src, /mirror_ports_split; then[\s\S]*root_block_entry_stealth/);
});
