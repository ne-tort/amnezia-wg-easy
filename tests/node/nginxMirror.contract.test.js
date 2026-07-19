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
