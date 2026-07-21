'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const templatePath = path.join(__dirname, '../../nginx/panel-subpath.conf.template');

test('panel-subpath template rewrites API/UI when using variable proxy_pass', () => {
  const src = fs.readFileSync(templatePath, 'utf8');
  assert.match(src, /rewrite \^\$\{WEBUI_PUBLIC_PREFIX\}\/api\/\(\.\*\)\$ \/api\/\$1 break;/);
  assert.match(src, /rewrite \^\$\{WEBUI_PUBLIC_PREFIX\}\/\(\.\*\)\$ \/\$1 break;/);
  // Variable + URI on proxy_pass drops the path suffix — must not use /api/ or /sub/ on proxy_pass.
  assert.doesNotMatch(src, /proxy_pass http:\/\/\$panel_upstream:\$\{PANEL_PORT\}\/api\//);
  assert.doesNotMatch(src, /proxy_pass http:\/\/\$panel_upstream:\$\{PANEL_PORT\}\/sub\//);
  assert.doesNotMatch(src, /proxy_pass http:\/\/\$panel_upstream:\$\{PANEL_PORT\}\/;/);
  assert.match(src, /set \$panel_upstream amnezia-awg;/);
  assert.match(src, /location \$\{SUB_PUBLIC_PREFIX\}\/[\s\S]*?proxy_pass http:\/\/\$panel_upstream:\$\{PANEL_PORT\};/);
  assert.match(src, /port_in_redirect off;/);
  assert.match(src, /return 302 https:\/\/\$\{PANEL_HTTPS_REDIRECT_HOST\}\$\{WEBUI_PUBLIC_PREFIX\}\/;/);
});
