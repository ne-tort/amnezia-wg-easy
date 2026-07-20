#!/usr/bin/env node
'use strict';

/**
 * Validate mirror-bank.seed.json entries via HTTPS preflight.
 * Usage: node scripts/validate-mirror-bank.js [--fail-on-dead]
 */

const path = require('node:path');

process.chdir(path.join(__dirname, '..'));

const masqueradeBank = require('../src/lib/masqueradeBank');

async function main() {
  const failOnDead = process.argv.includes('--fail-on-dead');
  const domains = masqueradeBank.loadMirrorBankDomains();
  if (!domains.length) {
    console.error('No domains in mirror bank');
    process.exit(1);
  }
  console.log(`Checking ${domains.length} masquerade bank entries…`);
  const results = await masqueradeBank.validateBankEntries(domains);
  let dead = 0;
  for (const r of results) {
    const mark = r.ok ? 'OK' : 'FAIL';
    if (!r.ok) dead += 1;
    console.log(`${mark}\t${r.domain}\t${r.status || '-'}${r.message ? `\t${r.message}` : ''}`);
  }
  console.log(`Done: ${results.length - dead} ok, ${dead} failed`);
  if (failOnDead && dead > 0) process.exit(1);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
