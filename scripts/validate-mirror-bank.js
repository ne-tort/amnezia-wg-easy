#!/usr/bin/env node
'use strict';

/**
 * Validate mirror-bank.seed.json entries as nginx root mirror stubs.
 * Usage:
 *   node scripts/validate-mirror-bank.js [--fail-on-dead] [--write]
 * --write  rewrite seed JSON keeping only hosts that pass validateMirrorHost
 */

const fs = require('node:fs');
const path = require('node:path');

process.chdir(path.join(__dirname, '..'));

const SEED = path.join(process.cwd(), 'config', 'mirror-bank.seed.json');
const masqueradeBank = require('../src/lib/masqueradeBank');

async function main() {
  const failOnDead = process.argv.includes('--fail-on-dead');
  const writeOk = process.argv.includes('--write');
  const domains = masqueradeBank.loadMirrorBankDomains();
  if (!domains.length) {
    console.error('No domains in mirror bank');
    process.exit(1);
  }
  console.log(`Checking ${domains.length} mirror bank entries (strict GET mirror probe)…`);
  const results = await masqueradeBank.validateBankEntries(domains);
  let dead = 0;
  const okDomains = [];
  for (const r of results) {
    const mark = r.ok ? 'OK' : 'FAIL';
    if (!r.ok) dead += 1;
    else okDomains.push(r.domain);
    const detail = [
      r.status || '-',
      r.finalHost && r.finalHost !== r.domain ? `→${r.finalHost}` : '',
      r.message || '',
    ].filter(Boolean).join('\t');
    console.log(`${mark}\t${r.domain}\t${detail}`);
  }
  console.log(`Done: ${results.length - dead} ok, ${dead} failed`);
  if (writeOk) {
    fs.writeFileSync(SEED, `${JSON.stringify(okDomains, null, 2)}\n`, 'utf8');
    console.log(`Wrote ${okDomains.length} domains to ${SEED}`);
  }
  if (failOnDead && dead > 0) process.exit(1);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
