'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');

const srcRoot = path.resolve(__dirname, '../../src');

function loadFinder(wgPath) {
  process.env.WG_PATH = wgPath;
  const confFile = path.join(srcRoot, 'config.js');
  const finderFile = path.join(srcRoot, 'lib', 'sniFinder.js');
  delete require.cache[confFile];
  delete require.cache[finderFile];
  // eslint-disable-next-line import/no-dynamic-require, global-require
  return require(finderFile);
}

test('isPublicIpv4 rejects private/special ranges', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sni-ip-'));
  const f = loadFinder(tmp);
  assert.equal(f.isPublicIpv4('8.8.8.8'), true);
  assert.equal(f.isPublicIpv4('10.0.0.1'), false);
  assert.equal(f.isPublicIpv4('192.168.1.1'), false);
  assert.equal(f.isPublicIpv4('100.64.0.1'), false);
});

test('isBlockedAutoTld skips .ru/.su/.рф; domainsFromCert omits them', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sni-tld-'));
  const f = loadFinder(tmp);
  assert.equal(f.isBlockedAutoTld('www.rutube.ru'), true);
  assert.equal(f.isBlockedAutoTld('mail.yandex.ru'), true);
  assert.equal(f.isBlockedAutoTld('example.su'), true);
  assert.equal(f.isBlockedAutoTld('site.xn--p1ai'), true);
  assert.equal(f.isBlockedAutoTld('www.gov.uk'), false);
  assert.equal(f.isBlockedAutoTld('foo.ru.com'), false);
  const domains = f.domainsFromCert('www.rutube.ru', ['www.sbb.ch', 'cdn.example.su']);
  assert.deepEqual(domains, ['www.sbb.ch']);
});

test('loadBankDomains / pickDefaultSni ignore blocked TLD in bank', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sni-bank-ru-'));
  const f = loadFinder(tmp);
  fs.mkdirSync(path.join(tmp, 'xray'), { recursive: true });
  fs.writeFileSync(
    path.join(tmp, 'xray', 'sni-bank.json'),
    JSON.stringify(['www.rutube.ru', 'ok.example.com']),
  );
  assert.deepEqual(f.loadBankDomains(), ['ok.example.com']);
  assert.equal(f.pickDefaultSni(), 'ok.example.com');
});

test('parseCidr / expandCidrHosts caps at /24 and rejects private', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sni-cidr-'));
  const f = loadFinder(tmp);
  const exp = f.expandCidrHosts('8.8.8.10/24');
  assert.equal(exp.meta.cidr, '8.8.8.0/24');
  assert.equal(exp.hosts.length, 254);
  assert.throws(() => f.parseCidr('8.8.0.0/16'), (err) => err.code === 'CIDR_TOO_LARGE');
  assert.throws(() => f.parseCidr('10.0.0.0/24'), (err) => err.code === 'CIDR_PRIVATE');
});

test('domainsFromCert expands wildcards; score orders by latency+distance', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sni-dom-'));
  const f = loadFinder(tmp);
  const domains = f.domainsFromCert('*.Example.COM', ['WWW.other.test']);
  assert.deepEqual(domains, ['example.com', 'www.example.com', 'www.other.test']);
  const near = f.scoreCandidate(10, '8.8.8.10', '8.8.8.1');
  const far = f.scoreCandidate(10, '1.1.1.1', '8.8.8.1');
  assert.ok(near < far);
});

test('mergeScanResults keeps prior scan domains', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sni-merge-'));
  const f = loadFinder(tmp);
  f.mergeScanResults(
    [{ domain: 'old.example', ip: '8.8.8.1', latencyMs: 5, score: 5 }],
    { refIp: '8.8.8.8', cidr: '8.8.8.0/24' },
  );
  f.mergeScanResults(
    [{ domain: 'new.example', ip: '8.8.8.2', latencyMs: 3, score: 3 }],
    { refIp: '8.8.8.8', cidr: '8.8.8.0/24' },
  );
  const list = f.getUnifiedList();
  const scan = list.entries.filter((e) => e.source === 'scan');
  const names = scan.map((e) => e.domain).sort();
  assert.deepEqual(names, ['new.example', 'old.example']);
});

test('unified list: bank below scan; pickDefault prefers scan', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sni-pick-'));
  const f = loadFinder(tmp);
  // volume bank override for isolation
  fs.mkdirSync(path.join(tmp, 'xray'), { recursive: true });
  fs.writeFileSync(path.join(tmp, 'xray', 'sni-bank.json'), JSON.stringify(['bank.example.com']));
  f.mergeScanResults(
    [{ domain: 'scan.example.com', ip: '1.1.1.1', latencyMs: 1, score: 1 }],
    { refIp: '1.1.1.1', cidr: '1.1.1.0/24' },
  );
  const list = f.getUnifiedList();
  const idxScan = list.entries.findIndex((e) => e.domain === 'scan.example.com');
  const idxBank = list.entries.findIndex((e) => e.domain === 'bank.example.com');
  assert.ok(idxScan >= 0 && idxBank >= 0);
  assert.ok(idxScan < idxBank);
  assert.equal(f.pickDefaultSni(), 'scan.example.com');
});

test('pickDefaultSni falls back to bank when no scan', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sni-bankonly-'));
  const f = loadFinder(tmp);
  fs.mkdirSync(path.join(tmp, 'xray'), { recursive: true });
  fs.writeFileSync(path.join(tmp, 'xray', 'sni-bank.json'), JSON.stringify(['only-bank.example']));
  assert.equal(f.pickDefaultSni(), 'only-bank.example');
});

test('cacheStatus marks expired scan as stale', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sni-cache-'));
  const f = loadFinder(tmp);
  const now = Date.now();
  f.writeCache({
    refIp: '8.8.8.8',
    cidr: '8.8.8.0/24',
    scannedAt: now - 48 * 3600 * 1000,
    expiresAt: now - 1000,
    entries: [{
      domain: 'a.example', ip: '8.8.8.1', source: 'scan', alive: true, latencyMs: 1, score: 1,
    }],
  });
  const st = f.cacheStatus();
  assert.equal(st.stale, true);
  assert.equal(st.scannedAliveCount, 1);
});

test('startScan rejects private CIDR synchronously', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sni-start-'));
  const f = loadFinder(tmp);
  f._job.phase = 'idle';
  f._job.promise = null;
  assert.throws(
    () => f.startScan({ cidr: '192.168.0.0/24', force: true }),
    (err) => err.code === 'CIDR_PRIVATE' && err.status === 400,
  );
});

test('finishEmpty path via soft codes keeps prior entries', async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sni-empty-'));
  const f = loadFinder(tmp);
  f.mergeScanResults(
    [{ domain: 'keep.example', ip: '8.8.8.1', latencyMs: 2, score: 2 }],
    { refIp: '8.8.8.8', cidr: '8.8.8.0/24' },
  );
  // Simulate finishEmpty
  f._job.phase = 'done';
  f._job.error = null;
  f._job.result = {
    empty: true,
    message: f.EMPTY_MSG,
    entries: f.getUnifiedList().entries,
  };
  assert.equal(f._job.result.empty, true);
  assert.equal(f._job.result.message, 'Nothing found');
  assert.ok(f.getUnifiedList().entries.some((e) => e.domain === 'keep.example'));
});
