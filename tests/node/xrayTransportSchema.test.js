'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const schema = require('../../src/lib/xrayTransportSchema');
const xrayVless = require('../../src/lib/xrayVlessConfig');
const { SSL_CERT_AUTO } = require('../../src/lib/sidecarAutoCert');
const sidecarValidate = require('../../src/lib/sidecarValidate');
const amneziaHysteria = require('../../src/lib/amneziaHysteria');

test('xrayTransportSchema security matrix', () => {
  assert.deepEqual(schema.allowedSecurities('ws'), ['tls', 'none']);
  assert.deepEqual(schema.allowedSecurities('tcp'), ['reality', 'tls', 'none']);
  assert.equal(schema.supportsReality('grpc'), true);
  assert.equal(schema.supportsReality('ws'), false);
  assert.deepEqual(schema.allowedCertTypes('reality', 'ws'), []);
  assert.deepEqual(schema.allowedCertTypes('tls', 'ws'), ['self_signed', 'lets_encrypt', 'lets_encrypt_ip', 'manual']);
});

test('inheritTransportFields fills wsHost from sni', () => {
  const out = schema.inheritTransportFields({ sni: 'cdn.example.com' }, 'ws', {});
  assert.equal(out.wsHost, 'cdn.example.com');
});

test('buildStreamSettings supports ws grpc xhttp kcp', () => {
  const ws = xrayVless.buildStreamSettings({
    security: 'tls',
    network: 'ws',
    sni: 'cdn.example.com',
    wsPath: '/vless',
    wsHost: 'cdn.example.com',
  });
  assert.equal(ws.network, 'ws');
  assert.equal(ws.wsSettings.path, '/vless');

  const grpc = xrayVless.buildStreamSettings({
    security: 'reality',
    network: 'grpc',
    sni: 'cdn.example.com',
    grpcServiceName: 'grpc',
    grpcMultiMode: true,
  });
  assert.equal(grpc.grpcSettings.serviceName, 'grpc');
  assert.equal(grpc.grpcSettings.multiMode, true);

  const xhttp = xrayVless.buildStreamSettings({
    security: 'reality',
    network: 'xhttp',
    xhttpMode: 'auto',
    xhttpPath: '/x',
  });
  assert.equal(xhttp.xhttpSettings.mode, 'auto');

  const kcp = xrayVless.buildStreamSettings({
    security: 'tls',
    network: 'kcp',
    kcpMtu: 1350,
    kcpCongestion: true,
  });
  assert.equal(kcp.kcpSettings.mtu, 1350);
  assert.equal(kcp.kcpSettings.congestion, true);
  assert.equal(kcp.kcpSettings.header, undefined);
  assert.equal(kcp.kcpSettings.seed, undefined);

  const hy = xrayVless.buildStreamSettings({
    security: 'tls',
    network: 'hysteria',
    hysteriaAuth: 'secret',
  });
  assert.equal(hy.network, 'hysteria');
  assert.equal(hy.hysteriaSettings.auth, 'secret');
  assert.deepEqual(hy.tlsSettings.alpn, ['h3']);
});

test('hysteria transport builds VLESS inbound with required auth', () => {
  const inbound = xrayVless.buildServerInbound({
    security: 'tls',
    network: 'hysteria',
    port: 24443,
    sni: 'cdn.example.com',
    tlsCert: '/cert.pem',
    tlsKey: '/key.pem',
    hysteriaAuth: 'shared-secret',
    clients: [{ xray_uuid: '11111111-1111-4111-8111-111111111111', name: 'alice' }],
  });
  assert.equal(inbound.protocol, 'vless');
  assert.equal(inbound.streamSettings.network, 'hysteria');
  assert.equal(inbound.streamSettings.hysteriaSettings.auth, 'shared-secret');
  assert.deepEqual(inbound.streamSettings.tlsSettings.alpn, ['h3']);
  assert.equal(inbound.settings.clients[0].id, '11111111-1111-4111-8111-111111111111');

  assert.throws(() => xrayVless.buildServerInbound({
    security: 'tls',
    network: 'hysteria',
    port: 24443,
    clients: [],
  }), /hysteriaAuth/);

  const url = xrayVless.buildVlessUrl({
    uuid: '11111111-1111-4111-8111-111111111111',
    host: '1.2.3.4',
    port: 4433,
    security: 'tls',
    network: 'hysteria',
    sni: 'cdn.example.com',
    hysteriaAuth: 'shared-secret',
  });
  assert.match(url, /^vless:\/\//);
  assert.match(url, /type=hysteria/);
  assert.match(url, /auth=shared-secret/);
  assert.match(url, /alpn=h3/);

  const client = xrayVless.buildClientJson({
    uuid: '11111111-1111-4111-8111-111111111111',
    host: '1.2.3.4',
    port: 4433,
    security: 'tls',
    network: 'hysteria',
    sni: 'cdn.example.com',
    hysteriaAuth: 'shared-secret',
  });
  assert.equal(client.outbounds[0].protocol, 'vless');
  assert.equal(client.outbounds[0].streamSettings.hysteriaSettings.auth, 'shared-secret');
});

test('xrayHysteriaInbound maps gecko to salamander packetSize', () => {
  const { buildHysteriaInbound } = require('../../src/lib/xrayHysteriaInbound');
  const inbound = buildHysteriaInbound({
    port: 34443,
    users: [{ auth: 'p', email: 'u' }],
    sni: 't.example',
    tlsCert: '/c',
    tlsKey: '/k',
    obfsType: 'gecko',
    obfsPassword: 'secret',
    obfsGeckoMin: 512,
    obfsGeckoMax: 1200,
  });
  assert.equal(inbound.protocol, 'hysteria');
  assert.equal(inbound.streamSettings.finalmask.udp[0].type, 'salamander');
  assert.equal(inbound.streamSettings.finalmask.udp[0].settings.password, 'secret');
  assert.equal(inbound.streamSettings.finalmask.udp[0].settings.packetSize, '512-1200');
});

test('buildVlessUrl encodes transport params', () => {
  const url = xrayVless.buildVlessUrl({
    uuid: '11111111-1111-4111-8111-111111111111',
    host: '1.2.3.4',
    port: 443,
    security: 'tls',
    network: 'xhttp',
    xhttpPath: '/dl',
    xhttpHost: 'cdn.example.com',
    xhttpMode: 'auto',
  });
  assert.match(url, /type=xhttp/);
  assert.match(url, /path=%2Fdl/);
  assert.match(url, /mode=auto/);
});

test('effectiveFlow clears flow for grpc', () => {
  assert.equal(xrayVless.effectiveFlow({
    security: 'reality',
    network: 'grpc',
    flow: 'xtls-rprx-vision',
  }), '');
});

test('validateXray accepts __auto__ sslCertId', () => {
  const r = sidecarValidate.validateXray({
    security: 'tls',
    network: 'tcp',
    publicPort: 8443,
    sslCertId: SSL_CERT_AUTO,
  });
  assert.equal(r.ok, true);
  assert.equal(r.autoCert, true);
});

test('validateXray rejects reality on ws', () => {
  const r = sidecarValidate.validateXray({
    security: 'reality',
    network: 'ws',
    publicPort: 443,
    sni: 'example.com',
  });
  assert.equal(r.ok, false);
});

test('hysteria buildServerYamlObject gecko and congestion', () => {
  const obj = amneziaHysteria.buildServerYamlObject({
    userpass: { u: 'p' },
    certDomain: 'test.local',
    sni: 'test.local',
    obfsType: 'gecko',
    obfsPassword: 'secret',
    obfsGeckoMin: 512,
    obfsGeckoMax: 1200,
    congestionType: 'bbr',
    bbrProfile: 'aggressive',
    listenMode: 'port_hopping',
    portRange: '20000-50000',
  });
  assert.equal(obj.listen, ':20000-50000');
  assert.equal(obj.obfs.type, 'gecko');
  assert.equal(obj.obfs.gecko.minPacketSize, 512);
  assert.equal(obj.congestion.bbrProfile, 'aggressive');
  const yaml = amneziaHysteria.renderServerYaml(obj);
  assert.match(yaml, /type: gecko/);
  assert.match(yaml, /congestion:/);
});

test('hysteria buildHy2Url includes ech param', () => {
  const url = amneziaHysteria.buildHy2Url({
    username: 'u',
    password: 'p',
    host: '1.2.3.4',
    port: 443,
    sni: 'test.local',
    ech: 'AEz+DQBIAAAg',
    insecure: true,
  });
  assert.match(url, /ech=AEz/);
});

test('hysteria buildServerYamlObject adds ech when ech.pem exists on volume', () => {
  const fs = require('node:fs');
  const os = require('node:os');
  const path = require('node:path');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hy-ech-'));
  process.env.WG_PATH = `${dir}${path.sep}`;
  delete require.cache[require.resolve('../../src/config')];
  delete require.cache[require.resolve('../../src/lib/amneziaHysteria')];
  const hy = require('../../src/lib/amneziaHysteria');
  const pemPath = path.join(dir, 'hysteria', 'ech.pem');
  fs.mkdirSync(path.dirname(pemPath), { recursive: true });
  fs.writeFileSync(pemPath, `-----BEGIN ECH CONFIGS-----\nABC\n-----END ECH CONFIGS-----\n`, 'utf8');
  const obj = hy.buildServerYamlObject({
    userpass: { u: 'p' },
    certDomain: 'test.local',
    sni: 'test.local',
    echEnabled: true,
  });
  assert.ok(obj.tls.ech);
  assert.equal(obj.tls.ech.keyPath, '/opt/amnezia/awg/hysteria/ech.pem');
  fs.rmSync(dir, { recursive: true, force: true });
  delete process.env.WG_PATH;
  delete require.cache[require.resolve('../../src/config')];
  delete require.cache[require.resolve('../../src/lib/amneziaHysteria')];
});
