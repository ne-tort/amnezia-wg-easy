'use strict';

/**
 * VLESS transport UI (mirrors src/lib/xrayTransportSchema.js for browser).
 */

const SSL_CERT_AUTO = '__auto__';

const XRAY_TRANSPORTS = [
  { id: 'tcp', label: 'RAW TCP', deprecated: false },
  { id: 'xhttp', label: 'XHTTP', deprecated: false },
  { id: 'grpc', label: 'gRPC', deprecated: true },
  { id: 'ws', label: 'WebSocket', deprecated: true },
  { id: 'httpupgrade', label: 'HTTPUpgrade', deprecated: true },
  { id: 'kcp', label: 'mKCP', deprecated: false },
  { id: 'hysteria', label: 'Hysteria', deprecated: false },
];

const SECURITY_BY_TRANSPORT = {
  tcp: ['reality', 'tls', 'none'],
  xhttp: ['reality', 'tls', 'none'],
  grpc: ['reality', 'tls', 'none'],
  ws: ['tls', 'none'],
  httpupgrade: ['tls', 'none'],
  kcp: ['tls', 'none'],
  hysteria: ['tls'],
};

const TCP_CONGESTION = ['bbr', 'cubic', 'reno', 'bbr2'];
const HTTP_VERSIONS = ['1.1', '2'];
const HTTP_METHODS = ['GET', 'POST', 'PUT', 'HEAD', 'OPTIONS'];
const DOMAIN_STRATEGIES = ['AsIs', 'UseIP', 'UseIPv4', 'UseIPv6'];
const XHTTP_MODES = ['auto', 'stream-one', 'stream-up', 'packet-up'];
const TCP_HEADER_TYPES = ['none', 'http'];

const SOCKOPT_FIELDS = [
  { key: 'tcpFastOpen', type: 'bool', optional: true, scope: 'shared', labelKey: 'xrayTfTcpFastOpen' },
  { key: 'tcpCongestion', type: 'select', optional: true, scope: 'shared', labelKey: 'xrayTfTcpCongestion', options: TCP_CONGESTION, default: 'bbr' },
  { key: 'domainStrategy', type: 'select', optional: true, scope: 'shared', labelKey: 'xrayTfDomainStrategy', options: DOMAIN_STRATEGIES },
  { key: 'acceptProxyProtocol', type: 'bool', optional: true, scope: 'shared', labelKey: 'xrayTfAcceptProxyProtocol' },
];

const TRANSPORT_FIELDS = {
  tcp: [
    { key: 'headerType', type: 'select', optional: true, default: 'none', scope: 'shared', labelKey: 'xrayTfHeaderType', options: TCP_HEADER_TYPES },
    { key: 'httpVersion', type: 'select', optional: true, scope: 'shared', labelKey: 'xrayTfHttpVersion', default: '1.1', options: HTTP_VERSIONS, showIf: { headerType: 'http' } },
    { key: 'httpMethod', type: 'select', optional: true, scope: 'shared', labelKey: 'xrayTfHttpMethod', default: 'GET', options: HTTP_METHODS, showIf: { headerType: 'http' } },
    { key: 'httpPath', type: 'text', optional: true, scope: 'shared', labelKey: 'xrayTfHttpPath', default: '/', showIf: { headerType: 'http' } },
    { key: 'httpHost', type: 'text', optional: true, scope: 'shared', labelKey: 'xrayTfHttpHost', inheritFrom: 'sni', showIf: { headerType: 'http' } },
    ...SOCKOPT_FIELDS,
  ],
  ws: [
    { key: 'wsPath', type: 'text', optional: true, default: '/', scope: 'shared', labelKey: 'xrayTfWsPath' },
    { key: 'wsHost', type: 'text', optional: true, scope: 'shared', labelKey: 'xrayTfWsHost', inheritFrom: 'sni' },
    { key: 'wsHeaders', type: 'json', optional: true, scope: 'shared', labelKey: 'xrayTfWsHeaders' },
    { key: 'acceptProxyProtocol', type: 'bool', optional: true, scope: 'shared', labelKey: 'xrayTfAcceptProxyProtocol' },
  ],
  grpc: [
    { key: 'grpcServiceName', type: 'text', optional: false, scope: 'shared', labelKey: 'xrayTfGrpcServiceName' },
    { key: 'grpcMultiMode', type: 'bool', optional: true, scope: 'shared', labelKey: 'xrayTfGrpcMultiMode' },
    { key: 'grpcAuthority', type: 'text', optional: true, scope: 'shared', labelKey: 'xrayTfGrpcAuthority', inheritFrom: 'sni' },
    { key: 'grpcIdleTimeout', type: 'number', optional: true, scope: 'shared', labelKey: 'xrayTfGrpcIdleTimeout' },
  ],
  kcp: [
    { key: 'kcpMtu', type: 'number', optional: true, scope: 'shared', labelKey: 'xrayTfKcpMtu' },
    { key: 'kcpTti', type: 'number', optional: true, scope: 'shared', labelKey: 'xrayTfKcpTti' },
    { key: 'kcpUplinkCapacity', type: 'number', optional: true, scope: 'shared', labelKey: 'xrayTfKcpUplinkCapacity' },
    { key: 'kcpDownlinkCapacity', type: 'number', optional: true, scope: 'shared', labelKey: 'xrayTfKcpDownlinkCapacity' },
    { key: 'kcpReadBufferSize', type: 'number', optional: true, scope: 'shared', labelKey: 'xrayTfKcpReadBufferSize' },
    { key: 'kcpWriteBufferSize', type: 'number', optional: true, scope: 'shared', labelKey: 'xrayTfKcpWriteBufferSize' },
    { key: 'kcpCongestion', type: 'bool', optional: true, scope: 'shared', labelKey: 'xrayTfKcpCongestion' },
  ],
  httpupgrade: [
    { key: 'httpupgradeHost', type: 'text', optional: true, scope: 'shared', labelKey: 'xrayTfHttpupgradeHost', inheritFrom: 'sni' },
    { key: 'httpupgradePath', type: 'text', optional: true, default: '/', scope: 'shared', labelKey: 'xrayTfHttpupgradePath' },
    { key: 'httpupgradeHeaders', type: 'json', optional: true, scope: 'shared', labelKey: 'xrayTfHttpupgradeHeaders' },
  ],
  xhttp: [
    { key: 'xhttpMode', type: 'select', optional: true, default: 'auto', scope: 'shared', labelKey: 'xrayTfXhttpMode', options: XHTTP_MODES },
    { key: 'xhttpHost', type: 'text', optional: true, scope: 'shared', labelKey: 'xrayTfXhttpHost', inheritFrom: 'sni' },
    { key: 'xhttpPath', type: 'text', optional: true, default: '/', scope: 'shared', labelKey: 'xrayTfXhttpPath' },
    { key: 'xhttpExtra', type: 'text', optional: true, scope: 'shared', labelKey: 'xrayTfXhttpExtra' },
    { key: 'xhttpHeaders', type: 'json', optional: true, scope: 'shared', labelKey: 'xrayTfXhttpHeaders' },
    ...SOCKOPT_FIELDS,
  ],
  hysteria: [
    { key: 'hysteriaVersion', type: 'select', optional: true, default: '2', scope: 'shared', labelKey: 'xrayTfHysteriaVersion', options: ['2'] },
    { key: 'hysteriaAuth', type: 'text', optional: true, scope: 'shared', labelKey: 'xrayTfHysteriaAuth' },
    { key: 'hysteriaUdpIdleTimeout', type: 'number', optional: true, default: 60, scope: 'shared', labelKey: 'xrayTfHysteriaUdpIdleTimeout' },
    { key: 'hysteriaUpMbps', type: 'number', optional: true, scope: 'client', labelKey: 'xrayTfHysteriaUpMbps' },
    { key: 'hysteriaDownMbps', type: 'number', optional: true, scope: 'client', labelKey: 'xrayTfHysteriaDownMbps' },
    { key: 'hysteriaMasqueradeType', type: 'select', optional: true, default: '', scope: 'shared', labelKey: 'xrayTfHysteriaMasqueradeType', options: ['', 'proxy', 'string', 'file'] },
    { key: 'hysteriaMasqueradeUrl', type: 'text', optional: true, scope: 'shared', labelKey: 'xrayTfHysteriaMasqueradeUrl', showIf: { hysteriaMasqueradeType: 'proxy' } },
    { key: 'hysteriaMasqueradeContent', type: 'text', optional: true, scope: 'shared', labelKey: 'xrayTfHysteriaMasqueradeContent', showIf: { hysteriaMasqueradeType: 'string' } },
    { key: 'hysteriaMasqueradeDir', type: 'text', optional: true, default: '/var/www/html', scope: 'shared', labelKey: 'xrayTfHysteriaMasqueradeDir', showIf: { hysteriaMasqueradeType: 'file' } },
  ],
};

function allowedSecuritiesForNetwork(network) {
  return SECURITY_BY_TRANSPORT[network] || SECURITY_BY_TRANSPORT.tcp;
}

function flowSupportedForNetwork(network) {
  return network === 'tcp' || network === 'xhttp';
}

/** uTLS fingerprint: Reality/TCP-TLS only — not none, not Hysteria/QUIC. */
function fingerprintSupportedFor(network, security) {
  const sec = String(security || '').toLowerCase();
  const net = String(network || 'tcp').toLowerCase();
  if (sec !== 'reality' && sec !== 'tls') return false;
  if (net === 'hysteria') return false;
  return true;
}

function fieldsByScope(fields, scope, types) {
  return fields.filter((f) => {
    const sc = f.scope || 'shared';
    if (scope === 'client' ? sc !== 'client' : sc === 'client') return false;
    if (types && !types.includes(f.type)) return false;
    return true;
  });
}

window.XrayTransportUi = {
  SSL_CERT_AUTO,
  XRAY_TRANSPORTS,
  SECURITY_BY_TRANSPORT,
  TRANSPORT_FIELDS,

  initialState() {
    return {
      amneziaXrayNetwork: 'tcp',
      amneziaXrayTransportSettings: {},
      amneziaXrayTransportFields: [],
      amneziaXrayTransportModalOpen: false,
      xrayTransportProfileBankOpen: false,
      xrayTransportProfileBankEntries: [],
      xrayTransportProfileBankBusy: false,
      xrayTransportProfileSaveBusy: false,
      xrayTransportActiveProfileId: '',
    };
  },

  computed: {
    amneziaXrayTransportList() {
      if (Array.isArray(this.amneziaXrayTransportsFromStatus) && this.amneziaXrayTransportsFromStatus.length) {
        return this.amneziaXrayTransportsFromStatus;
      }
      return XRAY_TRANSPORTS;
    },
    amneziaXraySecuritiesFiltered() {
      const net = String(this.amneziaXrayNetwork || 'tcp').toLowerCase();
      const allowed = allowedSecuritiesForNetwork(net);
      const base = Array.isArray(this.amneziaXraySecurities) ? this.amneziaXraySecurities : ['reality', 'tls', 'none'];
      return base.filter((s) => allowed.includes(s));
    },
    showXrayFlowField() {
      return flowSupportedForNetwork(String(this.amneziaXrayNetwork || 'tcp').toLowerCase())
        && this.amneziaXraySecurity !== 'none';
    },
    showXrayFingerprintField() {
      return fingerprintSupportedFor(
        String(this.amneziaXrayNetwork || 'tcp').toLowerCase(),
        String(this.amneziaXraySecurity || 'reality').toLowerCase(),
      );
    },
    xrayTransportModalFields() {
      const fields = Array.isArray(this.amneziaXrayTransportFields) && this.amneziaXrayTransportFields.length
        ? this.amneziaXrayTransportFields
        : [];
      return fields.filter((f) => this.xrayTransportFieldVisible(f));
    },
    xrayTransportSharedSelectFields() {
      return fieldsByScope(this.xrayTransportModalFields, 'shared', ['select']);
    },
    xrayTransportSharedInputFields() {
      return fieldsByScope(this.xrayTransportModalFields, 'shared', ['text', 'number', 'json']);
    },
    xrayTransportSharedBoolFields() {
      return fieldsByScope(this.xrayTransportModalFields, 'shared', ['bool']);
    },
    xrayTransportClientSelectFields() {
      return fieldsByScope(this.xrayTransportModalFields, 'client', ['select']);
    },
    xrayTransportClientInputFields() {
      return fieldsByScope(this.xrayTransportModalFields, 'client', ['text', 'number', 'json']);
    },
    xrayTransportClientBoolFields() {
      return fieldsByScope(this.xrayTransportModalFields, 'client', ['bool']);
    },
    xrayTransportHasClientFields() {
      return this.xrayTransportClientSelectFields.length
        || this.xrayTransportClientInputFields.length
        || this.xrayTransportClientBoolFields.length;
    },
  },

  methods: {
    xrayTransportFieldLabel(field) {
      if (!field) return '';
      const key = field.labelKey || field.key;
      return this.$t(key) || field.label || key;
    },
    xrayTransportLabel(id) {
      const t = (this.amneziaXrayTransportList || []).find((x) => x.id === id);
      if (!t) return id;
      let label = t.label || id;
      if (t.deprecated) label += ` (${this.$t('xrayTransportDeprecated') || 'deprecated'})`;
      return label;
    },
    xrayTransportInheritedValue(field) {
      if (!field || field.inheritFrom !== 'sni') return '';
      if (this.amneziaXraySecurity === 'reality' || this.amneziaXraySecurity === 'tls') {
        const c = this.sslFindCertById
          ? this.sslFindCertById(this.amneziaXraySslCertId)
          : (this.sslCerts || []).find((x) => x.id === this.amneziaXraySslCertId);
        if (c && c.sni) return c.sni;
        if (c && c.domain) return c.domain;
      }
      return String(this.amneziaXraySni || '').trim();
    },
    xrayTransportFieldVisible(field) {
      if (!field || !field.showIf) return true;
      for (const [k, v] of Object.entries(field.showIf)) {
        const cur = this.amneziaXrayTransportSettings[k];
        if (cur !== v) return false;
      }
      return true;
    },
    openXrayTransportModal() {
      if (this.amneziaXrayModalMode === 'manage') return;
      this.amneziaXrayTransportModalOpen = true;
    },
    closeXrayTransportModal() {
      this.amneziaXrayTransportModalOpen = false;
    },
    async openXrayTransportProfileBank() {
      this.xrayTransportProfileBankOpen = true;
      this.xrayTransportProfileBankBusy = true;
      try {
        const net = String(this.amneziaXrayNetwork || 'tcp').toLowerCase();
        const res = await this.api.getXrayTransportProfileBank(net);
        this.xrayTransportProfileBankEntries = (res && res.profiles) || [];
      } catch {
        this.xrayTransportProfileBankEntries = [];
      } finally {
        this.xrayTransportProfileBankBusy = false;
      }
    },
    closeXrayTransportProfileBank() {
      this.xrayTransportProfileBankOpen = false;
    },
    defaultXrayTransportSettings(network) {
      const net = String(network || this.amneziaXrayNetwork || 'tcp').toLowerCase();
      const fields = TRANSPORT_FIELDS[net] || TRANSPORT_FIELDS.tcp;
      const out = {};
      for (const f of fields) {
        if (f.default !== undefined) out[f.key] = f.default;
      }
      return out;
    },
    applyXrayTransportProfile(entry) {
      if (!entry || !entry.settings) return;
      const net = String(this.amneziaXrayNetwork || 'tcp').toLowerCase();
      const fields = TRANSPORT_FIELDS[net] || TRANSPORT_FIELDS.tcp;
      const allowed = new Set(fields.map((f) => f.key));
      const next = this.defaultXrayTransportSettings(net);
      for (const [key, val] of Object.entries(entry.settings || {})) {
        if (!allowed.has(key)) continue;
        next[key] = val;
      }
      this.amneziaXrayTransportSettings = next;
      this.xrayTransportActiveProfileId = entry.id || '';
      this.closeXrayTransportProfileBank();
    },
    async saveXrayTransportProfile() {
      if (this.xrayTransportProfileSaveBusy) return;
      const name = window.prompt(this.$t('xrayTransportProfileNamePrompt') || 'Profile name');
      if (!name || !String(name).trim()) return;
      this.xrayTransportProfileSaveBusy = true;
      try {
        const net = String(this.amneziaXrayNetwork || 'tcp').toLowerCase();
        const payload = typeof this.buildXrayTransportSettingsPayload === 'function'
          ? this.buildXrayTransportSettingsPayload()
          : (this.amneziaXrayTransportSettings || {});
        const res = await this.api.saveXrayTransportProfile({
          network: net,
          name: String(name).trim(),
          settings: payload,
        });
        if (res && res.profile && res.profile.id) this.xrayTransportActiveProfileId = res.profile.id;
      } catch (err) {
        alert((err && err.message) || this.$t('xrayTransportProfileSaveFailed'));
      } finally {
        this.xrayTransportProfileSaveBusy = false;
      }
    },
    onXrayNetworkChange() {
      const net = String(this.amneziaXrayNetwork || 'tcp').toLowerCase();
      this.amneziaXrayTransportFields = TRANSPORT_FIELDS[net] || TRANSPORT_FIELDS.tcp;
      this.amneziaXrayTransportSettings = this.defaultXrayTransportSettings(net);
      this.xrayTransportActiveProfileId = '';
      const allowed = allowedSecuritiesForNetwork(net);
      if (!allowed.includes(this.amneziaXraySecurity)) {
        this.amneziaXraySecurity = allowed.includes('tls') ? 'tls' : allowed[0];
        this.amneziaXraySslCertId = SSL_CERT_AUTO;
      }
      if (!flowSupportedForNetwork(net)) {
        this.amneziaXrayFlow = '';
      } else if (!this.amneziaXrayFlow) {
        this.amneziaXrayFlow = 'xtls-rprx-vision';
      }
    },
    hydrateXrayTransportFromStatus(st) {
      if (!st || typeof st !== 'object') return;
      if (st.network) this.amneziaXrayNetwork = st.network;
      if (st.transportSettings && typeof st.transportSettings === 'object') {
        this.amneziaXrayTransportSettings = { ...st.transportSettings };
      }
      if (Array.isArray(st.transports)) {
        this.amneziaXrayTransportsFromStatus = st.transports;
      }
      const net = String(st.network || this.amneziaXrayNetwork || 'tcp').toLowerCase();
      this.amneziaXrayTransportFields = (Array.isArray(st.transportFields) && st.transportFields.length)
        ? st.transportFields
        : (TRANSPORT_FIELDS[net] || TRANSPORT_FIELDS.tcp);
    },
    buildXrayTransportSettingsPayload() {
      const out = {};
      const fields = this.xrayTransportModalFields.length
        ? this.xrayTransportModalFields
        : (this.amneziaXrayTransportFields || []);
      for (const f of fields) {
        const val = this.amneziaXrayTransportSettings[f.key];
        if (val === null || val === undefined || val === '') continue;
        if (f.type === 'bool') {
          out[f.key] = val === true;
          continue;
        }
        out[f.key] = val;
      }
      return out;
    },
  },
};
