'use strict';

/**
 * VLESS transport UI helpers (mirrors src/lib/xrayTransportSchema.js for browser).
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

const SOCKOPT_FIELDS = [
  { key: 'tcpFastOpen', type: 'bool', optional: true, group: 'socket', label: 'TCP Fast Open' },
  { key: 'tcpCongestion', type: 'text', optional: true, group: 'socket', label: 'TCP congestion', placeholder: 'bbr' },
  { key: 'domainStrategy', type: 'select', optional: true, group: 'socket', label: 'Domain strategy',
    options: ['AsIs', 'UseIP', 'UseIPv4', 'UseIPv6'] },
  { key: 'acceptProxyProtocol', type: 'bool', optional: true, group: 'socket', label: 'Accept PROXY protocol (inbound)' },
];

const TRANSPORT_FIELDS = {
  tcp: [
    { key: 'headerType', type: 'select', optional: true, default: 'none', group: 'basic', label: 'Header type',
      options: ['none', 'http'] },
    { key: 'httpVersion', type: 'text', optional: true, group: 'httpHeader', label: 'HTTP version', default: '1.1',
      showIf: { headerType: 'http' } },
    { key: 'httpMethod', type: 'text', optional: true, group: 'httpHeader', label: 'HTTP method', default: 'GET',
      showIf: { headerType: 'http' } },
    { key: 'httpPath', type: 'text', optional: true, group: 'httpHeader', label: 'HTTP path (comma-separated)',
      default: '/', showIf: { headerType: 'http' } },
    { key: 'httpHost', type: 'text', optional: true, group: 'httpHeader', label: 'HTTP Host header',
      inheritFrom: 'sni', showIf: { headerType: 'http' } },
    ...SOCKOPT_FIELDS,
  ],
  ws: [
    { key: 'wsPath', type: 'text', optional: true, default: '/', group: 'basic', label: 'Path' },
    { key: 'wsHost', type: 'text', optional: true, group: 'basic', label: 'Host', inheritFrom: 'sni' },
    { key: 'wsHeaders', type: 'json', optional: true, group: 'advanced', label: 'Extra headers (JSON map)' },
    { key: 'acceptProxyProtocol', type: 'bool', optional: true, group: 'advanced', label: 'Accept PROXY protocol (inbound)' },
  ],
  grpc: [
    { key: 'grpcServiceName', type: 'text', optional: false, group: 'basic', label: 'Service name' },
    { key: 'grpcMultiMode', type: 'bool', optional: true, group: 'basic', label: 'Multi mode' },
    { key: 'grpcAuthority', type: 'text', optional: true, group: 'advanced', label: 'Authority', inheritFrom: 'sni' },
    { key: 'grpcIdleTimeout', type: 'number', optional: true, group: 'advanced', label: 'Idle timeout (seconds)' },
  ],
  kcp: [
    { key: 'kcpMtu', type: 'number', optional: true, group: 'basic', label: 'MTU' },
    { key: 'kcpTti', type: 'number', optional: true, group: 'basic', label: 'TTI' },
    { key: 'kcpUplinkCapacity', type: 'number', optional: true, group: 'basic', label: 'Uplink capacity (MB)' },
    { key: 'kcpDownlinkCapacity', type: 'number', optional: true, group: 'basic', label: 'Downlink capacity (MB)' },
    { key: 'kcpReadBufferSize', type: 'number', optional: true, group: 'advanced', label: 'Read buffer (MB)' },
    { key: 'kcpWriteBufferSize', type: 'number', optional: true, group: 'advanced', label: 'Write buffer (MB)' },
    { key: 'kcpCongestion', type: 'bool', optional: true, group: 'advanced', label: 'Enable congestion' },
    { key: 'kcpSeed', type: 'text', optional: true, group: 'advanced', label: 'Seed' },
    { key: 'kcpHeaderType', type: 'select', optional: true, default: 'none', group: 'basic', label: 'Header type',
      options: ['none', 'srtp', 'utp', 'wechat-video', 'wechat-audio', 'dtls', 'wireguard'] },
  ],
  httpupgrade: [
    { key: 'httpupgradeHost', type: 'text', optional: true, group: 'basic', label: 'Host', inheritFrom: 'sni' },
    { key: 'httpupgradePath', type: 'text', optional: true, default: '/', group: 'basic', label: 'Path' },
    { key: 'httpupgradeHeaders', type: 'json', optional: true, group: 'advanced', label: 'Extra headers (JSON map)' },
  ],
  xhttp: [
    { key: 'xhttpMode', type: 'select', optional: true, default: 'auto', group: 'basic', label: 'Mode',
      options: ['auto', 'stream-one', 'stream-up', 'packet-up'] },
    { key: 'xhttpHost', type: 'text', optional: true, group: 'basic', label: 'Host', inheritFrom: 'sni' },
    { key: 'xhttpPath', type: 'text', optional: true, default: '/', group: 'basic', label: 'Path' },
    { key: 'xhttpExtra', type: 'text', optional: true, group: 'advanced', label: 'Extra download path' },
    { key: 'xhttpHeaders', type: 'json', optional: true, group: 'advanced', label: 'Extra headers (JSON map)' },
    ...SOCKOPT_FIELDS,
  ],
  hysteria: [
    { key: 'hysteriaUpMbps', type: 'number', optional: true, group: 'basic', label: 'Upload (Mbps)' },
    { key: 'hysteriaDownMbps', type: 'number', optional: true, group: 'basic', label: 'Download (Mbps)' },
  ],
};

const TRANSPORT_FIELD_GROUPS = {
  basic: 'xrayTransportGroupBasic',
  httpHeader: 'xrayTransportGroupHttpHeader',
  advanced: 'xrayTransportGroupAdvanced',
  socket: 'xrayTransportGroupSocket',
};

function allowedSecuritiesForNetwork(network) {
  return SECURITY_BY_TRANSPORT[network] || SECURITY_BY_TRANSPORT.tcp;
}

function flowSupportedForNetwork(network) {
  return network === 'tcp' || network === 'xhttp';
}

window.XrayTransportUi = {
  SSL_CERT_AUTO,
  XRAY_TRANSPORTS,
  SECURITY_BY_TRANSPORT,
  TRANSPORT_FIELD_GROUPS,

  initialState() {
    return {
      amneziaXrayNetwork: 'tcp',
      amneziaXrayTransportSettings: {},
      amneziaXrayTransportFields: [],
      amneziaXrayTransportModalOpen: false,
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
    xrayTransportModalFields() {
      const fields = Array.isArray(this.amneziaXrayTransportFields) && this.amneziaXrayTransportFields.length
        ? this.amneziaXrayTransportFields
        : [];
      return fields.filter((f) => this.xrayTransportFieldVisible(f));
    },
    xrayTransportModalGroups() {
      const groups = ['basic', 'httpHeader', 'advanced', 'socket'];
      return groups.filter((g) => this.xrayTransportModalFields.some((f) => f.group === g));
    },
  },

  methods: {
    xrayTransportGroupLabel(group) {
      const key = TRANSPORT_FIELD_GROUPS[group] || group;
      return this.$t(key) || group;
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
    onXrayNetworkChange() {
      const net = String(this.amneziaXrayNetwork || 'tcp').toLowerCase();
      this.amneziaXrayTransportFields = TRANSPORT_FIELDS[net] || TRANSPORT_FIELDS.tcp;
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
          if (val === true) out[f.key] = true;
          continue;
        }
        out[f.key] = val;
      }
      return out;
    },
  },
};
