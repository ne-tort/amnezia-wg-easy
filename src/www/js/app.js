/* eslint-disable no-console */
/* eslint-disable no-alert */
/* eslint-disable no-undef */
/* eslint-disable no-new */

'use strict';

const CHANGELOG_URL = 'https://raw.githubusercontent.com/spcfox/amnezia-wg-easy/production/docs/changelog.json';

function bytes(bytes, decimals, kib, maxunit) {
  kib = kib || false;
  if (bytes === 0) return '0 B';
  if (Number.isNaN(parseFloat(bytes)) && !Number.isFinite(bytes)) return 'NaN';
  const k = kib ? 1024 : 1000;
  const dm = decimals != null && !Number.isNaN(decimals) && decimals >= 0 ? decimals : 2;
  const sizes = kib
    ? ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB', 'EiB', 'ZiB', 'YiB', 'BiB']
    : ['B', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB', 'BB'];
  let i = Math.floor(Math.log(bytes) / Math.log(k));
  if (maxunit !== undefined) {
    const index = sizes.indexOf(maxunit);
    if (index !== -1) i = index;
  }
  // eslint-disable-next-line no-restricted-properties
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(dm))} ${sizes[i]}`;
}

// * Default UI language. No auto-detection; user selects via language switcher only.
const DEFAULT_LOCALE = 'ru';
const LOCALE_STORAGE_KEY = 'lang';

const i18n = new VueI18n({
  locale: localStorage.getItem(LOCALE_STORAGE_KEY) || DEFAULT_LOCALE,
  fallbackLocale: DEFAULT_LOCALE,
  messages,
});

// * Labels for language switcher (code -> short label).
const LOCALE_LABELS = {
  ru: 'Рус', en: 'En', ua: 'Укр', de: 'De', fr: 'Fr', es: 'Es', pl: 'Pl', pt: 'Pt', it: 'It', nl: 'Nl',
  tr: 'Tr', no: 'No', ko: 'Ko', vi: 'Vi', th: 'Th', hi: 'Hi', is: 'Is', ca: 'Ca', chs: '简', cht: '繁',
};
function getLocaleLabel(code) {
  return LOCALE_LABELS[code] || code;
}

const UI_CHART_TYPES = [
  { type: false, strokeWidth: 0 },
  { type: 'line', strokeWidth: 3 },
  { type: 'area', strokeWidth: 0 },
  { type: 'bar', strokeWidth: 0 },
];

// * Profile id -> label and qrFriendly (order comes from API /signatures/profiles).
const PROFILE_META = {
  quic: { label: 'QUIC', qrFriendly: false },
  dns: { label: 'DNS', qrFriendly: true },
  sip: { label: 'SIP', qrFriendly: true },
  stun: { label: 'STUN', qrFriendly: true },
  webrtc: { label: 'WebRTC', qrFriendly: true },
  dtls: { label: 'DTLS', qrFriendly: true },
};
const FALLBACK_PROFILE_IDS = ['dns', 'quic', 'stun', 'sip', 'webrtc', 'dtls'];

const CHART_COLORS = {
  rx: { light: 'rgba(128,128,128,0.3)', dark: 'rgba(255,255,255,0.3)' },
  tx: { light: 'rgba(128,128,128,0.4)', dark: 'rgba(255,255,255,0.3)' },
  gradient: { light: ['rgba(0,0,0,1.0)', 'rgba(0,0,0,1.0)'], dark: ['rgba(128,128,128,0)', 'rgba(128,128,128,0)'] },
};

new Vue({
  el: '#app',
  components: {
    apexchart: VueApexCharts,
  },
  i18n,
  data: {
    authenticated: null,
    authenticating: false,
    username: null,
    password: null,

    clients: null,
    clientsPersist: {},
    clientDelete: null,
    clientCreate: null,
    clientCreateName: '',
    clientEditName: null,
    clientEditNameId: null,
    clientEditAddress: null,
    clientEditAddressId: null,
    qrcode: null,
    configViewClient: null,
    configViewText: '',

    clientLevels: {},
    clientProfiles: {},
    profileIds: [],
    defaultProfile: 'dns',
    regeneratingSignatures: false,
    ruleProfiles: [],
    globalFirewallRules: [],
    globalRuleEdit: null,
    profileRulesExpanded: null,
    profileRulesList: [],
    profileRuleEdit: null,
    clientExpiryEdit: null,
    expiryEditValue: '',
    expandedClientStatsId: null,

    currentRelease: null,
    latestRelease: null,

    uiTrafficStats: false,

    uiChartType: 0,
    uiShowCharts: localStorage.getItem('uiShowCharts') === '1',
    firewallBlocksVisible: localStorage.getItem('firewallBlocksVisible') === '1',
    uiTheme: localStorage.theme || 'auto',
    prefersDarkScheme: window.matchMedia('(prefers-color-scheme: dark)'),
    currentLocale: localStorage.getItem(LOCALE_STORAGE_KEY) || DEFAULT_LOCALE,

    chartOptions: {
      chart: {
        background: 'transparent',
        stacked: false,
        toolbar: {
          show: false,
        },
        animations: {
          enabled: false,
        },
        parentHeightOffset: 0,
        sparkline: {
          enabled: true,
        },
      },
      colors: [],
      stroke: {
        curve: 'smooth',
      },
      fill: {
        type: 'gradient',
        gradient: {
          shade: 'dark',
          type: 'vertical',
          shadeIntensity: 0,
          gradientToColors: CHART_COLORS.gradient[this.theme],
          inverseColors: false,
          opacityTo: 0,
          stops: [0, 100],
        },
      },
      dataLabels: {
        enabled: false,
      },
      plotOptions: {
        bar: {
          horizontal: false,
        },
      },
      xaxis: {
        labels: {
          show: false,
        },
        axisTicks: {
          show: false,
        },
        axisBorder: {
          show: false,
        },
      },
      yaxis: {
        labels: {
          show: false,
        },
        min: 0,
      },
      tooltip: {
        enabled: false,
      },
      legend: {
        show: false,
      },
      grid: {
        show: false,
        padding: {
          left: -10,
          right: 0,
          bottom: -15,
          top: -15,
        },
        column: {
          opacity: 0,
        },
        xaxis: {
          lines: {
            show: false,
          },
        },
      },
    },
  },
  methods: {
    getClientLevel(client) {
      return this.clientLevels[client.id] ?? 1;
    },
    cycleClientLevel(client) {
      const prev = this.getClientLevel(client);
      const next = prev === 0 ? 1 : (prev === 5 ? 0 : prev + 1);
      this.$set(this.clientLevels, client.id, next);
      this.api.updateClientObfuscation({ clientId: client.id, level: next })
        .catch((err) => {
          this.$set(this.clientLevels, client.id, prev);
          alert(err.message || err.toString());
        });
    },
    onObfuscationLevelChange(client, ev) {
      const raw = ev.target.value;
      const level = raw === '' || raw === 'null' ? 0 : parseInt(raw, 10);
      const prev = this.getClientLevel(client);
      if (Number.isNaN(level) || level < 0 || level > 5) return;
      this.$set(this.clientLevels, client.id, level);
      this.api.updateClientObfuscation({ clientId: client.id, level })
        .catch((err) => {
          this.$set(this.clientLevels, client.id, prev);
          ev.target.value = prev;
          alert(err.message || err.toString());
        });
    },
    getClientProfile(client) {
      return this.clientProfiles[client.id] ?? this.defaultProfile;
    },
    getClientProfileLabel(client) {
      const id = this.getClientProfile(client);
      return this.getProfileLabel(id);
    },
    getProfileLabel(profileId) {
      const meta = PROFILE_META[profileId];
      return meta ? meta.label : profileId;
    },
    isProfileQRFriendly(profileId) {
      const meta = PROFILE_META[profileId];
      return meta ? meta.qrFriendly === true : false;
    },
    cycleClientProfile(client) {
      const list = this.profileIds.length ? this.profileIds : ['dns', 'quic', 'stun', 'sip', 'webrtc', 'dtls'];
      const current = this.getClientProfile(client);
      let idx = list.indexOf(current);
      if (idx < 0) idx = 0;
      const next = list[(idx + 1) % list.length];
      const prev = current;
      this.$set(this.clientProfiles, client.id, next);
      this.api.updateClientObfuscation({ clientId: client.id, profile: next })
        .catch((err) => {
          this.$set(this.clientProfiles, client.id, prev);
          alert(err.message || err.toString());
        });
    },
    onObfuscationProfileChange(client, ev) {
      const profile = ev.target.value;
      const prev = this.getClientProfile(client);
      this.$set(this.clientProfiles, client.id, profile);
      this.api.updateClientObfuscation({ clientId: client.id, profile })
        .catch((err) => {
          this.$set(this.clientProfiles, client.id, prev);
          ev.target.value = prev;
          alert(err.message || err.toString());
        });
    },
    async regenerateSignatures() {
      if (this.regeneratingSignatures) return;
      this.regeneratingSignatures = true;
      try {
        const result = await this.api.regenerateSignatures();
        if (!result || (!result.started && !result.success)) {
          const msg = (result && result.message) || this.$t('signaturesRegenerateFailed') || 'Regeneration failed.';
          alert(msg);
        }
      } catch (err) {
        alert(err.message || this.$t('signaturesRegenerateFailed') || 'Regeneration failed.');
      } finally {
        this.regeneratingSignatures = false;
      }
    },
    async copyConfig(client) {
      try {
        const config = await this.api.getConfiguration(client.id, this.getClientLevel(client), this.getClientProfile(client));
        const ta = document.createElement('textarea');
        ta.value = config;
        ta.setAttribute('readonly', '');
        ta.style.cssText = 'position:fixed;top:0;left:0;width:2em;height:2em;padding:0;border:none;outline:none;boxShadow:none;background:transparent;opacity:0;';
        document.body.appendChild(ta);
        ta.focus();
        ta.select();
        const ok = document.execCommand('copy');
        document.body.removeChild(ta);
        if (!ok) throw new Error('Copy failed');
      } catch (err) {
        alert(err.message || 'Copy failed');
      }
    },
    async showConfig(client) {
      try {
        const config = await this.api.getConfiguration(client.id, this.getClientLevel(client), this.getClientProfile(client));
        this.configViewClient = client;
        this.configViewText = config;
      } catch (err) {
        alert(err.message || 'Failed to load config');
      }
    },
    async showQR(client) {
      try {
        const svg = await this.api.getClientQRCodeSVG(client.id, this.getClientLevel(client), this.getClientProfile(client));
        this.qrcode = 'data:image/svg+xml,' + encodeURIComponent(svg);
      } catch (err) {
        alert(err.message || 'Failed to load QR code');
      }
    },
    closeConfigView() {
      this.configViewClient = null;
      this.configViewText = '';
    },
    copyFromConfigView() {
      if (!this.configViewText) return;
      try {
        const ta = document.createElement('textarea');
        ta.value = this.configViewText;
        ta.setAttribute('readonly', '');
        ta.style.cssText = 'position:fixed;top:0;left:0;width:2em;height:2em;padding:0;border:none;outline:none;boxShadow:none;background:transparent;opacity:0;';
        document.body.appendChild(ta);
        ta.focus();
        ta.select();
        const ok = document.execCommand('copy');
        document.body.removeChild(ta);
        if (!ok) throw new Error('Copy failed');
      } catch (err) {
        alert(err.message || 'Copy failed');
      }
    },
    dateTime: (value) => {
      return new Intl.DateTimeFormat(undefined, {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: 'numeric',
        minute: 'numeric',
      }).format(value);
    },
    async refresh({
      updateCharts = false,
    } = {}) {
      if (!this.authenticated) return;

      const clients = await this.api.getClients();
      this.clients = clients.map((client) => {
        this.$set(this.clientLevels, client.id, client.defaultLevel != null ? client.defaultLevel : 1);
        this.$set(this.clientProfiles, client.id, client.defaultProfile || this.defaultProfile || 'dns');

        if (client.name.includes('@') && client.name.includes('.')) {
          client.avatar = `https://gravatar.com/avatar/${sha256(client.name.toLowerCase().trim())}.jpg`;
        }

        if (!this.clientsPersist[client.id]) {
          this.clientsPersist[client.id] = {};
          this.clientsPersist[client.id].transferRxHistory = Array(50).fill(0);
          this.clientsPersist[client.id].transferRxPrevious = client.transferRx;
          this.clientsPersist[client.id].transferTxHistory = Array(50).fill(0);
          this.clientsPersist[client.id].transferTxPrevious = client.transferTx;
        }

        // Debug
        // client.transferRx = this.clientsPersist[client.id].transferRxPrevious + Math.random() * 1000;
        // client.transferTx = this.clientsPersist[client.id].transferTxPrevious + Math.random() * 1000;
        // client.latestHandshakeAt = new Date();

        this.clientsPersist[client.id].transferRxCurrent = client.transferRx - this.clientsPersist[client.id].transferRxPrevious;
        this.clientsPersist[client.id].transferRxPrevious = client.transferRx;
        this.clientsPersist[client.id].transferTxCurrent = client.transferTx - this.clientsPersist[client.id].transferTxPrevious;
        this.clientsPersist[client.id].transferTxPrevious = client.transferTx;

        if (updateCharts) {
          this.clientsPersist[client.id].transferRxHistory.push(this.clientsPersist[client.id].transferRxCurrent);
          this.clientsPersist[client.id].transferRxHistory.shift();

          this.clientsPersist[client.id].transferTxHistory.push(this.clientsPersist[client.id].transferTxCurrent);
          this.clientsPersist[client.id].transferTxHistory.shift();

          this.clientsPersist[client.id].transferTxSeries = [{
            name: 'Tx',
            data: this.clientsPersist[client.id].transferTxHistory,
          }];

          this.clientsPersist[client.id].transferRxSeries = [{
            name: 'Rx',
            data: this.clientsPersist[client.id].transferRxHistory,
          }];

          client.transferTxHistory = this.clientsPersist[client.id].transferTxHistory;
          client.transferRxHistory = this.clientsPersist[client.id].transferRxHistory;
          client.transferMax = Math.max(...client.transferTxHistory, ...client.transferRxHistory);

          client.transferTxSeries = this.clientsPersist[client.id].transferTxSeries;
          client.transferRxSeries = this.clientsPersist[client.id].transferRxSeries;
        }

        client.transferTxCurrent = this.clientsPersist[client.id].transferTxCurrent;
        client.transferRxCurrent = this.clientsPersist[client.id].transferRxCurrent;

        client.hoverTx = this.clientsPersist[client.id].hoverTx;
        client.hoverRx = this.clientsPersist[client.id].hoverRx;

        return client;
      });
    },
    login(e) {
      e.preventDefault();

      if (!this.username || !this.password) return;
      if (this.authenticating) return;

      this.authenticating = true;
      this.api.createSession({ username: this.username, password: this.password })
        .then(async () => {
          const session = await this.api.getSession();
          this.authenticated = session.authenticated;
          return this.refresh();
        })
        .catch((err) => {
          const msg = err.status === 409 || err.code === 'USERNAME_EXISTS'
            ? (this.$t ? this.$t('usernameExists') : 'Username already exists')
            : (err.message || err.toString());
          alert(msg);
        })
        .finally(() => {
          this.authenticating = false;
          this.password = null;
        });
    },
    onFirewallProfileChange(client, ev) {
      const raw = ev.target.value;
      const ruleProfileId = raw === '' || raw === 'null' ? null : parseInt(raw, 10);
      const prev = client.ruleProfileId;
      client.ruleProfileId = Number.isNaN(ruleProfileId) ? null : ruleProfileId;
      this.api.updateClientRuleProfile({ clientId: client.id, rule_profile_id: ruleProfileId })
        .catch((err) => {
          client.ruleProfileId = prev;
          ev.target.value = prev == null ? '' : prev;
          alert(err.message || err.toString());
        });
    },
    loadGlobalFirewallRules() {
      this.api.getGlobalFirewallRules()
        .then((r) => { this.globalFirewallRules = Array.isArray(r) ? r : []; })
        .catch(() => { this.globalFirewallRules = []; });
    },
    openAddGlobalRule() {
      this.globalRuleEdit = { action: 'allow', destination_cidr: '', port_range: '', protocol: '', sort_order: 0 };
    },
    openEditGlobalRule(rule) {
      this.globalRuleEdit = {
        id: rule.id,
        action: rule.action || 'allow',
        destination_cidr: rule.destination_cidr || '',
        port_range: rule.port_range || '',
        protocol: rule.protocol || '',
        sort_order: rule.sort_order ?? 0,
      };
    },
    saveGlobalRule() {
      const r = this.globalRuleEdit;
      if (!r || !r.destination_cidr) return;
      const body = {
        action: r.action,
        destination_cidr: r.destination_cidr.trim(),
        port_range: r.port_range ? r.port_range.trim() || null : null,
        protocol: r.protocol ? r.protocol.trim() || null : null,
        sort_order: parseInt(r.sort_order, 10) || 0,
      };
      const p = r.id
        ? this.api.updateGlobalFirewallRule(r.id, body)
        : this.api.createGlobalFirewallRule(body);
      p.then(() => {
        this.globalRuleEdit = null;
        this.loadGlobalFirewallRules();
      }).catch((err) => alert(err.message || err.toString()));
    },
    deleteGlobalRule(rule) {
      if (!rule.id) return;
      if (!confirm(this.$t('globalRuleDeleteConfirm'))) return;
      this.api.deleteGlobalFirewallRule(rule.id)
        .then(() => this.loadGlobalFirewallRules())
        .catch((err) => alert(err.message || err.toString()));
    },
    closeGlobalRuleEdit() {
      this.globalRuleEdit = null;
    },
    expandProfileRules(profile) {
      if (this.profileRulesExpanded === profile.id) {
        this.profileRulesExpanded = null;
        this.profileRulesList = [];
        return;
      }
      this.profileRulesExpanded = profile.id;
      this.api.getRuleProfile(profile.id)
        .then((data) => { this.profileRulesList = Array.isArray(data.rules) ? data.rules : []; })
        .catch(() => { this.profileRulesList = []; });
    },
    loadProfileRulesList() {
      if (this.profileRulesExpanded == null) return;
      this.api.getRuleProfile(this.profileRulesExpanded)
        .then((data) => { this.profileRulesList = Array.isArray(data.rules) ? data.rules : []; })
        .catch(() => { this.profileRulesList = []; });
    },
    openAddProfileRule(profileId) {
      this.profileRuleEdit = { rule_profile_id: profileId, action: 'allow', destination_cidr: '', port_range: '', protocol: '', sort_order: 0 };
    },
    openEditProfileRule(rule) {
      this.profileRuleEdit = {
        id: rule.id,
        rule_profile_id: rule.rule_profile_id,
        action: rule.action || 'allow',
        destination_cidr: rule.destination_cidr || '',
        port_range: rule.port_range || '',
        protocol: rule.protocol || '',
        sort_order: rule.sort_order ?? 0,
      };
    },
    saveProfileRule() {
      const r = this.profileRuleEdit;
      if (!r || !r.destination_cidr) return;
      const body = {
        action: r.action,
        destination_cidr: r.destination_cidr.trim(),
        port_range: r.port_range ? r.port_range.trim() || null : null,
        protocol: r.protocol ? r.protocol.trim() || null : null,
        sort_order: parseInt(r.sort_order, 10) || 0,
      };
      if (r.id) {
        this.api.updateIpRule(r.id, body).then(() => { this.profileRuleEdit = null; this.loadProfileRulesList(); }).catch((err) => alert(err.message || err.toString()));
      } else {
        body.rule_profile_id = r.rule_profile_id;
        this.api.createIpRule(body).then(() => { this.profileRuleEdit = null; this.loadProfileRulesList(); }).catch((err) => alert(err.message || err.toString()));
      }
    },
    deleteProfileRule(rule) {
      if (!rule.id) return;
      if (!confirm(this.$t('globalRuleDeleteConfirm'))) return;
      this.api.deleteIpRule(rule.id).then(() => this.loadProfileRulesList()).catch((err) => alert(err.message || err.toString()));
    },
    closeProfileRuleEdit() {
      this.profileRuleEdit = null;
    },
    openExpiryEdit(client) {
      this.clientExpiryEdit = client;
      this.expiryEditValue = client.expiresAt ? client.expiresAt.toISOString().slice(0, 10) : '';
    },
    saveExpiryEdit() {
      const client = this.clientExpiryEdit;
      if (!client) return;
      const expiresAt = this.expiryEditValue ? new Date(this.expiryEditValue + 'T00:00:00Z').getTime() / 1000 : null;
      this.api.updateClientExpires({ clientId: client.id, expires_at: expiresAt })
        .then(() => {
          client.expiresAt = this.expiryEditValue ? new Date(this.expiryEditValue + 'T00:00:00Z') : null;
          this.clientExpiryEdit = null;
          this.expiryEditValue = '';
        })
        .catch((err) => alert(err.message || err.toString()));
    },
    clearExpiryEdit() {
      this.expiryEditValue = '';
    },
    closeExpiryEdit() {
      this.clientExpiryEdit = null;
      this.expiryEditValue = '';
    },
    logout(e) {
      e.preventDefault();

      this.api.deleteSession()
        .then(() => {
          this.authenticated = false;
          this.clients = null;
        })
        .catch((err) => {
          alert(err.message || err.toString());
        });
    },
    createClient() {
      const name = this.clientCreateName;
      if (!name) return;

      this.api.createClient({ name })
        .catch((err) => alert(err.message || err.toString()))
        .finally(() => this.refresh().catch(console.error));
    },
    deleteClient(client) {
      this.api.deleteClient({ clientId: client.id })
        .catch((err) => alert(err.message || err.toString()))
        .finally(() => this.refresh().catch(console.error));
    },
    enableClient(client) {
      this.api.enableClient({ clientId: client.id })
        .catch((err) => alert(err.message || err.toString()))
        .finally(() => this.refresh().catch(console.error));
    },
    disableClient(client) {
      this.api.disableClient({ clientId: client.id })
        .catch((err) => alert(err.message || err.toString()))
        .finally(() => this.refresh().catch(console.error));
    },
    updateClientName(client, name) {
      this.api.updateClientName({ clientId: client.id, name })
        .catch((err) => alert(err.message || err.toString()))
        .finally(() => this.refresh().catch(console.error));
    },
    updateClientAddress(client, address) {
      this.api.updateClientAddress({ clientId: client.id, address })
        .catch((err) => {
          const msg = err.status === 409 ? (this.$t('addressAlreadyInUse') || err.message) : (err.message || err.toString());
          alert(msg);
        })
        .finally(() => this.refresh().catch(console.error));
    },
    toggleTheme() {
      const themes = ['light', 'dark', 'auto'];
      const currentIndex = themes.indexOf(this.uiTheme);
      const newIndex = (currentIndex + 1) % themes.length;
      this.uiTheme = themes[newIndex];
      localStorage.theme = this.uiTheme;
      this.setTheme(this.uiTheme);
    },
    setLocale(locale) {
      if (!locale || !this.$i18n.availableLocales.includes(locale)) return;
      this.currentLocale = locale;
      this.$i18n.locale = locale;
      localStorage.setItem(LOCALE_STORAGE_KEY, locale);
    },
    getLocaleLabel(code) {
      return getLocaleLabel(code);
    },
    setTheme(theme) {
      const { classList } = document.documentElement;
      const shouldAddDarkClass = theme === 'dark' || (theme === 'auto' && this.prefersDarkScheme.matches);
      classList.toggle('dark', shouldAddDarkClass);
    },
    handlePrefersChange(e) {
      if (localStorage.theme === 'auto') {
        this.setTheme(e.matches ? 'dark' : 'light');
      }
    },
    toggleCharts() {
      localStorage.setItem('uiShowCharts', this.uiShowCharts ? 1 : 0);
    },
    toggleClientStats(client) {
      this.expandedClientStatsId = this.expandedClientStatsId === client.id ? null : client.id;
    },
    toggleFirewallBlocks() {
      this.firewallBlocksVisible = !this.firewallBlocksVisible;
      localStorage.setItem('firewallBlocksVisible', this.firewallBlocksVisible ? '1' : '0');
    },
  },
  filters: {
    bytes,
    timeago: (value) => {
      return timeago.format(value, i18n.locale);
    },
  },
  mounted() {
    this.prefersDarkScheme.addListener(this.handlePrefersChange);
    this.setTheme(this.uiTheme);

    this.api = new API();
    this.api.getSession()
      .then((session) => {
        this.authenticated = session.authenticated;
        this.api.getSignaturesProfiles()
          .then((r) => {
            this.profileIds = r && r.profileIds ? r.profileIds : FALLBACK_PROFILE_IDS;
            this.defaultProfile = (r && r.defaultProfile) || 'dns';
          })
          .catch(() => {
            this.profileIds = FALLBACK_PROFILE_IDS;
            this.defaultProfile = 'dns';
          });
        this.api.getRuleProfiles()
          .then((r) => { this.ruleProfiles = Array.isArray(r) ? r : []; })
          .catch(() => { this.ruleProfiles = []; });
        this.loadGlobalFirewallRules();
        this.refresh({
          updateCharts: this.updateCharts,
        }).catch((err) => {
          alert(err.message || err.toString());
        });
      })
      .catch((err) => {
        alert(err.message || err.toString());
      });

    setInterval(() => {
      this.refresh({
        updateCharts: this.updateCharts,
      }).catch(console.error);
    }, 1000);

    this.api.getuiTrafficStats()
      .then((res) => {
        this.uiTrafficStats = res;
      })
      .catch(() => {
        this.uiTrafficStats = false;
      });

    this.api.getChartType()
      .then((res) => {
        this.uiChartType = parseInt(res, 10);
      })
      .catch(() => {
        this.uiChartType = 0;
      });

    Promise.resolve().then(async () => {
      const checkUpdate = await this.api.getCheckUpdate();
      if (!checkUpdate) return;

      const currentRelease = await this.api.getRelease();
      const latestRelease = await fetch(CHANGELOG_URL)
        .then((res) => res.json())
        .then((releases) => {
          const releasesArray = Object.entries(releases).map(([version, changelog]) => ({
            version: parseInt(version, 10),
            changelog,
          }));
          releasesArray.sort((a, b) => {
            return b.version - a.version;
          });

          return releasesArray[0];
        });

      if (currentRelease >= latestRelease.version) return;

      this.currentRelease = currentRelease;
      this.latestRelease = latestRelease;
    }).catch((err) => console.error(err));
  },
  computed: {
    chartOptionsTX() {
      const opts = {
        ...this.chartOptions,
        colors: [CHART_COLORS.tx[this.theme]],
      };
      opts.chart.type = UI_CHART_TYPES[this.uiChartType].type || false;
      opts.stroke.width = UI_CHART_TYPES[this.uiChartType].strokeWidth;
      return opts;
    },
    chartOptionsRX() {
      const opts = {
        ...this.chartOptions,
        colors: [CHART_COLORS.rx[this.theme]],
      };
      opts.chart.type = UI_CHART_TYPES[this.uiChartType].type || false;
      opts.stroke.width = UI_CHART_TYPES[this.uiChartType].strokeWidth;
      return opts;
    },
    updateCharts() {
      return this.uiChartType > 0 && this.uiShowCharts;
    },
    theme() {
      if (this.uiTheme === 'auto') {
        return this.prefersDarkScheme.matches ? 'dark' : 'light';
      }
      return this.uiTheme;
    },
    localeOptions() {
      return this.$i18n.availableLocales.map((code) => ({
        code,
        label: getLocaleLabel(code),
      }));
    },
  },
});
