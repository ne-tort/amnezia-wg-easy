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

// * Formats bytes as "X.XX MB" / "X.XX GB" etc.: 2 decimals, unit from MB, switch at 0.1 of next unit.
function formatTrafficShort(bytesIn) {
  if (bytesIn == null || !Number.isFinite(bytesIn) || bytesIn < 0) return '0.00 MB';
  const k = 1024;
  const units = ['MB', 'GB', 'TB', 'PB'];
  let valueMb = bytesIn / (k * k);
  let idx = 0;
  while (idx < units.length - 1 && valueMb >= 0.1 * k) {
    valueMb /= k;
    idx += 1;
  }
  const value = parseFloat(valueMb.toFixed(2));
  return `${value} ${units[idx]}`;
}

// * Default UI language. No auto-detection; user selects via language switcher only.
const DEFAULT_LOCALE = 'ru';
const LOCALE_STORAGE_KEY = 'lang';

/** Parse IPv4 to unsigned 32-bit int, or null. */
function ipv4ToInt(ip) {
  if (typeof ip !== 'string') return null;
  const parts = ip.trim().split('.');
  if (parts.length !== 4) return null;
  let n = 0;
  for (let i = 0; i < 4; i += 1) {
    const o = parseInt(parts[i], 10);
    if (!Number.isInteger(o) || o < 0 || o > 255) return null;
    n = (n << 8) | o;
  }
  return n >>> 0;
}

/** True if IPv4 host is inside CIDR (a.b.c.d/m). */
function ipv4InCidr(ip, cidr) {
  if (typeof cidr !== 'string') return false;
  const slash = cidr.indexOf('/');
  if (slash < 0) return false;
  const addr = ipv4ToInt(cidr.slice(0, slash).trim());
  const prefix = parseInt(cidr.slice(slash + 1).trim(), 10);
  const host = ipv4ToInt(ip);
  if (addr == null || host == null || !Number.isInteger(prefix) || prefix < 0 || prefix > 32) return false;
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return (host & mask) === (addr & mask);
}

function ipv4InAnyCidr(ip, cidrs) {
  return Array.isArray(cidrs) && cidrs.some((c) => ipv4InCidr(ip, c));
}

const i18n = new VueI18n({
  locale: localStorage.getItem(LOCALE_STORAGE_KEY) || DEFAULT_LOCALE,
  fallbackLocale: DEFAULT_LOCALE,
  messages,
});

// * Labels for language switcher (code -> short label).
const LOCALE_LABELS = { ru: 'Рус', en: 'En' };
function getLocaleLabel(code) {
  return LOCALE_LABELS[code] || code;
}

const UI_CHART_TYPES = [
  { type: false, strokeWidth: 0 },
  { type: 'line', strokeWidth: 3 },
  { type: 'area', strokeWidth: 0 },
  { type: 'bar', strokeWidth: 0 },
];

// Profile labels come from GET /api/signatures/profiles → profiles[].label

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
    panelUsername: null,
    panelUserId: null,
    panelRole: null,
    panelCapabilities: [],
    userActionsOpen: false,
    passwordModalOpen: false,
    passwordTargets: [],
    passwordTargetUserId: null,
    passwordNew: '',
    passwordConfirm: '',
    passwordFieldErrors: { password: '', passwordConfirm: '', _form: '' },
    passwordChangeSubmitting: false,
    createUserModalOpen: false,
    createUserUsername: '',
    createUserPassword: '',
    createUserConfirm: '',
    createUserRole: 'user',
    createUserCidr: '',
    createUserFieldErrors: { username: '', password: '', passwordConfirm: '', cidr: '', _form: '' },
    createUserSubmitting: false,
    sessionAssignedCidrs: [],
    vpnPools: [],
    cidrPoolEdit: null,
    cidrPoolAssign: null,
    cidrPoolAssignSelected: [],
    cidrPoolAssignSubmitting: false,
    roleLabels: {},
    panelUsers: [],
    clientAssignModalClient: null,
    clientAssignModalUserId: null,
    clientAssignSubmitting: false,
    clientAssignFieldError: '',
    loginFieldErrors: { username: '', password: '', _form: '' },

    clients: null,
    clientsPersist: {},
    clientDelete: null,
    clientCreate: null,
    clientCreateName: '',
    clientEditName: null,
    clientEditNameId: null,
    clientEditAddress: null,
    clientEditAddressId: null,
    qrcodeText: null,
    qrcodeTextPayload: null,
    qrcodeTextILimit: null,
    qrcodeAmneziaSvgs: null,
    qrcodeAmneziaPayloads: null,
    qrcodeAmneziaILimit: null,
    qrcodeTab: 'amnezia',
    configViewClient: null,
    configViewText: '',

    clientLevels: {},
    clientProfiles: {},
    clientSignatures: {},
    /** Draft junk / dirty flags for obfuscation Apply/Cancel. */
    clientJunk: {},
    clientObfuscationDirty: {},
    clientObfuscationBusy: {},
    clientJunkPins: {},
    clientMtuProfiles: {},
    mtuProfileCatalog: [],
    mtuDefaultProfile: '1280',
    serverJunk: null,
    /** Config text loaded for QR modal Preview tab (committed server state). */
    qrcodePreviewText: '',
    /** Per-client download format for configuration link: 'conf' | 'amnezia' */
    clientDownloadFormat: {},
    clientUseServerDns: {},
    profileIds: [],
    profileCatalog: [],
    defaultProfile: 'dns',
    signaturesBankError: null,
    regeneratingSignatures: false,
    amneziaDnsAvailable: false,
    amneziaDnsPhase: 'off',
    amneziaDnsBusy: false,
    amneziaDnsError: null,
    amneziaDnsPollTimer: null,
    amneziaDnsProfileId: null,
    amneziaDnsProfile: null,
    amneziaDnsProfiles: [],
    amneziaDnsProfilesError: null,
    amneziaDnsInstallOpen: false,
    amneziaDnsInstallSelected: null,
    amneziaDnsModalMode: 'install',
    amneziaXrayAvailable: false,
    amneziaXrayHealthy: false,
    amneziaXraySmokeOk: false,
    amneziaXrayPhase: 'off',
    amneziaXrayBusy: false,
    amneziaXrayError: null,
    amneziaXrayPollTimer: null,
    amneziaXraySni: '',
    amneziaXrayAddress: '',
    amneziaXrayFingerprint: 'chrome',
    amneziaXrayFlow: 'xtls-rprx-vision',
    amneziaXrayPort: '',
    amneziaXrayPublicPort: 443,
    amneziaXrayMode: null,
    amneziaXrayDemuxPeers: [],
    amneziaXrayInstallOpen: false,
    amneziaXrayModalMode: 'install',
    amneziaXrayFingerprints: ['chrome', 'firefox', 'safari', 'ios', 'android', 'edge', 'random'],
    amneziaXrayFlows: [
      { value: 'xtls-rprx-vision', label: 'xtls-rprx-vision' },
      { value: 'xtls-rprx-vision-udp443', label: 'xtls-rprx-vision-udp443' },
      { value: '', label: '(none)' },
    ],
    ...(typeof SidecarPanels !== 'undefined' ? SidecarPanels.initialState() : {}),
    sniFinderDefaultSni: null,
    sniFinderOpen: false,
    sniFinderPublicIp: null,
    sniFinderDefaultCidr: '',
    sniFinderCidr: '',
    sniFinderPublicIpError: null,
    sniFinderError: null,
    sniFinderEmptyMsg: null,
    sniFinderBusy: false,
    sniFinderPhase: 'idle',
    sniFinderProgress: { done: 0, total: 0 },
    sniFinderEntries: [],
    sniFinderAliveCount: 0,
    sniFinderRechecking: null,
    sniFinderPollTimer: null,
    qrcodeXraySvg: null,
    qrcodeXraySubUrl: '',
    qrcodeXrayVlessUrl: '',
    qrcodeXrayJson: '',
    qrcodeXrayClientId: null,
    ruleProfiles: [],
    globalFirewallRules: [],
    globalRuleEdit: null,
    expandedProfileIds: [],
    profileRulesByExpandedId: {},
    profileRuleEdit: null,
    profileCreate: null,
    profileEdit: null,
    clientExpiryEdit: null,
    expiryEditValue: '',
    expandedClientStatsId: null,
    clientTrafficHistory: {},
    aggregateTrafficDisplay: '0.00 MB',
    resettingTrafficClientId: null,

    currentRelease: null,
    latestRelease: null,

    refreshError: null,

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
    formatTrafficShort(bytesIn) {
      return formatTrafficShort(bytesIn);
    },
    getClientLevel(client) {
      return this.clientLevels[client.id] ?? 1;
    },
    isObfuscationDirty(client) {
      return !!(client && this.clientObfuscationDirty[client.id]);
    },
    isObfuscationBusy(client) {
      return !!(client && this.clientObfuscationBusy[client.id]);
    },
    markObfuscationDirty(clientId) {
      this.$set(this.clientObfuscationDirty, clientId, true);
    },
    clearObfuscationDirty(clientId) {
      this.$set(this.clientObfuscationDirty, clientId, false);
    },
    committedObfuscationFromClient(client) {
      const profile = client.defaultProfile || this.defaultProfile || 'dns';
      const pins = client.junkPins || this.clientJunkPins[client.id] || {};
      const junk = (pins && pins[profile])
        || this.serverJunk
        || this.clientJunk[client.id]
        || null;
      return {
        level: client.defaultLevel != null ? client.defaultLevel : 1,
        profile,
        signature: client.defaultSignature != null ? String(client.defaultSignature) : null,
        junk,
        junkPins: pins,
      };
    },
    syncObfuscationDraftFromClient(client, { force = false } = {}) {
      if (!client || (!force && this.isObfuscationDirty(client))) return;
      const c = this.committedObfuscationFromClient(client);
      this.$set(this.clientLevels, client.id, c.level);
      this.$set(this.clientProfiles, client.id, c.profile);
      if (c.signature != null) this.$set(this.clientSignatures, client.id, c.signature);
      if (c.junk) this.$set(this.clientJunk, client.id, c.junk);
      this.$set(this.clientJunkPins, client.id, c.junkPins || {});
      this.$set(
        this.clientMtuProfiles,
        client.id,
        client.mtuProfile || this.mtuDefaultProfile || '1280',
      );
      this.clearObfuscationDirty(client.id);
    },
    formatJunkSummary(junk) {
      if (!junk) return '';
      return this.$t('obfuscationJunkSummary', {
        jc: junk.jc,
        jmin: junk.jmin,
        jmax: junk.jmax,
        s1: junk.s1,
        s2: junk.s2,
        s3: junk.s3,
        s4: junk.s4,
      });
    },
    cycleClientLevel(client) {
      const prev = this.getClientLevel(client);
      const next = prev === 0 ? 1 : (prev === 5 ? 0 : prev + 1);
      this.$set(this.clientLevels, client.id, next);
      this.markObfuscationDirty(client.id);
    },
    /** Committed obfuscation from server (not UI draft) for download/QR. */
    getCommittedLevel(client) {
      return client && client.defaultLevel != null ? client.defaultLevel : 1;
    },
    getCommittedProfile(client) {
      return (client && client.defaultProfile) || this.defaultProfile || 'dns';
    },
    getClientMtuProfile(client) {
      return this.clientMtuProfiles[client.id]
        || client.mtuProfile
        || this.mtuDefaultProfile
        || '1280';
    },
    getClientMtuLabel(client) {
      const id = this.getClientMtuProfile(client);
      const row = (this.mtuProfileCatalog || []).find((p) => p.id === id);
      if (row && row.label != null) return row.label;
      return id;
    },
    cycleClientMtu(client) {
      const list = (this.mtuProfileCatalog || []).map((p) => p.id);
      if (!list.length) return;
      const current = this.getClientMtuProfile(client);
      let idx = list.indexOf(current);
      if (idx < 0) idx = 0;
      const next = list[(idx + 1) % list.length];
      this.$set(this.clientMtuProfiles, client.id, next);
      this.markObfuscationDirty(client.id);
    },
    async reloadMtuProfiles() {
      try {
        const r = await this.api.getMtuProfiles();
        this.mtuProfileCatalog = (r && Array.isArray(r.profiles)) ? r.profiles : [];
        this.mtuDefaultProfile = (r && r.defaultProfile) || '1280';
      } catch {
        this.mtuProfileCatalog = [];
      }
    },
    onObfuscationLevelChange(client, ev) {
      const raw = ev.target.value;
      const level = raw === '' || raw === 'null' ? 0 : parseInt(raw, 10);
      if (Number.isNaN(level) || level < 0 || level > 5) return;
      this.$set(this.clientLevels, client.id, level);
      this.markObfuscationDirty(client.id);
    },
    getClientProfile(client) {
      return this.clientProfiles[client.id] ?? client.defaultProfile ?? this.defaultProfile;
    },
    getClientSignature(client) {
      return this.clientSignatures[client.id] ?? client.defaultSignature ?? null;
    },
    getClientJunk(client) {
      return this.clientJunk[client.id] || null;
    },
    getClientProfileLabel(client) {
      return this.getProfileLabel(this.getClientProfile(client));
    },
    getProfileLabel(profileId) {
      const row = (this.profileCatalog || []).find((p) => (p.id || p.profile_id) === profileId);
      if (row && row.label) return row.label;
      return profileId;
    },
    getProfileHint(profileId) {
      const row = (this.profileCatalog || []).find((p) => (p.id || p.profile_id) === profileId);
      if (!row || row.count == null) return '';
      return this.$t('signatureVariants', { count: row.count });
    },
    async cycleClientProfile(client) {
      if (this.signaturesBankError) {
        alert(this.signaturesBankError);
        return;
      }
      const list = this.profileIds.length ? this.profileIds : [this.defaultProfile || 'dns'];
      const current = this.getClientProfile(client);
      let idx = list.indexOf(current);
      if (idx < 0) idx = 0;
      const next = list[(idx + 1) % list.length];
      await this.cycleClientProfileTo(client, next);
    },
    onObfuscationProfileChange(client, ev) {
      const profile = ev.target.value;
      this.cycleClientProfileTo(client, profile);
    },
    async cycleClientProfileTo(client, next) {
      const prevProfile = this.getClientProfile(client);
      const prevSig = this.getClientSignature(client);
      const prevJunk = this.getClientJunk(client);
      try {
        const r = await this.api.previewClientObfuscation({
          clientId: client.id,
          profile: next,
          level: this.getClientLevel(client),
          signature: prevSig,
        });
        this.$set(this.clientProfiles, client.id, r.profile || next);
        if (r.signature != null) this.$set(this.clientSignatures, client.id, String(r.signature));
        if (r.junk) this.$set(this.clientJunk, client.id, r.junk);
        this.markObfuscationDirty(client.id);
      } catch (err) {
        this.$set(this.clientProfiles, client.id, prevProfile);
        if (prevSig != null) this.$set(this.clientSignatures, client.id, prevSig);
        if (prevJunk) this.$set(this.clientJunk, client.id, prevJunk);
        alert(err.message || this.$t('obfuscationPreviewFailed'));
      }
    },
    async refreshClientSignature(client) {
      if (this.regeneratingSignatures) return;
      if (this.signaturesBankError) {
        alert(this.signaturesBankError);
        return;
      }
      this.regeneratingSignatures = true;
      const prevSig = this.getClientSignature(client);
      const prevJunk = this.getClientJunk(client);
      try {
        const result = await this.api.previewClientObfuscation({
          clientId: client.id,
          profile: this.getClientProfile(client),
          level: this.getClientLevel(client),
          signature: prevSig,
          refreshSignature: true,
          regenerateJunk: true,
        });
        if (result && result.signature != null) {
          this.$set(this.clientSignatures, client.id, String(result.signature));
        }
        if (result && result.profile) {
          this.$set(this.clientProfiles, client.id, result.profile);
        }
        if (result && result.junk) {
          this.$set(this.clientJunk, client.id, result.junk);
        }
        this.markObfuscationDirty(client.id);
      } catch (err) {
        if (prevSig != null) this.$set(this.clientSignatures, client.id, prevSig);
        if (prevJunk) this.$set(this.clientJunk, client.id, prevJunk);
        alert(err.message || this.$t('signaturesRefreshFailed') || 'Refresh failed.');
      } finally {
        this.regeneratingSignatures = false;
      }
    },
    cancelClientObfuscation(client) {
      if (this.isObfuscationBusy(client)) return;
      this.syncObfuscationDraftFromClient(client, { force: true });
    },
    async applyClientObfuscation(client) {
      if (!client || this.isObfuscationBusy(client) || !this.isObfuscationDirty(client)) return;
      this.$set(this.clientObfuscationBusy, client.id, true);
      try {
        let junk = this.getClientJunk(client);
        // Legacy server junk (e.g. S4>32) cannot be re-applied — generate a valid set first.
        if (!junk || junk.s4 > 32) {
          const preview = await this.api.previewClientObfuscation({
            clientId: client.id,
            profile: this.getClientProfile(client),
            level: this.getClientLevel(client),
            signature: this.getClientSignature(client),
            regenerateJunk: true,
          });
          junk = preview.junk;
          if (preview.signature != null) {
            this.$set(this.clientSignatures, client.id, String(preview.signature));
          }
          if (preview.junk) this.$set(this.clientJunk, client.id, preview.junk);
        }
        if (!junk) {
          throw new Error(this.$t('obfuscationApplyFailed'));
        }
        const mtuProfile = this.getClientMtuProfile(client);
        const result = await this.api.applyClientObfuscation({
          clientId: client.id,
          level: this.getClientLevel(client),
          profile: this.getClientProfile(client),
          signature: this.getClientSignature(client),
          junk,
          mtuProfile,
        });
        if (result && result.junk) this.$set(this.clientJunk, client.id, result.junk);
        if (result && result.junkPins) this.$set(this.clientJunkPins, client.id, result.junkPins);
        if (result && result.serverJunk) this.serverJunk = result.serverJunk;
        if (result && result.profile) this.$set(this.clientProfiles, client.id, result.profile);
        if (result && result.signature != null) {
          this.$set(this.clientSignatures, client.id, String(result.signature));
        }
        if (result && result.level != null) this.$set(this.clientLevels, client.id, result.level);
        if (result && result.mtuProfile) {
          this.$set(this.clientMtuProfiles, client.id, result.mtuProfile);
          client.mtuProfile = result.mtuProfile;
        } else {
          client.mtuProfile = mtuProfile;
        }
        // Keep local client object committed fields in sync for cancel/refresh.
        client.defaultProfile = this.getClientProfile(client);
        client.defaultSignature = this.getClientSignature(client);
        client.defaultLevel = this.getClientLevel(client);
        client.junkPins = result.junkPins || this.clientJunkPins[client.id] || {};
        this.clearObfuscationDirty(client.id);
        await this.refresh().catch(() => {});
      } catch (err) {
        alert(err.message || this.$t('obfuscationApplyFailed'));
      } finally {
        this.$set(this.clientObfuscationBusy, client.id, false);
      }
    },
    guardDirtyObfuscation(client, ev) {
      if (!this.isObfuscationDirty(client)) return false;
      if (ev) ev.preventDefault();
      alert(this.$t('obfuscationDownloadBlocked'));
      return true;
    },
    async reloadSignatureProfiles({ attempts = 5 } = {}) {
      let lastErr = null;
      for (let i = 0; i < attempts; i += 1) {
        try {
          const r = await this.api.getSignaturesProfiles();
          this.signaturesBankError = null;
          this.profileIds = r && Array.isArray(r.profileIds) ? r.profileIds : [];
          this.profileCatalog = r && Array.isArray(r.protocols) ? r.protocols : [];
          this.defaultProfile = (r && (r.defaultProtocol || r.defaultProfile))
            || (this.profileIds[0] || 'dns');
          return true;
        } catch (err) {
          lastErr = err;
          if (i < attempts - 1) {
            await new Promise((resolve) => setTimeout(resolve, 350 * (i + 1)));
          }
        }
      }
      const msg = (lastErr && lastErr.message) || '';
      const status = lastErr && lastErr.status;
      // Keep a previous good catalog; avoid sticky red banner on transient 5xx/network blips.
      const transient = status >= 500
        || (lastErr && lastErr.code === 'NETWORK_ERROR')
        || msg === 'NETWORK_ERROR'
        || /^Internal Server Error$/i.test(msg)
        || /^Bad Gateway$/i.test(msg);
      if (transient && this.profileIds && this.profileIds.length) {
        return false;
      }
      this.signaturesBankError = msg || this.$t('signaturesBankUnavailable') || 'signatures.json unavailable';
      if (!this.profileIds || !this.profileIds.length) {
        this.profileIds = [];
        this.profileCatalog = [];
      }
      return false;
    },
    applyAmneziaDnsCapability(caps) {
      const c = caps || {};
      this.amneziaDnsAvailable = c.amneziaDnsAvailable === true;
      const st = c.amneziaDns || {};
      if (st.phase) this.amneziaDnsPhase = st.phase;
      this.amneziaDnsBusy = st.busy === true
        || st.phase === 'installing'
        || st.phase === 'removing';
      this.amneziaDnsError = st.lastError || null;
      if (st.profileId != null) this.amneziaDnsProfileId = st.profileId;
      if (st.profile !== undefined) this.amneziaDnsProfile = st.profile;
      if (this.amneziaDnsBusy) this.ensureAmneziaDnsPoll();
      else this.stopAmneziaDnsPoll();
    },
    async refreshAmneziaDnsStatus() {
      try {
        const st = await this.api.getAmneziaDnsStatus();
        this.applyAmneziaDnsCapability({
          amneziaDnsAvailable: st.available === true,
          amneziaDns: st,
        });
        return st;
      } catch (err) {
        this.amneziaDnsError = (err && err.message) || String(err);
        return null;
      }
    },
    ensureAmneziaDnsPoll() {
      if (this.amneziaDnsPollTimer) return;
      this.amneziaDnsPollTimer = setInterval(() => {
        this.refreshAmneziaDnsStatus().then((st) => {
          if (st && (st.phase === 'running' || st.phase === 'off' || st.phase === 'error')) {
            this.refresh().catch(() => {});
          }
        });
      }, 1000);
    },
    stopAmneziaDnsPoll() {
      if (this.amneziaDnsPollTimer) {
        clearInterval(this.amneziaDnsPollTimer);
        this.amneziaDnsPollTimer = null;
      }
    },
    amneziaDnsHeaderTitle() {
      const phase = this.amneziaDnsPhase;
      if (phase === 'installing' || phase === 'removing' || this.amneziaDnsBusy) {
        return this.$t('dnsHeaderBusy');
      }
      if (phase === 'error') {
        return (this.amneziaDnsError && `${this.$t('dnsHeaderError')}: ${this.amneziaDnsError}`)
          || this.$t('dnsHeaderError');
      }
      if (phase === 'degraded') return this.$t('dnsHeaderDegraded');
      if (phase === 'running') {
        const name = this.amneziaDnsProfile && this.amneziaDnsProfile.name;
        return name
          ? `${this.$t('dnsHeaderManage')} (${name})`
          : this.$t('dnsHeaderManage');
      }
      return this.$t('dnsHeaderEnable');
    },
    withAmneziaDnsTimeout(promise, ms = 100000) {
      let timer;
      const timeout = new Promise((_, reject) => {
        timer = setTimeout(() => {
          reject(new Error(`${this.$t('dnsToggleFailed')} (timeout)`));
        }, ms);
      });
      return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
    },
    formatDnsServerEndpoint(server) {
      if (!server || !server.address) return '';
      const port = server.port != null ? server.port : '';
      return port !== '' ? `${server.address}:${port}` : String(server.address);
    },
    formatDnsProfileEndpoints(profile) {
      const servers = (profile && profile.servers) || [];
      return servers.map((s) => this.formatDnsServerEndpoint(s)).filter(Boolean).join('  ·  ');
    },
    dnsProfileDisplayMs(profile) {
      if (!profile || profile.available === false) return null;
      if (profile.displayMs != null) return profile.displayMs;
      if (profile.pingMs != null) return profile.pingMs;
      if (profile.latencyMs != null) return profile.latencyMs;
      return null;
    },
    dnsLatencyClass(ms) {
      if (ms == null) return '';
      if (ms < 50) return 'is-good';
      if (ms < 100) return 'is-ok';
      if (ms < 200) return 'is-slow';
      if (ms < 400) return 'is-bad';
      return 'is-dead';
    },
    closeAmneziaDnsInstall() {
      this.amneziaDnsInstallOpen = false;
      this.amneziaDnsInstallSelected = null;
      this.amneziaDnsModalMode = 'install';
    },
    async openAmneziaDnsInstall({ mode = 'install' } = {}) {
      this.amneziaDnsModalMode = mode;
      this.amneziaDnsProfilesError = null;
      try {
        // Cached server-side probes (5 min TTL) — no blocking wait on open.
        const catalog = await this.api.getAmneziaDnsProfiles({ refresh: false });
        this.amneziaDnsProfiles = (catalog && catalog.profiles) || [];
        if (!this.amneziaDnsProfiles.length) {
          throw new Error((catalog && catalog.error) || this.$t('dnsProfilesEmpty'));
        }
        const available = this.amneziaDnsProfiles.filter((p) => p.available !== false);
        if (!available.length) {
          throw new Error(this.$t('dnsProfilesEmpty'));
        }
        const preferredId = this.amneziaDnsProfileId
          || (catalog && catalog.defaultProfile)
          || available[0].id;
        const preferred = available.find((p) => p.id === preferredId) || available[0];
        this.amneziaDnsInstallSelected = preferred.id;
        this.amneziaDnsInstallOpen = true;
      } catch (err) {
        this.amneziaDnsProfilesError = (err && err.message) || this.$t('dnsProfilesUnavailable');
        alert(this.amneziaDnsProfilesError);
      }
    },
    async confirmAmneziaDnsInstall() {
      const profileId = this.amneziaDnsInstallSelected;
      const selected = this.amneziaDnsProfiles.find((p) => p.id === profileId);
      if (!profileId || this.amneziaDnsBusy || !selected || selected.available === false) return;
      this.closeAmneziaDnsInstall();
      this.amneziaDnsBusy = true;
      this.ensureAmneziaDnsPoll();
      try {
        await this.withAmneziaDnsTimeout(
          this.api.enableAmneziaDns({ profileId }),
          100000,
        );
        await this.refreshAmneziaDnsStatus();
        await this.refresh();
      } catch (err) {
        this.amneziaDnsError = (err && err.message) || this.$t('dnsToggleFailed');
        alert(this.amneziaDnsError);
        await this.refreshAmneziaDnsStatus();
      } finally {
        this.amneziaDnsBusy = false;
        if (!['installing', 'removing'].includes(this.amneziaDnsPhase)) {
          this.stopAmneziaDnsPoll();
        }
      }
    },
    async confirmAmneziaDnsDisable() {
      if (this.amneziaDnsBusy) return;
      if (!window.confirm(this.$t('dnsUninstallConfirm'))) return;
      this.closeAmneziaDnsInstall();
      this.amneziaDnsBusy = true;
      this.ensureAmneziaDnsPoll();
      try {
        await this.withAmneziaDnsTimeout(this.api.disableAmneziaDns(), 60000);
        await this.refreshAmneziaDnsStatus();
        await this.refresh();
      } catch (err) {
        this.amneziaDnsError = (err && err.message) || this.$t('dnsToggleFailed');
        alert(this.amneziaDnsError);
        await this.refreshAmneziaDnsStatus();
      } finally {
        this.amneziaDnsBusy = false;
        if (!['installing', 'removing'].includes(this.amneziaDnsPhase)) {
          this.stopAmneziaDnsPoll();
        }
      }
    },
    async toggleAmneziaDns() {
      if (this.amneziaDnsBusy) return;
      const phase = this.amneziaDnsPhase;
      if (phase === 'running' || phase === 'degraded') {
        await this.openAmneziaDnsInstall({ mode: 'manage' });
        return;
      }
      if (phase === 'error') {
        this.amneziaDnsBusy = true;
        this.ensureAmneziaDnsPoll();
        try {
          await this.withAmneziaDnsTimeout(this.api.forceCleanupAmneziaDns(), 60000);
          await this.refreshAmneziaDnsStatus();
          await this.refresh();
        } catch (err) {
          this.amneziaDnsError = (err && err.message) || this.$t('dnsToggleFailed');
          alert(this.amneziaDnsError);
          await this.refreshAmneziaDnsStatus();
        } finally {
          this.amneziaDnsBusy = false;
          this.stopAmneziaDnsPoll();
        }
        return;
      }
      await this.openAmneziaDnsInstall({ mode: 'install' });
    },
    applyAmneziaXrayCapability(caps) {
      const c = caps || {};
      const st = c.xray || {};
      const smokeOk = !!(st.smoke && st.smoke.ok === true);
      const healthy = st.healthy === true
        || (st.phase === 'running' && smokeOk)
        || (c.xrayAvailable === true && smokeOk);
      this.amneziaXraySmokeOk = smokeOk;
      this.amneziaXrayHealthy = healthy;
      this.amneziaXrayAvailable = healthy;
      if (st.phase) this.amneziaXrayPhase = st.phase;
      this.amneziaXrayBusy = st.busy === true
        || st.phase === 'installing'
        || st.phase === 'removing';
      this.amneziaXrayError = st.lastError || null;
      // While install/manage modal is open, keep draft — poll must not clobber fields.
      if (!this.amneziaXrayInstallOpen && this.amneziaXrayModalMode !== 'manage') {
        if (st.sniStored) this.amneziaXraySni = st.sniStored;
        else if (st.sni && !this.amneziaXraySni) this.amneziaXraySni = st.sni;
        if (st.addressStored) this.amneziaXrayAddress = st.addressStored;
        else if (st.address && !this.amneziaXrayAddress) this.amneziaXrayAddress = st.address;
        if (st.fingerprint) this.amneziaXrayFingerprint = st.fingerprint;
        if (st.flow !== undefined && st.flow !== null) this.amneziaXrayFlow = st.flow;
        if (st.port) this.amneziaXrayPort = st.port;
        if (st.publicPort) this.amneziaXrayPublicPort = st.publicPort;
      }
      this.amneziaXrayMode = st.mode || null;
      this.amneziaXrayDemuxPeers = Array.isArray(st.demuxPeers) ? st.demuxPeers : [];
      if (Array.isArray(st.fingerprints) && st.fingerprints.length) {
        this.amneziaXrayFingerprints = st.fingerprints;
      }
      if (this.amneziaXrayBusy) this.ensureAmneziaXrayPoll();
      else this.stopAmneziaXrayPoll();
    },
    async refreshAmneziaXrayStatus() {
      if (!this.canManageXray) return null;
      try {
        const st = await this.api.getAmneziaXrayStatus();
        this.applyAmneziaXrayCapability({
          xrayAvailable: st.available === true,
          xray: st,
        });
        return st;
      } catch (err) {
        this.amneziaXrayError = (err && err.message) || String(err);
        return null;
      }
    },
    ensureAmneziaXrayPoll() {
      if (this.amneziaXrayPollTimer) return;
      this.amneziaXrayPollTimer = setInterval(() => {
        this.refreshAmneziaXrayStatus().then((st) => {
          if (st && (st.phase === 'running' || st.phase === 'off' || st.phase === 'error')) {
            this.refresh().catch(() => {});
          }
        });
      }, 1000);
    },
    stopAmneziaXrayPoll() {
      if (this.amneziaXrayPollTimer) {
        clearInterval(this.amneziaXrayPollTimer);
        this.amneziaXrayPollTimer = null;
      }
    },
    amneziaXrayHeaderTitle() {
      const phase = this.amneziaXrayPhase;
      if (phase === 'installing' || phase === 'removing' || this.amneziaXrayBusy) {
        return this.$t('xrayHeaderBusy');
      }
      if (phase === 'error') {
        return (this.amneziaXrayError && `${this.$t('xrayHeaderError')}: ${this.amneziaXrayError}`)
          || this.$t('xrayHeaderError');
      }
      if (phase === 'degraded' || (phase === 'running' && !this.amneziaXrayHealthy)) {
        return this.$t('xrayHeaderDegraded');
      }
      if (phase === 'running' && this.amneziaXrayHealthy) return this.$t('xrayHeaderManage');
      return this.$t('xrayHeaderEnable');
    },
    closeAmneziaXrayInstall() {
      this.amneziaXrayInstallOpen = false;
      this.amneziaXrayModalMode = 'install';
    },
    openAmneziaXrayInstall({ mode = 'install' } = {}) {
      this.amneziaXrayModalMode = mode;
      // Prefill from persisted status; address defaults to how the panel was opened.
      Promise.all([
        this.refreshAmneziaXrayStatus(),
        this.refreshSniCache({ ensureBg: true }),
      ]).finally(() => {
        if (!String(this.amneziaXrayAddress || '').trim()) {
          this.amneziaXrayAddress = (typeof window !== 'undefined' && window.location && window.location.hostname)
            ? window.location.hostname
            : '';
        }
        if (!String(this.amneziaXraySni || '').trim() && this.sniFinderDefaultSni) {
          this.amneziaXraySni = this.sniFinderDefaultSni;
        }
        this.amneziaXrayInstallOpen = true;
      });
    },
    async confirmAmneziaXrayInstall() {
      if (
        this.amneziaXrayBusy
        || !String(this.amneziaXraySni || '').trim()
        || !String(this.amneziaXrayAddress || '').trim()
        || !this.isValidAmneziaXrayPort
        || !this.isValidAmneziaXrayPublicPort
      ) return;
      this.closeAmneziaXrayInstall();
      this.amneziaXrayBusy = true;
      this.ensureAmneziaXrayPoll();
      try {
        await this.preflightSniForInstall(this.amneziaXraySni);
        const body = {
          address: String(this.amneziaXrayAddress).trim(),
          sni: String(this.amneziaXraySni).trim(),
          fingerprint: this.amneziaXrayFingerprint,
          flow: this.amneziaXrayFlow,
          publicPort: Number(this.amneziaXrayPublicPort) || 443,
        };
        const portRaw = String(this.amneziaXrayPort == null ? '' : this.amneziaXrayPort).trim();
        if (portRaw !== '') body.port = Number(portRaw);
        await this.withAmneziaDnsTimeout(
          this.api.enableAmneziaXray(body),
          180000,
        );
        await this.refreshAmneziaXrayStatus();
        await this.refresh();
      } catch (err) {
        this.amneziaXrayError = (err && err.message) || this.$t('xrayToggleFailed');
        alert(this.amneziaXrayError);
        await this.refreshAmneziaXrayStatus();
      } finally {
        this.amneziaXrayBusy = false;
        if (!['installing', 'removing'].includes(this.amneziaXrayPhase)) {
          this.stopAmneziaXrayPoll();
        }
      }
    },
    async confirmAmneziaXrayReset() {
      if (this.amneziaXrayBusy) return;
      if (!window.confirm(this.$t('xrayResetConfirm'))) return;
      this.amneziaXrayBusy = true;
      this.ensureAmneziaXrayPoll();
      try {
        await this.withAmneziaDnsTimeout(this.api.resetAmneziaXray(), 120000);
        await this.refreshAmneziaXrayStatus();
        await this.refresh();
        alert(this.$t('xrayResetDone'));
      } catch (err) {
        this.amneziaXrayError = (err && err.message) || this.$t('xrayToggleFailed');
        alert(this.amneziaXrayError);
        await this.refreshAmneziaXrayStatus();
      } finally {
        this.amneziaXrayBusy = false;
        if (!['installing', 'removing'].includes(this.amneziaXrayPhase)) {
          this.stopAmneziaXrayPoll();
        }
      }
    },
    stopSniFinderPoll() {
      if (this.sniFinderPollTimer) {
        clearInterval(this.sniFinderPollTimer);
        this.sniFinderPollTimer = null;
      }
    },
    applySniCachePayload(data) {
      if (!data || typeof data !== 'object') return;
      this.sniFinderPublicIp = data.publicIp || null;
      this.sniFinderDefaultCidr = data.defaultCidr || '';
      if (!this.sniFinderCidr) {
        this.sniFinderCidr = data.defaultCidr || data.cidr || '';
      }
      this.sniFinderPublicIpError = (data.publicIpError && data.publicIpError.message) || null;
      this.sniFinderAliveCount = Number(data.scannedAliveCount) || 0;
      this.sniFinderDefaultSni = data.defaultSni || null;
      if (Array.isArray(data.entries)) {
        this.sniFinderEntries = data.entries;
      }
      if (data.scan) this.applySniScanStatus(data.scan);
    },
    applySniScanStatus(st) {
      if (!st || typeof st !== 'object') return;
      this.sniFinderPhase = st.phase || 'idle';
      this.sniFinderProgress = st.progress || { done: 0, total: 0 };
      this.sniFinderBusy = st.busy === true
        || ['starting', 'detecting', 'probing', 'verifying'].includes(st.phase);
      if (st.result && st.result.empty) {
        this.sniFinderEmptyMsg = this.$t('xraySniNothingFound');
        this.sniFinderError = null;
      } else if (st.error && st.error.message) {
        this.sniFinderEmptyMsg = null;
        this.sniFinderError = st.error.code
          ? `[${st.error.code}] ${st.error.message}`
          : st.error.message;
      }
      if (st.result && Array.isArray(st.result.entries)) {
        this.sniFinderEntries = st.result.entries;
        this.sniFinderAliveCount = st.result.entries.filter(
          (e) => e.source === 'scan' && e.alive !== false,
        ).length;
        if (st.result.cidr) this.sniFinderCidr = st.result.cidr;
        if (st.result.refIp) this.sniFinderPublicIp = st.result.refIp;
      } else if (st.result && Array.isArray(st.result.domains) && !st.result.entries) {
        /* legacy */
      }
      if (st.phase === 'done' || st.phase === 'error' || st.phase === 'idle') {
        if (!this.sniFinderBusy) this.stopSniFinderPoll();
      }
    },
    ensureSniFinderPoll() {
      if (this.sniFinderPollTimer) return;
      this.sniFinderPollTimer = setInterval(async () => {
        try {
          const st = await this.api.getXraySniScanStatus();
          this.applySniScanStatus(st);
          if (!this.sniFinderBusy) {
            await this.refreshSniCache({ ensureBg: false });
          }
        } catch {
          /* ignore poll errors */
        }
      }, 1000);
    },
    async refreshSniCache({ ensureBg } = {}) {
      try {
        const data = await this.api.getXraySniCache({ ensureBg: !!ensureBg });
        this.applySniCachePayload(data);
        if (data.scan && data.scan.busy) this.ensureSniFinderPoll();
        return data;
      } catch (err) {
        if (this.sniFinderOpen) {
          this.sniFinderError = (err && err.message) || this.$t('xraySniScanFailed');
        }
        return null;
      }
    },
    async openSniFinder() {
      this.sniFinderOpen = true;
      this.sniFinderError = null;
      this.sniFinderEmptyMsg = null;
      await this.refreshSniCache({ ensureBg: true });
    },
    closeSniFinder() {
      this.sniFinderOpen = false;
      this.stopSniFinderPoll();
    },
    sniRowBlockedForTarget(row) {
      if (!row || row.alive === false) return true;
      return !String(row.domain || '').trim();
    },
    pickSniDomain(row) {
      if (!row || row.alive === false) return;
      if (this.sniRowBlockedForTarget(row)) return;
      const domain = typeof row === 'string' ? row : row.domain;
      if (!domain) return;
      const value = String(domain).trim();
      this.amneziaXraySni = '';
      this.$nextTick(() => {
        this.amneziaXraySni = value;
      });
      this.closeSniFinder();
    },
    /**
     * Recheck SNI (public DNS + TLS/h2) before enable. Reality needs a real hostname.
     */
    async preflightSniForInstall(sni) {
      const domain = String(sni || '').trim();
      if (!domain) {
        throw new Error(this.$t('sniPreflightEmpty') || 'SNI is required');
      }
      const updated = await this.api.recheckXraySni({ domain });
      if (!updated || updated.alive === false) {
        throw new Error(
          this.$t('sniPreflightDead', { domain })
          || `SNI «${domain}» failed DNS/TLS check (need a real public hostname)`,
        );
      }
      return updated;
    },
    async recheckSniDomain(row) {
      if (!row || !row.domain || this.sniFinderRechecking) return;
      this.sniFinderRechecking = row.domain;
      try {
        const updated = await this.api.recheckXraySni({ domain: row.domain });
        if (updated && updated.domain) {
          const list = this.sniFinderEntries.slice();
          const idx = list.findIndex((e) => e.domain === updated.domain);
          if (idx >= 0) list.splice(idx, 1, updated);
          else list.push(updated);
          this.sniFinderEntries = list;
          this.sniFinderAliveCount = list.filter(
            (e) => e.source === 'scan' && e.alive !== false,
          ).length;
        } else {
          await this.refreshSniCache({ ensureBg: false });
        }
      } catch (err) {
        this.sniFinderError = (err && err.message) || this.$t('xraySniScanFailed');
      } finally {
        this.sniFinderRechecking = null;
      }
    },
    async startSniScan(force) {
      if (this.sniFinderBusy) return;
      this.sniFinderError = null;
      this.sniFinderEmptyMsg = null;
      this.sniFinderBusy = true;
      this.ensureSniFinderPoll();
      try {
        const st = await this.api.startXraySniScan({
          cidr: String(this.sniFinderCidr || '').trim() || undefined,
          force: force === true,
        });
        this.applySniScanStatus(st);
      } catch (err) {
        this.sniFinderBusy = false;
        this.stopSniFinderPoll();
        const code = err && err.code;
        const msg = (err && err.message) || this.$t('xraySniScanFailed');
        this.sniFinderError = code ? `[${code}] ${msg}` : msg;
      }
    },
    async confirmAmneziaXrayDisable() {
      if (!this.canManageXray || this.amneziaXrayBusy) return;
      if (!window.confirm(this.$t('xrayUninstallConfirm'))) return;
      this.closeAmneziaXrayInstall();
      this.amneziaXrayBusy = true;
      this.ensureAmneziaXrayPoll();
      try {
        await this.withAmneziaDnsTimeout(this.api.disableAmneziaXray(), 60000);
        await this.refreshAmneziaXrayStatus();
        await this.refresh();
      } catch (err) {
        this.amneziaXrayError = (err && err.message) || this.$t('xrayToggleFailed');
        alert(this.amneziaXrayError);
        await this.refreshAmneziaXrayStatus();
      } finally {
        this.amneziaXrayBusy = false;
        if (!['installing', 'removing'].includes(this.amneziaXrayPhase)) {
          this.stopAmneziaXrayPoll();
        }
      }
    },
    async toggleAmneziaXray() {
      if (!this.canManageXray || this.amneziaXrayBusy) return;
      const phase = this.amneziaXrayPhase;
      if (phase === 'running' || phase === 'degraded') {
        await this.openAmneziaXrayInstall({ mode: 'manage' });
        return;
      }
      if (phase === 'error') {
        this.amneziaXrayBusy = true;
        this.ensureAmneziaXrayPoll();
        try {
          await this.withAmneziaDnsTimeout(this.api.forceCleanupAmneziaXray(), 60000);
          await this.refreshAmneziaXrayStatus();
          await this.refresh();
        } catch (err) {
          this.amneziaXrayError = (err && err.message) || this.$t('xrayToggleFailed');
          alert(this.amneziaXrayError);
          await this.refreshAmneziaXrayStatus();
        } finally {
          this.amneziaXrayBusy = false;
          this.stopAmneziaXrayPoll();
        }
        return;
      }
      this.openAmneziaXrayInstall({ mode: 'install' });
    },
    getClientUseServerDns(client) {
      return this.clientUseServerDns[client.id] !== false;
    },
    toggleClientDns(client) {
      if (!this.amneziaDnsAvailable) return;
      const next = !this.getClientUseServerDns(client);
      const prev = this.getClientUseServerDns(client);
      this.$set(this.clientUseServerDns, client.id, next);
      this.$set(client, 'useServerDns', next);
      this.api.updateClientDns({ clientId: client.id, useServerDns: next })
        .catch((err) => {
          this.$set(this.clientUseServerDns, client.id, prev);
          this.$set(client, 'useServerDns', prev);
          alert(err.message || err.toString());
        });
    },
    /** Avoids ReferenceError if cached HTML references state before/without data key (use ?v= bump after deploy). */
    downloadFormatValue(clientId) {
      const m = this.clientDownloadFormat;
      if (m == null || typeof m !== 'object') return 'conf';
      return m[clientId] || 'conf';
    },
    onDownloadFormatChange(clientId, ev) {
      const value = ev && ev.target ? ev.target.value : '';
      if (this.clientDownloadFormat == null || typeof this.clientDownloadFormat !== 'object') {
        this.$set(this, 'clientDownloadFormat', {});
      }
      this.$set(this.clientDownloadFormat, clientId, value);
    },
    clientConfigurationDownloadHref(client) {
      // Committed server binding only — ignore UI draft.
      const level = this.getCommittedLevel(client);
      const profile = this.getCommittedProfile(client);
      const signature = client.defaultSignature != null ? String(client.defaultSignature) : null;
      const map = this.clientDownloadFormat;
      const fmt = (map && map[client.id]) || 'conf';
      const params = [`level=${Number(level)}`];
      if (profile) params.push(`profile=${encodeURIComponent(profile)}`);
      if (signature) params.push(`signature=${encodeURIComponent(signature)}`);
      if (fmt === 'amnezia') params.push('format=amnezia');
      return `/api/wireguard/client/${client.id}/configuration?${params.join('&')}`;
    },
    clientDownloadFilename(client) {
      const safe = String(client.name || client.id || 'configuration')
        .replace(/[^a-zA-Z0-9_=+.-]/g, '-')
        .replace(/(-{2,}|-$)/g, '-')
        .replace(/-$/, '')
        .substring(0, 32);
      const map = this.clientDownloadFormat;
      const fmt = (map && map[client.id]) || 'conf';
      const base = safe || 'configuration';
      return fmt === 'amnezia' ? `${base}.vpn` : `${base}.conf`;
    },
    async showQR(client) {
      try {
        const level = this.getCommittedLevel(client);
        const profile = this.getCommittedProfile(client);
        const xrayPromise = this.amneziaXrayAvailable
          ? this.api.getClientXray(client.id)
          : Promise.reject(new Error('xray off'));
        const [textRes, amneziaRes, previewRes, xrayRes] = await Promise.allSettled([
          this.api.getClientQRCodeSVG(client.id, level, profile, 'text'),
          this.api.getClientQRCodeSVG(client.id, level, profile, 'amnezia'),
          this.api.getConfiguration(client.id, level, profile),
          xrayPromise,
        ]);

        this.qrcodeText = null;
        this.qrcodeTextPayload = null;
        this.qrcodeTextILimit = null;
        this.qrcodeAmneziaSvgs = null;
        this.qrcodeAmneziaPayloads = null;
        this.qrcodeAmneziaILimit = null;
        this.qrcodePreviewText = '';
        this.qrcodeXraySvg = null;
        this.qrcodeXraySubUrl = '';
        this.qrcodeXrayVlessUrl = '';
        this.qrcodeXrayJson = '';
        this.qrcodeXrayClientId = client.id;

        if (textRes.status === 'fulfilled' && textRes.value && textRes.value.svg) {
          this.qrcodeText = 'data:image/svg+xml,' + encodeURIComponent(textRes.value.svg);
          this.qrcodeTextPayload = textRes.value.payload;
          this.qrcodeTextILimit = textRes.value.iLimit || null;
        }
        if (amneziaRes.status === 'fulfilled' && amneziaRes.value && Array.isArray(amneziaRes.value.svgs)) {
          this.qrcodeAmneziaSvgs = amneziaRes.value.svgs.map(
            (s) => 'data:image/svg+xml,' + encodeURIComponent(s),
          );
          this.qrcodeAmneziaPayloads = amneziaRes.value.payloads || [];
          this.qrcodeAmneziaILimit = amneziaRes.value.iLimit || null;
        }
        if (previewRes.status === 'fulfilled') {
          this.qrcodePreviewText = previewRes.value || '';
        }
        if (xrayRes.status === 'fulfilled' && xrayRes.value) {
          const x = xrayRes.value;
          this.qrcodeXraySubUrl = x.subUrl || '';
          this.qrcodeXrayVlessUrl = x.vlessUrl || '';
          this.qrcodeXrayJson = x.clientJson
            ? JSON.stringify(x.clientJson, null, 2)
            : '';
          if (x.subQrSvg) {
            this.qrcodeXraySvg = 'data:image/svg+xml,' + encodeURIComponent(x.subQrSvg);
          }
        }

        const hasAny = this.qrcodeText
          || (this.qrcodeAmneziaSvgs && this.qrcodeAmneziaSvgs.length)
          || this.qrcodePreviewText
          || this.qrcodeXraySvg
          || this.qrcodeXraySubUrl;
        if (!hasAny) {
          const err = (textRes.status === 'rejected' && textRes.reason)
            || (amneziaRes.status === 'rejected' && amneziaRes.reason)
            || (previewRes.status === 'rejected' && previewRes.reason);
          throw err || new Error('Failed to load QR code');
        }

        if (this.qrcodeAmneziaSvgs && this.qrcodeAmneziaSvgs.length) this.qrcodeTab = 'amnezia';
        else if (this.qrcodeText) this.qrcodeTab = 'text';
        else if (this.qrcodeXraySvg || this.qrcodeXraySubUrl) this.qrcodeTab = 'xray';
        else this.qrcodeTab = 'preview';

        if (!this.qrcodeText && textRes.status === 'rejected') {
          console.warn('Text QR unavailable:', textRes.reason && textRes.reason.message);
        }
      } catch (err) {
        alert(err.message || 'Failed to load QR code');
      }
    },
    closeQR() {
      this.qrcodeText = null;
      this.qrcodeTextPayload = null;
      this.qrcodeTextILimit = null;
      this.qrcodeAmneziaSvgs = null;
      this.qrcodeAmneziaPayloads = null;
      this.qrcodeAmneziaILimit = null;
      this.qrcodePreviewText = '';
      this.qrcodeXraySvg = null;
      this.qrcodeXraySubUrl = '';
      this.qrcodeXrayVlessUrl = '';
      this.qrcodeXrayJson = '';
      this.qrcodeXrayClientId = null;
      this.qrcodeTab = 'amnezia';
    },
    async copyQrXraySub() {
      try {
        await this.copyTextToClipboard(this.qrcodeXraySubUrl || '');
      } catch (err) {
        alert(err.message || 'Copy failed');
      }
    },
    async copyQrXrayVless() {
      try {
        await this.copyTextToClipboard(this.qrcodeXrayVlessUrl || '');
      } catch (err) {
        alert(err.message || 'Copy failed');
      }
    },
    async copyQrXrayJson() {
      try {
        await this.copyTextToClipboard(this.qrcodeXrayJson || '');
      } catch (err) {
        alert(err.message || 'Copy failed');
      }
    },
    formatQrILimitNote(iLimit) {
      if (!iLimit || !iLimit.limited) return '';
      if (iLimit.excluded || iLimit.effective === 0) return this.$t('qrIParamsExcluded');
      return this.$t('qrIParamsLimited', { n: iLimit.effective });
    },
    async copyQrPreview() {
      try {
        await this.copyTextToClipboard(this.qrcodePreviewText || '');
      } catch (err) {
        alert(err.message || 'Copy failed');
      }
    },
    async copyTextToClipboard(text) {
      if (text == null || text === '') return;
      if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(text);
        return;
      }
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.setAttribute('readonly', '');
      ta.style.cssText = 'position:fixed;top:0;left:0;width:2em;height:2em;padding:0;border:none;outline:none;boxShadow:none;background:transparent;opacity:0;';
      document.body.appendChild(ta);
      ta.focus();
      ta.select();
      const ok = document.execCommand('copy');
      document.body.removeChild(ta);
      if (!ok) throw new Error('Copy failed');
    },
    async copyQrPayload(payload) {
      try {
        await this.copyTextToClipboard(payload);
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
    formatClientCreated(client) {
      if (!client || !client.createdAt) return '—';
      const d = client.createdAt instanceof Date ? client.createdAt : new Date(client.createdAt);
      const dd = String(d.getDate()).padStart(2, '0');
      const mm = String(d.getMonth() + 1).padStart(2, '0');
      const yyyy = d.getFullYear();
      const name = client.createdByUsername || '—';
      return `${dd}.${mm}.${yyyy} ${name}`;
    },
    async refresh({
      updateCharts = false,
    } = {}) {
      if (!this.authenticated) return;

      try {
        if (this.signaturesBankError) {
          this.reloadSignatureProfiles({ attempts: 1 }).catch(() => {});
        }
        const res = await this.api.getClients();
        this.refreshError = null;
        this.applyAmneziaDnsCapability(res.serverCapabilities);
        this.applyAmneziaXrayCapability(res.serverCapabilities);
        if (typeof this.applySidecarCapabilities === 'function') {
          this.applySidecarCapabilities(res.serverCapabilities);
        }
        if (res.serverJunk) this.serverJunk = res.serverJunk;
        const list = Array.isArray(res.clients) ? res.clients : [];
        this.clients = list.map((client) => {
        if (client.junkPins) this.$set(this.clientJunkPins, client.id, client.junkPins);
        // Do not overwrite in-progress drafts (level/profile/junk/MTU) on poll refresh.
        this.syncObfuscationDraftFromClient(client, { force: false });
        if (this.amneziaDnsAvailable) {
          this.$set(this.clientUseServerDns, client.id, client.useServerDns !== false);
        }

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
        this.loadAggregateTraffic().catch(() => {});
      } catch (err) {
        this.refreshError = err.code === 'NETWORK_ERROR' ? 'NETWORK_ERROR' : (err.message || String(err));
        throw err;
      }
    },
    async loadClientTrafficHistory(clientId) {
      const periods = ['hour', 'day', 'week', 'month', 'year'];
      const result = {};
      await Promise.all(periods.map(async (period) => {
        const data = await this.api.getTrafficClient(clientId, period).catch(() => ({
          rx: 0, tx: 0, awg: { rx: 0, tx: 0 }, xray: { rx: 0, tx: 0 },
        }));
        result[period] = data;
      }));
      this.$set(this.clientTrafficHistory, clientId, result);
    },
    clientTrafficTotal(clientId, period) {
      const row = this.clientTrafficHistory[clientId] && this.clientTrafficHistory[clientId][period];
      if (!row) return 0;
      return (row.rx || 0) + (row.tx || 0);
    },
    /** Year totals split AWG vs XRay for the bar under traffic history. */
    clientTrafficSplit(clientId) {
      const row = this.clientTrafficHistory[clientId] && this.clientTrafficHistory[clientId].year;
      if (!row) return null;
      const awgBytes = ((row.awg && row.awg.rx) || 0) + ((row.awg && row.awg.tx) || 0);
      const xrayBytes = ((row.xray && row.xray.rx) || 0) + ((row.xray && row.xray.tx) || 0);
      const total = awgBytes + xrayBytes;
      if (total <= 0) {
        return { awgBytes: 0, xrayBytes: 0, awgPct: 0, xrayPct: 0 };
      }
      const awgPct = Math.round((awgBytes * 1000) / total) / 10;
      const xrayPct = Math.round((1000 - awgPct * 10)) / 10;
      return { awgBytes, xrayBytes, awgPct, xrayPct };
    },
    async loadAggregateTraffic() {
      const data = await this.api.getTrafficAggregate('year').catch(() => ({ rx: 0, tx: 0 }));
      const total = (data.rx || 0) + (data.tx || 0);
      this.aggregateTrafficDisplay = formatTrafficShort(total);
    },
    async resetClientTraffic(client) {
      if (this.resettingTrafficClientId) return;
      this.resettingTrafficClientId = client.id;
      try {
        await this.api.resetTrafficHistory(client.id);
        await this.loadClientTrafficHistory(client.id);
        await this.loadAggregateTraffic();
      } catch (err) {
        const msg = err.status === 403
          ? (this.$t('trafficResetForbidden') || 'Not allowed to reset traffic.')
          : (err.message || String(err));
        alert(msg);
      } finally {
        this.resettingTrafficClientId = null;
      }
    },
    refreshErrorDisplay() {
      if (!this.refreshError) return '';
      return this.refreshError === 'NETWORK_ERROR' && this.$t('networkError')
        ? this.$t('networkError')
        : this.refreshError;
    },
    /** Must complete before first refresh() so firewall profile <select> has <option> rows (avoids empty dropdown on first paint). */
    ensureRuleProfiles() {
      if (!this.canManageFirewall) {
        this.ruleProfiles = [];
        return Promise.resolve();
      }
      return this.api.getRuleProfiles()
        .then((r) => { this.ruleProfiles = Array.isArray(r) ? r : []; })
        .catch(() => { this.ruleProfiles = []; });
    },
    login(e) {
      e.preventDefault();

      if (!this.username || !this.password) {
        this.loginFieldErrors.username = !this.username ? this.$t('fieldRequired') : '';
        this.loginFieldErrors.password = !this.password ? this.$t('fieldRequired') : '';
        return;
      }
      if (this.authenticating) return;

      this.loginFieldErrors = { username: '', password: '', _form: '' };
      this.authenticating = true;
      this.api.createSession({ username: this.username, password: this.password })
        .then(async () => {
          const session = await this.api.getSession();
          this.authenticated = session.authenticated;
          this.syncPanelUserFromSession(session);
          await this.reloadPanelUsers();
          await this.ensureRuleProfiles();
          if (this.canManageFirewall) this.loadGlobalFirewallRules();
          return this.refresh();
        })
        .catch((err) => {
          if (err.status === 401) {
            this.loginFieldErrors._form = this.$t('loginErrInvalid');
          } else {
            this.loginFieldErrors._form = (err.message || err.toString());
          }
        })
        .finally(() => {
          this.authenticating = false;
          this.password = null;
        });
    },
    onFirewallProfileChange(client, ev) {
      const raw = ev.target.value;
      const ruleProfileId = raw === '' || raw === 'null' ? 1 : parseInt(raw, 10);
      const prev = client.ruleProfileId;
      client.ruleProfileId = Number.isNaN(ruleProfileId) ? 1 : ruleProfileId;
      this.api.updateClientRuleProfile({ clientId: client.id, rule_profile_id: ruleProfileId })
        .catch((err) => {
          client.ruleProfileId = prev;
          ev.target.value = (prev == null ? 1 : prev).toString();
          alert(err.message || err.toString());
        });
    },
    loadGlobalFirewallRules() {
      if (!this.canManageFirewall) {
        this.globalFirewallRules = [];
        return;
      }
      this.api.getGlobalFirewallRules()
        .then((r) => { this.globalFirewallRules = Array.isArray(r) ? r : []; })
        .catch(() => { this.globalFirewallRules = []; });
    },
    sortedProfileRules(profileId) {
      const list = this.profileRulesByExpandedId[profileId] || [];
      return list.slice().sort((a, b) => (a.sort_order ?? 0) - (b.sort_order ?? 0) || (a.id - b.id));
    },
    moveGlobalRuleUp(rule) {
      const list = this.sortedGlobalFirewallRules;
      const idx = list.findIndex((r) => r.id === rule.id);
      if (idx <= 0) return;
      const prev = list[idx - 1];
      const myOrder = rule.sort_order ?? 0;
      const prevOrder = prev.sort_order ?? 0;
      Promise.all([
        this.api.updateGlobalFirewallRule(rule.id, { action: rule.action, destination_cidr: rule.destination_cidr, port_range: rule.port_range ?? null, protocol: rule.protocol ?? null, sort_order: prevOrder }),
        this.api.updateGlobalFirewallRule(prev.id, { action: prev.action, destination_cidr: prev.destination_cidr, port_range: prev.port_range ?? null, protocol: prev.protocol ?? null, sort_order: myOrder }),
      ]).then(() => this.loadGlobalFirewallRules()).catch((err) => alert(err.message || err.toString()));
    },
    moveGlobalRuleDown(rule) {
      const list = this.sortedGlobalFirewallRules;
      const idx = list.findIndex((r) => r.id === rule.id);
      if (idx < 0 || idx >= list.length - 1) return;
      const next = list[idx + 1];
      const myOrder = rule.sort_order ?? 0;
      const nextOrder = next.sort_order ?? 0;
      Promise.all([
        this.api.updateGlobalFirewallRule(rule.id, { action: rule.action, destination_cidr: rule.destination_cidr, port_range: rule.port_range ?? null, protocol: rule.protocol ?? null, sort_order: nextOrder }),
        this.api.updateGlobalFirewallRule(next.id, { action: next.action, destination_cidr: next.destination_cidr, port_range: next.port_range ?? null, protocol: next.protocol ?? null, sort_order: myOrder }),
      ]).then(() => this.loadGlobalFirewallRules()).catch((err) => alert(err.message || err.toString()));
    },
    moveProfileRuleUp(profileId, rule) {
      const list = this.sortedProfileRules(profileId);
      const idx = list.findIndex((r) => r.id === rule.id);
      if (idx <= 0) return;
      const prev = list[idx - 1];
      const myOrder = rule.sort_order ?? 0;
      const prevOrder = prev.sort_order ?? 0;
      Promise.all([
        this.api.updateIpRule(rule.id, { action: rule.action, destination_cidr: rule.destination_cidr, port_range: rule.port_range ?? null, protocol: rule.protocol ?? null, sort_order: prevOrder }),
        this.api.updateIpRule(prev.id, { action: prev.action, destination_cidr: prev.destination_cidr, port_range: prev.port_range ?? null, protocol: prev.protocol ?? null, sort_order: myOrder }),
      ]).then(() => this.loadRulesForProfile(profileId)).catch((err) => alert(err.message || err.toString()));
    },
    moveProfileRuleDown(profileId, rule) {
      const list = this.sortedProfileRules(profileId);
      const idx = list.findIndex((r) => r.id === rule.id);
      if (idx < 0 || idx >= list.length - 1) return;
      const next = list[idx + 1];
      const myOrder = rule.sort_order ?? 0;
      const nextOrder = next.sort_order ?? 0;
      Promise.all([
        this.api.updateIpRule(rule.id, { action: rule.action, destination_cidr: rule.destination_cidr, port_range: rule.port_range ?? null, protocol: rule.protocol ?? null, sort_order: nextOrder }),
        this.api.updateIpRule(next.id, { action: next.action, destination_cidr: next.destination_cidr, port_range: next.port_range ?? null, protocol: next.protocol ?? null, sort_order: myOrder }),
      ]).then(() => this.loadRulesForProfile(profileId)).catch((err) => alert(err.message || err.toString()));
    },
    openAddGlobalRule() {
      this.globalRuleEdit = { action: 'allow', destination_cidr: '', port_range: '', protocol: '' };
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
      const dest = (r.destination_cidr || '').trim().replace(/\\/g, '/');
      if (!dest) return;
      const portVal = (r.port_range || '').trim();
      const protoVal = (r.protocol || '').trim().toLowerCase();
      const body = {
        action: r.action,
        destination_cidr: dest,
        port_range: (!portVal || /^(any|all)$/i.test(portVal)) ? null : portVal.replace(':', '-'),
        protocol: (!protoVal || /^(any|all)$/.test(protoVal)) ? null : protoVal,
      };
      if (r.id) body.sort_order = r.sort_order ?? 0;
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
    openProfileCreate() {
      this.profileCreate = { name: '', description: '' };
    },
    closeProfileCreate() {
      this.profileCreate = null;
    },
    openProfileEdit(profile) {
      this.profileEdit = { id: profile.id, name: profile.name || '', description: (profile.description || '').trim() || '' };
    },
    closeProfileEdit() {
      this.profileEdit = null;
    },
    saveProfileEdit() {
      const p = this.profileEdit;
      if (!p || !p.name || !p.name.trim()) return;
      this.api.updateRuleProfile(p.id, { name: p.name.trim(), description: (p.description || '').trim() || null })
        .then(() => {
          this.profileEdit = null;
          return this.api.getRuleProfiles();
        })
        .then((r) => { this.ruleProfiles = Array.isArray(r) ? r : []; })
        .catch((err) => alert(err.message || err.toString()));
    },
    saveProfileCreate() {
      const p = this.profileCreate;
      if (!p || !p.name || !p.name.trim()) return;
      this.api.createRuleProfile({ name: p.name.trim(), description: (p.description || '').trim() || null })
        .then((r) => {
          this.profileCreate = null;
          return this.api.getRuleProfiles();
        })
        .then((r) => { this.ruleProfiles = Array.isArray(r) ? r : []; })
        .catch((err) => alert(err.message || err.toString()));
    },
    deleteRuleProfile(profile) {
      if (profile.id === 1 || profile.id === 'global') return;
      const inUse = (this.clients || []).some((c) => c.ruleProfileId === profile.id);
      if (inUse) {
        alert(this.$t('profileInUseCannotDelete'));
        return;
      }
      if (!confirm(this.$t('globalRuleDeleteConfirm'))) return;
      this.api.deleteRuleProfile(profile.id)
        .then(() => this.api.getRuleProfiles())
        .then((r) => {
          this.ruleProfiles = Array.isArray(r) ? r : [];
          const idx = this.expandedProfileIds.indexOf(profile.id);
          if (idx >= 0) {
            this.expandedProfileIds.splice(idx, 1);
            delete this.profileRulesByExpandedId[profile.id];
          }
        })
        .catch((err) => {
          const msg = (err && err.status === 409) ? this.$t('profileInUseCannotDelete') : (err && (err.message || err.toString())) || '';
          alert(msg);
        });
    },
    expandProfileRules(profile) {
      const idx = this.expandedProfileIds.indexOf(profile.id);
      if (idx >= 0) {
        this.expandedProfileIds.splice(idx, 1);
        delete this.profileRulesByExpandedId[profile.id];
        return;
      }
      this.expandedProfileIds.push(profile.id);
      if (profile.id === 'global') {
        this.loadGlobalFirewallRules();
        return;
      }
      if (profile.id === 'cidr') {
        this.loadVpnPools();
        return;
      }
      this.api.getRuleProfile(profile.id)
        .then((data) => {
          this.$set(this.profileRulesByExpandedId, profile.id, Array.isArray(data.rules) ? data.rules : []);
        })
        .catch(() => { this.$set(this.profileRulesByExpandedId, profile.id, []); });
    },
    loadVpnPools() {
      if (!this.canManageSettings) {
        this.vpnPools = [];
        return Promise.resolve();
      }
      return Promise.all([
        this.api.getVpnPools().then((data) => {
          this.vpnPools = Array.isArray(data && data.pools) ? data.pools : [];
        }).catch(() => { this.vpnPools = []; }),
        this.reloadPanelUsers(),
      ]);
    },
    openCidrPoolCreate() {
      this.cidrPoolEdit = { id: null, name: '', cidr: '', gateway: '' };
    },
    openCidrPoolEdit(pool) {
      this.cidrPoolEdit = {
        id: pool.id,
        name: pool.name || '',
        cidr: pool.cidr || '',
        gateway: pool.gateway || '',
      };
    },
    closeCidrPoolEdit() {
      this.cidrPoolEdit = null;
    },
    saveCidrPoolEdit() {
      const edit = this.cidrPoolEdit;
      if (!edit) return;
      const name = (edit.name || '').trim();
      const cidr = (edit.cidr || '').trim();
      if (!name || !cidr) {
        alert(this.$t('fieldRequired'));
        return;
      }
      const body = { name, cidr };
      const gw = (edit.gateway || '').trim();
      // Only send gateway if it still belongs to the CIDR; otherwise server picks default.
      if (gw && ipv4InCidr(gw, cidr)) body.gateway = gw;
      const req = edit.id
        ? this.api.updateVpnPool(edit.id, body)
        : this.api.createVpnPool(body);
      req
        .then(() => {
          this.closeCidrPoolEdit();
          return this.loadVpnPools();
        })
        .catch((err) => alert(err.message || err.toString()))
        .finally(() => this.refresh().catch(console.error));
    },
    deleteCidrPool(pool) {
      if (!confirm(this.$t('cidrPoolDeleteConfirm'))) return;
      this.api.deleteVpnPool(pool.id)
        .then(() => this.loadVpnPools())
        .catch((err) => alert(err.message || err.toString()))
        .finally(() => this.refresh().catch(console.error));
    },
    openCidrPoolAssign(pool) {
      this.cidrPoolAssign = pool;
      this.cidrPoolAssignSelected = Array.isArray(pool.userIds) ? pool.userIds.slice() : [];
      this.reloadPanelUsers();
    },
    closeCidrPoolAssign() {
      this.cidrPoolAssign = null;
      this.cidrPoolAssignSelected = [];
    },
    toggleCidrPoolAssignUser(userId) {
      const i = this.cidrPoolAssignSelected.indexOf(userId);
      if (i >= 0) this.cidrPoolAssignSelected.splice(i, 1);
      else this.cidrPoolAssignSelected.push(userId);
    },
    saveCidrPoolAssign() {
      if (!this.cidrPoolAssign) return;
      this.cidrPoolAssignSubmitting = true;
      this.api.setVpnPoolUsers(this.cidrPoolAssign.id, this.cidrPoolAssignSelected.slice())
        .then(() => {
          this.closeCidrPoolAssign();
          return this.loadVpnPools();
        })
        .catch((err) => alert(err.message || err.toString()))
        .finally(() => {
          this.cidrPoolAssignSubmitting = false;
        });
    },
    vpnPoolUsernames(pool) {
      const ids = new Set(Array.isArray(pool.userIds) ? pool.userIds : []);
      return (this.panelUsers || []).filter((u) => ids.has(u.id)).map((u) => u.username).join(', ') || '—';
    },
    loadRulesForProfile(profileId) {
      if (!profileId) return;
      if (profileId === 'global') {
        this.loadGlobalFirewallRules();
        return;
      }
      this.api.getRuleProfile(profileId)
        .then((data) => {
          this.$set(this.profileRulesByExpandedId, profileId, Array.isArray(data.rules) ? data.rules : []);
        })
        .catch(() => { this.$set(this.profileRulesByExpandedId, profileId, []); });
    },
    openAddProfileRule(profileId) {
      this.profileRuleEdit = { rule_profile_id: profileId, action: 'allow', destination_cidr: '', port_range: '', protocol: '' };
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
      const dest = (r.destination_cidr || '').trim().replace(/\\/g, '/');
      if (!dest) return;
      const portVal = (r.port_range || '').trim();
      const protoVal = (r.protocol || '').trim().toLowerCase();
      const body = {
        action: r.action,
        destination_cidr: dest,
        port_range: (!portVal || /^(any|all)$/i.test(portVal)) ? null : portVal.replace(':', '-'),
        protocol: (!protoVal || /^(any|all)$/.test(protoVal)) ? null : protoVal,
      };
      if (r.id) body.sort_order = r.sort_order ?? 0;
      if (r.id) {
        const profileId = r.rule_profile_id;
        this.api.updateIpRule(r.id, body).then(() => { this.profileRuleEdit = null; this.loadRulesForProfile(profileId); }).catch((err) => alert(err.message || err.toString()));
      } else {
        body.rule_profile_id = r.rule_profile_id;
        const profileId = r.rule_profile_id;
        this.api.createIpRule(body).then(() => { this.profileRuleEdit = null; this.loadRulesForProfile(profileId); }).catch((err) => alert(err.message || err.toString()));
      }
    },
    deleteProfileRule(rule) {
      if (!rule.id) return;
      if (!confirm(this.$t('globalRuleDeleteConfirm'))) return;
      const profileId = rule.rule_profile_id;
      this.api.deleteIpRule(rule.id).then(() => this.loadRulesForProfile(profileId)).catch((err) => alert(err.message || err.toString()));
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
          this.clearPasswordChangeUi();
        })
        .catch((err) => {
          alert(err.message || err.toString());
        });
    },
    createClient() {
      const name = (this.clientCreateName || '').trim();
      if (!name) return;
      if ((this.clients || []).some((c) => c.name === name)) {
        alert(this.$t('clientNameAlreadyExists'));
        return;
      }
      if (this.panelRole === 'user' && !(this.sessionAssignedCidrs || []).length) {
        alert(this.$t('noCidrAssignedCannotCreateClient'));
        return;
      }

      this.api.createClient({ name })
        .catch((err) => {
          const msg = (err.status === 409 || (err.data && err.data.code === 'CLIENT_NAME_EXISTS'))
            ? this.$t('clientNameAlreadyExists')
            : (err.message || err.toString());
          alert(msg);
        })
        .finally(() => this.refresh().catch(console.error));
    },
    deleteClient(client) {
      this.api.deleteClient({ clientId: client.id })
        .catch((err) => alert(err.message || err.toString()))
        .finally(() => this.refresh().catch(console.error));
    },
    enableClient(client) {
      this.api.enableClient({ clientId: client.id })
        .catch((err) => {
          const msg = err.status === 400
            ? (this.$t('clientAddressInvalid') || err.message)
            : (err.message || err.toString());
          alert(msg);
        })
        .finally(() => this.refresh().catch(console.error));
    },
    disableClient(client) {
      this.api.disableClient({ clientId: client.id })
        .catch((err) => alert(err.message || err.toString()))
        .finally(() => this.refresh().catch(console.error));
    },
    updateClientName(client, name) {
      const trimmed = (name || '').trim();
      if (!trimmed) return;
      if ((this.clients || []).some((c) => c.id !== client.id && c.name === trimmed)) {
        alert(this.$t('clientNameAlreadyExists'));
        return;
      }
      this.api.updateClientName({ clientId: client.id, name: trimmed })
        .catch((err) => {
          const msg = (err.status === 409 || (err.data && err.data.code === 'CLIENT_NAME_EXISTS'))
            ? this.$t('clientNameAlreadyExists')
            : (err.message || err.toString());
          alert(msg);
        })
        .finally(() => this.refresh().catch(console.error));
    },
    updateClientAddress(client, address) {
      const trimmed = (address || '').trim();
      if (!trimmed) return;
      const ranges = this.sessionAssignedCidrs || [];
      if (!ranges.length) {
        alert(this.$t('noCidrAssignedCannotCreateClient'));
        return;
      }
      if (!ipv4InAnyCidr(trimmed, ranges)) {
        alert(this.$t('addressOutsideAssignedCidrs'));
        return;
      }
      this.api.updateClientAddress({ clientId: client.id, address: trimmed })
        .catch((err) => {
          let msg = err.message || err.toString();
          if (err.status === 409) msg = this.$t('addressAlreadyInUse') || msg;
          else if (err.status === 403 || err.status === 400) {
            msg = this.$t('addressOutsideAssignedCidrs') || msg;
          }
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
      const next = this.expandedClientStatsId === client.id ? null : client.id;
      this.expandedClientStatsId = next;
      if (next) this.loadClientTrafficHistory(next).catch(() => {});
    },
    toggleFirewallBlocks() {
      this.firewallBlocksVisible = !this.firewallBlocksVisible;
      localStorage.setItem('firewallBlocksVisible', this.firewallBlocksVisible ? '1' : '0');
    },
    toggleUserActions() {
      this.userActionsOpen = !this.userActionsOpen;
    },
    clearFieldError(storeName, field) {
      const store = this[storeName];
      if (store && field in store) {
        this.$set(store, field, '');
      }
      if (store && store._form) {
        this.$set(store, '_form', '');
      }
    },
    emptyFieldErrors() {
      return { password: '', passwordConfirm: '', _form: '' };
    },
    validatePasswordFields(password, passwordConfirm, errors) {
      errors.password = '';
      errors.passwordConfirm = '';
      errors._form = '';
      let ok = true;
      if (!password || password.length < 5) {
        errors.password = this.$t('passwordErrTooShort');
        ok = false;
      } else if (password.length > 256) {
        errors.password = this.$t('passwordErrTooLong');
        ok = false;
      }
      if (password !== passwordConfirm) {
        errors.passwordConfirm = this.$t('passwordErrMismatch');
        ok = false;
      }
      return ok;
    },
    applyPasswordApiError(err, errors) {
      const c = err && err.code;
      if (c === 'PASSWORD_TOO_SHORT') errors.password = this.$t('passwordErrTooShort');
      else if (c === 'PASSWORD_TOO_LONG') errors.password = this.$t('passwordErrTooLong');
      else if (c === 'PASSWORD_MISMATCH') errors.passwordConfirm = this.$t('passwordErrMismatch');
      else errors._form = (err && err.message) || String(err);
    },
    syncPanelUserFromSession(session) {
      this.panelUsername = session && session.authenticated ? (session.username || null) : null;
      this.panelUserId = session && session.authenticated ? (session.userId || session.id || null) : null;
      this.panelRole = session && session.authenticated ? (session.role || null) : null;
      this.panelCapabilities = session && session.authenticated && Array.isArray(session.capabilities)
        ? session.capabilities
        : [];
      this.sessionAssignedCidrs = session && session.authenticated && Array.isArray(session.assigned_cidrs)
        ? session.assigned_cidrs
        : [];
      if (!this.canManageFirewall) {
        this.firewallBlocksVisible = false;
      }
    },
    hasCapability(cap) {
      return Array.isArray(this.panelCapabilities) && this.panelCapabilities.includes(cap);
    },
    clearPasswordChangeUi() {
      this.panelUsername = null;
      this.panelUserId = null;
      this.panelRole = null;
      this.panelCapabilities = [];
      this.userActionsOpen = false;
      this.passwordModalOpen = false;
      this.passwordTargets = [];
      this.passwordTargetUserId = null;
      this.passwordNew = '';
      this.passwordConfirm = '';
      this.passwordFieldErrors = { password: '', passwordConfirm: '', _form: '' };
      this.createUserModalOpen = false;
      this.createUserUsername = '';
      this.createUserPassword = '';
      this.createUserConfirm = '';
      this.createUserRole = 'user';
      this.createUserFieldErrors = { username: '', password: '', passwordConfirm: '', _form: '' };
      this.roleLabels = {};
      this.panelUsers = [];
      this.clientAssignModalClient = null;
      this.clientAssignModalUserId = null;
      this.clientAssignFieldError = '';
      this.loginFieldErrors = { username: '', password: '', _form: '' };
    },
    openPasswordModal() {
      this.userActionsOpen = false;
      this.passwordNew = '';
      this.passwordConfirm = '';
      this.passwordFieldErrors = { password: '', passwordConfirm: '', _form: '' };
      this.passwordModalOpen = true;
      this.api.getPasswordTargets()
        .then((list) => {
          this.passwordTargets = Array.isArray(list) ? list : [];
          if (this.showPasswordUserSelect) {
            const self = this.passwordTargets.find((u) => u.id === this.panelUserId)
              || this.passwordTargets[0];
            this.passwordTargetUserId = self ? self.id : null;
          } else {
            this.passwordTargetUserId = this.panelUserId;
          }
        })
        .catch((err) => {
          this.passwordFieldErrors._form = (err && err.message) || String(err);
          this.passwordModalOpen = false;
        });
    },
    closePasswordModal() {
      this.passwordModalOpen = false;
      this.passwordNew = '';
      this.passwordConfirm = '';
      this.passwordFieldErrors = { password: '', passwordConfirm: '', _form: '' };
    },
    openCreateUserModal() {
      this.userActionsOpen = false;
      this.createUserUsername = '';
      this.createUserPassword = '';
      this.createUserConfirm = '';
      this.createUserRole = 'user';
      this.createUserCidr = '';
      this.createUserFieldErrors = { username: '', password: '', passwordConfirm: '', cidr: '', _form: '' };
      this.roleLabels = {};
      this.createUserModalOpen = true;
      if (this.panelRole === 'admin') {
        this.api.getRoles(this.currentLocale)
          .then((labels) => {
            this.roleLabels = labels && typeof labels === 'object' ? labels : {};
          })
          .catch(() => {
            this.roleLabels = {};
          });
      }
      if (this.canManageSettings) {
        this.loadVpnPools().then(() => {
          if (!this.createUserCidr && this.vpnPools.length) {
            this.createUserCidr = this.vpnPools[0].cidr;
          }
        });
      }
    },
    closeCreateUserModal() {
      this.createUserModalOpen = false;
      this.createUserUsername = '';
      this.createUserPassword = '';
      this.createUserConfirm = '';
      this.createUserRole = 'user';
      this.createUserCidr = '';
      this.createUserFieldErrors = { username: '', password: '', passwordConfirm: '', cidr: '', _form: '' };
    },
    submitPasswordChange() {
      if (this.passwordChangeSubmitting) return;
      const errors = { password: '', passwordConfirm: '', _form: '' };
      if (!this.validatePasswordFields(this.passwordNew, this.passwordConfirm, errors)) {
        this.passwordFieldErrors = errors;
        return;
      }
      const targetId = this.showPasswordUserSelect
        ? this.passwordTargetUserId
        : this.panelUserId;
      if (!targetId) return;
      this.passwordChangeSubmitting = true;
      this.passwordFieldErrors = { password: '', passwordConfirm: '', _form: '' };
      this.api.changeUserPassword({
        userId: targetId,
        password: this.passwordNew,
        passwordConfirm: this.passwordConfirm,
      })
        .then(() => {
          this.closePasswordModal();
        })
        .catch((err) => {
          const next = { password: '', passwordConfirm: '', _form: '' };
          this.applyPasswordApiError(err, next);
          this.passwordFieldErrors = next;
        })
        .finally(() => {
          this.passwordChangeSubmitting = false;
        });
    },
    submitCreateUser() {
      if (this.createUserSubmitting) return;
      const errors = { username: '', password: '', passwordConfirm: '', cidr: '', _form: '' };
      if (!this.createUserUsername || !this.createUserUsername.trim()) {
        errors.username = this.$t('fieldRequired');
      }
      if (!this.validatePasswordFields(this.createUserPassword, this.createUserConfirm, errors)) {
        // validatePasswordFields may set password/passwordConfirm
      }
      if (!this.createUserCidr) {
        errors.cidr = this.$t('createUserCidrRequired');
      }
      if (errors.username || errors.password || errors.passwordConfirm || errors.cidr) {
        this.createUserFieldErrors = errors;
        return;
      }
      this.createUserSubmitting = true;
      this.createUserFieldErrors = { username: '', password: '', passwordConfirm: '', cidr: '', _form: '' };
      const role = this.panelRole === 'admin' ? (this.createUserRole || 'user') : 'user';
      const payload = {
        username: this.createUserUsername.trim(),
        password: this.createUserPassword,
        role,
        assigned_cidrs: [this.createUserCidr],
      };
      this.api.createUser(payload)
        .then(() => {
          this.closeCreateUserModal();
          return this.reloadPanelUsers();
        })
        .catch((err) => {
          const next = { username: '', password: '', passwordConfirm: '', cidr: '', _form: '' };
          if (err.status === 409 || err.code === 'USERNAME_EXISTS') {
            next.username = this.$t('usernameExists');
          } else if (err.status === 400) {
            this.applyPasswordApiError(err, next);
            if (!next.password && !next.passwordConfirm) {
              next._form = (err && err.message) || String(err);
            }
          } else {
            next._form = (err && err.message) || String(err);
          }
          this.createUserFieldErrors = next;
        })
        .finally(() => {
          this.createUserSubmitting = false;
        });
    },
    reloadPanelUsers() {
      if (!this.canAssignClients && !this.canCreateUsers) {
        this.panelUsers = [];
        return Promise.resolve();
      }
      return this.api.getUsers()
        .then((list) => {
          this.panelUsers = Array.isArray(list) ? list.filter((u) => u && u.is_active) : [];
        })
        .catch(() => {
          this.panelUsers = [];
        });
    },
    assignableUsersForClient(client) {
      const assigned = new Set((client.users || []).map((u) => u.id));
      return (this.panelUsers || []).filter((u) => u && !assigned.has(u.id));
    },
    revokeClientUser(client, user) {
      const nextIds = (client.users || []).filter((u) => u.id !== user.id).map((u) => u.id);
      this.api.setClientUsers({ clientId: client.id, userIds: nextIds })
        .then((users) => {
          this.$set(client, 'users', Array.isArray(users) ? users : []);
        })
        .catch((err) => {
          this.clientAssignFieldError = (err && err.message) || String(err);
        });
    },
    openClientAssignModal(client) {
      this.clientAssignModalClient = client;
      this.clientAssignModalUserId = null;
      this.clientAssignFieldError = '';
    },
    closeClientAssignModal() {
      this.clientAssignModalClient = null;
      this.clientAssignModalUserId = null;
      this.clientAssignFieldError = '';
    },
    submitClientAssign() {
      const client = this.clientAssignModalClient;
      const uid = this.clientAssignModalUserId;
      if (!client || !uid) {
        this.clientAssignFieldError = this.$t('fieldRequired');
        return;
      }
      this.clientAssignSubmitting = true;
      this.clientAssignFieldError = '';
      const nextIds = [...(client.users || []).map((u) => u.id), uid];
      this.api.setClientUsers({ clientId: client.id, userIds: nextIds })
        .then((users) => {
          this.$set(client, 'users', Array.isArray(users) ? users : []);
          this.closeClientAssignModal();
        })
        .catch((err) => {
          this.clientAssignFieldError = (err && err.message) || String(err);
        })
        .finally(() => {
          this.clientAssignSubmitting = false;
        });
    },
    ...(typeof SidecarPanels !== 'undefined' ? SidecarPanels.methods : {}),
  },
  filters: {
    bytes,
    timeago: (value) => {
      return timeago.format(value, i18n.locale);
    },
  },
  created() {
    if (this.clientDownloadFormat == null || typeof this.clientDownloadFormat !== 'object') {
      this.$set(this, 'clientDownloadFormat', {});
    }
  },
  mounted() {
    this.prefersDarkScheme.addListener(this.handlePrefersChange);
    this.setTheme(this.uiTheme);
    if (!this.$i18n.availableLocales.includes(this.currentLocale)) {
      this.currentLocale = DEFAULT_LOCALE;
      localStorage.setItem(LOCALE_STORAGE_KEY, DEFAULT_LOCALE);
      this.$i18n.locale = DEFAULT_LOCALE;
    }

    this.api = new API();
    this.api.getSession()
      .then((session) => {
        this.authenticated = session.authenticated;
        this.syncPanelUserFromSession(session);
        this.reloadSignatureProfiles();
        this.reloadMtuProfiles();
        this.loadGlobalFirewallRules();
        return Promise.all([
          this.ensureRuleProfiles(),
          this.reloadPanelUsers(),
        ]);
      })
      .then(() => {
        return this.refresh({
          updateCharts: this.updateCharts,
        });
      })
      .catch((err) => {
        alert(err.message || err.toString());
      });

    setInterval(() => {
      this.refresh({
        updateCharts: this.updateCharts,
      }).catch(() => { /* refreshError already set; avoid duplicate log */ });
    }, 5000);

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
    canManageFirewall() {
      return this.hasCapability('system.firewall');
    },
    canManageXray() {
      return this.hasCapability('system.xray');
    },
    ...(typeof SidecarPanels !== 'undefined' ? SidecarPanels.computed : {}),
    isValidAmneziaXrayPort() {
      const raw = String(this.amneziaXrayPort == null ? '' : this.amneziaXrayPort).trim();
      if (raw === '') return true;
      const n = Number(raw);
      return Number.isInteger(n) && n >= 1 && n <= 65535;
    },
    isValidAmneziaXrayPublicPort() {
      const n = Number(this.amneziaXrayPublicPort);
      return Number.isInteger(n) && n >= 1 && n <= 65535;
    },
    sniFinderProgressPct() {
      const t = Number(this.sniFinderProgress && this.sniFinderProgress.total) || 0;
      const d = Number(this.sniFinderProgress && this.sniFinderProgress.done) || 0;
      if (t <= 0) return this.sniFinderBusy ? 8 : 0;
      return Math.max(0, Math.min(100, Math.round((d / t) * 100)));
    },
    sniFinderPhaseLabel() {
      const phase = this.sniFinderPhase;
      if (phase === 'detecting' || phase === 'starting') return this.$t('xraySniPhaseDetecting');
      if (phase === 'probing') return this.$t('xraySniPhaseProbing');
      if (phase === 'verifying') return this.$t('xraySniPhaseVerifying');
      if (phase === 'done') return this.$t('xraySniPhaseDone');
      if (phase === 'error') return this.$t('xraySniPhaseError');
      return phase || '';
    },
    canManageSettings() {
      return this.hasCapability('system.settings');
    },
    canCreateClient() {
      return Array.isArray(this.sessionAssignedCidrs) && this.sessionAssignedCidrs.length > 0;
    },
    canCreateUsers() {
      return this.hasCapability('users.write');
    },
    canAssignClients() {
      return this.hasCapability('clients.assign');
    },
    showPasswordUserSelect() {
      return this.panelRole === 'admin' || this.panelRole === 'moderator';
    },
    createUserRoleOptions() {
      const fallback = {
        admin: this.$t('roleAdmin') || 'Administrator',
        moderator: this.$t('roleModerator') || 'Moderator',
        user: this.$t('roleUser') || 'User',
      };
      const labels = this.roleLabels && Object.keys(this.roleLabels).length
        ? this.roleLabels
        : fallback;
      return ['admin', 'moderator', 'user'].map((id) => ({
        id,
        label: labels[id] || fallback[id] || id,
      }));
    },
    amneziaQrCols() {
      const n = this.amneziaQrImages.length;
      return Math.max(1, Math.min(3, n || 1));
    },
    amneziaQrGridStyle() {
      return { '--amnezia-qr-cols': String(this.amneziaQrCols) };
    },
    amneziaQrModalStyle() {
      const cols = this.amneziaQrCols;
      const gapPx = 16;
      const cell = 560;
      const pad = 32;
      const w = cols * cell + (cols - 1) * gapPx + pad;
      return {
        '--amnezia-qr-modal-width': `min(100vw - 1rem, ${w}px)`,
        width: `min(100vw - 1rem, ${w}px)`,
      };
    },
    qrcodeModalVisible() {
      return this.qrcodeText != null
        || (Array.isArray(this.qrcodeAmneziaSvgs) && this.qrcodeAmneziaSvgs.length > 0)
        || !!this.qrcodePreviewText
        || !!this.qrcodeXraySvg
        || !!this.qrcodeXraySubUrl;
    },
    /** Safe for Vue 2 template (avoids ReferenceError if stale cached app.js lacks data key). */
    amneziaQrImages() {
      const q = this.qrcodeAmneziaSvgs;
      return Array.isArray(q) ? q : [];
    },
    qrTextILimitNote() {
      return this.formatQrILimitNote(this.qrcodeTextILimit);
    },
    qrAmneziaILimitNote() {
      return this.formatQrILimitNote(this.qrcodeAmneziaILimit);
    },
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
    sortedGlobalFirewallRules() {
      const list = this.globalFirewallRules || [];
      return list.slice().sort((a, b) => (a.sort_order ?? 0) - (b.sort_order ?? 0) || (a.id - b.id));
    },
    firewallProfileList() {
      const list = [];
      list.push({ id: 'global', name: this.$t('globalFirewallRulesTitle'), isGlobal: true });
      const profiles = this.ruleProfiles || [];
      const fullAccess = profiles.find((p) => p.id === 1);
      if (fullAccess) {
        list.push({ ...fullAccess, name: this.$t('firewallProfileFullAccess') });
      }
      const rest = profiles.filter((p) => p.id !== 1).sort((a, b) => (a.sort_order || 0) - (b.sort_order || 0) || a.id - b.id);
      rest.forEach((p) => list.push(p));
      list.push({ id: 'cidr', name: this.$t('cidrPoolsTitle'), isCidr: true });
      return list;
    },
  },
});
