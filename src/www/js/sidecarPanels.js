'use strict';

/**
 * Header sidecar panels (Mieru / Hysteria / Naive) + shared manage-modal helpers.
 * Loaded before app.js; merged into the Vue root instance.
 */

function sidecarDefaultAddress() {
  return (typeof window !== 'undefined' && window.location && window.location.hostname)
    ? window.location.hostname
    : '';
}

function sidecarBusyFromPhase(phase, busy) {
  return busy === true || phase === 'installing' || phase === 'removing';
}

const SIDECAR_POLL_MS = 2500;

/** Refresh client list only when a sidecar install/remove job finishes. */
function onSidecarPollStatus(vm, phaseKey, st) {
  if (!st) return;
  const trackKey = `_${phaseKey}Poll`;
  const prev = vm[trackKey];
  const cur = st.phase;
  vm[trackKey] = cur;
  if ((prev === 'installing' || prev === 'removing')
    && ['running', 'off', 'error', 'degraded'].includes(cur)) {
    vm.refresh().catch(() => {});
  }
}

/** Extract human-readable warning from API status objects. */
function formatSidecarWarning(value) {
  if (!value) return null;
  if (typeof value === 'string') return value.trim() || null;
  if (typeof value === 'object' && value.warning && value.message) {
    return String(value.message).trim() || null;
  }
  return null;
}

function sidecarValidPort(n) {
  const p = Number(n);
  return Number.isInteger(p) && p >= 1 && p <= 65535;
}

window.SidecarPanels = {
  initialState() {
    return {
      amneziaDnsModalMode: 'install',
      amneziaXrayModalMode: 'install',

      amneziaMieruAvailable: false,
      amneziaMieruHealthy: false,
      amneziaMieruPhase: 'off',
      amneziaMieruBusy: false,
      amneziaMieruError: null,
      amneziaMieruPollTimer: null,
      amneziaMieruModalMode: 'install',
      amneziaMieruInstallOpen: false,
      amneziaMieruAddress: '',
      amneziaMieruEnableTcp: true,
      amneziaMieruEnableUdp: false,
      amneziaMieruTcpPublicPort: 3080,
      amneziaMieruUdpPublicPort: 3080,
      amneziaMieruPort: '',
      amneziaMieruMtu: '',
      amneziaMieruLoggingLevel: 'INFO',
      amneziaMieruLoggingLevels: ['ERROR', 'WARN', 'INFO', 'DEBUG', 'TRACE'],
      amneziaMieruMultiplexing: 'LOW',
      amneziaMieruMultiplexingLevels: ['OFF', 'LOW', 'MIDDLE', 'HIGH'],
      amneziaMieruHandshakeNoWait: false,
      amneziaMieruAdvancedOpen: false,
      amneziaMieruFieldErrors: {},
      amneziaMieruClockWarning: null,

      amneziaHysteriaAvailable: false,
      amneziaHysteriaHealthy: false,
      amneziaHysteriaPhase: 'off',
      amneziaHysteriaBusy: false,
      amneziaHysteriaError: null,
      amneziaHysteriaPollTimer: null,
      amneziaHysteriaModalMode: 'install',
      amneziaHysteriaInstallOpen: false,
      amneziaHysteriaAddress: '',
      amneziaHysteriaSni: '',
      amneziaHysteriaPublicPort: 443,
      amneziaHysteriaMasqueradeUrl: '',
      amneziaHysteriaMasqueradeId: '',
      amneziaHysteriaObfsType: '',
      amneziaHysteriaObfsTypes: ['', 'salamander', 'gecko'],
      amneziaHysteriaObfsPassword: '',
      amneziaHysteriaCore: 'original',
      amneziaHysteriaCores: ['original', 'xray'],
      amneziaHysteriaBandwidthUp: '',
      amneziaHysteriaBandwidthDown: '',
      amneziaHysteriaSslCertId: '__auto__',
      amneziaHysteriaObfsGeckoMin: '',
      amneziaHysteriaObfsGeckoMax: '',
      amneziaHysteriaCongestionType: 'bbr',
      amneziaHysteriaBbrProfile: 'standard',
      amneziaHysteriaEchEnabled: false,
      amneziaHysteriaEchConfigList: '',
      amneziaHysteriaEchTechOpen: false,
      amneziaHysteriaListenMode: 'direct',
      amneziaHysteriaPortRange: '',
      amneziaHysteriaRealmUri: '',
      amneziaHysteriaAdvancedOpen: false,
      amneziaHysteriaFieldErrors: {},
      masqueradeBankOpen: false,
      masqueradeBankEntries: [],
      masqueradeBankBusy: false,

      panelHttpsPort: 443,
      panelDomain: '',
      certbotEmail: '',

      amneziaNaiveAvailable: false,
      amneziaNaiveHealthy: false,
      amneziaNaivePhase: 'off',
      amneziaNaiveBusy: false,
      amneziaNaiveError: null,
      amneziaNaivePollTimer: null,
      amneziaNaiveModalMode: 'install',
      amneziaNaiveInstallOpen: false,
      amneziaNaiveAddress: '',
      amneziaNaiveSni: '',
      amneziaNaiveSslCertId: '',
      amneziaNaivePublicPort: 443,
      amneziaNaiveProbeDomain: '',
      amneziaNaiveEnableTcp: true,
      amneziaNaiveEnableQuic: false,
      amneziaNaiveFieldErrors: {},

      qrcodeMieruLink: '',
      qrcodeMieruLinks: [],
      qrcodeMieruSvg: null,
      qrcodeHysteriaLink: '',
      qrcodeHysteriaSvg: null,
      qrcodeNaiveLink: '',
      qrcodeNaiveJson: '',
      qrcodeNaiveSvg: null,
    };
  },

  computed: {
    canManageMieru() {
      return this.hasCapability('system.mieru');
    },
    canManageHysteria() {
      return this.hasCapability('system.hysteria');
    },
    canManageNaive() {
      return this.hasCapability('system.naive');
    },
    canConfirmAmneziaMieruInstall() {
      if (!String(this.amneziaMieruAddress || '').trim()) return false;
      if (!this.amneziaMieruEnableTcp && !this.amneziaMieruEnableUdp) return false;
      if (this.amneziaMieruEnableTcp && !sidecarValidPort(this.amneziaMieruTcpPublicPort)) return false;
      if (this.amneziaMieruEnableUdp && !sidecarValidPort(this.amneziaMieruUdpPublicPort)) return false;
      return true;
    },
    isValidAmneziaHysteriaPublicPort() {
      return sidecarValidPort(this.amneziaHysteriaPublicPort);
    },
    isValidAmneziaNaivePublicPort() {
      return sidecarValidPort(this.amneziaNaivePublicPort);
    },
    canConfirmAmneziaNaiveInstall() {
      if (!String(this.amneziaNaiveAddress || '').trim()) return false;
      if (!this.isValidAmneziaNaivePublicPort) return false;
      if (!String(this.amneziaNaiveSslCertId || '').trim()) return false;
      if (!this.amneziaNaiveEnableTcp && !this.amneziaNaiveEnableQuic) return false;
      return true;
    },
    canConfirmAmneziaHysteriaInstall() {
      if (!String(this.amneziaHysteriaAddress || '').trim()) return false;
      if (!this.isValidAmneziaHysteriaPublicPort) return false;
      if (!String(this.amneziaHysteriaSslCertId || '__auto__').trim()) return false;
      return true;
    },
    hysteriaSslCertOptions() {
      const list = (this.sslCerts || []).filter((c) => c && c.type !== 'reality' && c.type !== 'masquerade');
      const autoOpt = { id: '__auto__', type: '_auto', label: this.$t('sslCreateAuto') || 'Create automatically' };
      const selected = this.sslFindCertById
        ? this.sslFindCertById(this.amneziaHysteriaSslCertId)
        : (this.sslCerts || []).find((c) => c.id === this.amneziaHysteriaSslCertId);
      let out = [autoOpt, ...list];
      if (selected && selected.id !== '__auto__' && !list.some((c) => c.id === selected.id)) {
        out = [autoOpt, selected, ...list];
      }
      return out;
    },
    hysteriaMasqueradeOptions() {
      const list = (this.sslCerts || []).filter((c) => c && c.type === 'masquerade');
      const selected = this.sslFindCertById
        ? this.sslFindCertById(this.amneziaHysteriaMasqueradeId)
        : (this.sslCerts || []).find((c) => c.id === this.amneziaHysteriaMasqueradeId);
      if (selected && !list.some((c) => c.id === selected.id)) {
        return [selected, ...list];
      }
      return list;
    },
    hysteriaObfsTypesFiltered() {
      const all = (this.amneziaHysteriaObfsTypes || []).filter(Boolean);
      // Xray finalmask: salamander + optional gecko (packetSize). Same choices as original core.
      return all;
    },
    naiveSslCertOptions() {
      const list = (this.sslCerts || []).filter((c) => c && c.type === 'lets_encrypt');
      const selected = this.sslFindCertById
        ? this.sslFindCertById(this.amneziaNaiveSslCertId)
        : (this.sslCerts || []).find((c) => c.id === this.amneziaNaiveSslCertId);
      if (selected && !list.some((c) => c.id === selected.id)) {
        return [selected, ...list];
      }
      return list;
    },
    // Hysteria is plain TLS (own FQDN for LE), not Reality — no foreign SNI bank.
    showHysteriaSniFinder() {
      return false;
    },
  },

  methods: {
    sidecarFieldError(fieldErrors, field) {
      if (!fieldErrors || !fieldErrors[field]) return '';
      const raw = String(fieldErrors[field]);
      // Prefer concrete API messages (port/SNI conflicts) over generic i18n labels.
      if (/Host |UDP |TCP |port|SNI|used|busy|conflict/i.test(raw)) return raw;
      const key = `fieldError_${field}`;
      const translated = this.$t(key);
      return translated !== key ? translated : raw;
    },
    securityLabel(sec) {
      const key = `security_${sec}`;
      const t = this.$t(key);
      return (t && t !== key) ? t : sec;
    },
    sniPreflightRequiredForHysteria() {
      // Reality-style SNI Finder preflight is for camouflage hosts, not own LE domains.
      return false;
    },
    normalizeHostnameInput(raw) {
      let s = String(raw || '').trim().toLowerCase();
      if (!s) return '';
      s = s.replace(/^https?:\/\//i, '');
      s = s.split('/')[0].split('?')[0];
      if (s.includes(':') && !s.includes(']')) {
        const parts = s.split(':');
        if (parts.length === 2 && /^\d+$/.test(parts[1])) s = parts[0];
      }
      return s.replace(/\.$/, '');
    },
    onHysteriaCoreChange() {
      // salamander/gecko available for both original and xray cores (xray: finalmask)
    },
    onHysteriaSslCertChange() {
      const c = this.sslFindCertById
        ? this.sslFindCertById(this.amneziaHysteriaSslCertId)
        : (this.sslCerts || []).find((x) => x.id === this.amneziaHysteriaSslCertId);
      if (c) this.amneziaHysteriaSni = c.sni || c.domain || '';
    },
    onNaiveSslCertChange() {
      const c = this.sslFindCertById
        ? this.sslFindCertById(this.amneziaNaiveSslCertId)
        : (this.sslCerts || []).find((x) => x.id === this.amneziaNaiveSslCertId);
      if (c) {
        this.amneziaNaiveSni = this.normalizeHostnameInput(c.sni || c.domain || '');
      }
    },
    onHysteriaMasqueradeChange() {
      const c = this.sslFindCertById
        ? this.sslFindCertById(this.amneziaHysteriaMasqueradeId)
        : (this.sslCerts || []).find((x) => x.id === this.amneziaHysteriaMasqueradeId);
      this.amneziaHysteriaMasqueradeUrl = c
        ? (c.masqueradeUrl || (c.domain ? `https://${c.domain}/` : ''))
        : '';
    },
    syncHysteriaMasqueradeIdFromUrl() {
      const url = String(this.amneziaHysteriaMasqueradeUrl || '').trim().toLowerCase().replace(/\/+$/, '');
      if (!url) {
        this.amneziaHysteriaMasqueradeId = '';
        return;
      }
      const match = (this.sslCerts || []).find((c) => {
        if (!c || c.type !== 'masquerade') return false;
        const u = String(c.masqueradeUrl || '').trim().toLowerCase().replace(/\/+$/, '');
        const d = String(c.domain || '').trim().toLowerCase();
        if (u && u === url) return true;
        if (d && (url === `https://${d}` || url === `http://${d}`)) return true;
        return false;
      });
      this.amneziaHysteriaMasqueradeId = match ? match.id : '';
    },
    async openMasqueradeBank() {
      this.masqueradeBankOpen = true;
      this.masqueradeBankBusy = true;
      try {
        const res = await this.api.getMasqueradeBank();
        this.masqueradeBankEntries = (res && res.entries) || [];
      } catch {
        this.masqueradeBankEntries = [];
      } finally {
        this.masqueradeBankBusy = false;
      }
    },
    closeMasqueradeBank() {
      this.masqueradeBankOpen = false;
    },
    async pickMasqueradeUrl(entry) {
      const url = entry && (entry.url || (entry.domain ? `https://${entry.domain}/` : ''));
      if (!url) return;
      this.masqueradeBankBusy = true;
      try {
        const res = await this.api.createSslMasquerade({
          url,
          label: (entry && entry.domain) || undefined,
          source: 'bank',
        });
        if (this.refreshSslCerts) await this.refreshSslCerts();
        const cert = res && res.cert;
        if (cert && cert.id) {
          this.amneziaHysteriaMasqueradeId = cert.id;
          this.amneziaHysteriaMasqueradeUrl = cert.masqueradeUrl || url;
        } else {
          this.amneziaHysteriaMasqueradeUrl = url;
        }
        this.closeMasqueradeBank();
      } catch (err) {
        this.amneziaHysteriaFieldErrors = {
          masqueradeUrl: (err && err.message) || this.$t('sslActionFailed'),
        };
      } finally {
        this.masqueradeBankBusy = false;
      }
    },
    clearSidecarFieldErrors(service) {
      if (service === 'mieru') this.amneziaMieruFieldErrors = {};
      else if (service === 'hysteria') this.amneziaHysteriaFieldErrors = {};
      else if (service === 'naive') this.amneziaNaiveFieldErrors = {};
    },
    async runPortPlanValidate(service, body) {
      const map = {
        mieru: 'amneziaMieruFieldErrors',
        hysteria: 'amneziaHysteriaFieldErrors',
        naive: 'amneziaNaiveFieldErrors',
      };
      const stateKey = map[service];
      if (!stateKey) return false;
      try {
        const res = await this.api.validatePortPlan({ service, ...(body || {}) });
        if (!res || res.ok === false) {
          this[stateKey] = (res && res.fieldErrors) || { _form: this.$t('portPlanValidateFailed') };
          return false;
        }
        this[stateKey] = {};
        return true;
      } catch (err) {
        this[stateKey] = { _form: (err && err.message) || this.$t('portPlanValidateFailed') };
        return false;
      }
    },
    buildMieruInstallBody() {
      const body = {
        address: String(this.amneziaMieruAddress).trim(),
        enableTcp: this.amneziaMieruEnableTcp,
        enableUdp: this.amneziaMieruEnableUdp,
        tcpPublicPort: Number(this.amneziaMieruTcpPublicPort) || 3080,
        udpPublicPort: Number(this.amneziaMieruUdpPublicPort) || 3080,
        loggingLevel: this.amneziaMieruLoggingLevel || 'INFO',
        multiplexing: this.amneziaMieruMultiplexing || 'LOW',
        handshakeNoWait: this.amneziaMieruHandshakeNoWait === true,
      };
      const mtuRaw = String(this.amneziaMieruMtu == null ? '' : this.amneziaMieruMtu).trim();
      if (mtuRaw !== '') body.mtu = Number(mtuRaw);
      const portRaw = String(this.amneziaMieruPort == null ? '' : this.amneziaMieruPort).trim();
      if (portRaw !== '') body.port = Number(portRaw);
      if (this.amneziaMieruEnableTcp && !this.amneziaMieruEnableUdp) {
        body.protocol = 'TCP';
        body.publicPort = body.tcpPublicPort;
      } else if (this.amneziaMieruEnableUdp && !this.amneziaMieruEnableTcp) {
        body.protocol = 'UDP';
        body.publicPort = body.udpPublicPort;
      }
      return body;
    },
    buildHysteriaInstallBody() {
      const body = {
        address: String(this.amneziaHysteriaAddress).trim(),
        publicPort: Number(this.amneziaHysteriaPublicPort) || 443,
        sslCertId: String(this.amneziaHysteriaSslCertId || '__auto__').trim(),
        core: String(this.amneziaHysteriaCore || 'original').trim().toLowerCase(),
      };
      const masq = String(this.amneziaHysteriaMasqueradeUrl || '').trim();
      body.masqueradeUrl = masq;
      const obfsType = String(this.amneziaHysteriaObfsType || '').trim();
      if (obfsType === 'salamander' || obfsType === 'gecko') {
        body.obfsType = obfsType;
        // Password is auto-generated on the server when empty.
        if (obfsType === 'gecko') {
          const gmin = String(this.amneziaHysteriaObfsGeckoMin || '').trim();
          const gmax = String(this.amneziaHysteriaObfsGeckoMax || '').trim();
          if (gmin) body.obfsGeckoMin = Number(gmin);
          if (gmax) body.obfsGeckoMax = Number(gmax);
        }
      }
      const up = String(this.amneziaHysteriaBandwidthUp || '').trim();
      const down = String(this.amneziaHysteriaBandwidthDown || '').trim();
      if (up) body.bandwidthUp = up;
      if (down) body.bandwidthDown = down;
      const core = body.core;
      if (core !== 'xray') {
        if (this.amneziaHysteriaCongestionType) {
          body.congestionType = this.amneziaHysteriaCongestionType;
          if (this.amneziaHysteriaCongestionType === 'bbr' && this.amneziaHysteriaBbrProfile) {
            body.bbrProfile = this.amneziaHysteriaBbrProfile;
          }
        }
        if (this.amneziaHysteriaEchEnabled) body.echEnabled = true;
        if (this.amneziaHysteriaListenMode) body.listenMode = this.amneziaHysteriaListenMode;
        if (this.amneziaHysteriaPortRange) body.portRange = String(this.amneziaHysteriaPortRange).trim();
        if (this.amneziaHysteriaRealmUri) body.realmUri = String(this.amneziaHysteriaRealmUri).trim();
      }
      return body;
    },
    buildNaiveInstallBody() {
      const cert = this.sslFindCertById
        ? this.sslFindCertById(this.amneziaNaiveSslCertId)
        : (this.sslCerts || []).find((x) => x.id === this.amneziaNaiveSslCertId);
      const sniFromCert = cert
        ? this.normalizeHostnameInput(cert.sni || cert.domain || '')
        : '';
      const body = {
        address: String(this.amneziaNaiveAddress).trim(),
        sni: sniFromCert || this.normalizeHostnameInput(this.amneziaNaiveSni),
        publicPort: Number(this.amneziaNaivePublicPort) || 443,
        sslCertId: String(this.amneziaNaiveSslCertId || '').trim(),
        enableTcp: this.amneziaNaiveEnableTcp === true,
        enableQuic: this.amneziaNaiveEnableQuic === true,
      };
      const probe = String(this.amneziaNaiveProbeDomain || '').trim();
      if (probe) body.probeResistanceDomain = probe;
      return body;
    },
    applySidecarCapabilities(caps) {
      const c = caps || {};
      if (c.panelHttpsPort != null) this.panelHttpsPort = Number(c.panelHttpsPort) || 443;
      if (c.panelDomain != null) this.panelDomain = String(c.panelDomain || '');
      if (c.certbotEmail != null && String(c.certbotEmail).trim()) {
        this.certbotEmail = String(c.certbotEmail).trim();
      }
      this.applyAmneziaMieruCapability(c);
      this.applyAmneziaHysteriaCapability(c);
      this.applyAmneziaNaiveCapability(c);
    },
    applyAmneziaMieruCapability(caps) {
      const c = caps || {};
      const st = c.mieru || {};
      const smokeOk = !!(st.smoke && st.smoke.ok === true);
      const healthy = st.healthy === true || (st.phase === 'running' && smokeOk);
      this.amneziaMieruHealthy = healthy;
      this.amneziaMieruAvailable = healthy;
      if (st.phase) this.amneziaMieruPhase = st.phase;
      this.amneziaMieruBusy = sidecarBusyFromPhase(st.phase, st.busy);
      this.amneziaMieruError = st.lastError || null;
      this.amneziaMieruClockWarning = formatSidecarWarning(st.clockWarning);
      if (!this.amneziaMieruInstallOpen) {
        if (st.addressStored) this.amneziaMieruAddress = st.addressStored;
        else if (st.address && !this.amneziaMieruAddress) this.amneziaMieruAddress = st.address;
        if (st.tcpEnabled != null) this.amneziaMieruEnableTcp = st.tcpEnabled === true;
        else if (st.protocol) this.amneziaMieruEnableTcp = String(st.protocol).toUpperCase() === 'TCP';
        if (st.udpEnabled != null) this.amneziaMieruEnableUdp = st.udpEnabled === true;
        else if (st.protocol) this.amneziaMieruEnableUdp = String(st.protocol).toUpperCase() === 'UDP';
        if (st.tcpPublicPort) this.amneziaMieruTcpPublicPort = st.tcpPublicPort;
        if (st.udpPublicPort) this.amneziaMieruUdpPublicPort = st.udpPublicPort;
        if (st.publicPort && !st.tcpPublicPort && !st.udpPublicPort) {
          this.amneziaMieruTcpPublicPort = st.publicPort;
          this.amneziaMieruUdpPublicPort = st.publicPort;
        }
        if (st.port) this.amneziaMieruPort = st.port;
        if (st.mtu != null && st.mtu !== '') this.amneziaMieruMtu = st.mtu;
        if (st.loggingLevel) this.amneziaMieruLoggingLevel = st.loggingLevel;
        if (st.multiplexing) this.amneziaMieruMultiplexing = st.multiplexing;
        if (st.handshakeMode) {
          this.amneziaMieruHandshakeNoWait = st.handshakeMode === 'HANDSHAKE_NO_WAIT';
        }
      }
      if (this.amneziaMieruBusy) this.ensureAmneziaMieruPoll();
      else this.stopAmneziaMieruPoll();
    },
    async refreshAmneziaMieruStatus() {
      if (!this.canManageMieru) return null;
      try {
        const st = await this.api.getAmneziaMieruStatus();
        this.applyAmneziaMieruCapability({ mieruAvailable: st.available === true, mieru: st });
        return st;
      } catch (err) {
        this.amneziaMieruError = (err && err.message) || String(err);
        return null;
      }
    },
    ensureAmneziaMieruPoll() {
      if (this.amneziaMieruPollTimer) return;
      this._amneziaMieruPhasePoll = this.amneziaMieruPhase;
      this.amneziaMieruPollTimer = setInterval(() => {
        this.refreshAmneziaMieruStatus().then((st) => onSidecarPollStatus(this, 'amneziaMieruPhase', st));
      }, SIDECAR_POLL_MS);
    },
    stopAmneziaMieruPoll() {
      if (this.amneziaMieruPollTimer) {
        clearInterval(this.amneziaMieruPollTimer);
        this.amneziaMieruPollTimer = null;
      }
    },
    amneziaMieruHeaderTitle() {
      const phase = this.amneziaMieruPhase;
      if (phase === 'installing' || phase === 'removing' || this.amneziaMieruBusy) return this.$t('mieruHeaderBusy');
      if (phase === 'error') {
        return (this.amneziaMieruError && `${this.$t('mieruHeaderError')}: ${this.amneziaMieruError}`)
          || this.$t('mieruHeaderError');
      }
      if (phase === 'degraded' || (phase === 'running' && !this.amneziaMieruHealthy)) return this.$t('mieruHeaderDegraded');
      if (phase === 'running' && this.amneziaMieruHealthy) return this.$t('mieruHeaderManage');
      return this.$t('mieruHeaderEnable');
    },
    closeAmneziaMieruInstall() {
      this.amneziaMieruInstallOpen = false;
      this.amneziaMieruModalMode = 'install';
      this.clearSidecarFieldErrors('mieru');
    },
    openAmneziaMieruInstall({ mode = 'install' } = {}) {
      this.amneziaMieruModalMode = mode;
      this.clearSidecarFieldErrors('mieru');
      this.amneziaMieruInstallOpen = true;
      this.refreshAmneziaMieruStatus().finally(() => {
        if (!String(this.amneziaMieruAddress || '').trim()) {
          this.amneziaMieruAddress = sidecarDefaultAddress();
        }
      });
    },
    async confirmAmneziaMieruInstall() {
      if (this.amneziaMieruBusy || !this.canConfirmAmneziaMieruInstall) return;
      const body = this.buildMieruInstallBody();
      const valid = await this.runPortPlanValidate('mieru', body);
      if (!valid) return;
      this.closeAmneziaMieruInstall();
      this.amneziaMieruBusy = true;
      this.ensureAmneziaMieruPoll();
      try {
        await this.withAmneziaDnsTimeout(this.api.enableAmneziaMieru(body), 180000);
        await this.refreshAmneziaMieruStatus();
        await this.refresh();
      } catch (err) {
        this.amneziaMieruError = (err && err.message) || this.$t('mieruToggleFailed');
        alert(this.amneziaMieruError);
        await this.refreshAmneziaMieruStatus();
      } finally {
        this.amneziaMieruBusy = false;
        if (!['installing', 'removing'].includes(this.amneziaMieruPhase)) this.stopAmneziaMieruPoll();
      }
    },
    async confirmAmneziaMieruDisable() {
      if (this.amneziaMieruBusy) return;
      if (!window.confirm(this.$t('mieruUninstallConfirm'))) return;
      this.closeAmneziaMieruInstall();
      this.amneziaMieruBusy = true;
      this.ensureAmneziaMieruPoll();
      try {
        await this.withAmneziaDnsTimeout(this.api.disableAmneziaMieru(), 60000);
        await this.refreshAmneziaMieruStatus();
        await this.refresh();
      } catch (err) {
        this.amneziaMieruError = (err && err.message) || this.$t('mieruToggleFailed');
        alert(this.amneziaMieruError);
        await this.refreshAmneziaMieruStatus();
      } finally {
        this.amneziaMieruBusy = false;
        if (!['installing', 'removing'].includes(this.amneziaMieruPhase)) this.stopAmneziaMieruPoll();
      }
    },
    async toggleAmneziaMieru() {
      if (!this.canManageMieru || this.amneziaMieruBusy) return;
      const phase = this.amneziaMieruPhase;
      if (phase === 'running' || phase === 'degraded') {
        await this.openAmneziaMieruInstall({ mode: 'manage' });
        return;
      }
      if (phase === 'error') {
        this.amneziaMieruBusy = true;
        this.ensureAmneziaMieruPoll();
        try {
          await this.withAmneziaDnsTimeout(this.api.forceCleanupAmneziaMieru(), 60000);
          await this.refreshAmneziaMieruStatus();
          await this.refresh();
        } catch (err) {
          this.amneziaMieruError = (err && err.message) || this.$t('mieruToggleFailed');
          alert(this.amneziaMieruError);
          await this.refreshAmneziaMieruStatus();
        } finally {
          this.amneziaMieruBusy = false;
          this.stopAmneziaMieruPoll();
        }
        return;
      }
      await this.openAmneziaMieruInstall({ mode: 'install' });
    },

    applyAmneziaHysteriaCapability(caps) {
      const c = caps || {};
      const st = c.hysteria || {};
      const smokeOk = !!(st.smoke && st.smoke.ok === true);
      const healthy = st.healthy === true || (st.phase === 'running' && smokeOk);
      this.amneziaHysteriaHealthy = healthy;
      this.amneziaHysteriaAvailable = healthy;
      if (st.phase) this.amneziaHysteriaPhase = st.phase;
      this.amneziaHysteriaBusy = sidecarBusyFromPhase(st.phase, st.busy);
      this.amneziaHysteriaError = st.lastError || null;
      if (!this.amneziaHysteriaInstallOpen) {
        if (st.addressStored) this.amneziaHysteriaAddress = st.addressStored;
        else if (st.address && !this.amneziaHysteriaAddress) this.amneziaHysteriaAddress = st.address;
        if (st.sniStored) this.amneziaHysteriaSni = st.sniStored;
        else if (st.sni && !this.amneziaHysteriaSni) this.amneziaHysteriaSni = st.sni;
        if (st.publicPort) this.amneziaHysteriaPublicPort = st.publicPort;
        if (st.masqueradeUrlStored) this.amneziaHysteriaMasqueradeUrl = st.masqueradeUrlStored;
        else if (st.masqueradeUrl && !this.amneziaHysteriaMasqueradeUrl) {
          this.amneziaHysteriaMasqueradeUrl = st.masqueradeUrl;
        }
        this.syncHysteriaMasqueradeIdFromUrl();
        if (st.obfsType) this.amneziaHysteriaObfsType = st.obfsType;
        if (st.obfsPassword) this.amneziaHysteriaObfsPassword = st.obfsPassword;
        if (st.core) this.amneziaHysteriaCore = st.core;
        if (st.obfsGeckoMin) this.amneziaHysteriaObfsGeckoMin = String(st.obfsGeckoMin);
        if (st.obfsGeckoMax) this.amneziaHysteriaObfsGeckoMax = String(st.obfsGeckoMax);
        if (st.congestionType) this.amneziaHysteriaCongestionType = st.congestionType;
        if (st.bbrProfile) this.amneziaHysteriaBbrProfile = st.bbrProfile;
        if (st.echEnabled != null) this.amneziaHysteriaEchEnabled = st.echEnabled === true;
        if (st.echConfigList) this.amneziaHysteriaEchConfigList = st.echConfigList;
        if (st.listenMode) this.amneziaHysteriaListenMode = st.listenMode;
        if (st.portRange) this.amneziaHysteriaPortRange = st.portRange;
        if (st.realmUri) this.amneziaHysteriaRealmUri = st.realmUri;
        if (st.bandwidthUp) this.amneziaHysteriaBandwidthUp = st.bandwidthUp;
        if (st.bandwidthDown) this.amneziaHysteriaBandwidthDown = st.bandwidthDown;
        if (st.sslCertId) this.amneziaHysteriaSslCertId = st.sslCertId;
        else if (!this.amneziaHysteriaSslCertId) this.amneziaHysteriaSslCertId = '__auto__';
      }
      if (this.amneziaHysteriaBusy) this.ensureAmneziaHysteriaPoll();
      else this.stopAmneziaHysteriaPoll();
    },
    async refreshAmneziaHysteriaStatus() {
      if (!this.canManageHysteria) return null;
      try {
        const st = await this.api.getAmneziaHysteriaStatus();
        this.applyAmneziaHysteriaCapability({ hysteriaAvailable: st.available === true, hysteria: st });
        return st;
      } catch (err) {
        this.amneziaHysteriaError = (err && err.message) || String(err);
        return null;
      }
    },
    ensureAmneziaHysteriaPoll() {
      if (this.amneziaHysteriaPollTimer) return;
      this._amneziaHysteriaPhasePoll = this.amneziaHysteriaPhase;
      this.amneziaHysteriaPollTimer = setInterval(() => {
        this.refreshAmneziaHysteriaStatus().then((st) => onSidecarPollStatus(this, 'amneziaHysteriaPhase', st));
      }, SIDECAR_POLL_MS);
    },
    stopAmneziaHysteriaPoll() {
      if (this.amneziaHysteriaPollTimer) {
        clearInterval(this.amneziaHysteriaPollTimer);
        this.amneziaHysteriaPollTimer = null;
      }
    },
    amneziaHysteriaHeaderTitle() {
      const phase = this.amneziaHysteriaPhase;
      if (phase === 'installing' || phase === 'removing' || this.amneziaHysteriaBusy) return this.$t('hysteriaHeaderBusy');
      if (phase === 'error') {
        return (this.amneziaHysteriaError && `${this.$t('hysteriaHeaderError')}: ${this.amneziaHysteriaError}`)
          || this.$t('hysteriaHeaderError');
      }
      if (phase === 'degraded' || (phase === 'running' && !this.amneziaHysteriaHealthy)) return this.$t('hysteriaHeaderDegraded');
      if (phase === 'running' && this.amneziaHysteriaHealthy) return this.$t('hysteriaHeaderManage');
      return this.$t('hysteriaHeaderEnable');
    },
    closeAmneziaHysteriaInstall() {
      this.amneziaHysteriaInstallOpen = false;
      this.amneziaHysteriaModalMode = 'install';
      this.clearSidecarFieldErrors('hysteria');
    },
    openAmneziaHysteriaInstall({ mode = 'install' } = {}) {
      this.amneziaHysteriaModalMode = mode;
      this.clearSidecarFieldErrors('hysteria');
      this.amneziaHysteriaInstallOpen = true;
      Promise.all([
        this.refreshAmneziaHysteriaStatus(),
        this.refreshSslCerts ? this.refreshSslCerts() : Promise.resolve(),
      ]).finally(() => {
        if (!String(this.amneziaHysteriaAddress || '').trim()) {
          this.amneziaHysteriaAddress = sidecarDefaultAddress();
        }
        if (this.amneziaHysteriaSslCertId) this.onHysteriaSslCertChange();
        this.syncHysteriaMasqueradeIdFromUrl();
      });
    },
    async confirmAmneziaHysteriaInstall() {
      if (this.amneziaHysteriaBusy || !this.canConfirmAmneziaHysteriaInstall) return;
      const body = this.buildHysteriaInstallBody();
      const valid = await this.runPortPlanValidate('hysteria', body);
      if (!valid) return;
      this.closeAmneziaHysteriaInstall();
      this.amneziaHysteriaBusy = true;
      this.ensureAmneziaHysteriaPoll();
      try {
        if (this.sniPreflightRequiredForHysteria() && body.sni) {
          await this.preflightSniForInstall(body.sni);
        }
        const masq = String(body.masqueradeUrl || '').trim();
        if (masq) {
          try {
            const mp = await this.api.preflightMasqueradeUrl({ url: masq });
            if (!mp || mp.ok === false) {
              throw new Error(
                this.$t('hysteriaMasqueradePreflightFailed', { url: masq })
                || `Masquerade URL failed check: ${masq}`,
              );
            }
          } catch (err) {
            // Old panel without route → serveStatic 405; do not block install
            if (err && (err.status === 404 || err.status === 405)) {
              /* continue */
            } else {
              throw err;
            }
          }
        }
        await this.withAmneziaDnsTimeout(this.api.enableAmneziaHysteria(body), 300000);
        await this.refreshAmneziaHysteriaStatus();
        await this.refresh();
      } catch (err) {
        this.amneziaHysteriaError = (err && err.message) || this.$t('hysteriaToggleFailed');
        alert(this.amneziaHysteriaError);
        await this.refreshAmneziaHysteriaStatus();
      } finally {
        this.amneziaHysteriaBusy = false;
        if (!['installing', 'removing'].includes(this.amneziaHysteriaPhase)) this.stopAmneziaHysteriaPoll();
      }
    },
    async confirmAmneziaHysteriaDisable() {
      if (this.amneziaHysteriaBusy) return;
      if (!window.confirm(this.$t('hysteriaUninstallConfirm'))) return;
      this.closeAmneziaHysteriaInstall();
      this.amneziaHysteriaBusy = true;
      this.ensureAmneziaHysteriaPoll();
      try {
        await this.withAmneziaDnsTimeout(this.api.disableAmneziaHysteria(), 60000);
        await this.refreshAmneziaHysteriaStatus();
        await this.refresh();
      } catch (err) {
        this.amneziaHysteriaError = (err && err.message) || this.$t('hysteriaToggleFailed');
        alert(this.amneziaHysteriaError);
        await this.refreshAmneziaHysteriaStatus();
      } finally {
        this.amneziaHysteriaBusy = false;
        if (!['installing', 'removing'].includes(this.amneziaHysteriaPhase)) this.stopAmneziaHysteriaPoll();
      }
    },
    async toggleAmneziaHysteria() {
      if (!this.canManageHysteria || this.amneziaHysteriaBusy) return;
      const phase = this.amneziaHysteriaPhase;
      if (phase === 'running' || phase === 'degraded') {
        await this.openAmneziaHysteriaInstall({ mode: 'manage' });
        return;
      }
      if (phase === 'error') {
        this.amneziaHysteriaBusy = true;
        this.ensureAmneziaHysteriaPoll();
        try {
          await this.withAmneziaDnsTimeout(this.api.forceCleanupAmneziaHysteria(), 60000);
          await this.refreshAmneziaHysteriaStatus();
          await this.refresh();
        } catch (err) {
          this.amneziaHysteriaError = (err && err.message) || this.$t('hysteriaToggleFailed');
          alert(this.amneziaHysteriaError);
          await this.refreshAmneziaHysteriaStatus();
        } finally {
          this.amneziaHysteriaBusy = false;
          this.stopAmneziaHysteriaPoll();
        }
        return;
      }
      await this.openAmneziaHysteriaInstall({ mode: 'install' });
    },

    applyAmneziaNaiveCapability(caps) {
      const c = caps || {};
      const st = c.naive || {};
      const smokeOk = !!(st.smoke && st.smoke.ok === true);
      const healthy = st.healthy === true || (st.phase === 'running' && smokeOk);
      this.amneziaNaiveHealthy = healthy;
      this.amneziaNaiveAvailable = healthy;
      if (st.phase) this.amneziaNaivePhase = st.phase;
      this.amneziaNaiveBusy = sidecarBusyFromPhase(st.phase, st.busy);
      this.amneziaNaiveError = st.lastError || null;
      if (!this.amneziaNaiveInstallOpen) {
        if (st.addressStored) this.amneziaNaiveAddress = st.addressStored;
        else if (st.address && !this.amneziaNaiveAddress) this.amneziaNaiveAddress = st.address;
        if (st.sniStored) this.amneziaNaiveSni = st.sniStored;
        else if (st.sni && !this.amneziaNaiveSni) this.amneziaNaiveSni = st.sni;
        if (st.probeResistanceDomain && !this.amneziaNaiveProbeDomain) {
          this.amneziaNaiveProbeDomain = st.probeResistanceDomain;
        }
        if (st.publicPort) this.amneziaNaivePublicPort = st.publicPort;
        if (st.sslCertId) this.amneziaNaiveSslCertId = st.sslCertId;
        if (st.tcpEnabled != null) this.amneziaNaiveEnableTcp = st.tcpEnabled === true;
        if (st.quicEnabled != null) this.amneziaNaiveEnableQuic = st.quicEnabled === true;
      }
      if (this.amneziaNaiveBusy) this.ensureAmneziaNaivePoll();
      else this.stopAmneziaNaivePoll();
    },
    async refreshAmneziaNaiveStatus() {
      if (!this.canManageNaive) return null;
      try {
        const st = await this.api.getAmneziaNaiveStatus();
        this.applyAmneziaNaiveCapability({ naiveAvailable: st.available === true, naive: st });
        return st;
      } catch (err) {
        this.amneziaNaiveError = (err && err.message) || String(err);
        return null;
      }
    },
    ensureAmneziaNaivePoll() {
      if (this.amneziaNaivePollTimer) return;
      this._amneziaNaivePhasePoll = this.amneziaNaivePhase;
      this.amneziaNaivePollTimer = setInterval(() => {
        this.refreshAmneziaNaiveStatus().then((st) => onSidecarPollStatus(this, 'amneziaNaivePhase', st));
      }, SIDECAR_POLL_MS);
    },
    stopAmneziaNaivePoll() {
      if (this.amneziaNaivePollTimer) {
        clearInterval(this.amneziaNaivePollTimer);
        this.amneziaNaivePollTimer = null;
      }
    },
    amneziaNaiveHeaderTitle() {
      const phase = this.amneziaNaivePhase;
      if (phase === 'installing' || phase === 'removing' || this.amneziaNaiveBusy) return this.$t('naiveHeaderBusy');
      if (phase === 'error') {
        return (this.amneziaNaiveError && `${this.$t('naiveHeaderError')}: ${this.amneziaNaiveError}`)
          || this.$t('naiveHeaderError');
      }
      if (phase === 'degraded' || (phase === 'running' && !this.amneziaNaiveHealthy)) return this.$t('naiveHeaderDegraded');
      if (phase === 'running' && this.amneziaNaiveHealthy) return this.$t('naiveHeaderManage');
      return this.$t('naiveHeaderEnable');
    },
    closeAmneziaNaiveInstall() {
      this.amneziaNaiveInstallOpen = false;
      this.amneziaNaiveModalMode = 'install';
      this.clearSidecarFieldErrors('naive');
    },
    openAmneziaNaiveInstall({ mode = 'install' } = {}) {
      this.amneziaNaiveModalMode = mode;
      this.clearSidecarFieldErrors('naive');
      this.amneziaNaiveInstallOpen = true;
      Promise.all([
        this.refreshAmneziaNaiveStatus(),
        this.refreshSslCerts ? this.refreshSslCerts() : Promise.resolve(),
      ]).finally(() => {
        if (!String(this.amneziaNaiveAddress || '').trim()) {
          this.amneziaNaiveAddress = sidecarDefaultAddress();
        }
        if (this.amneziaNaiveSslCertId) this.onNaiveSslCertChange();
      });
    },
    async confirmAmneziaNaiveInstall() {
      if (this.amneziaNaiveBusy || !this.canConfirmAmneziaNaiveInstall) return;
      const body = this.buildNaiveInstallBody();
      this.amneziaNaiveSni = body.sni;
      const valid = await this.runPortPlanValidate('naive', body);
      if (!valid) return;
      this.closeAmneziaNaiveInstall();
      this.amneziaNaiveBusy = true;
      this.ensureAmneziaNaivePoll();
      try {
        await this.withAmneziaDnsTimeout(this.api.enableAmneziaNaive(body), 180000);
        await this.refreshAmneziaNaiveStatus();
        await this.refresh();
      } catch (err) {
        this.amneziaNaiveError = (err && err.message) || this.$t('naiveToggleFailed');
        alert(this.amneziaNaiveError);
        await this.refreshAmneziaNaiveStatus();
      } finally {
        this.amneziaNaiveBusy = false;
        if (!['installing', 'removing'].includes(this.amneziaNaivePhase)) this.stopAmneziaNaivePoll();
      }
    },
    async confirmAmneziaNaiveDisable() {
      if (this.amneziaNaiveBusy) return;
      if (!window.confirm(this.$t('naiveUninstallConfirm'))) return;
      this.closeAmneziaNaiveInstall();
      this.amneziaNaiveBusy = true;
      this.ensureAmneziaNaivePoll();
      try {
        await this.withAmneziaDnsTimeout(this.api.disableAmneziaNaive(), 60000);
        await this.refreshAmneziaNaiveStatus();
        await this.refresh();
      } catch (err) {
        this.amneziaNaiveError = (err && err.message) || this.$t('naiveToggleFailed');
        alert(this.amneziaNaiveError);
        await this.refreshAmneziaNaiveStatus();
      } finally {
        this.amneziaNaiveBusy = false;
        if (!['installing', 'removing'].includes(this.amneziaNaivePhase)) this.stopAmneziaNaivePoll();
      }
    },
    async toggleAmneziaNaive() {
      if (!this.canManageNaive || this.amneziaNaiveBusy) return;
      const phase = this.amneziaNaivePhase;
      if (phase === 'running' || phase === 'degraded') {
        await this.openAmneziaNaiveInstall({ mode: 'manage' });
        return;
      }
      if (phase === 'error') {
        this.amneziaNaiveBusy = true;
        this.ensureAmneziaNaivePoll();
        try {
          await this.withAmneziaDnsTimeout(this.api.forceCleanupAmneziaNaive(), 60000);
          await this.refreshAmneziaNaiveStatus();
          await this.refresh();
        } catch (err) {
          this.amneziaNaiveError = (err && err.message) || this.$t('naiveToggleFailed');
          alert(this.amneziaNaiveError);
          await this.refreshAmneziaNaiveStatus();
        } finally {
          this.amneziaNaiveBusy = false;
          this.stopAmneziaNaivePoll();
        }
        return;
      }
      await this.openAmneziaNaiveInstall({ mode: 'install' });
    },
  },
};
