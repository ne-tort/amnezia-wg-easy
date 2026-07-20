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
      amneziaMieruPublicPort: 3080,
      amneziaMieruPort: '',
      amneziaMieruProtocol: 'TCP',
      amneziaMieruProtocols: ['TCP', 'UDP'],
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
      amneziaNaivePublicPort: 443,
      amneziaNaiveProbeDomain: '',

      qrcodeMieruLink: '',
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
    isValidAmneziaMieruPublicPort() {
      const n = Number(this.amneziaMieruPublicPort);
      return Number.isInteger(n) && n >= 1 && n <= 65535;
    },
    isValidAmneziaHysteriaPublicPort() {
      const n = Number(this.amneziaHysteriaPublicPort);
      return Number.isInteger(n) && n >= 1 && n <= 65535;
    },
    isValidAmneziaNaivePublicPort() {
      const n = Number(this.amneziaNaivePublicPort);
      return Number.isInteger(n) && n >= 1 && n <= 65535;
    },
  },

  methods: {
    applySidecarCapabilities(caps) {
      const c = caps || {};
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
      this.amneziaMieruClockWarning = st.clockWarning || null;
      if (!this.amneziaMieruInstallOpen) {
        if (st.addressStored) this.amneziaMieruAddress = st.addressStored;
        else if (st.address && !this.amneziaMieruAddress) this.amneziaMieruAddress = st.address;
        if (st.protocol) this.amneziaMieruProtocol = st.protocol;
        if (st.port) this.amneziaMieruPort = st.port;
        if (st.publicPort) this.amneziaMieruPublicPort = st.publicPort;
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
      this.amneziaMieruPollTimer = setInterval(() => {
        this.refreshAmneziaMieruStatus().then((st) => {
          if (st && (st.phase === 'running' || st.phase === 'off' || st.phase === 'error')) {
            this.refresh().catch(() => {});
          }
        });
      }, 1000);
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
    },
    openAmneziaMieruInstall({ mode = 'install' } = {}) {
      this.amneziaMieruModalMode = mode;
      this.refreshAmneziaMieruStatus().finally(() => {
        if (!String(this.amneziaMieruAddress || '').trim()) {
          this.amneziaMieruAddress = sidecarDefaultAddress();
        }
        this.amneziaMieruInstallOpen = true;
      });
    },
    async confirmAmneziaMieruInstall() {
      if (this.amneziaMieruBusy || !String(this.amneziaMieruAddress || '').trim() || !this.isValidAmneziaMieruPublicPort) return;
      this.closeAmneziaMieruInstall();
      this.amneziaMieruBusy = true;
      this.ensureAmneziaMieruPoll();
      try {
        const body = {
          address: String(this.amneziaMieruAddress).trim(),
          publicPort: Number(this.amneziaMieruPublicPort) || 3080,
          protocol: this.amneziaMieruProtocol,
        };
        const portRaw = String(this.amneziaMieruPort == null ? '' : this.amneziaMieruPort).trim();
        if (portRaw !== '') body.port = Number(portRaw);
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
      this.amneziaHysteriaPollTimer = setInterval(() => {
        this.refreshAmneziaHysteriaStatus().then((st) => {
          if (st && (st.phase === 'running' || st.phase === 'off' || st.phase === 'error')) {
            this.refresh().catch(() => {});
          }
        });
      }, 1000);
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
    },
    openAmneziaHysteriaInstall({ mode = 'install' } = {}) {
      this.amneziaHysteriaModalMode = mode;
      Promise.all([
        this.refreshAmneziaHysteriaStatus(),
        this.refreshSniCache({ ensureBg: true }),
      ]).finally(() => {
        if (!String(this.amneziaHysteriaAddress || '').trim()) {
          this.amneziaHysteriaAddress = sidecarDefaultAddress();
        }
        if (!String(this.amneziaHysteriaSni || '').trim() && this.sniFinderDefaultSni) {
          this.amneziaHysteriaSni = this.sniFinderDefaultSni;
        }
        this.amneziaHysteriaInstallOpen = true;
      });
    },
    async confirmAmneziaHysteriaInstall() {
      if (
        this.amneziaHysteriaBusy
        || !String(this.amneziaHysteriaSni || '').trim()
        || !String(this.amneziaHysteriaAddress || '').trim()
        || !this.isValidAmneziaHysteriaPublicPort
      ) return;
      this.closeAmneziaHysteriaInstall();
      this.amneziaHysteriaBusy = true;
      this.ensureAmneziaHysteriaPoll();
      try {
        await this.preflightSniForInstall(this.amneziaHysteriaSni);
        await this.withAmneziaDnsTimeout(this.api.enableAmneziaHysteria({
          address: String(this.amneziaHysteriaAddress).trim(),
          sni: String(this.amneziaHysteriaSni).trim(),
          publicPort: Number(this.amneziaHysteriaPublicPort) || 443,
        }), 180000);
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
      this.amneziaNaivePollTimer = setInterval(() => {
        this.refreshAmneziaNaiveStatus().then((st) => {
          if (st && (st.phase === 'running' || st.phase === 'off' || st.phase === 'error')) {
            this.refresh().catch(() => {});
          }
        });
      }, 1000);
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
    },
    openAmneziaNaiveInstall({ mode = 'install' } = {}) {
      this.amneziaNaiveModalMode = mode;
      Promise.all([
        this.refreshAmneziaNaiveStatus(),
        this.refreshSniCache({ ensureBg: true }),
      ]).finally(() => {
        if (!String(this.amneziaNaiveAddress || '').trim()) {
          this.amneziaNaiveAddress = sidecarDefaultAddress();
        }
        this.amneziaNaiveInstallOpen = true;
      });
    },
    async confirmAmneziaNaiveInstall() {
      if (
        this.amneziaNaiveBusy
        || !String(this.amneziaNaiveSni || '').trim()
        || !String(this.amneziaNaiveAddress || '').trim()
        || !this.isValidAmneziaNaivePublicPort
      ) return;
      this.closeAmneziaNaiveInstall();
      this.amneziaNaiveBusy = true;
      this.ensureAmneziaNaivePoll();
      try {
        await this.preflightSniForInstall(this.amneziaNaiveSni);
        const body = {
          address: String(this.amneziaNaiveAddress).trim(),
          sni: String(this.amneziaNaiveSni).trim(),
          publicPort: Number(this.amneziaNaivePublicPort) || 443,
        };
        const probe = String(this.amneziaNaiveProbeDomain || '').trim();
        if (probe) body.probeResistanceDomain = probe;
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
