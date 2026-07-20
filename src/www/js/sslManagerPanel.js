'use strict';

/* global API */

/**
 * SSL Certificate Manager panel — Vue mixin (state + methods).
 * Merged into app like SidecarPanels.
 */
const SslManagerPanel = {
  initialState() {
    return {
      sslManagerOpen: false,
      sslManagerView: 'list', // list | detail | create
      sslManagerCreateType: '', // self_signed | lets_encrypt | reality | import_pem | import_path
      sslManagerBusy: false,
      sslManagerError: null,
      sslCerts: [],
      sslCertbotEmail: '',
      sslSelectedId: null,
      sslDetail: null,
      sslForm: {
        domain: '',
        label: '',
        email: '',
        sni: '',
        dest: '',
        days: '825',
        certPem: '',
        keyPem: '',
        certPath: '',
        keyPath: '',
      },
    };
  },

  computed: {
    sslSelectedCert() {
      if (!this.sslSelectedId) return null;
      return (this.sslCerts || []).find((c) => c.id === this.sslSelectedId) || this.sslDetail;
    },
  },

  methods: {
    sslTypeLabel(type) {
      const key = `sslType_${type}`;
      const t = this.$t(key);
      return (t && t !== key) ? t : type;
    },
    sslFormatExpiry(notAfter) {
      if (!notAfter) return '—';
      try {
        const d = new Date(Number(notAfter) * 1000);
        if (Number.isNaN(d.getTime())) return '—';
        return d.toISOString().slice(0, 10);
      } catch {
        return '—';
      }
    },
    resetSslForm() {
      this.sslForm = {
        domain: '',
        label: '',
        email: String(this.sslCertbotEmail || this.certbotEmail || '').trim(),
        sni: '',
        dest: '',
        days: '825',
        certPem: '',
        keyPem: '',
        certPath: '',
        keyPath: '',
      };
    },
    async openSslManager() {
      if (!this.canManageSettings) return;
      this.sslManagerOpen = true;
      this.sslManagerView = 'list';
      this.sslManagerCreateType = '';
      this.sslSelectedId = null;
      this.sslDetail = null;
      this.sslManagerError = null;
      this.resetSslForm();
      await this.refreshSslCerts();
    },
    closeSslManager() {
      this.sslManagerOpen = false;
      this.sslManagerView = 'list';
      this.sslManagerCreateType = '';
      this.sslSelectedId = null;
      this.sslDetail = null;
      this.sslManagerError = null;
    },
    async refreshSslCerts() {
      this.sslManagerBusy = true;
      this.sslManagerError = null;
      try {
        const res = await this.api.listSslCerts();
        this.sslCerts = (res && res.certs) || [];
        if (res && res.certbotEmail) {
          this.sslCertbotEmail = res.certbotEmail;
          if (!String(this.certbotEmail || '').trim()) this.certbotEmail = res.certbotEmail;
        }
      } catch (err) {
        this.sslManagerError = (err && err.message) || this.$t('sslLoadFailed');
        this.sslCerts = [];
      } finally {
        this.sslManagerBusy = false;
      }
    },
    async openSslDetail(cert) {
      if (!cert || !cert.id) return;
      this.sslSelectedId = cert.id;
      this.sslManagerView = 'detail';
      this.sslManagerBusy = true;
      this.sslManagerError = null;
      try {
        this.sslDetail = await this.api.getSslCert(cert.id);
      } catch (err) {
        this.sslDetail = cert;
        this.sslManagerError = (err && err.message) || this.$t('sslLoadFailed');
      } finally {
        this.sslManagerBusy = false;
      }
    },
    backSslList() {
      this.sslManagerView = 'list';
      this.sslManagerCreateType = '';
      this.sslSelectedId = null;
      this.sslDetail = null;
      this.sslManagerError = null;
    },
    openSslCreate(type) {
      this.sslManagerCreateType = type;
      this.sslManagerView = 'create';
      this.resetSslForm();
      this.sslManagerError = null;
    },
    async submitSslCreate() {
      if (this.sslManagerBusy || !this.sslManagerCreateType) return;
      this.sslManagerBusy = true;
      this.sslManagerError = null;
      try {
        const f = this.sslForm;
        let res;
        switch (this.sslManagerCreateType) {
          case 'self_signed':
            res = await this.api.createSslSelfSigned({
              domain: f.domain,
              label: f.label || undefined,
            });
            break;
          case 'lets_encrypt':
            res = await this.api.createSslLetsEncrypt({
              domain: f.domain,
              email: f.email,
              label: f.label || undefined,
            });
            if (f.email) this.certbotEmail = f.email;
            break;
          case 'reality':
            res = await this.api.createSslReality({
              sni: f.sni || f.domain,
              dest: f.dest || undefined,
              label: f.label || undefined,
            });
            break;
          case 'import_pem':
            res = await this.api.importSslPem({
              domain: f.domain,
              label: f.label || undefined,
              certPem: f.certPem,
              keyPem: f.keyPem,
            });
            break;
          case 'import_path':
            res = await this.api.importSslPath({
              domain: f.domain,
              label: f.label || undefined,
              certPath: f.certPath,
              keyPath: f.keyPath,
            });
            break;
          default:
            throw new Error('Unknown type');
        }
        await this.refreshSslCerts();
        const cert = (res && res.cert) || null;
        if (cert && cert.id) await this.openSslDetail(cert);
        else this.backSslList();
      } catch (err) {
        this.sslManagerError = (err && err.message) || this.$t('sslActionFailed');
      } finally {
        this.sslManagerBusy = false;
      }
    },
    async renewSslSelected() {
      const c = this.sslDetail || this.sslSelectedCert;
      if (!c || this.sslManagerBusy) return;
      this.sslManagerBusy = true;
      this.sslManagerError = null;
      try {
        const res = await this.api.renewSslCert(c.id);
        this.sslDetail = (res && res.cert) || this.sslDetail;
        await this.refreshSslCerts();
      } catch (err) {
        this.sslManagerError = (err && err.message) || this.$t('sslActionFailed');
      } finally {
        this.sslManagerBusy = false;
      }
    },
    async deleteSslSelected() {
      const c = this.sslDetail || this.sslSelectedCert;
      if (!c || c.managed || this.sslManagerBusy) return;
      if (!window.confirm(this.$t('sslDeleteConfirm'))) return;
      this.sslManagerBusy = true;
      this.sslManagerError = null;
      try {
        await this.api.deleteSslCert(c.id);
        this.backSslList();
        await this.refreshSslCerts();
      } catch (err) {
        this.sslManagerError = (err && err.message) || this.$t('sslActionFailed');
      } finally {
        this.sslManagerBusy = false;
      }
    },
    copySslText(text) {
      const raw = String(text || '');
      if (!raw) return;
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(raw).catch(() => {});
      }
    },
  },
};

if (typeof window !== 'undefined') {
  window.SslManagerPanel = SslManagerPanel;
}
