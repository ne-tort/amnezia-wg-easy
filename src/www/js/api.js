/* eslint-disable no-unused-vars */
/* eslint-disable no-undef */

'use strict';

class API {

  async call({ method, path, body }) {
    let res;
    try {
      res = await fetch(`/api${path}`, {
        method,
        credentials: 'include',
        headers: {
          'Content-Type': 'application/json',
        },
        body: body
          ? JSON.stringify(body)
          : undefined,
      });
    } catch (e) {
      const msg = (e && e.message === 'Failed to fetch') || (e && e.name === 'TypeError')
        ? 'NETWORK_ERROR'
        : (e && e.message) || 'Request failed';
      const err = new Error(msg);
      err.code = msg === 'NETWORK_ERROR' ? 'NETWORK_ERROR' : err.code;
      throw err;
    }

    if (res.status === 204) {
      return undefined;
    }

    const text = await res.text();
    let json;
    try {
      json = text ? JSON.parse(text) : {};
    } catch (e) {
      const preview = String(text).replace(/\s+/g, ' ').trim().slice(0, 160);
      const isHtml = preview.startsWith('<') || preview.toUpperCase().startsWith('<!DOCTYPE');
      const err = new Error(
        isHtml
          ? 'Server returned HTML instead of JSON (check API path and HTTP method).'
          : `Invalid JSON response: ${preview}`,
      );
      err.status = res.status;
      throw err;
    }

    if (!res.ok) {
      const msg = json.error
        || json.message
        || json.statusMessage
        || (json.data && (json.data.error || json.data.message))
        || res.statusText
        || `HTTP ${res.status}`;
      const err = new Error(msg);
      err.status = res.status;
      err.code = json.code || (json.data && json.data.code);
      throw err;
    }

    return json;
  }

  async getConfiguration(clientId, level, profile, format) {
    const params = [];
    if (level !== undefined && level !== null) params.push(`level=${Number(level)}`);
    if (profile !== undefined && profile !== null && profile !== '') params.push(`profile=${encodeURIComponent(profile)}`);
    if (format === 'amnezia' || format === 'vpn') params.push('format=amnezia');
    const qs = params.length ? `?${params.join('&')}` : '';
    const res = await fetch(`/api/wireguard/client/${clientId}/configuration${qs}`, {
      credentials: 'include',
    });
    if (!res.ok) throw new Error(res.statusText);
    return res.text();
  }

  /**
   * Fetches QR code SVG(s) for client. When level/profile are passed, config is built with that obfuscation.
   * @param {string} clientId
   * @param {number} [level] 0–5 (I0–I5)
   * @param {string} [profile] quic, dns, sip
   * @param {string} [encoding] 'text' (plain ini in one SVG) or 'amnezia' (AmneziaVPN chunked JSON → array of SVG)
   * @returns {Promise<string|string[]>} SVG markup, or array of SVGs for Amnezia
   */
  async getClientQRCodeSVG(clientId, level, profile, encoding) {
    const params = [];
    if (level !== undefined && level !== null) params.push(`level=${Number(level)}`);
    if (profile !== undefined && profile !== null && profile !== '') params.push(`profile=${encodeURIComponent(profile)}`);
    if (encoding === 'amnezia' || encoding === 'text') params.push(`encoding=${encodeURIComponent(encoding)}`);
    const qs = params.length ? `?${params.join('&')}` : '';
    const res = await fetch(`/api/wireguard/client/${clientId}/qrcode.svg${qs}`, {
      credentials: 'include',
    });
    if (!res.ok) throw new Error(res.statusText);
    const data = await res.json();
    if (encoding === 'amnezia') {
      if (!data.svgs || !Array.isArray(data.svgs)) throw new Error('Invalid QR response');
      return {
        svgs: data.svgs,
        payloads: Array.isArray(data.payloads) ? data.payloads : [],
      };
    }
    if (!data.svg || typeof data.payload !== 'string') throw new Error('Invalid QR response');
    return { svg: data.svg, payload: data.payload };
  }

  async getCheckUpdate() {
    return this.call({
      method: 'get',
      path: '/check-update',
    });
  }

  async getRelease() {
    return this.call({
      method: 'get',
      path: '/release',
    });
  }

  async getLang() {
    return this.call({
      method: 'get',
      path: '/lang',
    });
  }

  async getuiTrafficStats() {
    return this.call({
      method: 'get',
      path: '/ui-traffic-stats',
    });
  }

  async getChartType() {
    return this.call({
      method: 'get',
      path: '/ui-chart-type',
    });
  }

  async getSession() {
    return this.call({
      method: 'get',
      path: '/session',
    });
  }

  async createSession({ username, password }) {
    return this.call({
      method: 'post',
      path: '/session',
      body: { username, password },
    });
  }

  async deleteSession() {
    return this.call({
      method: 'delete',
      path: '/session',
    });
  }

  async changePassword({ password, passwordConfirm }) {
    return this.call({
      method: 'post',
      path: '/me/password',
      body: { password, passwordConfirm },
    });
  }

  async getClients() {
    return this.call({
      method: 'get',
      path: '/wireguard/client',
    }).then((res) => {
      const raw = res.clients;
      const list = Array.isArray(raw)
        ? raw
        : (raw && typeof raw === 'object' ? Object.values(raw) : []);
      const clients = list.map((client) => ({
        ...client,
        createdAt: new Date(client.createdAt),
        updatedAt: new Date(client.updatedAt),
        latestHandshakeAt: client.latestHandshakeAt !== null && client.latestHandshakeAt !== undefined
          ? new Date(client.latestHandshakeAt)
          : null,
        expiresAt: client.expiresAt !== null && client.expiresAt !== undefined
          ? new Date(client.expiresAt)
          : null,
      }));
      return { clients, serverCapabilities: res.serverCapabilities || {} };
    });
  }

  async createClient({ name }) {
    return this.call({
      method: 'post',
      path: '/wireguard/client',
      body: { name },
    });
  }

  async deleteClient({ clientId }) {
    return this.call({
      method: 'delete',
      path: `/wireguard/client/${clientId}`,
    });
  }

  async enableClient({ clientId }) {
    return this.call({
      method: 'post',
      path: `/wireguard/client/${clientId}/enable`,
    });
  }

  async disableClient({ clientId }) {
    return this.call({
      method: 'post',
      path: `/wireguard/client/${clientId}/disable`,
    });
  }

  async updateClientName({ clientId, name }) {
    return this.call({
      method: 'put',
      path: `/wireguard/client/${clientId}/name/`,
      body: { name },
    });
  }

  async updateClientAddress({ clientId, address }) {
    return this.call({
      method: 'put',
      path: `/wireguard/client/${clientId}/address/`,
      body: { address },
    });
  }

  async updateClientObfuscation({ clientId, profile, signature, level }) {
    return this.call({
      method: 'put',
      path: `/wireguard/client/${clientId}/obfuscation`,
      body: { profile, signature, level },
    });
  }

  async refreshClientSignature({ clientId }) {
    return this.call({
      method: 'post',
      path: `/wireguard/client/${clientId}/obfuscation/refresh`,
    });
  }

  async updateClientDns({ clientId, useServerDns }) {
    return this.call({
      method: 'put',
      path: `/wireguard/client/${clientId}/dns`,
      body: { useServerDns },
    });
  }

  async getAmneziaDnsStatus() {
    return this.call({ method: 'get', path: '/amnezia-dns' });
  }

  async getAmneziaDnsProfiles({ refresh = false } = {}) {
    const q = refresh ? '?refresh=1' : '';
    return this.call({ method: 'get', path: `/amnezia-dns/profiles${q}` });
  }

  async enableAmneziaDns({ profileId } = {}) {
    return this.call({
      method: 'post',
      path: '/amnezia-dns/enable',
      body: { profileId },
    });
  }

  async disableAmneziaDns() {
    return this.call({ method: 'post', path: '/amnezia-dns/disable' });
  }

  async forceCleanupAmneziaDns() {
    return this.call({ method: 'post', path: '/amnezia-dns/force-cleanup' });
  }

  async getRuleProfiles() {
    return this.call({ method: 'get', path: '/rule-profiles' });
  }

  async getRuleProfile(id) {
    return this.call({ method: 'get', path: `/rule-profiles/${id}` });
  }

  async createRuleProfile(body) {
    return this.call({ method: 'post', path: '/rule-profiles', body });
  }

  async updateRuleProfile(id, body) {
    return this.call({ method: 'put', path: `/rule-profiles/${id}`, body });
  }

  async deleteRuleProfile(id) {
    return this.call({ method: 'delete', path: `/rule-profiles/${id}` });
  }

  async createIpRule(body) {
    return this.call({ method: 'post', path: '/ip-rules', body });
  }

  async updateIpRule(id, body) {
    return this.call({ method: 'put', path: `/ip-rules/${id}`, body });
  }

  async deleteIpRule(id) {
    return this.call({ method: 'delete', path: `/ip-rules/${id}` });
  }

  async updateClientRuleProfile({ clientId, rule_profile_id }) {
    return this.call({
      method: 'put',
      path: `/wireguard/client/${clientId}/firewall-profile`,
      body: { rule_profile_id },
    });
  }

  async updateClientExpires({ clientId, expires_at }) {
    return this.call({
      method: 'put',
      path: `/wireguard/client/${clientId}/expires`,
      body: { expires_at },
    });
  }

  async getGlobalFirewallRules() {
    return this.call({ method: 'get', path: '/global-firewall-rules' });
  }

  async createGlobalFirewallRule(body) {
    return this.call({ method: 'post', path: '/global-firewall-rules', body });
  }

  async updateGlobalFirewallRule(id, body) {
    return this.call({ method: 'put', path: `/global-firewall-rules/${id}`, body });
  }

  async deleteGlobalFirewallRule(id) {
    return this.call({ method: 'delete', path: `/global-firewall-rules/${id}` });
  }

  async getSignaturesProfiles() {
    return this.call({ method: 'get', path: '/signatures/profiles' });
  }

  async getTrafficClient(clientId, period) {
    return this.call({
      method: 'get',
      path: `/traffic/client/${clientId}?period=${encodeURIComponent(period)}`,
    });
  }

  async getTrafficAggregate(period) {
    return this.call({
      method: 'get',
      path: `/traffic/aggregate?period=${encodeURIComponent(period)}`,
    });
  }

  async resetTrafficHistory(clientId) {
    return this.call({
      method: 'delete',
      path: `/traffic/client/${clientId}/history`,
    });
  }

}
