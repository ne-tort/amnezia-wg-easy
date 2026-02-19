/* eslint-disable no-unused-vars */
/* eslint-disable no-undef */

'use strict';

class API {

  async call({ method, path, body }) {
    const res = await fetch(`./api${path}`, {
      method,
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json',
      },
      body: body
        ? JSON.stringify(body)
        : undefined,
    });

    if (res.status === 204) {
      return undefined;
    }

    const json = await res.json();

    if (!res.ok) {
      const msg = json.error || json.message || res.statusText;
      const err = new Error(msg);
      err.status = res.status;
      err.code = json.code;
      throw err;
    }

    return json;
  }

  async getConfiguration(clientId, level, profile) {
    const params = [];
    if (level !== undefined && level !== null) params.push(`level=${Number(level)}`);
    if (profile !== undefined && profile !== null && profile !== '') params.push(`profile=${encodeURIComponent(profile)}`);
    const qs = params.length ? `?${params.join('&')}` : '';
    const res = await fetch(`./api/wireguard/client/${clientId}/configuration${qs}`, {
      credentials: 'include',
    });
    if (!res.ok) throw new Error(res.statusText);
    return res.text();
  }

  /**
   * Fetches QR code SVG for client. When level/profile are passed, config is built with that obfuscation.
   * @param {string} clientId
   * @param {number} [level] 0–5 (I0–I5)
   * @param {string} [profile] quic, dns, sip
   * @returns {Promise<string>} SVG markup
   */
  async getClientQRCodeSVG(clientId, level, profile) {
    const params = [];
    if (level !== undefined && level !== null) params.push(`level=${Number(level)}`);
    if (profile !== undefined && profile !== null && profile !== '') params.push(`profile=${encodeURIComponent(profile)}`);
    const qs = params.length ? `?${params.join('&')}` : '';
    const res = await fetch(`./api/wireguard/client/${clientId}/qrcode.svg${qs}`, {
      credentials: 'include',
    });
    if (!res.ok) throw new Error(res.statusText);
    return res.text();
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

  async getClients() {
    return this.call({
      method: 'get',
      path: '/wireguard/client',
    }).then((clients) => clients.map((client) => ({
      ...client,
      createdAt: new Date(client.createdAt),
      updatedAt: new Date(client.updatedAt),
      latestHandshakeAt: client.latestHandshakeAt !== null && client.latestHandshakeAt !== undefined
        ? new Date(client.latestHandshakeAt)
        : null,
      expiresAt: client.expiresAt !== null && client.expiresAt !== undefined
        ? new Date(client.expiresAt)
        : null,
    })));
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

  async updateClientObfuscation({ clientId, profile, level }) {
    return this.call({
      method: 'put',
      path: `/wireguard/client/${clientId}/obfuscation`,
      body: { profile, level },
    });
  }

  async getRuleProfiles() {
    return this.call({ method: 'get', path: '/rule-profiles' });
  }

  async getRuleProfile(id) {
    return this.call({ method: 'get', path: `/rule-profiles/${id}` });
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

  async regenerateSignatures() {
    return this.call({ method: 'post', path: '/signatures/regenerate' });
  }

}
