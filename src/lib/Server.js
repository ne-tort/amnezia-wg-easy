'use strict';

const { createServer } = require('node:http');
const { stat, readFile } = require('node:fs/promises');
const { resolve, sep } = require('node:path');

const expressSession = require('express-session');
const SqliteStore = require('better-sqlite3-session-store')(expressSession);
const debug = require('debug')('Server');

const {
  createApp,
  createError,
  createRouter,
  defineEventHandler,
  fromNodeMiddleware,
  getQuery,
  getRouterParam,
  toNodeListener,
  readBody,
  setHeader,
  serveStatic,
} = require('h3');

const db = require('./db');
const auth = require('./auth');
const WireGuard = require('./WireGuard');
const { isKnownProfile, getProfileIds, DEFAULT_PROFILE_ID } = require('./obfuscationProfiles');
const { runSignatureGeneration } = require('./signatures');
const { applyFirewall } = require('./firewall');
const {
  normalizeCidr,
  validateCidr,
  normalizePort,
  validatePort,
  normalizeProtocol,
  validateProtocol,
} = require('./firewall/validate');

const {
  PORT,
  WEBUI_HOST,
  RELEASE,
  SESSION_SECRET,
  WG_PERSISTENT_KEEPALIVE,
  WG_HOST,
  WG_PORT,
} = require('../config');

const APP_SETTINGS_DEFAULTS = {
  check_update: 'false',
  language: 'ru',
  ui_traffic_stats: 'false',
  ui_chart_type: '0',
  display_name: 'Amnezia WG-Easy',
};

module.exports = class Server {

  constructor() {
    db.getDb();
  }

  /**
   * Starts HTTP server (sessions, routes, listen).
   * Call only after admin exists; first-admin setup is done in server.js main().
   */
  async start() {
    const app = createApp();
    this.app = app;

    const sessionStore = new SqliteStore({ client: db.getDb() });
    app.use(fromNodeMiddleware(expressSession({
      store: sessionStore,
      secret: SESSION_SECRET,
      resave: false,
      saveUninitialized: false,
    })));

    const router = createRouter();
    app.use(router);

    router
      .get('/api/release', defineEventHandler((event) => {
        setHeader(event, 'Content-Type', 'application/json');
        return RELEASE;
      }))

      .get('/api/check-update', defineEventHandler((event) => {
        setHeader(event, 'Content-Type', 'application/json');
        return db.appSettings.get('check_update') ?? APP_SETTINGS_DEFAULTS.check_update;
      }))

      .get('/api/lang', defineEventHandler((event) => {
        setHeader(event, 'Content-Type', 'application/json');
        const lang = db.appSettings.get('language') ?? APP_SETTINGS_DEFAULTS.language;
        return `"${lang}"`;
      }))

      .get('/api/ui-traffic-stats', defineEventHandler((event) => {
        setHeader(event, 'Content-Type', 'application/json');
        return db.appSettings.get('ui_traffic_stats') ?? APP_SETTINGS_DEFAULTS.ui_traffic_stats;
      }))

      .get('/api/ui-chart-type', defineEventHandler((event) => {
        setHeader(event, 'Content-Type', 'application/json');
        return db.appSettings.get('ui_chart_type') ?? APP_SETTINGS_DEFAULTS.ui_chart_type;
      }))

      .get('/api/display-name', defineEventHandler((event) => {
        setHeader(event, 'Content-Type', 'application/json');
        const name = db.appSettings.get('display_name') ?? APP_SETTINGS_DEFAULTS.display_name;
        return `"${name}"`;
      }))

      .get('/api/session', defineEventHandler((event) => {
        const session = event.node.req.session;
        let authenticated = false;
        let role = null;
        if (session?.userId) {
          const user = db.panelUsers.findById(session.userId);
          if (user && user.is_active) {
            authenticated = true;
            role = user.role ?? null;
          }
        }
        return { authenticated, role };
      }))
      .post('/api/session', defineEventHandler(async (event) => {
        const body = await readBody(event);
        const username = typeof body.username === 'string' ? body.username.trim() : '';
        const password = typeof body.password === 'string' ? body.password : '';
        if (!username || !password) {
          throw createError({ status: 401, message: 'Missing: username or password' });
        }
        const user = db.panelUsers.findByUsername(username);
        if (!user) {
          throw createError({ status: 401, message: 'Incorrect username or password' });
        }
        const ok = await auth.verifyPassword(user.password_hash, password);
        if (!ok) {
          throw createError({ status: 401, message: 'Incorrect username or password' });
        }
        event.node.req.session.userId = user.id;
        event.node.req.session.role = user.role;
        event.node.req.session.authenticated = true;
        event.node.req.session.save();
        db.panelUsers.updateLastLogin(user.id, Math.floor(Date.now() / 1000));
        debug('Session: user %s', user.username);
        return { success: true, role: user.role };
      }));

    app.use(
      fromNodeMiddleware((req, res, next) => {
        if (!req.url.startsWith('/api/')) return next();
        const session = req.session;
        if (session?.userId) {
          const user = db.panelUsers.findById(session.userId);
          if (user && user.is_active) return next();
        }
        return res.status(401).json({ error: 'Not Logged In' });
      }),
    );

    function requireRoles(event, allowedRoles) {
      const role = event.node.req.session?.role;
      if (!role || !allowedRoles.includes(role)) {
        throw createError({ status: 403, message: 'Forbidden' });
      }
    }

    const router2 = createRouter();
    app.use(router2);

    router2
      .delete('/api/session', defineEventHandler((event) => {
        const sessionId = event.node.req.session.id;

        event.node.req.session.destroy();

        debug(`Deleted Session: ${sessionId}`);
        return { success: true };
      }))
      .get('/api/wireguard/client', defineEventHandler(() => WireGuard.getClients()))
      .get('/api/wireguard/client/:clientId/qrcode.svg', defineEventHandler(async (event) => {
        const clientId = getRouterParam(event, 'clientId');
        const query = getQuery(event);
        let level;
        if (query.level !== undefined) {
          const n = parseInt(query.level, 10);
          if (Number.isFinite(n) && n >= 0 && n <= 5) level = n;
        }
        let profile;
        if (query.profile !== undefined && isKnownProfile(query.profile)) profile = query.profile;
        const encoding = query.encoding === 'base64' ? 'base64' : 'text';
        const svg = await WireGuard.getClientQRCodeSVG({ clientId, level, profile, encoding });
        setHeader(event, 'Content-Type', 'image/svg+xml');
        return svg;
      }))
      .get('/api/wireguard/client/:clientId/configuration', defineEventHandler(async (event) => {
        const clientId = getRouterParam(event, 'clientId');
        const query = getQuery(event);
        let level;
        if (query.level !== undefined) {
          const n = parseInt(query.level, 10);
          if (Number.isFinite(n) && n >= 0 && n <= 5) level = n;
        }
        let profile;
        if (query.profile !== undefined && isKnownProfile(query.profile)) profile = query.profile;
        const client = await WireGuard.getClient({ clientId });
        const config = await WireGuard.getClientConfiguration({ clientId, level, profile });
        const serverRow = db.serverConfig.get();
        if (serverRow) {
          const now = Math.floor(Date.now() / 1000);
          const clientForAllowed = { id: clientId, ruleProfileId: client.ruleProfileId };
          db.clientConfigVersions.insert({
            client_id: clientId,
            created_at: now,
            private_key: client.privateKey,
            address: client.address,
            peer_public_key: serverRow.public_key,
            preshared_key: client.preSharedKey || null,
            allowed_ips: WireGuard.getAllowedIPsForClient(clientForAllowed),
            persistent_keepalive: WG_PERSISTENT_KEEPALIVE || '25',
            endpoint: db.appSettings.get('endpoint') || (WG_HOST && WG_PORT ? `${WG_HOST}:${WG_PORT}` : ''),
            config_raw: config,
            obfuscation_level: level != null ? level : null,
            obfuscation_profile: profile || null,
          });
        }
        const configName = client.name
          .replace(/[^a-zA-Z0-9_=+.-]/g, '-')
          .replace(/(-{2,}|-$)/g, '-')
          .replace(/-$/, '')
          .substring(0, 32);
        setHeader(event, 'Content-Disposition', `attachment; filename="${configName || clientId}.conf"`);
        setHeader(event, 'Content-Type', 'text/plain');
        return config;
      }))
      .get('/api/wireguard/client/:clientId/config-versions', defineEventHandler((event) => {
        const clientId = getRouterParam(event, 'clientId');
        const list = db.clientConfigVersions.getByClientId(clientId);
        return list.map((v) => ({ id: v.id, version: v.version, created_at: v.created_at }));
      }))
      .get('/api/wireguard/client/:clientId/config-versions/:versionId', defineEventHandler((event) => {
        const versionId = getRouterParam(event, 'versionId');
        const v = db.clientConfigVersions.getById(parseInt(versionId, 10));
        if (!v) throw createError({ status: 404, message: 'Version not found' });
        return {
          id: v.id,
          client_id: v.client_id,
          version: v.version,
          created_at: v.created_at,
          config_raw: v.config_raw,
        };
      }))
      .get('/api/wireguard/client/:clientId/config-versions/:versionId/download', defineEventHandler((event) => {
        const clientId = getRouterParam(event, 'clientId');
        const versionId = getRouterParam(event, 'versionId');
        const v = db.clientConfigVersions.getById(parseInt(versionId, 10));
        if (!v || v.client_id !== clientId) throw createError({ status: 404, message: 'Version not found' });
        const name = (db.clients.getById(clientId)?.name || clientId).replace(/[^a-zA-Z0-9_=+.-]/g, '-').substring(0, 32);
        setHeader(event, 'Content-Disposition', `attachment; filename="${name}-v${v.version}.conf"`);
        setHeader(event, 'Content-Type', 'text/plain');
        return v.config_raw || '';
      }))
      .post('/api/wireguard/client', defineEventHandler(async (event) => {
        requireRoles(event, ['admin', 'moderator']);
        const { name } = await readBody(event);
        await WireGuard.createClient({ name });
        return { success: true };
      }))
      .delete('/api/wireguard/client/:clientId', defineEventHandler(async (event) => {
        requireRoles(event, ['admin', 'moderator']);
        const clientId = getRouterParam(event, 'clientId');
        await WireGuard.deleteClient({ clientId });
        return { success: true };
      }))
      .post('/api/wireguard/client/:clientId/enable', defineEventHandler(async (event) => {
        requireRoles(event, ['admin', 'moderator']);
        const clientId = getRouterParam(event, 'clientId');
        if (clientId === '__proto__' || clientId === 'constructor' || clientId === 'prototype') {
          throw createError({ status: 403 });
        }
        await WireGuard.enableClient({ clientId });
        return { success: true };
      }))
      .post('/api/wireguard/client/:clientId/disable', defineEventHandler(async (event) => {
        requireRoles(event, ['admin', 'moderator']);
        const clientId = getRouterParam(event, 'clientId');
        if (clientId === '__proto__' || clientId === 'constructor' || clientId === 'prototype') {
          throw createError({ status: 403 });
        }
        await WireGuard.disableClient({ clientId });
        return { success: true };
      }))
      .put('/api/wireguard/client/:clientId/name', defineEventHandler(async (event) => {
        requireRoles(event, ['admin', 'moderator']);
        const clientId = getRouterParam(event, 'clientId');
        if (clientId === '__proto__' || clientId === 'constructor' || clientId === 'prototype') {
          throw createError({ status: 403 });
        }
        const { name } = await readBody(event);
        await WireGuard.updateClientName({ clientId, name });
        return { success: true };
      }))
      .put('/api/wireguard/client/:clientId/address', defineEventHandler(async (event) => {
        requireRoles(event, ['admin', 'moderator']);
        const clientId = getRouterParam(event, 'clientId');
        if (clientId === '__proto__' || clientId === 'constructor' || clientId === 'prototype') {
          throw createError({ status: 403 });
        }
        const { address } = await readBody(event);
        await WireGuard.updateClientAddress({ clientId, address });
        return { success: true };
      }))
      .put('/api/wireguard/client/:clientId/obfuscation', defineEventHandler(async (event) => {
        requireRoles(event, ['admin', 'moderator']);
        const clientId = getRouterParam(event, 'clientId');
        if (clientId === '__proto__' || clientId === 'constructor' || clientId === 'prototype') {
          throw createError({ status: 403 });
        }
        const body = await readBody(event);
        const profile = typeof body.profile === 'string' ? body.profile : undefined;
        const level = typeof body.level === 'number' ? body.level : (typeof body.level === 'string' ? parseInt(body.level, 10) : undefined);
        await WireGuard.updateClientObfuscation({ clientId, profile, level });
        return { success: true };
      }))
      .put('/api/wireguard/client/:clientId/firewall-profile', defineEventHandler(async (event) => {
        requireRoles(event, ['admin', 'moderator']);
        const clientId = getRouterParam(event, 'clientId');
        const body = await readBody(event);
        let ruleProfileId;
        if (body == null || body.rule_profile_id === undefined) {
          ruleProfileId = undefined;
        } else if (body.rule_profile_id === null || body.rule_profile_id === '') {
          ruleProfileId = null;
        } else {
          const raw = body.rule_profile_id;
          ruleProfileId = typeof raw === 'number' ? raw : parseInt(raw, 10);
          if (Number.isNaN(ruleProfileId) || ruleProfileId < 0) {
            throw createError({ status: 400, message: 'rule_profile_id must be a non-negative integer or null' });
          }
        }
        await WireGuard.updateClientRuleProfile({ clientId, ruleProfileId: ruleProfileId ?? null });
        return { success: true };
      }))
      .put('/api/wireguard/client/:clientId/expires', defineEventHandler(async (event) => {
        requireRoles(event, ['admin', 'moderator']);
        const clientId = getRouterParam(event, 'clientId');
        const body = await readBody(event);
        let expiresAt = null;
        if (body && body.expires_at !== undefined && body.expires_at !== null) {
          const v = body.expires_at;
          expiresAt = typeof v === 'number' ? v : (typeof v === 'string' ? Math.floor(new Date(v).getTime() / 1000) : null);
          if (Number.isNaN(expiresAt) || expiresAt < 0) expiresAt = null;
        }
        await WireGuard.updateClientExpires({ clientId, expiresAt });
        return { success: true };
      }))
      .get('/api/wireguard/client/:clientId/firewall-rules', defineEventHandler((event) => {
        requireRoles(event, ['admin', 'moderator']);
        const clientId = getRouterParam(event, 'clientId');
        const client = db.clients.getById(clientId);
        if (!client) throw createError({ status: 404, message: 'Client not found' });
        return db.clientFirewallRules.getByClientId(clientId);
      }))
      .post('/api/wireguard/client/:clientId/firewall-rules', defineEventHandler(async (event) => {
        requireRoles(event, ['admin', 'moderator']);
        const clientId = getRouterParam(event, 'clientId');
        const client = db.clients.getById(clientId);
        if (!client) throw createError({ status: 404, message: 'Client not found' });
        const body = await readBody(event);
        if (!body || body.action == null || !body.destination_cidr) {
          throw createError({ status: 400, message: 'action and destination_cidr required' });
        }
        if (body.action !== 'allow' && body.action !== 'deny') {
          throw createError({ status: 400, message: 'action must be allow or deny' });
        }
        const destination_cidr = normalizeCidr(body.destination_cidr);
        const vc = validateCidr(destination_cidr);
        if (!vc.ok) throw createError({ status: 400, message: vc.message });
        const port_range = normalizePort(body.port_range);
        const vp = validatePort(port_range);
        if (!vp.ok) throw createError({ status: 400, message: vp.message });
        const protocol = normalizeProtocol(body.protocol);
        const vpr = validateProtocol(protocol);
        if (!vpr.ok) throw createError({ status: 400, message: vpr.message });
        const nextSortOrder = db.clientFirewallRules.getMaxSortOrderForClient(clientId) + 1;
        const id = db.clientFirewallRules.create({
          client_id: clientId,
          action: body.action,
          destination_cidr,
          port_range,
          protocol,
          sort_order: nextSortOrder,
        });
        applyFirewall();
        return { id, success: true };
      }))
      .put('/api/wireguard/client/:clientId/firewall-rules/:id', defineEventHandler(async (event) => {
        requireRoles(event, ['admin', 'moderator']);
        const clientId = getRouterParam(event, 'clientId');
        const id = parseInt(getRouterParam(event, 'id'), 10);
        const client = db.clients.getById(clientId);
        if (!client) throw createError({ status: 404, message: 'Client not found' });
        const rule = db.clientFirewallRules.getById(id);
        if (!rule || rule.client_id !== clientId) throw createError({ status: 404, message: 'Rule not found' });
        const body = await readBody(event);
        if (!body || body.action == null || !body.destination_cidr) {
          throw createError({ status: 400, message: 'action and destination_cidr required' });
        }
        if (body.action !== 'allow' && body.action !== 'deny') {
          throw createError({ status: 400, message: 'action must be allow or deny' });
        }
        const destination_cidr = normalizeCidr(body.destination_cidr);
        const vc = validateCidr(destination_cidr);
        if (!vc.ok) throw createError({ status: 400, message: vc.message });
        const port_range = normalizePort(body.port_range);
        const vp = validatePort(port_range);
        if (!vp.ok) throw createError({ status: 400, message: vp.message });
        const protocol = normalizeProtocol(body.protocol);
        const vpr = validateProtocol(protocol);
        if (!vpr.ok) throw createError({ status: 400, message: vpr.message });
        db.clientFirewallRules.update(id, {
          action: body.action,
          destination_cidr,
          port_range,
          protocol,
          sort_order: body.sort_order !== undefined ? parseInt(body.sort_order, 10) : rule.sort_order,
        });
        applyFirewall();
        return { success: true };
      }))
      .delete('/api/wireguard/client/:clientId/firewall-rules/:id', defineEventHandler((event) => {
        requireRoles(event, ['admin', 'moderator']);
        const clientId = getRouterParam(event, 'clientId');
        const id = parseInt(getRouterParam(event, 'id'), 10);
        const client = db.clients.getById(clientId);
        if (!client) throw createError({ status: 404, message: 'Client not found' });
        const rule = db.clientFirewallRules.getById(id);
        if (!rule || rule.client_id !== clientId) throw createError({ status: 404, message: 'Rule not found' });
        db.clientFirewallRules.delete(id);
        applyFirewall();
        return { success: true };
      }))
      .get('/api/signatures/profiles', defineEventHandler(() => {
        return { profileIds: getProfileIds(), defaultProfile: DEFAULT_PROFILE_ID };
      }))
      .post('/api/signatures/regenerate', defineEventHandler((event) => {
        requireRoles(event, ['admin', 'moderator']);
        runSignatureGeneration();
        return { success: true, started: true, message: 'Regeneration started in background.' };
      }))
      .get('/api/rule-profiles', defineEventHandler(() => {
        return db.ruleProfiles.getAll();
      }))
      .get('/api/rule-profiles/:id', defineEventHandler((event) => {
        const id = parseInt(getRouterParam(event, 'id'), 10);
        const profile = db.ruleProfiles.getById(id);
        if (!profile) throw createError({ status: 404, message: 'Profile not found' });
        const rules = db.ipRules.getByProfileId(id);
        return { ...profile, rules };
      }))
      .post('/api/rule-profiles', defineEventHandler(async (event) => {
        requireRoles(event, ['admin', 'moderator']);
        const body = await readBody(event);
        if (!body || !body.name || typeof body.name !== 'string' || !body.name.trim()) {
          throw createError({ status: 400, message: 'name is required' });
        }
        const id = db.ruleProfiles.create({
          name: body.name.trim(),
          description: body.description != null ? String(body.description).trim() || null : null,
          sort_order: body.sort_order != null ? parseInt(body.sort_order, 10) : 10,
        });
        applyFirewall();
        return { id, success: true };
      }))
      .put('/api/rule-profiles/:id', defineEventHandler(async (event) => {
        requireRoles(event, ['admin', 'moderator']);
        const id = parseInt(getRouterParam(event, 'id'), 10);
        const profile = db.ruleProfiles.getById(id);
        if (!profile) throw createError({ status: 404, message: 'Profile not found' });
        const body = await readBody(event);
        if (!body) throw createError({ status: 400, message: 'body required' });
        const name = body.name != null ? String(body.name).trim() : profile.name;
        if (!name) throw createError({ status: 400, message: 'name cannot be empty' });
        db.ruleProfiles.update(id, {
          name,
          description: body.description !== undefined ? (String(body.description).trim() || null) : profile.description,
          sort_order: body.sort_order !== undefined ? parseInt(body.sort_order, 10) : profile.sort_order,
        });
        applyFirewall();
        return { success: true };
      }))
      .delete('/api/rule-profiles/:id', defineEventHandler((event) => {
        requireRoles(event, ['admin', 'moderator']);
        const id = parseInt(getRouterParam(event, 'id'), 10);
        if (id === 1) throw createError({ status: 403, message: 'Full Access profile cannot be deleted' });
        const profile = db.ruleProfiles.getById(id);
        if (!profile) throw createError({ status: 404, message: 'Profile not found' });
        const inUse = db.clientsCountByRuleProfileId(id);
        if (inUse > 0) throw createError({ status: 409, message: 'Profile is in use and cannot be deleted' });
        db.ruleProfiles.delete(id);
        applyFirewall();
        return { success: true };
      }))
      .post('/api/ip-rules', defineEventHandler(async (event) => {
        requireRoles(event, ['admin', 'moderator']);
        const body = await readBody(event);
        if (!body || body.rule_profile_id == null || body.action == null || !body.destination_cidr) {
          throw createError({ status: 400, message: 'rule_profile_id, action and destination_cidr required' });
        }
        if (body.action !== 'allow' && body.action !== 'deny') {
          throw createError({ status: 400, message: 'action must be allow or deny' });
        }
        const ruleProfileId = parseInt(body.rule_profile_id, 10);
        if (Number.isNaN(ruleProfileId) || !db.ruleProfiles.getById(ruleProfileId)) {
          throw createError({ status: 400, message: 'Invalid rule_profile_id' });
        }
        const destination_cidr = normalizeCidr(body.destination_cidr);
        const vc = validateCidr(destination_cidr);
        if (!vc.ok) throw createError({ status: 400, message: vc.message });
        const port_range = normalizePort(body.port_range);
        const vp = validatePort(port_range);
        if (!vp.ok) throw createError({ status: 400, message: vp.message });
        const protocol = normalizeProtocol(body.protocol);
        const vpr = validateProtocol(protocol);
        if (!vpr.ok) throw createError({ status: 400, message: vpr.message });
        const nextSortOrder = db.ipRules.getMaxSortOrderForProfile(ruleProfileId) + 1;
        const id = db.ipRules.create({
          rule_profile_id: ruleProfileId,
          action: body.action,
          destination_cidr,
          port_range,
          protocol,
          sort_order: nextSortOrder,
        });
        applyFirewall();
        return { id, success: true };
      }))
      .put('/api/ip-rules/:id', defineEventHandler(async (event) => {
        requireRoles(event, ['admin', 'moderator']);
        const id = parseInt(getRouterParam(event, 'id'), 10);
        const rule = db.ipRules.getById(id);
        if (!rule) throw createError({ status: 404, message: 'Rule not found' });
        const body = await readBody(event);
        if (!body || body.action == null || !body.destination_cidr) {
          throw createError({ status: 400, message: 'action and destination_cidr required' });
        }
        if (body.action !== 'allow' && body.action !== 'deny') {
          throw createError({ status: 400, message: 'action must be allow or deny' });
        }
        const destination_cidr = normalizeCidr(body.destination_cidr);
        const vc = validateCidr(destination_cidr);
        if (!vc.ok) throw createError({ status: 400, message: vc.message });
        const port_range = normalizePort(body.port_range);
        const vp = validatePort(port_range);
        if (!vp.ok) throw createError({ status: 400, message: vp.message });
        const protocol = normalizeProtocol(body.protocol);
        const vpr = validateProtocol(protocol);
        if (!vpr.ok) throw createError({ status: 400, message: vpr.message });
        db.ipRules.update(id, {
          action: body.action,
          destination_cidr,
          port_range,
          protocol,
          sort_order: body.sort_order ?? 0,
        });
        applyFirewall();
        return { success: true };
      }))
      .delete('/api/ip-rules/:id', defineEventHandler((event) => {
        requireRoles(event, ['admin', 'moderator']);
        const id = parseInt(getRouterParam(event, 'id'), 10);
        const rule = db.ipRules.getById(id);
        if (!rule) throw createError({ status: 404, message: 'Rule not found' });
        db.ipRules.delete(id);
        applyFirewall();
        return { success: true };
      }))
      .get('/api/global-firewall-rules', defineEventHandler(() => {
        return db.globalFirewallRules.getAll();
      }))
      .post('/api/global-firewall-rules', defineEventHandler(async (event) => {
        requireRoles(event, ['admin', 'moderator']);
        const body = await readBody(event);
        if (!body || body.action == null || !body.destination_cidr) {
          throw createError({ status: 400, message: 'action and destination_cidr required' });
        }
        if (body.action !== 'allow' && body.action !== 'deny') {
          throw createError({ status: 400, message: 'action must be allow or deny' });
        }
        const destination_cidr = normalizeCidr(body.destination_cidr);
        const vc = validateCidr(destination_cidr);
        if (!vc.ok) throw createError({ status: 400, message: vc.message });
        const port_range = normalizePort(body.port_range);
        const vp = validatePort(port_range);
        if (!vp.ok) throw createError({ status: 400, message: vp.message });
        const protocol = normalizeProtocol(body.protocol);
        const vpr = validateProtocol(protocol);
        if (!vpr.ok) throw createError({ status: 400, message: vpr.message });
        const nextSortOrder = db.globalFirewallRules.getMaxSortOrder() + 1;
        const id = db.globalFirewallRules.create({
          action: body.action,
          destination_cidr,
          port_range,
          protocol,
          sort_order: nextSortOrder,
        });
        applyFirewall();
        return { id, success: true };
      }))
      .put('/api/global-firewall-rules/:id', defineEventHandler(async (event) => {
        requireRoles(event, ['admin', 'moderator']);
        const id = parseInt(getRouterParam(event, 'id'), 10);
        const body = await readBody(event);
        if (!body || body.action == null || !body.destination_cidr) {
          throw createError({ status: 400, message: 'action and destination_cidr required' });
        }
        if (body.action !== 'allow' && body.action !== 'deny') {
          throw createError({ status: 400, message: 'action must be allow or deny' });
        }
        const destination_cidr = normalizeCidr(body.destination_cidr);
        const vc = validateCidr(destination_cidr);
        if (!vc.ok) throw createError({ status: 400, message: vc.message });
        const port_range = normalizePort(body.port_range);
        const vp = validatePort(port_range);
        if (!vp.ok) throw createError({ status: 400, message: vp.message });
        const protocol = normalizeProtocol(body.protocol);
        const vpr = validateProtocol(protocol);
        if (!vpr.ok) throw createError({ status: 400, message: vpr.message });
        db.globalFirewallRules.update(id, {
          action: body.action,
          destination_cidr,
          port_range,
          protocol,
          sort_order: body.sort_order ?? 0,
        });
        applyFirewall();
        return { success: true };
      }))
      .delete('/api/global-firewall-rules/:id', defineEventHandler((event) => {
        requireRoles(event, ['admin', 'moderator']);
        const id = parseInt(getRouterParam(event, 'id'), 10);
        db.globalFirewallRules.delete(id);
        applyFirewall();
        return { success: true };
      }))
      .get('/api/app-settings', defineEventHandler(() => {
        return db.appSettings.getAll();
      }))
      .put('/api/app-settings', defineEventHandler(async (event) => {
        requireRoles(event, ['admin']);
        const body = await readBody(event);
        if (body && typeof body.key === 'string') {
          db.appSettings.set(body.key, body.value);
          return { success: true };
        }
        if (body && typeof body.settings === 'object') {
          for (const [k, v] of Object.entries(body.settings)) {
            db.appSettings.set(k, v);
          }
          return { success: true };
        }
        throw createError({ status: 400, message: 'Bad request' });
      }))
      .get('/api/protocol-templates', defineEventHandler(() => {
        return db.protocolTemplates.getAll();
      }));

    const safePathJoin = (base, target) => {
      // Manage web root (edge case)
      if (target === '/') {
        return `${base}${sep}`;
      }

      // Prepend './' to prevent absolute paths
      const targetPath = `.${sep}${target}`;

      // Resolve the absolute path
      const resolvedPath = resolve(base, targetPath);

      // Check if resolvedPath is a subpath of base
      if (resolvedPath.startsWith(`${base}${sep}`)) {
        return resolvedPath;
      }

      throw createError({
        status: 400,
        message: 'Bad Request',
      });
    };

    // Static assets
    const publicDir = '/app/www';
    app.use(
      defineEventHandler((event) => {
        return serveStatic(event, {
          getContents: (id) => {
            return readFile(safePathJoin(publicDir, id));
          },
          getMeta: async (id) => {
            const filePath = safePathJoin(publicDir, id);

            const stats = await stat(filePath).catch(() => {});
            if (!stats || !stats.isFile()) {
              return;
            }

            if (id.endsWith('.html')) setHeader(event, 'Content-Type', 'text/html');
            if (id.endsWith('.js')) setHeader(event, 'Content-Type', 'application/javascript');
            if (id.endsWith('.json')) setHeader(event, 'Content-Type', 'application/json');
            if (id.endsWith('.css')) setHeader(event, 'Content-Type', 'text/css');
            if (id.endsWith('.png')) setHeader(event, 'Content-Type', 'image/png');
            if (id.endsWith('.svg')) setHeader(event, 'Content-Type', 'image/svg+xml');

            return {
              size: stats.size,
              mtime: stats.mtimeMs,
            };
          },
        });
      }),
    );

    const h3Listener = toNodeListener(app);
    const listener = (req, res) => {
      const out = h3Listener(req, res);
      if (out && typeof out.catch === 'function') {
        out.catch((err) => {
          if (res.headersSent) return;
          const code = err.statusCode ?? err.status ?? 500;
          res.writeHead(code, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: err.message || 'Internal Server Error' }));
        });
      }
    };
    createServer(listener).listen(PORT, WEBUI_HOST);
    debug(`Listening on http://${WEBUI_HOST}:${PORT}`);
  }

};
