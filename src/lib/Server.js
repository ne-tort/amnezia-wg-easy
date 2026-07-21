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
  getRequestURL,
  toNodeListener,
  readBody,
  setHeader,
  serveStatic,
} = require('h3');

const db = require('./db');
const auth = require('./auth');
const acl = require('./acl');
const roleLabels = require('./roleLabels');
const WireGuard = require('./WireGuard');
const {
  isKnownProfile,
  getProfileIds,
  DEFAULT_PROFILE_ID,
  getProfilesCatalog,
} = require('./obfuscationProfiles');
const { BankError } = require('./signaturesBank');
const amneziaDns = require('./amneziaDns');
const amneziaXray = require('./amneziaXray');
const amneziaMieru = require('./amneziaMieru');
const amneziaHysteria = require('./amneziaHysteria');
const amneziaNaive = require('./amneziaNaive');
const sniFinder = require('./sniFinder');
const mtuProfiles = require('./mtuProfiles');
const { applyFirewall } = require('./firewall');

/**
 * h3 strips bare `message` from JSON bodies; clients read statusMessage / data.error.
 * Keep statusMessage short (h3 may sanitize it); put the full text in data.error.
 */
function httpError(statusCode, message, code) {
  const shortByStatus = {
    400: 'Bad Request',
    401: 'Unauthorized',
    403: 'Forbidden',
    404: 'Not Found',
    409: 'Conflict',
    413: 'Payload Too Large',
    499: 'Client Closed Request',
    503: 'Service Unavailable',
    504: 'Gateway Timeout',
  };
  const data = { error: message };
  if (code) data.code = code;
  return createError({
    statusCode,
    statusMessage: shortByStatus[statusCode] || 'Error',
    message,
    data,
  });
}

function sniHttpError(err) {
  const status = (err && err.status) || 500;
  const code = (err && err.code) || undefined;
  const message = (err && err.message) || 'SNI finder error';
  return httpError(status, message, code);
}

function bankHttpError(err) {
  const message = (err && err.message) || 'signatures.json unavailable';
  const statusCode = (err && err.status) || 503;
  return httpError(statusCode, message);
}
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
  PANEL_HTTPS_PORT,
  PANEL_DOMAIN,
} = require('../config');
const { buildPanelPublicBaseUrl } = require('./panelPublicUrl');

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
  async start(options = {}) {
    this._listenPort = options.port;
    this._listenHost = options.host;
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
        const actor = acl.getActor(event);
        if (!actor) {
          return { authenticated: false, role: null, username: null, userId: null, capabilities: [] };
        }
        return {
          authenticated: true,
          role: actor.role,
          username: actor.username,
          userId: actor.id,
          capabilities: acl.capabilitiesForRole(actor.role),
          assigned_cidrs: actor.assigned_cidrs || [],
        };
      }))
      .post('/api/session', defineEventHandler(async (event) => {
        const body = (await readBody(event)) || {};
        const username = typeof body.username === 'string' ? body.username.trim() : '';
        const password = typeof body.password === 'string' ? body.password : '';
        if (!username || !password) {
          throw httpError(401, 'Missing: username or password');
        }
        const user = db.panelUsers.findByUsername(username);
        if (!user) {
          throw httpError(401, 'Incorrect username or password');
        }
        const ok = await auth.verifyPassword(user.password_hash, password);
        if (!ok) {
          throw httpError(401, 'Incorrect username or password');
        }
        event.node.req.session.userId = user.id;
        event.node.req.session.role = user.role;
        event.node.req.session.authenticated = true;
        event.node.req.session.save();
        db.panelUsers.updateLastLogin(user.id, Math.floor(Date.now() / 1000));
        debug('Session: user %s', user.username);
        return {
          success: true,
          role: user.role,
          username: user.username,
          userId: user.id,
          capabilities: acl.capabilitiesForRole(user.role),
        };
      }));

    app.use(
      defineEventHandler((event) => {
        const url = event.node.req.url || '';
        if (!url.startsWith('/api/')) return;
        const method = (event.node.req.method || 'GET').toUpperCase();
        const pathOnly = url.split('?')[0] || '';
        // Public endpoints (registered on the first router) — do not block.
        if (
          (pathOnly === '/api/session' && (method === 'GET' || method === 'POST'))
          || pathOnly === '/api/release'
          || pathOnly === '/api/check-update'
          || pathOnly === '/api/lang'
          || pathOnly === '/api/ui-traffic-stats'
          || pathOnly === '/api/ui-chart-type'
          || pathOnly === '/api/display-name'
        ) {
          return;
        }
        const session = event.node.req.session;
        if (session?.userId) {
          const user = db.panelUsers.findById(session.userId);
          if (user && user.is_active) {
            session.role = user.role;
            return;
          }
        }
        throw createError({ status: 401, message: 'Not Logged In' });
      }),
    );

    const router2 = createRouter();
    app.use(router2);

    router2
      .delete('/api/session', defineEventHandler((event) => {
        const sessionId = event.node.req.session.id;

        event.node.req.session.destroy();

        debug(`Deleted Session: ${sessionId}`);
        return { success: true };
      }))
      .post('/api/me/password', defineEventHandler(async (event) => {
        const actor = acl.requireActor(event);
        const body = await readBody(event);
        const password = typeof body.password === 'string' ? body.password : '';
        const passwordConfirm = typeof body.passwordConfirm === 'string' ? body.passwordConfirm : '';
        const minLen = 5;
        const maxLen = 256;
        if (password.length < minLen) {
          throw createError({
            status: 400,
            message: `Password must be at least ${minLen} characters`,
            data: { code: 'PASSWORD_TOO_SHORT' },
          });
        }
        if (password.length > maxLen) {
          throw createError({
            status: 400,
            message: `Password must be at most ${maxLen} characters`,
            data: { code: 'PASSWORD_TOO_LONG' },
          });
        }
        if (password !== passwordConfirm) {
          throw createError({
            status: 400,
            message: 'Passwords do not match',
            data: { code: 'PASSWORD_MISMATCH' },
          });
        }
        const password_hash = await auth.hashPassword(password);
        db.panelUsers.updatePasswordHash(actor.id, password_hash);
        return { success: true };
      }))
      .get('/api/users', defineEventHandler((event) => {
        acl.requireCapability(event, acl.CAP.USERS_READ);
        return db.panelUsers.list();
      }))
      .get('/api/users/password-targets', defineEventHandler((event) => {
        const actor = acl.requireActor(event);
        return acl.listPasswordTargets(actor);
      }))
      .get('/api/roles', defineEventHandler((event) => {
        acl.requireActor(event);
        const query = getQuery(event);
        const lang = typeof query.lang === 'string' ? query.lang : 'en';
        return roleLabels.getRoleLabels(lang);
      }))
      .post('/api/users/:id/password', defineEventHandler(async (event) => {
        const actor = acl.requireActor(event);
        const id = getRouterParam(event, 'id');
        const target = db.panelUsers.findById(id);
        if (!target) throw createError({ status: 404, message: 'User not found' });
        if (!acl.canChangePassword(actor, target)) {
          throw createError({ status: 403, message: 'Forbidden' });
        }
        const body = (await readBody(event)) || {};
        const password = typeof body.password === 'string' ? body.password : '';
        const passwordConfirm = typeof body.passwordConfirm === 'string' ? body.passwordConfirm : '';
        const minLen = 5;
        const maxLen = 256;
        if (password.length < minLen) {
          throw createError({
            status: 400,
            message: `Password must be at least ${minLen} characters`,
            data: { code: 'PASSWORD_TOO_SHORT' },
          });
        }
        if (password.length > maxLen) {
          throw createError({
            status: 400,
            message: `Password must be at most ${maxLen} characters`,
            data: { code: 'PASSWORD_TOO_LONG' },
          });
        }
        if (password !== passwordConfirm) {
          throw createError({
            status: 400,
            message: 'Passwords do not match',
            data: { code: 'PASSWORD_MISMATCH' },
          });
        }
        const password_hash = await auth.hashPassword(password);
        db.panelUsers.updatePasswordHash(id, password_hash);
        return { success: true };
      }))
      .post('/api/users', defineEventHandler(async (event) => {
        acl.requireCapability(event, acl.CAP.USERS_WRITE);
        const body = (await readBody(event)) || {};
        const username = typeof body.username === 'string' ? body.username.trim() : '';
        const password = typeof body.password === 'string' ? body.password : '';
        const role = typeof body.role === 'string' ? body.role.trim() : '';
        if (!username || !password) {
          throw createError({ status: 400, message: 'Missing username or password' });
        }
        if (!acl.isValidRole(role)) {
          throw createError({ status: 400, message: 'Invalid role' });
        }
        if (password.length < 5 || password.length > 256) {
          throw createError({ status: 400, message: 'Password must be 5–256 characters' });
        }
        let assignedCidrs;
        if (body.assigned_cidrs !== undefined) {
          const vpnAddress = require('./vpnAddress');
          const raw = Array.isArray(body.assigned_cidrs) ? body.assigned_cidrs : null;
          if (!raw) {
            throw createError({ status: 400, message: 'assigned_cidrs must be an array' });
          }
          const poolCidrs = db.vpnPools.list().map((p) => p.cidr);
          const validated = vpnAddress.validateAssignedCidrs(raw, poolCidrs);
          if (!validated.ok) {
            throw createError({ status: 400, message: validated.message });
          }
          assignedCidrs = validated.cidrs;
        }
        if (!assignedCidrs || !assignedCidrs.length) {
          throw createError({ status: 400, message: 'assigned_cidrs is required (at least one CIDR)' });
        }
        const now = Math.floor(Date.now() / 1000);
        const password_hash = await auth.hashPassword(password);
        const id = auth.generateUserId();
        try {
          db.panelUsers.create({
            id,
            username,
            password_hash,
            role,
            is_active: 1,
            created_at: now,
            updated_at: now,
          });
        } catch (err) {
          if (err.code === 'USERNAME_EXISTS') {
            throw createError({ status: 409, message: 'Username already exists', data: { code: 'USERNAME_EXISTS' } });
          }
          throw err;
        }
        db.panelUsers.update(id, { assigned_cidrs: assignedCidrs });
        event.node.res.statusCode = 201;
        return db.panelUsers.findByIdPublic(id);
      }))
      .get('/api/users/:id', defineEventHandler((event) => {
        acl.requireCapability(event, acl.CAP.USERS_READ);
        const id = getRouterParam(event, 'id');
        const user = db.panelUsers.findByIdPublic(id);
        if (!user) throw createError({ status: 404, message: 'User not found' });
        return user;
      }))
      .patch('/api/users/:id', defineEventHandler(async (event) => {
        acl.requireCapability(event, acl.CAP.USERS_WRITE);
        const id = getRouterParam(event, 'id');
        const target = db.panelUsers.findById(id);
        if (!target) throw createError({ status: 404, message: 'User not found' });
        const body = (await readBody(event)) || {};
        const fields = {};
        if (body.role !== undefined) {
          if (!acl.isValidRole(body.role)) {
            throw createError({ status: 400, message: 'Invalid role' });
          }
          fields.role = body.role;
        }
        if (body.is_active !== undefined) {
          fields.is_active = !!body.is_active;
        }
        if (body.password !== undefined) {
          const password = typeof body.password === 'string' ? body.password : '';
          if (password.length < 5 || password.length > 256) {
            throw createError({ status: 400, message: 'Password must be 5–256 characters' });
          }
          fields.password_hash = await auth.hashPassword(password);
        }
        if (body.assigned_cidrs !== undefined) {
          const vpnAddress = require('./vpnAddress');
          const raw = Array.isArray(body.assigned_cidrs) ? body.assigned_cidrs : null;
          if (!raw) {
            throw createError({ status: 400, message: 'assigned_cidrs must be an array' });
          }
          const poolCidrs = db.vpnPools.list().map((p) => p.cidr);
          const validated = vpnAddress.validateAssignedCidrs(raw, poolCidrs);
          if (!validated.ok) {
            throw createError({ status: 400, message: validated.message });
          }
          fields.assigned_cidrs = validated.cidrs;
        }
        const inv = acl.validateAdminInvariant(
          target,
          fields.role,
          fields.is_active !== undefined ? fields.is_active : undefined,
        );
        if (!inv.ok) throw createError({ status: 400, message: inv.message });
        const updated = db.panelUsers.update(id, fields);
        if (fields.is_active === false || fields.is_active === 0) {
          db.panelUsers.destroySessions(id);
        }
        return updated;
      }))
      .delete('/api/users/:id', defineEventHandler((event) => {
        acl.requireCapability(event, acl.CAP.USERS_WRITE);
        const id = getRouterParam(event, 'id');
        const target = db.panelUsers.findById(id);
        if (!target) throw createError({ status: 404, message: 'User not found' });
        const inv = acl.validateAdminInvariant(target, target.role, 0);
        if (!inv.ok) throw createError({ status: 400, message: inv.message });
        db.panelUsers.deactivate(id);
        db.panelUsers.destroySessions(id);
        return { success: true };
      }))
      .get('/api/vpn-pools', defineEventHandler((event) => {
        acl.requireCapability(event, acl.CAP.SYSTEM_SETTINGS);
        const pools = db.vpnPools.list().map((p) => ({
          ...p,
          userIds: db.vpnPools.listUserIds(p.id),
        }));
        return { pools };
      }))
      .post('/api/vpn-pools', defineEventHandler(async (event) => {
        acl.requireCapability(event, acl.CAP.SYSTEM_SETTINGS);
        const body = (await readBody(event)) || {};
        try {
          const pool = db.vpnPools.create({
            name: body.name,
            cidr: body.cidr,
            gateway: body.gateway,
            sort_order: body.sort_order,
          });
          try {
            await WireGuard.saveConfig();
          } catch {
            /* conf may be unavailable in tests */
          }
          event.node.res.statusCode = 201;
          return { ...pool, userIds: [] };
        } catch (err) {
          if (err.code === 'INVALID_CIDR' || err.code === 'INVALID_GATEWAY' || err.code === 'INVALID_NAME' || err.code === 'GATEWAY_EXISTS') {
            throw createError({ status: 400, message: err.message });
          }
          if (err.code === 'POOL_EXISTS') {
            throw createError({ status: 409, message: err.message });
          }
          throw err;
        }
      }))
      .put('/api/vpn-pools/:id', defineEventHandler(async (event) => {
        acl.requireCapability(event, acl.CAP.SYSTEM_SETTINGS);
        const id = parseInt(getRouterParam(event, 'id'), 10);
        if (!Number.isInteger(id)) {
          throw createError({ status: 400, message: 'Invalid pool id' });
        }
        const body = (await readBody(event)) || {};
        try {
          const pool = db.vpnPools.update(id, {
            name: body.name,
            cidr: body.cidr,
            gateway: body.gateway,
            sort_order: body.sort_order,
          });
          if (!pool) throw createError({ status: 404, message: 'Pool not found' });
          try {
            await WireGuard.saveConfig();
          } catch {
            /* */
          }
          return { ...pool, userIds: db.vpnPools.listUserIds(pool.id) };
        } catch (err) {
          if (err.statusCode) throw err;
          if (err.code === 'INVALID_CIDR' || err.code === 'INVALID_GATEWAY' || err.code === 'INVALID_NAME' || err.code === 'GATEWAY_EXISTS') {
            throw createError({ status: 400, message: err.message });
          }
          if (err.code === 'POOL_EXISTS') {
            throw createError({ status: 409, message: err.message });
          }
          throw err;
        }
      }))
      .patch('/api/vpn-pools/:id', defineEventHandler(async (event) => {
        // Alias of PUT (older clients / proxies); same handler body via re-dispatch is awkward — duplicate call.
        acl.requireCapability(event, acl.CAP.SYSTEM_SETTINGS);
        const id = parseInt(getRouterParam(event, 'id'), 10);
        if (!Number.isInteger(id)) {
          throw createError({ status: 400, message: 'Invalid pool id' });
        }
        const body = (await readBody(event)) || {};
        try {
          const pool = db.vpnPools.update(id, {
            name: body.name,
            cidr: body.cidr,
            gateway: body.gateway,
            sort_order: body.sort_order,
          });
          if (!pool) throw createError({ status: 404, message: 'Pool not found' });
          try {
            await WireGuard.saveConfig();
          } catch {
            /* */
          }
          return { ...pool, userIds: db.vpnPools.listUserIds(pool.id) };
        } catch (err) {
          if (err.statusCode) throw err;
          if (err.code === 'INVALID_CIDR' || err.code === 'INVALID_GATEWAY' || err.code === 'INVALID_NAME' || err.code === 'GATEWAY_EXISTS') {
            throw createError({ status: 400, message: err.message });
          }
          if (err.code === 'POOL_EXISTS') {
            throw createError({ status: 409, message: err.message });
          }
          throw err;
        }
      }))
      .put('/api/vpn-pools/:id/users', defineEventHandler(async (event) => {
        acl.requireCapability(event, acl.CAP.SYSTEM_SETTINGS);
        const id = parseInt(getRouterParam(event, 'id'), 10);
        if (!Number.isInteger(id)) {
          throw createError({ status: 400, message: 'Invalid pool id' });
        }
        if (!db.vpnPools.getById(id)) {
          throw createError({ status: 404, message: 'Pool not found' });
        }
        const body = (await readBody(event)) || {};
        if (!Array.isArray(body.userIds)) {
          throw createError({ status: 400, message: 'userIds must be an array' });
        }
        return db.vpnPools.setUsers(id, body.userIds);
      }))
      .delete('/api/vpn-pools/:id', defineEventHandler(async (event) => {
        acl.requireCapability(event, acl.CAP.SYSTEM_SETTINGS);
        const id = parseInt(getRouterParam(event, 'id'), 10);
        if (!Number.isInteger(id)) {
          throw createError({ status: 400, message: 'Invalid pool id' });
        }
        const deleted = db.vpnPools.delete(id);
        if (!deleted) throw createError({ status: 404, message: 'Pool not found' });
        try {
          await WireGuard.saveConfig();
        } catch {
          /* */
        }
        return { success: true };
      }))
      .get('/api/wireguard/client', defineEventHandler(async (event) => {
        const actor = acl.requireActor(event);
        const payload = await WireGuard.getClients();
        const clients = acl.enrichClientsWithUsers(
          acl.filterClientsForActor(actor, payload.clients || []),
        );
        return { ...payload, clients };
      }))
      .get('/api/wireguard/client/:clientId/qrcode.svg', defineEventHandler(async (event) => {
        const clientId = getRouterParam(event, 'clientId');
        acl.assertClientAccess(event, clientId);
        const query = getQuery(event);
        let level;
        if (query.level !== undefined) {
          const n = parseInt(query.level, 10);
          if (Number.isFinite(n) && n >= 0 && n <= 5) level = n;
        }
        let profile;
        if (query.profile !== undefined && isKnownProfile(query.profile)) profile = query.profile;
        let signature;
        if (query.signature !== undefined && query.signature !== '') signature = String(query.signature);
        try {
          if (query.encoding === 'amnezia') {
            const { svgs, payloads, iLimit } = await WireGuard.getClientAmneziaQRCodeSvgs({
              clientId, level, profile, signature,
            });
            setHeader(event, 'Content-Type', 'application/json');
            return JSON.stringify({ svgs, payloads, chunkCount: svgs.length, iLimit });
          }
          const { svg, payload, iLimit } = await WireGuard.getClientQRCodeSVG({
            clientId, level, profile, signature,
          });
          setHeader(event, 'Content-Type', 'application/json');
          return JSON.stringify({ svg, payload, iLimit });
        } catch (err) {
          const code = (err && (err.statusCode || err.status)) || 500;
          throw httpError(code, (err && err.message) || 'QR generation failed');
        }
      }))
      .get('/api/wireguard/client/:clientId/configuration', defineEventHandler(async (event) => {
        const clientId = getRouterParam(event, 'clientId');
        acl.assertClientAccess(event, clientId);
        const query = getQuery(event);
        let level;
        if (query.level !== undefined) {
          const n = parseInt(query.level, 10);
          if (Number.isFinite(n) && n >= 0 && n <= 5) level = n;
        }
        let profile;
        if (query.profile !== undefined && isKnownProfile(query.profile)) profile = query.profile;
        let signature;
        if (query.signature !== undefined && query.signature !== '') signature = String(query.signature);
        const amneziaExport =
          query.format === 'amnezia' || query.format === 'vpn';
        const client = await WireGuard.getClient({ clientId });
        const config = await WireGuard.getClientConfiguration({ clientId, level, profile, signature });
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
            endpoint: await WireGuard.getResolvedClientEndpointLine(),
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
        if (amneziaExport) {
          const vpnText = await WireGuard.getClientAmneziaVpnExport({ clientId, level, profile, signature });
          setHeader(
            event,
            'Content-Disposition',
            `attachment; filename="${configName || clientId}.vpn"`,
          );
          setHeader(event, 'Content-Type', 'text/plain; charset=utf-8');
          return vpnText;
        }
        setHeader(event, 'Content-Disposition', `attachment; filename="${configName || clientId}.conf"`);
        setHeader(event, 'Content-Type', 'text/plain');
        return config;
      }))
      .get('/api/wireguard/client/:clientId/config-versions', defineEventHandler((event) => {
        const clientId = getRouterParam(event, 'clientId');
        acl.assertClientAccess(event, clientId);
        const list = db.clientConfigVersions.getByClientId(clientId);
        return list.map((v) => ({ id: v.id, version: v.version, created_at: v.created_at }));
      }))
      .get('/api/wireguard/client/:clientId/config-versions/:versionId', defineEventHandler(async (event) => {
        const clientId = getRouterParam(event, 'clientId');
        acl.assertClientAccess(event, clientId);
        const versionId = getRouterParam(event, 'versionId');
        const v = db.clientConfigVersions.getById(parseInt(versionId, 10));
        if (!v || v.client_id !== clientId) throw createError({ status: 404, message: 'Version not found' });
        const config_raw = await WireGuard.rewriteIniEndpointForClientExport(v.config_raw || '');
        return {
          id: v.id,
          client_id: v.client_id,
          version: v.version,
          created_at: v.created_at,
          config_raw,
        };
      }))
      .get('/api/wireguard/client/:clientId/config-versions/:versionId/download', defineEventHandler(async (event) => {
        const clientId = getRouterParam(event, 'clientId');
        acl.assertClientAccess(event, clientId);
        const versionId = getRouterParam(event, 'versionId');
        const query = getQuery(event);
        const amneziaExport =
          query.format === 'amnezia' || query.format === 'vpn';
        const v = db.clientConfigVersions.getById(parseInt(versionId, 10));
        if (!v || v.client_id !== clientId) throw createError({ status: 404, message: 'Version not found' });
        const name = (db.clients.getById(clientId)?.name || clientId).replace(/[^a-zA-Z0-9_=+.-]/g, '-').substring(0, 32);
        if (amneziaExport) {
          const vpnText = await WireGuard.buildAmneziaVpnFromIni(v.config_raw || '', clientId);
          setHeader(
            event,
            'Content-Disposition',
            `attachment; filename="${name}-v${v.version}.vpn"`,
          );
          setHeader(event, 'Content-Type', 'text/plain; charset=utf-8');
          return vpnText;
        }
        setHeader(event, 'Content-Disposition', `attachment; filename="${name}-v${v.version}.conf"`);
        setHeader(event, 'Content-Type', 'text/plain');
        return await WireGuard.rewriteIniEndpointForClientExport(v.config_raw || '');
      }))
      .post('/api/wireguard/client', defineEventHandler(async (event) => {
        const actor = acl.requireCapability(event, acl.CAP.CLIENTS_WRITE);
        const body = (await readBody(event)) || {};
        const name = body.name;
        if (actor.role === 'user' && Array.isArray(body.userIds) && body.userIds.length > 0) {
          throw createError({ status: 403, message: 'Forbidden' });
        }
        const addressRanges = acl.getAddressRangesForActor(actor);
        if (!addressRanges.length) {
          throw createError({ status: 400, message: 'No VPN CIDRs assigned to this user' });
        }
        let created;
        try {
          created = await WireGuard.createClient({
            name,
            createdBy: actor.id,
            addressRanges,
          });
        } catch (err) {
          if (err instanceof BankError || err.name === 'BankError') {
            throw bankHttpError(err);
          }
          if (err && err.statusCode) {
            throw createError({
              status: err.statusCode,
              message: err.message,
              data: err.statusCode === 409 ? { code: 'CLIENT_NAME_EXISTS' } : undefined,
            });
          }
          throw err;
        }
        const id = created && created.id;
        if (id) {
          if (actor.role === 'user') {
            db.clientPanelUsers.assign(id, actor.id);
          } else if (Array.isArray(body.userIds)) {
            acl.setClientUsers(id, body.userIds);
          }
        }
        return { success: true, id, client: created };
      }))
      .get('/api/wireguard/client/:clientId/users', defineEventHandler((event) => {
        const clientId = getRouterParam(event, 'clientId');
        acl.assertClientAccess(event, clientId);
        return acl.listAssigneeUsers(clientId);
      }))
      .put('/api/wireguard/client/:clientId/users', defineEventHandler(async (event) => {
        acl.requireCapability(event, acl.CAP.CLIENTS_ASSIGN);
        const clientId = getRouterParam(event, 'clientId');
        if (!db.clients.getById(clientId)) {
          throw createError({ status: 404, message: 'Client not found' });
        }
        const body = (await readBody(event)) || {};
        if (!Array.isArray(body.userIds)) {
          throw createError({ status: 400, message: 'userIds must be an array' });
        }
        return acl.setClientUsers(clientId, body.userIds);
      }))
      .delete('/api/wireguard/client/:clientId', defineEventHandler(async (event) => {
        acl.requireCapability(event, acl.CAP.CLIENTS_WRITE);
        const clientId = getRouterParam(event, 'clientId');
        acl.assertClientAccess(event, clientId);
        await WireGuard.deleteClient({ clientId });
        return { success: true };
      }))
      .post('/api/wireguard/client/:clientId/enable', defineEventHandler(async (event) => {
        acl.requireCapability(event, acl.CAP.CLIENTS_WRITE);
        const clientId = getRouterParam(event, 'clientId');
        acl.assertClientAccess(event, clientId);
        try {
          await WireGuard.enableClient({ clientId });
        } catch (err) {
          if (err && err.statusCode) {
            throw createError({ status: err.statusCode, message: err.message });
          }
          throw err;
        }
        return { success: true };
      }))
      .post('/api/wireguard/client/:clientId/disable', defineEventHandler(async (event) => {
        acl.requireCapability(event, acl.CAP.CLIENTS_WRITE);
        const clientId = getRouterParam(event, 'clientId');
        acl.assertClientAccess(event, clientId);
        await WireGuard.disableClient({ clientId });
        return { success: true };
      }))
      .put('/api/wireguard/client/:clientId/name', defineEventHandler(async (event) => {
        acl.requireCapability(event, acl.CAP.CLIENTS_WRITE);
        const clientId = getRouterParam(event, 'clientId');
        acl.assertClientAccess(event, clientId);
        const { name } = await readBody(event);
        try {
          await WireGuard.updateClientName({ clientId, name });
        } catch (err) {
          if (err && err.statusCode) {
            throw createError({
              status: err.statusCode,
              message: err.message,
              data: err.statusCode === 409 ? { code: 'CLIENT_NAME_EXISTS' } : undefined,
            });
          }
          throw err;
        }
        return { success: true };
      }))
      .put('/api/wireguard/client/:clientId/address', defineEventHandler(async (event) => {
        const actor = acl.requireCapability(event, acl.CAP.CLIENTS_WRITE);
        const clientId = getRouterParam(event, 'clientId');
        acl.assertClientAccess(event, clientId);
        const { address } = await readBody(event);
        const opts = {
          clientId,
          address,
          allowedRanges: acl.getAddressRangesForActor(actor),
        };
        try {
          await WireGuard.updateClientAddress(opts);
        } catch (err) {
          if (err && err.statusCode) {
            throw createError({ status: err.statusCode, message: err.message });
          }
          throw err;
        }
        return { success: true };
      }))
      .get('/api/wireguard/client/:clientId/obfuscation', defineEventHandler(async (event) => {
        acl.requireCapability(event, acl.CAP.CLIENTS_WRITE);
        const clientId = getRouterParam(event, 'clientId');
        acl.assertClientAccess(event, clientId);
        try {
          return await WireGuard.getClientObfuscation({ clientId });
        } catch (err) {
          if (err instanceof BankError || err.name === 'BankError') {
            throw bankHttpError(err);
          }
          throw err;
        }
      }))
      .post('/api/wireguard/client/:clientId/obfuscation/preview', defineEventHandler(async (event) => {
        acl.requireCapability(event, acl.CAP.CLIENTS_WRITE);
        const clientId = getRouterParam(event, 'clientId');
        acl.assertClientAccess(event, clientId);
        try {
          const body = (await readBody(event)) || {};
          const profile = typeof body.profile === 'string' ? body.profile : undefined;
          const signature = body.signature != null ? String(body.signature) : undefined;
          const level = typeof body.level === 'number' ? body.level
            : (typeof body.level === 'string' ? parseInt(body.level, 10) : undefined);
          const result = await WireGuard.previewClientObfuscation({
            clientId,
            profile,
            signature,
            level,
            refreshSignature: body.refreshSignature === true || body.action === 'refresh',
            regenerateJunk: body.regenerateJunk === true || body.action === 'junk',
          });
          return { success: true, ...result };
        } catch (err) {
          if (err instanceof BankError || err.name === 'BankError') {
            throw bankHttpError(err);
          }
          throw err;
        }
      }))
      .post('/api/wireguard/client/:clientId/obfuscation/apply', defineEventHandler(async (event) => {
        acl.requireCapability(event, acl.CAP.CLIENTS_WRITE);
        const clientId = getRouterParam(event, 'clientId');
        acl.assertClientAccess(event, clientId);
        try {
          const body = (await readBody(event)) || {};
          const profile = typeof body.profile === 'string' ? body.profile : undefined;
          const signature = body.signature != null ? String(body.signature) : undefined;
          const level = typeof body.level === 'number' ? body.level
            : (typeof body.level === 'string' ? parseInt(body.level, 10) : undefined);
          const mtuProfile = body.mtuProfile != null ? body.mtuProfile
            : (body.profileId != null ? body.profileId : undefined);
          const result = await WireGuard.applyClientObfuscation({
            clientId,
            profile,
            signature,
            level,
            junk: body.junk,
            mtuProfile,
          });
          return { success: true, ...result };
        } catch (err) {
          if (err instanceof BankError || err.name === 'BankError') {
            throw bankHttpError(err);
          }
          throw err;
        }
      }))
      // Legacy immediate-write endpoints (prefer preview + apply).
      .put('/api/wireguard/client/:clientId/obfuscation', defineEventHandler(async (event) => {
        acl.requireCapability(event, acl.CAP.CLIENTS_WRITE);
        const clientId = getRouterParam(event, 'clientId');
        acl.assertClientAccess(event, clientId);
        try {
          const body = await readBody(event);
          const profile = typeof body.profile === 'string' ? body.profile : undefined;
          const signature = body.signature != null ? String(body.signature) : undefined;
          const level = typeof body.level === 'number' ? body.level : (typeof body.level === 'string' ? parseInt(body.level, 10) : undefined);
          const result = await WireGuard.updateClientObfuscation({ clientId, profile, signature, level });
          return { success: true, ...result };
        } catch (err) {
          if (err instanceof BankError || err.name === 'BankError') {
            throw bankHttpError(err);
          }
          throw err;
        }
      }))
      .post('/api/wireguard/client/:clientId/obfuscation/refresh', defineEventHandler(async (event) => {
        acl.requireCapability(event, acl.CAP.CLIENTS_WRITE);
        const clientId = getRouterParam(event, 'clientId');
        acl.assertClientAccess(event, clientId);
        try {
          const result = await WireGuard.refreshClientSignature({ clientId });
          return { success: true, ...result };
        } catch (err) {
          if (err instanceof BankError || err.name === 'BankError') {
            throw bankHttpError(err);
          }
          throw err;
        }
      }))
      .get('/api/mtu-profiles', defineEventHandler((event) => {
        acl.requireCapability(event, acl.CAP.CLIENTS_WRITE);
        try {
          return mtuProfiles.getCatalog();
        } catch (err) {
          throw httpError(err.status || 500, err.message || 'MTU profiles unavailable');
        }
      }))
      .put('/api/wireguard/client/:clientId/mtu', defineEventHandler(async (event) => {
        acl.requireCapability(event, acl.CAP.CLIENTS_WRITE);
        const clientId = getRouterParam(event, 'clientId');
        acl.assertClientAccess(event, clientId);
        const body = (await readBody(event)) || {};
        const profileId = body.profileId != null ? body.profileId : body.mtuProfile;
        const result = await WireGuard.updateClientMtu({ clientId, profileId });
        return { success: true, ...result };
      }))
      .put('/api/wireguard/client/:clientId/dns', defineEventHandler(async (event) => {
        acl.requireCapability(event, acl.CAP.CLIENTS_WRITE);
        const clientId = getRouterParam(event, 'clientId');
        acl.assertClientAccess(event, clientId);
        if (!amneziaDns.isAmneziaDnsAvailable()) {
          throw httpError(503, 'Amnezia DNS is not running');
        }
        const body = await readBody(event);
        const useServerDns = body.useServerDns === true;
        await WireGuard.updateClientDns({ clientId, useServerDns });
        return { success: true };
      }))
      .get('/api/ssl/certs', defineEventHandler(async (event) => {
        acl.requireCapability(event, acl.CAP.SYSTEM_SETTINGS);
        const sslManager = require('./sslManager');
        try {
          return await sslManager.list();
        } catch (err) {
          if (err && err.status) throw httpError(err.status, err.message);
          throw httpError(500, err.message || 'SSL list failed');
        }
      }))
      .get('/api/panel/settings', defineEventHandler(async (event) => {
        acl.requireCapability(event, acl.CAP.SYSTEM_SETTINGS);
        try {
          return await require('./panelSettings').getSettings();
        } catch (err) {
          if (err && err.status) throw httpError(err.status, err.message);
          throw httpError(500, err.message || 'Panel settings read failed');
        }
      }))
      .post('/api/panel/settings', defineEventHandler(async (event) => {
        acl.requireCapability(event, acl.CAP.SYSTEM_SETTINGS);
        try {
          const body = await readBody(event).catch(() => ({}));
          return await require('./panelSettings').applySettings(body || {});
        } catch (err) {
          if (err && err.status) throw httpError(err.status, err.message);
          throw httpError(500, err.message || 'Panel settings apply failed');
        }
      }))
      .get('/api/ssl/certs/:id', defineEventHandler(async (event) => {
        acl.requireCapability(event, acl.CAP.SYSTEM_SETTINGS);
        const sslManager = require('./sslManager');
        try {
          const id = getRouterParam(event, 'id');
          return await sslManager.get(id, { includeSecrets: true });
        } catch (err) {
          if (err && err.status) throw httpError(err.status, err.message);
          throw httpError(500, err.message || 'SSL get failed');
        }
      }))
      .post('/api/ssl/certs/self-signed', defineEventHandler(async (event) => {
        acl.requireCapability(event, acl.CAP.SYSTEM_SETTINGS);
        const sslManager = require('./sslManager');
        try {
          const body = await readBody(event).catch(() => ({}));
          return { success: true, cert: await sslManager.createSelfSigned(body || {}) };
        } catch (err) {
          if (err && err.status) throw httpError(err.status, err.message);
          throw httpError(500, err.message || 'Self-signed issue failed');
        }
      }))
      .post('/api/ssl/certs/lets-encrypt', defineEventHandler(async (event) => {
        acl.requireCapability(event, acl.CAP.SYSTEM_SETTINGS);
        const sslManager = require('./sslManager');
        try {
          const body = await readBody(event).catch(() => ({}));
          return { success: true, cert: await sslManager.createLetsEncrypt(body || {}) };
        } catch (err) {
          if (err && err.status) throw httpError(err.status, err.message);
          throw httpError(500, err.message || 'Let\'s Encrypt issue failed');
        }
      }))
      .post('/api/ssl/certs/reality', defineEventHandler(async (event) => {
        acl.requireCapability(event, acl.CAP.SYSTEM_SETTINGS);
        const sslManager = require('./sslManager');
        try {
          const body = await readBody(event).catch(() => ({}));
          return { success: true, cert: await sslManager.createReality(body || {}) };
        } catch (err) {
          if (err && err.status) throw httpError(err.status, err.message);
          throw httpError(500, err.message || 'Reality keys generation failed');
        }
      }))
      .post('/api/ssl/certs/masquerade', defineEventHandler(async (event) => {
        acl.requireCapability(event, acl.CAP.SYSTEM_SETTINGS);
        const sslManager = require('./sslManager');
        try {
          const body = await readBody(event).catch(() => ({}));
          return { success: true, cert: await sslManager.createMasquerade(body || {}) };
        } catch (err) {
          if (err && err.status) throw httpError(err.status, err.message);
          throw httpError(500, err.message || 'Masquerade create failed');
        }
      }))
      .post('/api/ssl/certs/import-pem', defineEventHandler(async (event) => {
        acl.requireCapability(event, acl.CAP.SYSTEM_SETTINGS);
        const sslManager = require('./sslManager');
        try {
          const body = await readBody(event).catch(() => ({}));
          return { success: true, cert: await sslManager.importPem(body || {}) };
        } catch (err) {
          if (err && err.status) throw httpError(err.status, err.message);
          throw httpError(500, err.message || 'PEM import failed');
        }
      }))
      .post('/api/ssl/certs/import-path', defineEventHandler(async (event) => {
        acl.requireCapability(event, acl.CAP.SYSTEM_SETTINGS);
        const sslManager = require('./sslManager');
        try {
          const body = await readBody(event).catch(() => ({}));
          return { success: true, cert: await sslManager.importPath(body || {}) };
        } catch (err) {
          if (err && err.status) throw httpError(err.status, err.message);
          throw httpError(500, err.message || 'Path import failed');
        }
      }))
      .post('/api/ssl/certs/:id/renew', defineEventHandler(async (event) => {
        acl.requireCapability(event, acl.CAP.SYSTEM_SETTINGS);
        const sslManager = require('./sslManager');
        try {
          const id = getRouterParam(event, 'id');
          const body = await readBody(event).catch(() => ({}));
          const force = body && body.force === false ? false : true;
          return { success: true, cert: await sslManager.renew(id, { force }) };
        } catch (err) {
          if (err && err.status) throw httpError(err.status, err.message);
          throw httpError(500, err.message || 'Renew failed');
        }
      }))
      .post('/api/ssl/certs/:id/recheck', defineEventHandler(async (event) => {
        acl.requireCapability(event, acl.CAP.SYSTEM_SETTINGS);
        const sslManager = require('./sslManager');
        try {
          const id = getRouterParam(event, 'id');
          return { success: true, cert: await sslManager.recheckReality(id) };
        } catch (err) {
          if (err && err.status) throw httpError(err.status, err.message);
          throw httpError(500, err.message || 'Recheck failed');
        }
      }))
      .post('/api/ssl/certs/:id/regenerate', defineEventHandler(async (event) => {
        acl.requireCapability(event, acl.CAP.SYSTEM_SETTINGS);
        const sslManager = require('./sslManager');
        try {
          const id = getRouterParam(event, 'id');
          return { success: true, cert: await sslManager.regenerateReality(id) };
        } catch (err) {
          if (err && err.status) throw httpError(err.status, err.message);
          throw httpError(500, err.message || 'Regenerate failed');
        }
      }))
      .post('/api/ssl/certs/:id/auto-renew', defineEventHandler(async (event) => {
        acl.requireCapability(event, acl.CAP.SYSTEM_SETTINGS);
        const sslManager = require('./sslManager');
        try {
          const id = getRouterParam(event, 'id');
          const body = await readBody(event).catch(() => ({}));
          const enabled = !!(body && (body.autoRenew === true || body.auto_renew === true || body.enabled === true));
          return { success: true, cert: sslManager.setAutoRenew(id, enabled) };
        } catch (err) {
          if (err && err.status) throw httpError(err.status, err.message);
          throw httpError(500, err.message || 'Auto-renew update failed');
        }
      }))
      .post('/api/ssl/certs/:id/assign-panel', defineEventHandler(async (event) => {
        acl.requireCapability(event, acl.CAP.SYSTEM_SETTINGS);
        const sslManager = require('./sslManager');
        try {
          const id = getRouterParam(event, 'id');
          return { success: true, cert: await sslManager.assignPanel(id) };
        } catch (err) {
          if (err && err.status) throw httpError(err.status, err.message);
          throw httpError(500, err.message || 'Assign panel cert failed');
        }
      }))
      .delete('/api/ssl/certs/:id', defineEventHandler(async (event) => {
        acl.requireCapability(event, acl.CAP.SYSTEM_SETTINGS);
        const sslManager = require('./sslManager');
        try {
          const id = getRouterParam(event, 'id');
          return await sslManager.remove(id);
        } catch (err) {
          if (err && err.status) throw httpError(err.status, err.message);
          throw httpError(500, err.message || 'Delete failed');
        }
      }))
      .post('/api/ssl/sync-panel', defineEventHandler(async (event) => {
        acl.requireCapability(event, acl.CAP.SYSTEM_SETTINGS);
        const sslManager = require('./sslManager');
        try {
          const cert = await sslManager.syncPanel();
          return { success: true, cert };
        } catch (err) {
          if (err && err.status) throw httpError(err.status, err.message);
          throw httpError(500, err.message || 'Panel cert sync failed');
        }
      }))
      .get('/api/amnezia-dns', defineEventHandler((event) => {
        acl.requireCapability(event, acl.CAP.SYSTEM_DNS);
        return amneziaDns.getStatus();
      }))
      .get('/api/amnezia-dns/profiles', defineEventHandler(async (event) => {
        acl.requireCapability(event, acl.CAP.SYSTEM_DNS);
        try {
          const q = getQuery(event) || {};
          const forceProbe = q.refresh === '1' || q.refresh === 'true';
          const catalog = await amneziaDns.listProfiles({ probe: true, forceProbe });
          if (catalog.error) {
            throw httpError(503, catalog.error);
          }
          return catalog;
        } catch (err) {
          if (err && err.statusCode) throw err;
          const status = (err && err.status) || 503;
          throw httpError(status, err.message || 'DNS profiles unavailable');
        }
      }))
      .post('/api/amnezia-dns/enable', defineEventHandler(async (event) => {
        acl.requireCapability(event, acl.CAP.SYSTEM_DNS);
        try {
          const body = await readBody(event).catch(() => ({}));
          const raw = body && body.profileId != null ? String(body.profileId).trim() : '';
          // Explicit profileId → use it. Omitted/empty → keep stored profile, else bank default
          // (amneziaDns.enableInternal → resolveProfile).
          const status = raw
            ? await amneziaDns.enable({ profileId: raw })
            : await amneziaDns.enable({});
          return { success: true, ...status };
        } catch (err) {
          if (err && err.statusCode) throw err;
          if (err && err.status === 409) throw httpError(409, err.message);
          if (err && err.status === 404) throw httpError(404, err.message);
          if (err && err.status === 400) throw httpError(400, err.message);
          if (err && err.status === 504) throw httpError(504, err.message);
          if (err && err.status === 503) throw httpError(503, err.message);
          throw httpError(500, err.message || 'Amnezia DNS enable failed');
        }
      }))
      .post('/api/amnezia-dns/disable', defineEventHandler(async (event) => {
        acl.requireCapability(event, acl.CAP.SYSTEM_DNS);
        try {
          const status = await amneziaDns.disable();
          return { success: true, ...status };
        } catch (err) {
          if (err && err.status === 409) throw httpError(409, err.message);
          throw httpError(500, err.message || 'Amnezia DNS disable failed');
        }
      }))
      .post('/api/amnezia-dns/force-cleanup', defineEventHandler(async (event) => {
        acl.requireCapability(event, acl.CAP.SYSTEM_DNS);
        try {
          const status = await amneziaDns.forceCleanup();
          return { success: true, ...status };
        } catch (err) {
          if (err && err.status === 409) throw httpError(409, err.message);
          throw httpError(500, err.message || 'Amnezia DNS cleanup failed');
        }
      }))
      .get('/api/amnezia-xray', defineEventHandler((event) => {
        acl.requireCapability(event, acl.CAP.SYSTEM_XRAY);
        return amneziaXray.getStatus();
      }))
      .post('/api/amnezia-xray/enable', defineEventHandler(async (event) => {
        acl.requireCapability(event, acl.CAP.SYSTEM_XRAY);
        try {
          const body = await readBody(event).catch(() => ({}));
          const status = await amneziaXray.enable({
            sni: body && body.sni,
            fingerprint: body && body.fingerprint,
            flow: body && body.flow,
            port: body && body.port,
            publicPort: body && (body.publicPort != null ? body.publicPort : body.public_port),
            address: body && body.address,
            security: body && body.security,
            network: body && body.network,
            sslCertId: body && (body.sslCertId != null ? body.sslCertId : body.ssl_cert_id),
            transportSettings: body && (body.transportSettings != null
              ? body.transportSettings
              : body.transport_settings),
            certSource: body && (body.certSource != null ? body.certSource : body.cert_source),
            certDomain: body && (body.certDomain != null ? body.certDomain : body.cert_domain),
            certPem: body && (body.certPem != null ? body.certPem : body.cert_pem),
            keyPem: body && (body.keyPem != null ? body.keyPem : body.key_pem),
            certPath: body && (body.certPath != null ? body.certPath : body.cert_path),
            keyPath: body && (body.keyPath != null ? body.keyPath : body.key_path),
            wsPath: body && (body.wsPath != null ? body.wsPath : body.ws_path),
            wsHost: body && (body.wsHost != null ? body.wsHost : body.ws_host),
            grpcServiceName: body && (body.grpcServiceName != null ? body.grpcServiceName : body.grpc_service_name),
            grpcMultiMode: body && (body.grpcMultiMode != null ? body.grpcMultiMode : body.grpc_multi_mode),
            alpn: body && (body.alpn != null ? body.alpn : body.tls_alpn),
            allowInsecure: body && (body.allowInsecure != null ? body.allowInsecure : body.allow_insecure),
            email: body && (body.email != null ? body.email : body.certbotEmail),
          });
          return { success: true, ...status };
        } catch (err) {
          if (err && err.statusCode) throw err;
          if (err && err.status === 409) throw httpError(409, err.message);
          if (err && err.status === 400) throw httpError(400, err.message);
          if (err && err.status === 504) throw httpError(504, err.message);
          if (err && err.status === 503) throw httpError(503, err.message);
          throw httpError(500, err.message || 'Amnezia Xray enable failed');
        }
      }))
      .post('/api/amnezia-xray/disable', defineEventHandler(async (event) => {
        acl.requireCapability(event, acl.CAP.SYSTEM_XRAY);
        try {
          const status = await amneziaXray.disable();
          return { success: true, ...status };
        } catch (err) {
          if (err && err.status === 409) throw httpError(409, err.message);
          throw httpError(500, err.message || 'Amnezia Xray disable failed');
        }
      }))
      .post('/api/amnezia-xray/force-cleanup', defineEventHandler(async (event) => {
        acl.requireCapability(event, acl.CAP.SYSTEM_XRAY);
        try {
          const status = await amneziaXray.forceCleanup();
          return { success: true, ...status };
        } catch (err) {
          if (err && err.status === 409) throw httpError(409, err.message);
          throw httpError(500, err.message || 'Amnezia Xray cleanup failed');
        }
      }))
      .post('/api/amnezia-xray/reset', defineEventHandler(async (event) => {
        acl.requireCapability(event, acl.CAP.SYSTEM_XRAY);
        try {
          const status = await amneziaXray.resetCredentials();
          return { success: true, ...status };
        } catch (err) {
          if (err && err.status === 409) throw httpError(409, err.message);
          throw httpError(500, err.message || 'Amnezia Xray reset failed');
        }
      }))
      .get('/api/amnezia-xray/sni-cache', defineEventHandler(async (event) => {
        acl.requireCapability(event, acl.CAP.SYSTEM_XRAY);
        const q = getQuery(event) || {};
        const ensureBg = q.ensureBg === '1' || q.ensureBg === 'true' || q.ensureBg === true;
        return sniFinder.getCacheWithPreview({ ensureBg });
      }))
      .get('/api/amnezia-xray/sni-scan', defineEventHandler((event) => {
        acl.requireCapability(event, acl.CAP.SYSTEM_XRAY);
        return sniFinder.getScanStatus();
      }))
      .post('/api/amnezia-xray/sni-scan', defineEventHandler(async (event) => {
        acl.requireCapability(event, acl.CAP.SYSTEM_XRAY);
        try {
          const body = await readBody(event).catch(() => ({}));
          return sniFinder.startScan({
            cidr: body && body.cidr,
            refIp: body && body.refIp,
            force: body && body.force,
          });
        } catch (err) {
          throw sniHttpError(err);
        }
      }))
      .post('/api/amnezia-xray/sni-scan/cancel', defineEventHandler((event) => {
        acl.requireCapability(event, acl.CAP.SYSTEM_XRAY);
        return sniFinder.cancelScan();
      }))
      .post('/api/amnezia-xray/sni-recheck', defineEventHandler(async (event) => {
        acl.requireCapability(event, acl.CAP.SYSTEM_XRAY);
        try {
          const body = await readBody(event).catch(() => ({}));
          const domain = body && body.domain;
          return await sniFinder.recheckDomain(domain);
        } catch (err) {
          throw sniHttpError(err);
        }
      }))
      .get('/api/amnezia-xray/transport-profiles', defineEventHandler((event) => {
        acl.requireCapability(event, acl.CAP.SYSTEM_XRAY);
        const q = getQuery(event) || {};
        const network = q.network != null ? String(q.network).trim().toLowerCase() : '';
        const xrayTransportProfileBank = require('./xrayTransportProfileBank');
        return { profiles: xrayTransportProfileBank.listProfiles(network) };
      }))
      .post('/api/amnezia-xray/transport-profiles', defineEventHandler(async (event) => {
        acl.requireCapability(event, acl.CAP.SYSTEM_XRAY);
        const body = await readBody(event).catch(() => ({}));
        const network = body && body.network != null ? String(body.network).trim().toLowerCase() : '';
        const name = body && body.name != null ? String(body.name).trim() : '';
        const settings = body && body.settings;
        const xrayTransportProfileBank = require('./xrayTransportProfileBank');
        const xrayTransportSchema = require('./xrayTransportSchema');
        const sanitized = xrayTransportSchema.sanitizeTransportSettings(network, settings || {});
        const check = xrayTransportSchema.validateTransportSettings(network, sanitized);
        if (!check.ok) {
          const msg = Object.values(check.fieldErrors || {}).join('; ') || 'Invalid transport settings';
          throw httpError(400, msg);
        }
        try {
          const saved = xrayTransportProfileBank.saveProfile(network, {
            id: body && body.id,
            name,
            settings: sanitized,
          });
          return { success: true, profile: saved };
        } catch (err) {
          if (err && err.status === 400) throw httpError(400, err.message);
          throw httpError(500, err.message || 'Failed to save transport profile');
        }
      }))
      .post('/api/tls/preflight-domain', defineEventHandler(async (event) => {
        acl.requireAnyCapability(event, [
          acl.CAP.SYSTEM_XRAY,
          acl.CAP.SYSTEM_NAIVE,
          acl.CAP.SYSTEM_HYSTERIA,
          acl.CAP.SYSTEM_MIERU,
        ]);
        try {
          const body = await readBody(event).catch(() => ({}));
          const domain = body && body.domain;
          if (!domain || !String(domain).trim()) {
            throw httpError(400, 'domain is required');
          }
          return await sniFinder.recheckDomain(String(domain).trim());
        } catch (err) {
          if (err && err.statusCode) throw err;
          throw sniHttpError(err);
        }
      }))
      .post('/api/port-plan/validate', defineEventHandler(async (event) => {
        acl.requireAnyCapability(event, [
          acl.CAP.SYSTEM_XRAY,
          acl.CAP.SYSTEM_NAIVE,
          acl.CAP.SYSTEM_HYSTERIA,
          acl.CAP.SYSTEM_MIERU,
          acl.CAP.SYSTEM_SETTINGS,
        ]);
        const body = await readBody(event).catch(() => ({}));
        const service = body && body.service;
        if (!service) throw httpError(400, 'service is required');
        const result = require('./sidecarValidate').validateInstall(String(service), body || {});
        if (!result.ok) {
          return { ok: false, fieldErrors: result.fieldErrors, code: result.code };
        }
        return { ok: true, ...result };
      }))
      .get('/api/amnezia-mieru', defineEventHandler((event) => {
        acl.requireCapability(event, acl.CAP.SYSTEM_MIERU);
        return amneziaMieru.getStatus();
      }))
      .post('/api/amnezia-mieru/enable', defineEventHandler(async (event) => {
        acl.requireCapability(event, acl.CAP.SYSTEM_MIERU);
        try {
          const body = await readBody(event).catch(() => ({}));
          const status = await amneziaMieru.enable({
            address: body && body.address,
            port: body && body.port,
            publicPort: body && (body.publicPort != null ? body.publicPort : body.public_port),
            protocol: body && body.protocol,
            enableTcp: body && body.enableTcp,
            enableUdp: body && body.enableUdp,
            tcpPublicPort: body && (body.tcpPublicPort != null ? body.tcpPublicPort : body.tcp_public_port),
            udpPublicPort: body && (body.udpPublicPort != null ? body.udpPublicPort : body.udp_public_port),
            mtu: body && body.mtu,
            loggingLevel: body && (body.loggingLevel != null ? body.loggingLevel : body.logging_level),
          });
          return { success: true, ...status };
        } catch (err) {
          if (err && err.statusCode) throw err;
          if (err && err.status === 409) throw httpError(409, err.message);
          if (err && err.status === 400) throw httpError(400, err.message);
          if (err && err.status === 504) throw httpError(504, err.message);
          throw httpError(500, err.message || 'Amnezia Mieru enable failed');
        }
      }))
      .post('/api/amnezia-mieru/disable', defineEventHandler(async (event) => {
        acl.requireCapability(event, acl.CAP.SYSTEM_MIERU);
        try {
          const status = await amneziaMieru.disable();
          return { success: true, ...status };
        } catch (err) {
          if (err && err.status === 409) throw httpError(409, err.message);
          throw httpError(500, err.message || 'Amnezia Mieru disable failed');
        }
      }))
      .post('/api/amnezia-mieru/force-cleanup', defineEventHandler(async (event) => {
        acl.requireCapability(event, acl.CAP.SYSTEM_MIERU);
        try {
          const status = await amneziaMieru.forceCleanup();
          return { success: true, ...status };
        } catch (err) {
          if (err && err.status === 409) throw httpError(409, err.message);
          throw httpError(500, err.message || 'Amnezia Mieru cleanup failed');
        }
      }))
      .post('/api/tls/preflight-masquerade-url', defineEventHandler(async (event) => {
        acl.requireAnyCapability(event, [
          acl.CAP.SYSTEM_HYSTERIA,
          acl.CAP.SYSTEM_SETTINGS,
        ]);
        const body = await readBody(event).catch(() => ({}));
        const url = body && (body.url != null ? body.url : body.masqueradeUrl);
        if (!url || !String(url).trim()) {
          throw httpError(400, 'url is required');
        }
        const masqueradeBank = require('./masqueradeBank');
        return masqueradeBank.preflightMasqueradeUrl(String(url).trim());
      }))
      .get('/api/amnezia-hysteria/masquerade-bank', defineEventHandler((event) => {
        acl.requireCapability(event, acl.CAP.SYSTEM_HYSTERIA);
        const masqueradeBank = require('./masqueradeBank');
        return { entries: masqueradeBank.listMasqueradeBank() };
      }))
      .get('/api/amnezia-hysteria', defineEventHandler((event) => {
        acl.requireCapability(event, acl.CAP.SYSTEM_HYSTERIA);
        return amneziaHysteria.getStatus();
      }))
      .post('/api/amnezia-hysteria/enable', defineEventHandler(async (event) => {
        acl.requireCapability(event, acl.CAP.SYSTEM_HYSTERIA);
        try {
          const body = await readBody(event).catch(() => ({}));
          const status = await amneziaHysteria.enable({
            address: body && body.address,
            sni: body && body.sni,
            publicPort: body && (body.publicPort != null ? body.publicPort : body.public_port),
            masqueradeUrl: body && (body.masqueradeUrl != null ? body.masqueradeUrl : body.masquerade_url),
            masqueradeType: body && (body.masqueradeType != null ? body.masqueradeType : body.masquerade_type),
            obfsType: body && (body.obfsType != null ? body.obfsType : body.obfs_type),
            obfsPassword: body && (body.obfsPassword != null ? body.obfsPassword : body.obfs_password),
            obfsGeckoMin: body && (body.obfsGeckoMin != null ? body.obfsGeckoMin : body.obfs_gecko_min),
            obfsGeckoMax: body && (body.obfsGeckoMax != null ? body.obfsGeckoMax : body.obfs_gecko_max),
            congestionType: body && (body.congestionType != null ? body.congestionType : body.congestion_type),
            bbrProfile: body && (body.bbrProfile != null ? body.bbrProfile : body.bbr_profile),
            echEnabled: body && (body.echEnabled != null ? body.echEnabled : body.ech_enabled),
            listenMode: body && (body.listenMode != null ? body.listenMode : body.listen_mode),
            portRange: body && (body.portRange != null ? body.portRange : body.port_range),
            realmUri: body && (body.realmUri != null ? body.realmUri : body.realm_uri),
            bandwidthUp: body && (body.bandwidthUp != null ? body.bandwidthUp : body.bandwidth_up),
            bandwidthDown: body && (body.bandwidthDown != null ? body.bandwidthDown : body.bandwidth_down),
            ignoreClientBandwidth: body && (body.ignoreClientBandwidth != null
              ? body.ignoreClientBandwidth
              : body.ignore_client_bandwidth),
            certSource: body && (body.certSource != null ? body.certSource : body.cert_source),
            certDomain: body && (body.certDomain != null ? body.certDomain : body.cert_domain),
            certPem: body && (body.certPem != null ? body.certPem : body.cert_pem),
            keyPem: body && (body.keyPem != null ? body.keyPem : body.key_pem),
            certPath: body && (body.certPath != null ? body.certPath : body.cert_path),
            keyPath: body && (body.keyPath != null ? body.keyPath : body.key_path),
            tlsInsecureClient: body && (body.tlsInsecureClient != null
              ? body.tlsInsecureClient
              : body.tls_insecure_client),
            sslCertId: body && (body.sslCertId != null ? body.sslCertId : body.ssl_cert_id),
            email: body && (body.email != null ? body.email : body.certbotEmail),
          });
          return { success: true, ...status };
        } catch (err) {
          if (err && err.statusCode) throw err;
          if (err && err.status === 409) throw httpError(409, err.message);
          if (err && err.status === 400) throw httpError(400, err.message);
          if (err && err.status === 504) throw httpError(504, err.message);
          throw httpError(500, err.message || 'Amnezia Hysteria enable failed');
        }
      }))
      .post('/api/amnezia-hysteria/disable', defineEventHandler(async (event) => {
        acl.requireCapability(event, acl.CAP.SYSTEM_HYSTERIA);
        try {
          const status = await amneziaHysteria.disable();
          return { success: true, ...status };
        } catch (err) {
          if (err && err.status === 409) throw httpError(409, err.message);
          throw httpError(500, err.message || 'Amnezia Hysteria disable failed');
        }
      }))
      .post('/api/amnezia-hysteria/force-cleanup', defineEventHandler(async (event) => {
        acl.requireCapability(event, acl.CAP.SYSTEM_HYSTERIA);
        try {
          const status = await amneziaHysteria.forceCleanup();
          return { success: true, ...status };
        } catch (err) {
          if (err && err.status === 409) throw httpError(409, err.message);
          throw httpError(500, err.message || 'Amnezia Hysteria cleanup failed');
        }
      }))
      .get('/api/amnezia-naive', defineEventHandler((event) => {
        acl.requireCapability(event, acl.CAP.SYSTEM_NAIVE);
        return amneziaNaive.getStatus();
      }))
      .post('/api/amnezia-naive/enable', defineEventHandler(async (event) => {
        acl.requireCapability(event, acl.CAP.SYSTEM_NAIVE);
        try {
          const body = await readBody(event).catch(() => ({}));
          const status = await amneziaNaive.enable({
            address: body && body.address,
            sni: body && body.sni,
            publicPort: body && (body.publicPort != null ? body.publicPort : body.public_port),
            probeResistanceDomain: body && (body.probeResistanceDomain != null
              ? body.probeResistanceDomain
              : body.probe_resistance_domain),
            certSource: body && (body.certSource != null ? body.certSource : body.cert_source),
            certDomain: body && (body.certDomain != null ? body.certDomain : body.cert_domain),
            certPem: body && (body.certPem != null ? body.certPem : body.cert_pem),
            keyPem: body && (body.keyPem != null ? body.keyPem : body.key_pem),
            certPath: body && (body.certPath != null ? body.certPath : body.cert_path),
            keyPath: body && (body.keyPath != null ? body.keyPath : body.key_path),
            email: body && (body.email != null ? body.email : body.certbotEmail),
          });
          return { success: true, ...status };
        } catch (err) {
          if (err && err.statusCode) throw err;
          if (err && err.status === 409) throw httpError(409, err.message);
          if (err && err.status === 400) throw httpError(400, err.message);
          if (err && err.status === 504) throw httpError(504, err.message);
          throw httpError(500, err.message || 'Amnezia Naive enable failed');
        }
      }))
      .post('/api/amnezia-naive/disable', defineEventHandler(async (event) => {
        acl.requireCapability(event, acl.CAP.SYSTEM_NAIVE);
        try {
          const status = await amneziaNaive.disable();
          return { success: true, ...status };
        } catch (err) {
          if (err && err.status === 409) throw httpError(409, err.message);
          throw httpError(500, err.message || 'Amnezia Naive disable failed');
        }
      }))
      .post('/api/amnezia-naive/force-cleanup', defineEventHandler(async (event) => {
        acl.requireCapability(event, acl.CAP.SYSTEM_NAIVE);
        try {
          const status = await amneziaNaive.forceCleanup();
          return { success: true, ...status };
        } catch (err) {
          if (err && err.status === 409) throw httpError(409, err.message);
          throw httpError(500, err.message || 'Amnezia Naive cleanup failed');
        }
      }))
      .get('/api/port-plan', defineEventHandler((event) => {
        acl.requireCapability(event, acl.CAP.SYSTEM_SETTINGS);
        return require('./portPlan').getStatusSummary();
      }))
      .post('/api/port-plan/apply', defineEventHandler(async (event) => {
        acl.requireCapability(event, acl.CAP.SYSTEM_SETTINGS);
        try {
          return await require('./portPlan').applyPlan();
        } catch (err) {
          if (err && err.status === 409) throw httpError(409, err.message);
          throw httpError(500, err.message || 'port plan apply failed');
        }
      }))
      .get('/api/wireguard/client/:clientId/xray', defineEventHandler(async (event) => {
        const clientId = getRouterParam(event, 'clientId');
        acl.assertClientAccess(event, clientId);
        if (!amneziaXray.isAmneziaXrayAvailable()) {
          throw httpError(503, 'Amnezia Xray is not running');
        }
        const client = db.clients.getById(clientId);
        if (!client) throw httpError(404, 'Client Not Found');
        amneziaXray.ensureClientUuids();
        const refreshed = db.clients.getById(clientId);
        let requestUrl = null;
        try {
          requestUrl = getRequestURL(event);
        } catch {
          requestUrl = null;
        }
        const baseUrl = buildPanelPublicBaseUrl({
          requestUrl,
          panelDomain: PANEL_DOMAIN,
          panelHttpsPort: PANEL_HTTPS_PORT,
          wgHost: WG_HOST,
        });
        const payload = amneziaXray.getClientXrayPayload(refreshed, { baseUrl });
        if (!payload) throw httpError(503, 'Xray keys not ready');
        let subQrSvg = null;
        try {
          const QRCode = require('qrcode');
          subQrSvg = await QRCode.toString(payload.subUrl, {
            type: 'svg',
            width: 512,
            errorCorrectionLevel: 'M',
          });
        } catch {
          subQrSvg = null;
        }
        return {
          uuid: payload.uuid,
          vlessUrl: payload.vlessUrl,
          subUrl: payload.subUrl,
          clientJson: payload.clientJson,
          subQrSvg,
        };
      }))
      .get('/api/wireguard/client/:clientId/mieru', defineEventHandler(async (event) => {
        const clientId = getRouterParam(event, 'clientId');
        acl.assertClientAccess(event, clientId);
        if (!amneziaMieru.isAmneziaMieruAvailable()) {
          throw httpError(503, 'Amnezia Mieru is not running');
        }
        const client = db.clients.getById(clientId);
        if (!client) throw httpError(404, 'Client Not Found');
        amneziaMieru.ensureClientPasswords();
        const refreshed = db.clients.getById(clientId);
        const payload = amneziaMieru.getClientMieruPayload(refreshed);
        if (!payload) throw httpError(503, 'Mieru credentials not ready');
        let linkQrSvg = null;
        try {
          const QRCode = require('qrcode');
          linkQrSvg = await QRCode.toString(payload.mieruUrl, {
            type: 'svg',
            width: 512,
            errorCorrectionLevel: 'M',
          });
        } catch {
          linkQrSvg = null;
        }
        return { ...payload, linkQrSvg };
      }))
      .get('/api/wireguard/client/:clientId/hysteria', defineEventHandler(async (event) => {
        const clientId = getRouterParam(event, 'clientId');
        acl.assertClientAccess(event, clientId);
        if (!amneziaHysteria.isAmneziaHysteriaAvailable()) {
          throw httpError(503, 'Amnezia Hysteria is not running');
        }
        const client = db.clients.getById(clientId);
        if (!client) throw httpError(404, 'Client Not Found');
        amneziaHysteria.ensureClientPasswords();
        const refreshed = db.clients.getById(clientId);
        const payload = amneziaHysteria.getClientHysteriaPayload(refreshed);
        if (!payload) throw httpError(503, 'Hysteria credentials not ready');
        let linkQrSvg = null;
        try {
          const QRCode = require('qrcode');
          linkQrSvg = await QRCode.toString(payload.hy2Url, {
            type: 'svg',
            width: 512,
            errorCorrectionLevel: 'M',
          });
        } catch {
          linkQrSvg = null;
        }
        return { ...payload, linkQrSvg };
      }))
      .get('/api/wireguard/client/:clientId/naive', defineEventHandler(async (event) => {
        const clientId = getRouterParam(event, 'clientId');
        acl.assertClientAccess(event, clientId);
        if (!amneziaNaive.isAmneziaNaiveAvailable()) {
          throw httpError(503, 'Amnezia Naive is not running');
        }
        const client = db.clients.getById(clientId);
        if (!client) throw httpError(404, 'Client Not Found');
        amneziaNaive.ensureClientPasswords();
        const refreshed = db.clients.getById(clientId);
        const payload = amneziaNaive.getClientNaivePayload(refreshed);
        if (!payload) throw httpError(503, 'Naive credentials not ready');
        let linkQrSvg = null;
        try {
          const QRCode = require('qrcode');
          linkQrSvg = await QRCode.toString(payload.shareUrl, {
            type: 'svg',
            width: 512,
            errorCorrectionLevel: 'M',
          });
        } catch {
          linkQrSvg = null;
        }
        return { ...payload, linkQrSvg };
      }))
      .put('/api/wireguard/client/:clientId/firewall-profile', defineEventHandler(async (event) => {
        acl.requireCapability(event, acl.CAP.SYSTEM_FIREWALL);
        const clientId = getRouterParam(event, 'clientId');
        acl.assertClientAccess(event, clientId);
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
        acl.requireCapability(event, acl.CAP.CLIENTS_WRITE);
        const clientId = getRouterParam(event, 'clientId');
        acl.assertClientAccess(event, clientId);
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
        acl.requireCapability(event, acl.CAP.SYSTEM_FIREWALL);
        const clientId = getRouterParam(event, 'clientId');
        acl.assertClientAccess(event, clientId);
        const client = db.clients.getById(clientId);
        if (!client) throw createError({ status: 404, message: 'Client not found' });
        return db.clientFirewallRules.getByClientId(clientId);
      }))
      .post('/api/wireguard/client/:clientId/firewall-rules', defineEventHandler(async (event) => {
        acl.requireCapability(event, acl.CAP.SYSTEM_FIREWALL);
        const clientId = getRouterParam(event, 'clientId');
        acl.assertClientAccess(event, clientId);
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
        acl.requireCapability(event, acl.CAP.SYSTEM_FIREWALL);
        const clientId = getRouterParam(event, 'clientId');
        acl.assertClientAccess(event, clientId);
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
        acl.requireCapability(event, acl.CAP.SYSTEM_FIREWALL);
        const clientId = getRouterParam(event, 'clientId');
        acl.assertClientAccess(event, clientId);
        const id = parseInt(getRouterParam(event, 'id'), 10);
        const client = db.clients.getById(clientId);
        if (!client) throw createError({ status: 404, message: 'Client not found' });
        const rule = db.clientFirewallRules.getById(id);
        if (!rule || rule.client_id !== clientId) throw createError({ status: 404, message: 'Rule not found' });
        db.clientFirewallRules.delete(id);
        applyFirewall();
        return { success: true };
      }))
      .get('/api/traffic/client/:clientId', defineEventHandler((event) => {
        const clientId = getRouterParam(event, 'clientId');
        acl.assertClientAccess(event, clientId);
        const query = getQuery(event);
        const period = (query.period && String(query.period).toLowerCase()) || 'day';
        const periodSeconds = { hour: 3600, day: 86400, week: 604800, month: 2592000, year: 31536000 }[period];
        if (!periodSeconds) throw createError({ status: 400, message: 'period must be hour, day, week, month, or year' });
        const tsFrom = Math.floor(Date.now() / 1000) - periodSeconds;
        return db.traffic.deltas.sumByClientAndPeriod(clientId, tsFrom);
      }))
      .delete('/api/traffic/client/:clientId/history', defineEventHandler(async (event) => {
        acl.requireCapability(event, acl.CAP.CLIENTS_WRITE);
        const clientId = getRouterParam(event, 'clientId');
        acl.assertClientAccess(event, clientId);
        const client = db.clients.getById(clientId);
        if (!client) throw createError({ status: 404, message: 'Client not found' });
        const Util = require('./Util');
        let lastRx = 0;
        let lastTx = 0;
        try {
          const dump = await Util.exec('wg show awg0 dump', { log: false });
          const lines = dump.trim().split('\n').slice(1);
          for (const line of lines) {
            const parts = line.split('\t');
            if (parts[0] === client.public_key) {
              lastRx = Number(parts[5]) || 0;
              lastTx = Number(parts[6]) || 0;
              break;
            }
          }
        } catch (_) {}

        let xrayRx = 0;
        let xrayTx = 0;
        try {
          const amneziaXray = require('./amneziaXray');
          if (amneziaXray.isAmneziaXrayAvailable()) {
            const stats = await amneziaXray.queryUserTrafficStats();
            const counters = stats.get(client.name);
            if (counters) {
              xrayRx = Number(counters.uplink) || 0;
              xrayTx = Number(counters.downlink) || 0;
            }
          }
        } catch (_) {}

        const now = Math.floor(Date.now() / 1000);
        const database = db.getDb();
        database.transaction(() => {
          db.traffic.deltas.deleteByClientId(clientId);
          db.traffic.snapshot.upsert(clientId, lastRx, lastTx, now);
          if (db.traffic.xraySnapshot) {
            db.traffic.xraySnapshot.upsert(clientId, xrayRx, xrayTx, now);
          }
        })();
        const { updateSnapshotForClient, updateXraySnapshotForClient } = require('./trafficRecorder');
        updateSnapshotForClient(clientId, lastRx, lastTx);
        if (updateXraySnapshotForClient) updateXraySnapshotForClient(clientId, xrayRx, xrayTx);
        return { success: true };
      }))
      .get('/api/traffic/aggregate', defineEventHandler((event) => {
        acl.requireCapability(event, acl.CAP.CLIENTS_READ_ALL);
        const query = getQuery(event);
        const period = (query.period && String(query.period).toLowerCase()) || 'day';
        const periodSeconds = { hour: 3600, day: 86400, week: 604800, month: 2592000, year: 31536000 }[period];
        if (!periodSeconds) throw createError({ status: 400, message: 'period must be hour, day, week, month, or year' });
        const tsFrom = Math.floor(Date.now() / 1000) - periodSeconds;
        return db.traffic.deltas.sumByPeriod(tsFrom);
      }))
      .get('/api/signatures/profiles', defineEventHandler((event) => {
        acl.requireCapability(event, acl.CAP.SYSTEM_SIGNATURES);
        try {
          const meta = getProfilesCatalog();
          if (meta.ok === false) {
            throw httpError(503, meta.error || 'signatures.json unavailable');
          }
          return {
            ok: true,
            profileIds: meta.profileIds || getProfileIds(),
            protocols: meta.protocols || [],
            defaultProtocol: meta.defaultProtocol || DEFAULT_PROFILE_ID,
            defaultProfile: meta.defaultProtocol || DEFAULT_PROFILE_ID,
          };
        } catch (err) {
          if (err && err.statusCode) throw err;
          throw httpError(503, (err && err.message) || 'signatures.json unavailable');
        }
      }))
      .get('/api/rule-profiles', defineEventHandler((event) => {
        acl.requireCapability(event, acl.CAP.SYSTEM_FIREWALL);
        return db.ruleProfiles.getAll();
      }))
      .get('/api/rule-profiles/:id', defineEventHandler((event) => {
        acl.requireCapability(event, acl.CAP.SYSTEM_FIREWALL);
        const id = parseInt(getRouterParam(event, 'id'), 10);
        const profile = db.ruleProfiles.getById(id);
        if (!profile) throw createError({ status: 404, message: 'Profile not found' });
        const rules = db.ipRules.getByProfileId(id);
        return { ...profile, rules };
      }))
      .post('/api/rule-profiles', defineEventHandler(async (event) => {
        acl.requireCapability(event, acl.CAP.SYSTEM_FIREWALL);
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
        acl.requireCapability(event, acl.CAP.SYSTEM_FIREWALL);
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
        acl.requireCapability(event, acl.CAP.SYSTEM_FIREWALL);
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
        acl.requireCapability(event, acl.CAP.SYSTEM_FIREWALL);
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
        acl.requireCapability(event, acl.CAP.SYSTEM_FIREWALL);
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
        acl.requireCapability(event, acl.CAP.SYSTEM_FIREWALL);
        const id = parseInt(getRouterParam(event, 'id'), 10);
        const rule = db.ipRules.getById(id);
        if (!rule) throw createError({ status: 404, message: 'Rule not found' });
        db.ipRules.delete(id);
        applyFirewall();
        return { success: true };
      }))
      .get('/api/global-firewall-rules', defineEventHandler((event) => {
        acl.requireCapability(event, acl.CAP.SYSTEM_FIREWALL);
        return db.globalFirewallRules.getAll();
      }))
      .post('/api/global-firewall-rules', defineEventHandler(async (event) => {
        acl.requireCapability(event, acl.CAP.SYSTEM_FIREWALL);
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
        acl.requireCapability(event, acl.CAP.SYSTEM_FIREWALL);
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
        acl.requireCapability(event, acl.CAP.SYSTEM_FIREWALL);
        const id = parseInt(getRouterParam(event, 'id'), 10);
        db.globalFirewallRules.delete(id);
        applyFirewall();
        return { success: true };
      }))
      .get('/api/app-settings', defineEventHandler((event) => {
        acl.requireCapability(event, acl.CAP.SYSTEM_SETTINGS);
        return db.appSettings.getAll();
      }))
      .put('/api/app-settings', defineEventHandler(async (event) => {
        acl.requireCapability(event, acl.CAP.SYSTEM_SETTINGS);
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

    // Public subscription bundle (no session; path is outside /api/)
    const decodeSubName = (event) => {
      const raw = getRouterParam(event, 'name') || '';
      try {
        return decodeURIComponent(raw);
      } catch {
        throw httpError(400, 'Invalid name');
      }
    };

    const buildSubBundle = (name) => {
      /** @type {Record<string, unknown>} */
      const bundle = {};
      let count = 0;

      if (amneziaXray.isAmneziaXrayAvailable()) {
        const client = amneziaXray.findEnabledClientByName(name);
        if (client) {
          const payload = amneziaXray.getClientXrayPayload(client);
          if (payload) {
            bundle.xray = { clientJson: payload.clientJson, vlessUrl: payload.vlessUrl };
            count += 1;
          }
        }
      }
      if (amneziaHysteria.isAmneziaHysteriaAvailable()) {
        const client = amneziaHysteria.findEnabledClientByName(name);
        if (client) {
          const payload = amneziaHysteria.getClientHysteriaPayload(client);
          if (payload) {
            bundle.hysteria = { hy2Url: payload.hy2Url, clientJson: payload };
            count += 1;
          }
        }
      }
      if (amneziaNaive.isAmneziaNaiveAvailable()) {
        const client = amneziaNaive.findEnabledClientByName(name);
        if (client) {
          const payload = amneziaNaive.getClientNaivePayload(client);
          if (payload) {
            bundle.naive = { shareUrl: payload.shareUrl, clientJson: payload.clientJson };
            count += 1;
          }
        }
      }
      if (amneziaMieru.isAmneziaMieruAvailable()) {
        const client = amneziaMieru.findEnabledClientByName(name);
        if (client) {
          const payload = amneziaMieru.getClientMieruPayload(client);
          if (payload) {
            bundle.mieru = { mieruUrl: payload.mieruUrl, mieruUrls: payload.mieruUrls };
            count += 1;
          }
        }
      }

      if (count === 0) {
        const xrayClient = amneziaXray.findEnabledClientByName(name);
        if (xrayClient && !amneziaXray.isAmneziaXrayAvailable()) {
          throw httpError(503, 'Xray is not available');
        }
        throw httpError(404, 'Not Found');
      }
      if (count === 1 && bundle.xray && bundle.xray.clientJson) {
        return { single: true, body: bundle.xray.clientJson };
      }
      return { single: false, body: bundle };
    };

    const subRouter = createRouter();
    subRouter
      .get('/sub/:name', defineEventHandler((event) => {
        const name = decodeSubName(event);
        const result = buildSubBundle(name);
        setHeader(event, 'Content-Type', 'application/json; charset=utf-8');
        setHeader(event, 'Cache-Control', 'no-store');
        return result.body;
      }))
      .get('/sub/:name/vless', defineEventHandler((event) => {
        if (!amneziaXray.isAmneziaXrayAvailable()) {
          throw httpError(503, 'Xray is not available');
        }
        const name = decodeSubName(event);
        const client = amneziaXray.findEnabledClientByName(name);
        if (!client) throw httpError(404, 'Not Found');
        const payload = amneziaXray.getClientXrayPayload(client);
        if (!payload) throw httpError(503, 'Xray keys not ready');
        setHeader(event, 'Content-Type', 'text/plain; charset=utf-8');
        setHeader(event, 'Cache-Control', 'no-store');
        return payload.vlessUrl;
      }))
      .get('/sub/:name/hy2', defineEventHandler((event) => {
        if (!amneziaHysteria.isAmneziaHysteriaAvailable()) {
          throw httpError(503, 'Hysteria is not available');
        }
        const name = decodeSubName(event);
        const client = amneziaHysteria.findEnabledClientByName(name);
        if (!client) throw httpError(404, 'Not Found');
        amneziaHysteria.ensureClientPasswords();
        const payload = amneziaHysteria.getClientHysteriaPayload(client);
        if (!payload) throw httpError(503, 'Hysteria not ready');
        setHeader(event, 'Content-Type', 'text/plain; charset=utf-8');
        setHeader(event, 'Cache-Control', 'no-store');
        return payload.hy2Url;
      }))
      .get('/sub/:name/naive', defineEventHandler((event) => {
        if (!amneziaNaive.isAmneziaNaiveAvailable()) {
          throw httpError(503, 'Naive is not available');
        }
        const name = decodeSubName(event);
        const client = amneziaNaive.findEnabledClientByName(name);
        if (!client) throw httpError(404, 'Not Found');
        amneziaNaive.ensureClientPasswords();
        const payload = amneziaNaive.getClientNaivePayload(client);
        if (!payload) throw httpError(503, 'Naive not ready');
        setHeader(event, 'Content-Type', 'text/plain; charset=utf-8');
        setHeader(event, 'Cache-Control', 'no-store');
        return payload.shareUrl;
      }))
      .get('/sub/:name/mieru', defineEventHandler((event) => {
        if (!amneziaMieru.isAmneziaMieruAvailable()) {
          throw httpError(503, 'Mieru is not available');
        }
        const name = decodeSubName(event);
        const client = amneziaMieru.findEnabledClientByName(name);
        if (!client) throw httpError(404, 'Not Found');
        amneziaMieru.ensureClientPasswords();
        const payload = amneziaMieru.getClientMieruPayload(client);
        if (!payload) throw httpError(503, 'Mieru not ready');
        setHeader(event, 'Content-Type', 'text/plain; charset=utf-8');
        setHeader(event, 'Cache-Control', 'no-store');
        return payload.mieruUrl;
      }));
    app.use(subRouter);

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
    const listenPort = this._listenPort != null ? this._listenPort : PORT;
    const listenHost = this._listenHost != null ? this._listenHost : WEBUI_HOST;
    this.httpServer = createServer(listener);
    await new Promise((resolve, reject) => {
      this.httpServer.once('error', reject);
      this.httpServer.listen(listenPort, listenHost, () => resolve());
    });
    const addr = this.httpServer.address();
    this.listenPort = typeof addr === 'object' && addr ? addr.port : listenPort;
    debug(`Listening on http://${listenHost}:${this.listenPort}`);
    return this.httpServer;
  }

  async stop() {
    if (!this.httpServer) return;
    const server = this.httpServer;
    this.httpServer = null;
    if (typeof server.closeAllConnections === 'function') {
      server.closeAllConnections();
    }
    await new Promise((resolve, reject) => {
      server.close((err) => (err ? reject(err) : resolve()));
    });
  }

};

