'use strict';

/**
 * Capability-based ACL for panel roles: admin | moderator | user.
 * Single source of truth for route guards and client visibility.
 */

const { createError } = require('h3');
const db = require('./db');

const ROLES = Object.freeze(['admin', 'moderator', 'user']);

const CAP = Object.freeze({
  USERS_READ: 'users.read',
  USERS_WRITE: 'users.write',
  CLIENTS_READ_ALL: 'clients.read_all',
  CLIENTS_READ_ASSIGNED: 'clients.read_assigned',
  CLIENTS_WRITE: 'clients.write',
  CLIENTS_ASSIGN: 'clients.assign',
  SYSTEM_FIREWALL: 'system.firewall',
  SYSTEM_DNS: 'system.dns',
  SYSTEM_XRAY: 'system.xray',
  SYSTEM_MTPROTO: 'system.mtproto',
  SYSTEM_SETTINGS: 'system.settings',
  SYSTEM_SIGNATURES: 'system.signatures',
});

const ROLE_CAPS = Object.freeze({
  admin: new Set([
    CAP.USERS_READ,
    CAP.USERS_WRITE,
    CAP.CLIENTS_READ_ALL,
    CAP.CLIENTS_READ_ASSIGNED,
    CAP.CLIENTS_WRITE,
    CAP.CLIENTS_ASSIGN,
    CAP.SYSTEM_FIREWALL,
    CAP.SYSTEM_DNS,
    CAP.SYSTEM_XRAY,
    CAP.SYSTEM_MTPROTO,
    CAP.SYSTEM_SETTINGS,
    CAP.SYSTEM_SIGNATURES,
  ]),
  moderator: new Set([
    CAP.USERS_READ,
    CAP.CLIENTS_READ_ALL,
    CAP.CLIENTS_READ_ASSIGNED,
    CAP.CLIENTS_WRITE,
    CAP.CLIENTS_ASSIGN,
    CAP.SYSTEM_DNS,
    CAP.SYSTEM_SIGNATURES,
  ]),
  user: new Set([
    CAP.CLIENTS_READ_ASSIGNED,
    CAP.CLIENTS_WRITE,
  ]),
});

function isValidRole(role) {
  return ROLES.includes(role);
}

function capabilitiesForRole(role) {
  const set = ROLE_CAPS[role];
  return set ? [...set] : [];
}

function hasCapability(role, cap) {
  const set = ROLE_CAPS[role];
  return !!(set && set.has(cap));
}

/**
 * Fresh panel user from DB for the request session. null if unauthenticated/inactive.
 * @returns {{ id: string, username: string, role: string, is_active: number }|null}
 */
function getActor(event) {
  const userId = event?.node?.req?.session?.userId;
  if (!userId) return null;
  const user = db.panelUsers.findById(userId);
  if (!user || !user.is_active) return null;
  return {
    id: user.id,
    username: user.username,
    role: user.role,
    is_active: user.is_active ? 1 : 0,
    assigned_cidrs: (() => {
      const { parseAssignedCidrsField } = require('./vpnAddress');
      return parseAssignedCidrsField(user.assigned_cidrs);
    })(),
  };
}

function requireActor(event) {
  const actor = getActor(event);
  if (!actor) {
    throw createError({ status: 401, message: 'Not authenticated' });
  }
  return actor;
}

function requireCapability(event, cap) {
  const actor = requireActor(event);
  if (!hasCapability(actor.role, cap)) {
    throw createError({ status: 403, message: 'Forbidden' });
  }
  return actor;
}

function canAccessClient(actor, clientId) {
  if (!actor || !clientId) return false;
  if (hasCapability(actor.role, CAP.CLIENTS_READ_ALL)) return true;
  if (!hasCapability(actor.role, CAP.CLIENTS_READ_ASSIGNED)) return false;
  return db.clientPanelUsers.isAssigned(clientId, actor.id);
}

/** Throws 404 when actor cannot see client (hides existence of foreign ids). */
function assertClientAccess(event, clientId) {
  const actor = requireActor(event);
  if (clientId === '__proto__' || clientId === 'constructor' || clientId === 'prototype') {
    throw createError({ status: 404, message: 'Client not found' });
  }
  const row = db.clients.getById(clientId);
  if (!row) {
    throw createError({ status: 404, message: 'Client not found' });
  }
  if (!canAccessClient(actor, clientId)) {
    throw createError({ status: 404, message: 'Client not found' });
  }
  return actor;
}

/**
 * Filter WireGuard client list objects (must have .id) for actor visibility.
 */
function filterClientsForActor(actor, clients) {
  if (!actor || !Array.isArray(clients)) return [];
  if (hasCapability(actor.role, CAP.CLIENTS_READ_ALL)) return clients;
  const allowed = new Set(db.clientPanelUsers.listClientIdsForUser(actor.id));
  return clients.filter((c) => c && allowed.has(c.id));
}

function enrichClientsWithUsers(clients) {
  if (!Array.isArray(clients) || !clients.length) return clients || [];
  const map = db.clientPanelUsers.mapForClientIds(clients.map((c) => c.id));
  return clients.map((c) => ({
    ...c,
    users: map[c.id] || [],
  }));
}

function listAssigneeUsers(clientId) {
  return db.clientPanelUsers.listUsers(clientId);
}

function setClientUsers(clientId, userIds) {
  return db.clientPanelUsers.setUsers(clientId, userIds);
}

/**
 * Guard: changing role/is_active must not leave zero active admins.
 * @returns {{ ok: true }|{ ok: false, message: string }}
 */
function validateAdminInvariant(targetUser, nextRole, nextActive) {
  const role = nextRole !== undefined ? nextRole : targetUser.role;
  const active = nextActive !== undefined ? (nextActive ? 1 : 0) : (targetUser.is_active ? 1 : 0);
  const wasActiveAdmin = targetUser.role === 'admin' && targetUser.is_active;
  const willBeActiveAdmin = role === 'admin' && active;
  if (wasActiveAdmin && !willBeActiveAdmin) {
    if (db.panelUsers.countActiveAdmins() <= 1) {
      return { ok: false, message: 'Cannot remove or demote the last active admin' };
    }
  }
  return { ok: true };
}

/**
 * Who may set another panel user's password (or own).
 * Admin: anyone. Moderator: self + role user. User: self only.
 */
function canChangePassword(actor, target) {
  if (!actor || !target) return false;
  if (actor.id === target.id) return true;
  if (actor.role === 'admin') return true;
  if (actor.role === 'moderator') return target.role === 'user';
  return false;
}

/** Active users whose password the actor may change (for UI dropdown). */
function listPasswordTargets(actor) {
  if (!actor) return [];
  if (actor.role === 'user') {
    const self = db.panelUsers.findByIdPublic(actor.id);
    return self ? [self] : [];
  }
  return db.panelUsers.list().filter((u) => u && u.is_active && canChangePassword(actor, u));
}

/**
 * CIDR ranges the actor may allocate / assign client addresses from.
 * Empty assigned_cidrs → no ranges for any role (including admin/mod). No auto-all-pools.
 * @returns {string[]}
 */
function getAddressRangesForActor(actor) {
  if (!actor) return [];
  db.vpnPools.ensureSeeded();
  return Array.isArray(actor.assigned_cidrs) ? actor.assigned_cidrs.slice() : [];
}

module.exports = {
  ROLES,
  CAP,
  ROLE_CAPS,
  isValidRole,
  capabilitiesForRole,
  hasCapability,
  getActor,
  requireActor,
  requireCapability,
  canAccessClient,
  assertClientAccess,
  filterClientsForActor,
  enrichClientsWithUsers,
  listAssigneeUsers,
  setClientUsers,
  validateAdminInvariant,
  canChangePassword,
  listPasswordTargets,
  getAddressRangesForActor,
};
