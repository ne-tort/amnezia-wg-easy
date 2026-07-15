'use strict';

const fs = require('fs');
const path = require('path');
const { ROLES } = require('./acl');

const FALLBACK = Object.freeze({
  admin: { en: 'Administrator', ru: 'Администратор' },
  moderator: { en: 'Moderator', ru: 'Модератор' },
  user: { en: 'User', ru: 'Пользователь' },
});

const CANDIDATE_PATHS = [
  // Docker: COPY src → /app, seeds under /app/config
  path.join(__dirname, '..', 'config', 'roles.labels.json'),
  // Local: src/lib → repo root config/
  path.join(__dirname, '..', '..', 'config', 'roles.labels.json'),
];

let cached = null;
let resolvedPath = null;

function loadRoleLabelsFile() {
  if (cached) return cached;
  for (const p of CANDIDATE_PATHS) {
    try {
      if (fs.existsSync(p)) {
        cached = JSON.parse(fs.readFileSync(p, 'utf8'));
        resolvedPath = p;
        return cached;
      }
    } catch (_) {
      // try next
    }
  }
  cached = { ...FALLBACK };
  resolvedPath = null;
  return cached;
}

/**
 * @param {string} [lang] e.g. en, ru
 * @returns {Record<string, string>}
 */
function getRoleLabels(lang) {
  const raw = loadRoleLabelsFile();
  const locale = typeof lang === 'string' && lang.toLowerCase().startsWith('ru') ? 'ru' : 'en';
  const out = {};
  for (const role of ROLES) {
    const entry = raw[role] || FALLBACK[role];
    out[role] = (entry && (entry[locale] || entry.en)) || role;
  }
  return out;
}

module.exports = {
  getRoleLabels,
  get labelsPath() {
    loadRoleLabelsFile();
    return resolvedPath || CANDIDATE_PATHS[0];
  },
};
