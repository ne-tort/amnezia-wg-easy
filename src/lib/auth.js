'use strict';

const argon2 = require('argon2');
const crypto = require('node:crypto');

/**
 * Hash a password for storage. Uses argon2id.
 * Never log or return the hash to the client.
 */
async function hashPassword(password) {
  return argon2.hash(password, { type: argon2.argon2id });
}

/**
 * Verify a plain password against a stored hash. Returns true if match.
 */
async function verifyPassword(hash, password) {
  return argon2.verify(hash, password);
}

function generateUserId() {
  return crypto.randomUUID();
}

module.exports = {
  hashPassword,
  verifyPassword,
  generateUserId,
};
