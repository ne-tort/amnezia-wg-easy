'use strict';

/**
 * Allocate free TCP listen ports in 20000–50000 for sidecar containers (Xray / MTProto).
 */

const PORT_MIN = 20000;
const PORT_MAX = 50000;

function randomInRange() {
  return PORT_MIN + Math.floor(Math.random() * (PORT_MAX - PORT_MIN + 1));
}

/**
 * @param {number[]} exclude
 * @param {number} [preferred]
 * @returns {number}
 */
function allocateInternalPort(exclude = [], preferred) {
  const blocked = new Set(
    (exclude || [])
      .map((n) => parseInt(String(n), 10))
      .filter((n) => Number.isFinite(n) && n > 0),
  );
  // Demux / common panel ports must never be chosen as internal listen.
  for (const p of [80, 443, 8443]) blocked.add(p);

  const pref = preferred != null ? parseInt(String(preferred), 10) : NaN;
  if (
    Number.isFinite(pref)
    && pref >= PORT_MIN
    && pref <= PORT_MAX
    && !blocked.has(pref)
  ) {
    return pref;
  }

  for (let i = 0; i < 64; i++) {
    const n = randomInRange();
    if (!blocked.has(n)) return n;
  }
  // Extremely unlikely
  for (let n = PORT_MIN; n <= PORT_MAX; n++) {
    if (!blocked.has(n)) return n;
  }
  throw new Error('No free internal TCP port in 20000–50000');
}

/**
 * Legacy host-published Xray used 443; demux owns 443 — force reallocation.
 */
function needsInternalRealloc(port) {
  const n = parseInt(String(port), 10);
  if (!Number.isFinite(n) || n < 1 || n > 65535) return true;
  if (n === 443 || n === 80 || n === 8443) return true;
  if (n < PORT_MIN || n > PORT_MAX) return true;
  return false;
}

module.exports = {
  PORT_MIN,
  PORT_MAX,
  allocateInternalPort,
  needsInternalRealloc,
};
