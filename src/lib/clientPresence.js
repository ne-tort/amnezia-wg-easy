'use strict';

/** Default UI/API window: same as legacy AWG handshake indicator (10 minutes). */
const DEFAULT_ONLINE_WINDOW_MS = 10 * 60 * 1000;

/**
 * Merge AWG handshake + Xray activity into presence fields for the client list API/UI.
 * @param {{ latestHandshakeAt?: Date|null, latestXrayActivityAt?: Date|null }} input
 * @param {{ now?: number, windowMs?: number }} [opts]
 * @returns {{
 *   latestHandshakeAt: Date|null,
 *   latestXrayActivityAt: Date|null,
 *   latestActivityAt: Date|null,
 *   isOnline: boolean,
 *   onlineSources: Array<'awg'|'xray'>,
 * }}
 */
function computeClientPresence(input, opts = {}) {
  const now = opts.now != null ? opts.now : Date.now();
  const windowMs = opts.windowMs != null ? opts.windowMs : DEFAULT_ONLINE_WINDOW_MS;
  const latestHandshakeAt = input.latestHandshakeAt instanceof Date && !Number.isNaN(input.latestHandshakeAt.getTime())
    ? input.latestHandshakeAt
    : null;
  const latestXrayActivityAt = input.latestXrayActivityAt instanceof Date
    && !Number.isNaN(input.latestXrayActivityAt.getTime())
    ? input.latestXrayActivityAt
    : null;

  const onlineSources = [];
  if (latestHandshakeAt && (now - latestHandshakeAt.getTime()) < windowMs) {
    onlineSources.push('awg');
  }
  if (latestXrayActivityAt && (now - latestXrayActivityAt.getTime()) < windowMs) {
    onlineSources.push('xray');
  }

  const times = [];
  if (latestHandshakeAt) times.push(latestHandshakeAt.getTime());
  if (latestXrayActivityAt) times.push(latestXrayActivityAt.getTime());
  const latestActivityAt = times.length ? new Date(Math.max(...times)) : null;

  return {
    latestHandshakeAt,
    latestXrayActivityAt,
    latestActivityAt,
    isOnline: onlineSources.length > 0,
    onlineSources,
  };
}

module.exports = {
  DEFAULT_ONLINE_WINDOW_MS,
  computeClientPresence,
};
