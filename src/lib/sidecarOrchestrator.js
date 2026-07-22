'use strict';

/**
 * Shared helpers for Amnezia sidecar orchestration (docker run, phase FSM, credentials).
 */

const { execFile } = require('node:child_process');
const { promisify } = require('node:util');
const crypto = require('node:crypto');

const execFileAsync = promisify(execFile);

const PANEL_CONTAINER = 'amnezia-awg';
const NGINX_CONTAINER = 'nginx';

function runCmd(bin, args, { timeout = 20_000 } = {}) {
  return execFileAsync(bin, args, { timeout, maxBuffer: 2 * 1024 * 1024 })
    .then(({ stdout, stderr }) => ({
      ok: true,
      stdout: String(stdout || ''),
      stderr: String(stderr || ''),
    }))
    .catch((err) => ({
      ok: false,
      stdout: String((err && err.stdout) || ''),
      stderr: String((err && err.stderr) || err.message || ''),
      error: err,
    }));
}

function createPhaseState() {
  return {
    phase: 'off',
    lastError: null,
    updatedAt: Date.now(),
    activeJob: null,
  };
}

function setPhaseState(state, next, err = null) {
  state.phase = next;
  if (err != null) state.lastError = String(err.message || err);
  else if (next === 'running' || next === 'off') state.lastError = null;
  state.updatedAt = Date.now();
}

function withJobFactory(getActiveJob, setActiveJob, _serviceLabel) {
  return function withJob(fn) {
    const existing = getActiveJob();
    if (existing) return existing;
    const job = Promise.resolve()
      .then(fn)
      .finally(() => {
        setActiveJob(null);
      });
    setActiveJob(job);
    return job;
  };
}

function clientUsername(name) {
  const base = String(name || 'client')
    .trim()
    .toLowerCase()
    .replace(/[^\w.-]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 48);
  return base || 'client';
}

function randomPassword(len = 16) {
  return crypto.randomBytes(Math.max(8, len)).toString('base64url').slice(0, len);
}

async function dockerContainerRunning(containerName) {
  const r = await runCmd('docker', [
    'inspect', '-f', '{{.State.Running}}', containerName,
  ]);
  return r.ok && r.stdout.trim() === 'true';
}

/** @returns {{ exists: boolean, status: string, running: boolean, restarting: boolean, restartCount: number }} */
async function dockerContainerState(containerName) {
  const r = await runCmd('docker', [
    'inspect', '-f',
    '{{.State.Status}} {{.State.Running}} {{.State.Restarting}} {{.RestartCount}}',
    containerName,
  ]);
  if (!r.ok) {
    return {
      exists: false, status: '', running: false, restarting: false, restartCount: 0,
    };
  }
  const parts = r.stdout.trim().split(/\s+/);
  return {
    exists: true,
    status: parts[0] || '',
    running: parts[1] === 'true',
    restarting: parts[2] === 'true',
    restartCount: parseInt(parts[3], 10) || 0,
  };
}

/** No Docker daemon auto-restart — healing only via explicit enable/repair in UI. */
const DOCKER_RESTART_POLICY = 'no';
const RECONCILE_INTERVAL_MS = 60_000;
const ENABLE_TIMEOUT_MS = 120_000;
const SMOKE_WAIT_MS = 45_000;
const CRASH_LOOP_RESTART_THRESHOLD = 5;

function containerLooksBroken(state) {
  if (!state || !state.exists) return true;
  if (state.restarting) return true;
  if (state.restartCount >= CRASH_LOOP_RESTART_THRESHOLD) return true;
  return !state.running;
}

/**
 * Observe-only health check for reconcile loops — never starts/recreates containers.
 * @param {string} containerName
 * @param {() => Promise<{ ok: boolean }>} runSmoke
 */
async function observeSidecarHealth(containerName, runSmoke) {
  const state = await dockerContainerState(containerName);
  let smoke = { ok: false, containerUp: false };
  if (state.running && !state.restarting) {
    smoke = await runSmoke();
  }
  let reason = null;
  if (!state.exists) {
    reason = new Error(`${containerName} container missing`);
  } else if (state.restarting) {
    reason = new Error(`${containerName} is restarting`);
  } else if (state.restartCount >= CRASH_LOOP_RESTART_THRESHOLD) {
    reason = new Error(`${containerName} crash loop (${state.restartCount} restarts)`);
  } else if (!state.running) {
    reason = new Error(`${containerName} not running (${state.status || 'down'})`);
  } else if (!smoke.ok) {
    const detail = smoke.dial && smoke.dial.out
      ? smoke.dial.out
      : (smoke.versionOut || 'smoke failed');
    reason = new Error(String(detail).trim().slice(0, 200));
  }
  return { state, smoke, unhealthy: !!reason, reason };
}

async function resolveAwgVolumeName() {
  const r = await runCmd('docker', [
    'inspect', '-f',
    '{{range .Mounts}}{{if eq .Destination "/opt/amnezia/awg"}}{{.Name}}{{end}}{{end}}',
    PANEL_CONTAINER,
  ]);
  const name = (r.ok ? r.stdout : '').trim();
  if (!name) {
    throw new Error('panel data volume not found (is amnezia-awg running with /opt/amnezia/awg?)');
  }
  return name;
}

async function resolveCertbotVolumeName() {
  const r = await runCmd('docker', [
    'inspect', '-f',
    '{{range .Mounts}}{{if eq .Destination "/etc/letsencrypt"}}{{.Name}}{{end}}{{end}}',
    NGINX_CONTAINER,
  ]);
  const name = (r.ok ? r.stdout : '').trim();
  if (!name) {
    throw new Error('certbot volume not found (is nginx running with /etc/letsencrypt?)');
  }
  return name;
}

module.exports = {
  PANEL_CONTAINER,
  NGINX_CONTAINER,
  runCmd,
  createPhaseState,
  setPhaseState,
  withJobFactory,
  clientUsername,
  randomPassword,
  dockerContainerRunning,
  dockerContainerState,
  containerLooksBroken,
  observeSidecarHealth,
  DOCKER_RESTART_POLICY,
  RECONCILE_INTERVAL_MS,
  ENABLE_TIMEOUT_MS,
  SMOKE_WAIT_MS,
  CRASH_LOOP_RESTART_THRESHOLD,
  resolveAwgVolumeName,
  resolveCertbotVolumeName,
};
