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
  resolveAwgVolumeName,
  resolveCertbotVolumeName,
};
