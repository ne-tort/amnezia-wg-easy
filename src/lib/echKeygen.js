'use strict';

/**
 * Hysteria ECH key generation via sing-box (recommended by Hysteria 2.10 docs).
 * Generates ech.pem on volume; extracts base64 config list for hy2:// and clients.
 */

const { execFile } = require('node:child_process');
const { promisify } = require('node:util');
const fs = require('node:fs');
const path = require('node:path');

const execFileAsync = promisify(execFile);

const ECH_PUBLIC_NAME_KEY = 'amnezia_hysteria_ech_public_name';
const ECH_CONFIG_LIST_KEY = 'amnezia_hysteria_ech_config_list';
const SING_BOX_BIN = '/usr/local/bin/sing-box';
const SING_BOX_IMAGE = 'ghcr.io/sagernet/sing-box:latest';

/**
 * @param {string} pemText
 * @returns {string|null} single-line base64 config list for hy2:// ech=
 */
function extractConfigListBase64(pemText) {
  const match = String(pemText || '').match(
    /-----BEGIN ECH CONFIGS-----\r?\n([\s\S]*?)\r?\n-----END ECH CONFIGS-----/,
  );
  if (!match) return null;
  const inner = match[1].replace(/\s+/g, '');
  return inner || null;
}

/**
 * Parse hysteria server log: INFO ECH enabled ... {"configList": "..."}
 * @param {string} logText
 * @returns {string|null}
 */
function extractConfigListFromLog(logText) {
  const m = String(logText || '').match(/"configList"\s*:\s*"([^"]+)"/);
  return m ? m[1] : null;
}

/**
 * @returns {Promise<string|null>}
 */
async function resolveSingBoxBin() {
  if (fs.existsSync(SING_BOX_BIN)) return SING_BOX_BIN;
  try {
    const { stdout } = await execFileAsync('which', ['sing-box'], { timeout: 5000 });
    const p = stdout.trim();
    if (p) return p;
  } catch {
    /* optional */
  }
  return null;
}

/**
 * @param {import('node:child_process').execFile} runCmd docker helper from caller
 * @param {() => Promise<string>} resolveVolume
 */
async function generateEchPemViaDocker(publicName, runCmd, resolveVolume) {
  const volume = await resolveVolume();
  const { stdout, ok, stderr } = await runCmd('docker', [
    'run', '--rm',
    '--entrypoint', 'sing-box',
    SING_BOX_IMAGE,
    'generate', 'ech-keypair', publicName,
  ], { timeout: 120_000 });
  if (!ok) {
    throw Object.assign(
      new Error((stderr || stdout || 'sing-box docker ECH generation failed').trim().slice(0, 400)),
      { status: 500, code: 'HYSTERIA_ECH_GENERATE_FAILED' },
    );
  }
  if (!stdout || !extractConfigListBase64(stdout)) {
    throw Object.assign(new Error('sing-box produced invalid ECH PEM output'), {
      status: 500,
      code: 'HYSTERIA_ECH_GENERATE_FAILED',
    });
  }
  void volume;
  return stdout;
}

/**
 * @param {string} publicName
 * @param {string} outPath
 * @param {{ runCmd?: Function, resolveVolume?: () => Promise<string> }} [deps]
 * @returns {Promise<string>} full PEM text (CONFIGS + KEYS)
 */
async function generateEchPem(publicName, outPath, deps = {}) {
  const name = String(publicName || '').trim().toLowerCase();
  if (!name || !/^[a-z0-9.-]+$/.test(name)) {
    throw Object.assign(new Error('Invalid ECH public name'), {
      status: 400,
      code: 'HYSTERIA_ECH_BAD_PUBLIC_NAME',
    });
  }

  let stdout = '';
  const bin = await resolveSingBoxBin();
  if (bin) {
    const res = await execFileAsync(bin, ['generate', 'ech-keypair', name], {
      timeout: 60_000,
      maxBuffer: 1024 * 1024,
    });
    stdout = res.stdout;
  } else if (deps.runCmd && deps.resolveVolume) {
    stdout = await generateEchPemViaDocker(name, deps.runCmd, deps.resolveVolume);
  } else {
    throw Object.assign(new Error('sing-box binary not found; rebuild panel image or install sing-box'), {
      status: 500,
      code: 'HYSTERIA_ECH_NO_SINGBOX',
    });
  }

  if (!extractConfigListBase64(stdout)) {
    throw Object.assign(new Error('Failed to parse ECH config list from sing-box output'), {
      status: 500,
      code: 'HYSTERIA_ECH_GENERATE_FAILED',
    });
  }

  fs.mkdirSync(path.dirname(outPath), { recursive: true });
  fs.writeFileSync(outPath, stdout.endsWith('\n') ? stdout : `${stdout}\n`, 'utf8');
  return stdout;
}

/**
 * Pick decoy public name (outer SNI) — not the real server SNI.
 * @param {string|string[]} [excludeSni]
 * @param {{ getSetting: (k: string, fb?: string) => string, setSetting: (k: string, v: string) => void }} store
 */
function pickEchPublicName(excludeSni, store) {
  const stored = store.getSetting(ECH_PUBLIC_NAME_KEY, '').trim().toLowerCase();
  if (stored) return stored;
  try {
    const alt = require('./sniFinder').pickAlternateSni(excludeSni);
    if (alt) {
      store.setSetting(ECH_PUBLIC_NAME_KEY, alt);
      return alt;
    }
  } catch {
    /* optional */
  }
  const fallback = 'www.cloudflare.com';
  store.setSetting(ECH_PUBLIC_NAME_KEY, fallback);
  return fallback;
}

/**
 * Ensure ech.pem exists and DB has config list when ECH is enabled.
 * @param {{
 *   enabled: boolean,
 *   outPath: string,
 *   excludeSni?: string|string[],
 *   getSetting: (k: string, fb?: string) => string,
 *   setSetting: (k: string, v: string) => void,
 *   runCmd?: Function,
 *   resolveVolume?: () => Promise<string>,
 * }} opts
 * @returns {Promise<{ configList: string|null, publicName: string|null, reused: boolean }>}
 */
async function ensureEchMaterial(opts) {
  const {
    enabled, outPath, excludeSni, getSetting, setSetting, runCmd, resolveVolume,
  } = opts;
  if (!enabled) {
    return { configList: null, publicName: null, reused: false };
  }

  const store = { getSetting, setSetting };
  fs.mkdirSync(path.dirname(outPath), { recursive: true });

  if (fs.existsSync(outPath)) {
    const pemText = fs.readFileSync(outPath, 'utf8');
    const configList = extractConfigListBase64(pemText);
    if (configList) {
      const publicName = getSetting(ECH_PUBLIC_NAME_KEY, '').trim().toLowerCase()
        || pickEchPublicName(excludeSni, store);
      setSetting(ECH_CONFIG_LIST_KEY, configList);
      return { configList, publicName, reused: true };
    }
  }

  const publicName = pickEchPublicName(excludeSni, store);
  const pemText = await generateEchPem(publicName, outPath, { runCmd, resolveVolume });
  const configList = extractConfigListBase64(pemText);
  if (!configList) {
    throw Object.assign(new Error('Failed to parse ECH config list after generation'), {
      status: 500,
      code: 'HYSTERIA_ECH_GENERATE_FAILED',
    });
  }
  setSetting(ECH_PUBLIC_NAME_KEY, publicName);
  setSetting(ECH_CONFIG_LIST_KEY, configList);
  return { configList, publicName, reused: false };
}

module.exports = {
  ECH_PUBLIC_NAME_KEY,
  ECH_CONFIG_LIST_KEY,
  extractConfigListBase64,
  extractConfigListFromLog,
  pickEchPublicName,
  generateEchPem,
  ensureEchMaterial,
  resolveSingBoxBin,
};
