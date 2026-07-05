'use strict';

/**
 * Bridge to capture_udp_sig (python -m siglab).
 * CAPTURE_UDP_SIG_ROOT — path to submodule checkout (optional).
 * Legacy: SIGLAB_ROOT, ./capture_udp_sig/
 */
const path = require('node:path');
const { execFileSync } = require('node:child_process');

function pythonBins() {
  const bins = [];
  if (process.env.PYTHON) bins.push(process.env.PYTHON);
  bins.push('python3', 'python');
  return [...new Set(bins.filter(Boolean))];
}

function labRoot() {
  const envRoot = process.env.CAPTURE_UDP_SIG_ROOT || process.env.SIGLAB_ROOT;
  if (envRoot) return path.resolve(envRoot);

  for (const name of ['capture_udp_sig', 'signature-lab']) {
    const candidate = path.join(process.cwd(), name);
    try {
      require('node:fs').accessSync(path.join(candidate, 'siglab', '__main__.py'));
      return candidate;
    } catch (_) {
      /* try next */
    }
  }
  return process.cwd();
}

function pythonEnv() {
  const root = labRoot();
  const env = { ...process.env, PYTHONPATH: root };
  const noBrowser = process.env.CAPTURE_NO_BROWSER || process.env.SIGLAB_NO_BROWSER;
  if (noBrowser) {
    env.CAPTURE_NO_BROWSER = noBrowser;
    env.SIGLAB_NO_BROWSER = noBrowser;
  }
  return { root, env };
}

function runSiglabJson(args) {
  const { root, env } = pythonEnv();
  const bins = pythonBins();
  for (const bin of bins) {
    try {
      const out = execFileSync(bin, ['-m', 'siglab', '--json', ...args], {
        encoding: 'utf8',
        cwd: root,
        env,
        windowsHide: true,
        maxBuffer: 8 * 1024 * 1024,
        timeout: 300000,
      });
      return JSON.parse(out.trim());
    } catch (_) {
      /* try next */
    }
  }
  return null;
}

function runLibraryApiJson(action, kwargs = {}) {
  const { root, env } = pythonEnv();
  const code = [
    'import json',
    'from python_signatures.library_api import invoke',
    `print(json.dumps(invoke(${JSON.stringify(action)}, **${JSON.stringify(kwargs)})))`,
  ].join('; ');
  const bins = pythonBins();
  for (const bin of bins) {
    try {
      const out = execFileSync(bin, ['-c', code], {
        encoding: 'utf8',
        cwd: root,
        env,
        windowsHide: true,
        maxBuffer: 8 * 1024 * 1024,
        timeout: 300000,
      });
      return JSON.parse(out.trim());
    } catch (_) {
      /* try next */
    }
  }
  return null;
}

function listProfilesMeta() {
  const viaSiglab = runSiglabJson(['list', '--available-only']);
  if (viaSiglab) return viaSiglab;
  const ids = runLibraryApiJson('known_profile_ids', { available_only: true });
  if (Array.isArray(ids)) {
    return { profile_ids: ids, default_profile: ids.includes('dns') ? 'dns' : ids[0] };
  }
  return null;
}

function captureProfile(profileId, signaturesPath) {
  return runLibraryApiJson('capture_profile', {
    profile_id: profileId,
    signatures_path: signaturesPath,
    merge_into_signatures: true,
    dry_run: process.env.CAPTURE_DRY_RUN === '1' || process.env.SIGLAB_DRY_RUN === '1',
  });
}

function regeneratePanelSignatures(outPath, configDir) {
  return runLibraryApiJson('regenerate_signatures', {
    out_path: outPath,
    config_dir: configDir,
    panel_format: true,
    available_only: true,
    dry_run: process.env.CAPTURE_DRY_RUN === '1' || process.env.SIGLAB_DRY_RUN === '1',
  });
}

module.exports = {
  labRoot,
  pythonEnv,
  runSiglabJson,
  runLibraryApiJson,
  listProfilesMeta,
  captureProfile,
  regeneratePanelSignatures,
};
