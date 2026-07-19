#!/usr/bin/env bash
# Live LE account register against real ACME with poisoned admin@localhost conf.
set -euo pipefail
export HOME=/root
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq curl ca-certificates cron >/dev/null
curl -fsSL https://get.acme.sh | sh -s email=admin@localhost --force
# shellcheck disable=SC1091
. /root/.acme.sh/acme.sh.env || true
ACME_HOME=/root/.acme.sh
eval "$(sed -n '/^# --- le-contact helpers ---/,/^acme_bin()/{ /^acme_bin()/q; p; }' /install.sh)"
logi() { echo "[i] $*"; }
logw() { echo "[w] $*"; }
loge() { echo "[e] $*"; }
acme_bin() { echo /root/.acme.sh/acme.sh; }

echo "BEFORE:"
grep -R "EMAIL=" /root/.acme.sh/account.conf /root/.acme.sh/ca 2>/dev/null | head -30 || true

ensure_acme_le_account ""
rc=$?

echo "AFTER:"
grep -R "EMAIL=" /root/.acme.sh/account.conf /root/.acme.sh/ca 2>/dev/null | head -30 || true

if grep -R "admin@localhost" /root/.acme.sh/account.conf /root/.acme.sh/ca 2>/dev/null | grep -E 'ACCOUNT_EMAIL|CA_EMAIL'; then
  echo "FAIL: admin@localhost still present"
  exit 1
fi
if grep -R "example.com" /root/.acme.sh/account.conf /root/.acme.sh/ca 2>/dev/null | grep -E 'ACCOUNT_EMAIL|CA_EMAIL'; then
  echo "FAIL: example.com contact still present"
  exit 1
fi

if [[ "$rc" -ne 0 ]]; then
  echo "FAIL: ensure_acme_le_account returned $rc"
  exit 1
fi

# Account must exist (registered without contact)
if ! find /root/.acme.sh/ca -name account.json 2>/dev/null | grep -q .; then
  echo "FAIL: no account.json after register"
  exit 1
fi
echo "OK live LE register"
