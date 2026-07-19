#!/usr/bin/env bash
# Regression: clear poisoned admin@localhost; never use @example.com; empty = no contact.
set -euo pipefail
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
export ACME_HOME="$TMP/acme"
mkdir -p "$ACME_HOME/ca/acme-v02.api.letsencrypt.org/directory"
printf "ACCOUNT_EMAIL='admin@localhost'\n" >"$ACME_HOME/account.conf"
printf "CA_EMAIL='admin@localhost'\n" >"$ACME_HOME/ca/acme-v02.api.letsencrypt.org/directory/ca.conf"

eval "$(sed -n '/^# --- le-contact helpers ---/,/^acme_bin()/{ /^acme_bin()/q; p; }' install.sh)"
logi() { echo "[i] $*"; }
logw() { echo "[w] $*"; }
loge() { echo "[e] $*"; }

email=$(resolve_le_contact_email "")
[[ -z "$email" ]] || { echo "FAIL resolve empty expected blank got: $email"; exit 1; }
email=$(resolve_le_contact_email "admin@localhost")
[[ -z "$email" ]] || { echo "FAIL resolve localhost: $email"; exit 1; }
email=$(resolve_le_contact_email "noreply@example.com")
[[ -z "$email" ]] || { echo "FAIL resolve example.com must be rejected: $email"; exit 1; }
email=$(resolve_le_contact_email "you@domain.tld")
[[ "$email" == "you@domain.tld" ]] || { echo "FAIL resolve good: $email"; exit 1; }

set_acme_contact_email_everywhere ""
grep -q "ACCOUNT_EMAIL=''" "$ACME_HOME/account.conf" || { echo FAIL account.conf; cat "$ACME_HOME/account.conf"; exit 1; }
grep -q "CA_EMAIL=''" "$ACME_HOME/ca/acme-v02.api.letsencrypt.org/directory/ca.conf" || { echo FAIL ca.conf; cat "$ACME_HOME/ca/"*/*/ca.conf; exit 1; }
# shellcheck disable=SC1090
. "$ACME_HOME/account.conf"
# shellcheck disable=SC1090
. "$ACME_HOME/ca/acme-v02.api.letsencrypt.org/directory/ca.conf"
[[ -z "${ACCOUNT_EMAIL}" ]] || { echo "FAIL sourced ACCOUNT_EMAIL=$ACCOUNT_EMAIL"; exit 1; }
[[ -z "${CA_EMAIL}" ]] || { echo "FAIL sourced CA_EMAIL=$CA_EMAIL"; exit 1; }

set_acme_contact_email_everywhere "you@domain.tld"
# shellcheck disable=SC1090
. "$ACME_HOME/account.conf"
# shellcheck disable=SC1090
. "$ACME_HOME/ca/acme-v02.api.letsencrypt.org/directory/ca.conf"
[[ "${ACCOUNT_EMAIL}" == "you@domain.tld" ]] || { echo "FAIL good ACCOUNT=$ACCOUNT_EMAIL"; exit 1; }
[[ "${CA_EMAIL}" == "you@domain.tld" ]] || { echo "FAIL good CA=$CA_EMAIL"; exit 1; }

echo "OK le-contact regression"
