#!/usr/bin/env bash
#
# Declare CloudGuard's Microsoft Graph application permissions on its own app
# registration.
#
# This is the half of the Azure deployment the ARM template cannot do. The
# template grants subscription access inside a *customer's* tenant; directory
# access comes from application permissions on CloudGuard's registration in
# CloudGuard's *own* tenant, and admin consent grants only what that
# registration declares at the moment the customer clicks it. A registration
# missing permissions therefore produces a consent screen that looks entirely
# normal, a connection that verifies, and a first scan that loses the whole
# identity category to "Insufficient privileges to complete the operation".
#
# Run it whenever REQUIRED_GRAPH_PERMISSIONS changes. It is idempotent: the
# manifest is declarative, so applying it twice is applying it once.
#
# What it deliberately does NOT do: grant consent. That is a Global
# Administrator of each customer tenant approving access to their own
# directory, and automating it away is not an oversight to be fixed -- it is
# the only thing standing between a multi-tenant app and every directory that
# ever installed it. Consent stays a human decision, per tenant, through the
# link on the connections page.
#
# Usage:
#   ./apply-app-registration.sh                # uses $AZURE_CLIENT_ID
#   ./apply-app-registration.sh <app-id-guid>

set -euo pipefail

MANIFEST="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/app-registration.json"
APP_ID="${1:-${AZURE_CLIENT_ID:-}}"

if [[ -z "$APP_ID" ]]; then
  cat >&2 <<'MSG'
No app id given.

Pass it as the first argument, or set AZURE_CLIENT_ID. The authoritative value
is the AZURE_CLIENT_ID variable on the deployed API service -- that is the exact
identity the running app authenticates with.

  ./apply-app-registration.sh 00000000-0000-0000-0000-000000000000
MSG
  exit 2
fi

if ! command -v az >/dev/null 2>&1; then
  echo "error: the Azure CLI is not installed. https://aka.ms/azure-cli" >&2
  exit 2
fi

if ! az account show >/dev/null 2>&1; then
  echo "error: not signed in. Run 'az login --allow-no-subscriptions' first." >&2
  exit 2
fi

signed_into="$(az account show --query tenantId -o tsv)"

# Checked before the update rather than after it fails. "Resource 'appid' does
# not exist or one of its queried reference-property objects are not present"
# is what Azure says when the app is real but lives in another directory, and
# it names neither the directory you are in nor the one you wanted.
if ! az ad app show --id "$APP_ID" >/dev/null 2>&1; then
  cat >&2 <<MSG
error: no app registration '$APP_ID' is visible in tenant $signed_into.

The registration lives in CloudGuard's home tenant, which is not necessarily
the tenant being scanned. Either you are signed into the wrong directory:

  az login --tenant <home-tenant-id> --allow-no-subscriptions

or the id is wrong. To list what is visible here:

  az ad app list --all --query "[?contains(displayName,'loud')].{name:displayName, appId:appId}" -o table
MSG
  exit 1
fi

app_name="$(az ad app show --id "$APP_ID" --query displayName -o tsv)"
echo "Applying Graph permissions to '$app_name' ($APP_ID) in tenant $signed_into"

az ad app update --id "$APP_ID" --required-resource-accesses "@$MANIFEST"

applied="$(az ad app show --id "$APP_ID" \
  --query "length(requiredResourceAccess[].resourceAccess[])" -o tsv)"
expected="$(grep -c '"type": "Role"' "$MANIFEST")"

if [[ "$applied" != "$expected" ]]; then
  echo "error: applied $applied permissions but the manifest declares $expected." >&2
  exit 1
fi

cat <<MSG

Declared $expected application permissions.

Not yet granted. Consent is a snapshot of what the registration declared when
it was taken, so every tenant that connected before this run is still on the
old set and must consent again -- including tenants that currently show as
verified. Re-run the consent link from the connections page for each.
MSG
