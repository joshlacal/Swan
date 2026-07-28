#!/usr/bin/env sh
set -eu

secrets_directory="${REFERENCE_PDS_SECRETS_DIR:-/run/secrets/reference-pds}"

load_secret() {
    variable="$1"
    name="$2"
    source="${secrets_directory}/${name}"

    if [ -L "$source" ] || [ ! -f "$source" ] || [ ! -r "$source" ]; then
        echo "reference PDS secret is missing or unsafe" >&2
        exit 1
    fi
    value="$(tr -d '\r\n' < "$source")"
    if [ -z "$value" ]; then
        echo "reference PDS secret is empty" >&2
        exit 1
    fi
    export "${variable}=${value}"
}

load_secret PDS_DPOP_SECRET pds-dpop-secret
load_secret PDS_JWT_SECRET pds-jwt-secret
load_secret PDS_ADMIN_PASSWORD pds-admin-password
load_secret PDS_REPO_SIGNING_KEY_K256_PRIVATE_KEY_HEX pds-repo-signing-key
load_secret PDS_PLC_ROTATION_KEY_K256_PRIVATE_KEY_HEX pds-plc-rotation-key

exec "$@"
