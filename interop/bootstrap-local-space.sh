#!/usr/bin/env sh
set -eu

SWAN_BIN="${SWAN_BIN:-/usr/local/bin/swan}"
DATA_DIRECTORY="${DATA_DIRECTORY:-/var/lib/swan/data}"
SECRETS_DIR="${SWAN_INTEROP_SECRETS_DIR:?set SWAN_INTEROP_SECRETS_DIR to an ignored directory of interop secrets}"

read_secret() {
    path="$1"
    file="${SECRETS_DIR}/${path}"
    if [ ! -r "$file" ]; then
        echo "interop bootstrap secret missing" >&2
        exit 1
    fi
    tr -d '\r\n' < "$file"
}

ensure_account() {
    label="$1"
    handle="$2"
    expected_did="$3"
    revision="$4"
    password_file="$5"
    request_id="interop-${label}-plc"
    identity_file="${DATA_DIRECTORY}/interop-${label}-identity.json"
    account_lookup_output=""
    account_lookup_status=0
    if account_lookup_output="$(${SWAN_BIN} account show \
        --data-directory "${DATA_DIRECTORY}" \
        --handle "${handle}" 2>&1)"; then
        existing_account="${account_lookup_output}"
        actual_did="$(printf '%s\n' "$existing_account" | tr -d '\n' | sed -n 's/.*"did":"\([^"]*\)".*/\1/p')"
        if [ -z "$actual_did" ] || [ "$actual_did" != "$expected_did" ]; then
            echo "interop account DID does not match the owner-only bootstrap identity" >&2
            exit 1
        fi
        return 0
    else
        account_lookup_status="$?"
        # `account show` uses the same nonzero CLI status for a missing row
        # and for storage/configuration failures. Only the exact sanitized
        # not-found diagnostic is safe to treat as an invitation to prepare
        # an account; every other failure must stop bootstrap before it can
        # mutate a PLC journal or identity file.
        if [ "$account_lookup_status" -ne 64 ] || ! printf '%s\n' "$account_lookup_output" | grep -q '^Error: account not found$'; then
            echo "interop bootstrap could not inspect existing account" >&2
            exit 1
        fi
    fi

    # The Compose account must be a real PLC-backed identity. `install-local`
    # is intentionally offline and therefore leaves public reads fail-closed;
    # prepare/activate records the signed genesis and its request binding.
    "${SWAN_BIN}" account prepare-plc \
        --data-directory "${DATA_DIRECTORY}" \
        --handle "${handle}" \
        --request-id "${request_id}" \
        --pds-origin "https://swan.test" \
        --repository-revision "${revision}" \
        --plc-origin "http://reference-plc:2582" \
        --plc-laboratory \
        --plc-laboratory-allowlisted-host "reference-plc" \
        --plc-reference-compatibility "did-plc-server-0.0.1" \
        --operator-secret-file "${SECRETS_DIR}/operator-secret" \
        --account-kek-file "${SECRETS_DIR}/account-kek" \
        > "${identity_file}.tmp"
    chmod 0600 "${identity_file}.tmp"
    mv -f "${identity_file}.tmp" "${identity_file}"

    prepared_did="$(tr -d '\r\n' < "${identity_file}" | sed -n 's/.*"did":"\([^\"]*\)".*/\1/p')"
    if [ -z "$prepared_did" ] || [ "$prepared_did" != "$expected_did" ]; then
        echo "prepared PLC DID does not match the owner-only bootstrap identity" >&2
        exit 1
    fi

    "${SWAN_BIN}" account activate-plc \
        --data-directory "${DATA_DIRECTORY}" \
        --request-id "${request_id}" \
        --password-file "${password_file}" \
        --plc-origin "http://reference-plc:2582" \
        --plc-laboratory \
        --plc-laboratory-allowlisted-host "reference-plc" \
        --static-laboratory-handle-proof \
        --operator-secret-file "${SECRETS_DIR}/operator-secret" \
        --account-kek-file "${SECRETS_DIR}/account-kek" \
        >/dev/null
}

empty_revision="$(read_secret "public-repo-revision")"
if [ -z "${empty_revision}" ]; then
    echo "interop bootstrap secret public-repo-revision is empty" >&2
    exit 1
fi

ensure_account \
    authority \
    "$(read_secret authority.handle)" \
    "$(read_secret authority.did)" \
    "${empty_revision}" \
    "${SECRETS_DIR}/authority.password"

ensure_account \
    member \
    "$(read_secret member.handle)" \
    "$(read_secret member.did)" \
    "${empty_revision}" \
    "${SECRETS_DIR}/member.password"

echo "interop bootstrap complete"
