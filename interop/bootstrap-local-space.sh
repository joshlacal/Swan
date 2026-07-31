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

identity_source_is_generated() {
    [ "$1" = "generate" ]
}

extract_identity_did() {
    # The CLI emits one sanitized JSON object. Keep this parser narrow so
    # bootstrap never accepts a DID-like value from an arbitrary field.
    tr -d '\r\n' < "$1" | sed -n 's/.*"did":"\([^"]*\)".*/\1/p'
}

require_identity_source() {
    label="$1"
    value="$2"
    case "$value" in
        generate)
            return 0
            ;;
        did:*)
            case "$value" in
                *[[:space:]]*)
                    echo "interop ${label} identity contains whitespace" >&2
                    exit 1
                    ;;
            esac
            return 0
            ;;
        *)
            echo "interop ${label} identity must be a canonical DID or generate" >&2
            exit 1
            ;;
    esac
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
        if [ -z "$actual_did" ]; then
            echo "interop account DID does not match the owner-only bootstrap identity" >&2
            exit 1
        fi
        if identity_source_is_generated "$expected_did"; then
            if [ ! -s "$identity_file" ]; then
                echo "interop generated identity record is missing" >&2
                exit 1
            fi
            durable_did="$(extract_identity_did "$identity_file")"
            if [ -z "$durable_did" ] || [ "$actual_did" != "$durable_did" ]; then
                echo "interop account DID does not match its durable generated identity" >&2
                exit 1
            fi
        elif [ "$actual_did" != "$expected_did" ]; then
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
    if identity_source_is_generated "$expected_did"; then
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
    else
        "${SWAN_BIN}" account prepare-plc \
            --data-directory "${DATA_DIRECTORY}" \
            --handle "${handle}" \
            --expected-did "${expected_did}" \
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
    fi
    chmod 0600 "${identity_file}.tmp"
    mv -f "${identity_file}.tmp" "${identity_file}"

    prepared_did="$(extract_identity_did "${identity_file}")"
    if [ -z "$prepared_did" ]; then
        echo "prepared PLC DID does not match the owner-only bootstrap identity" >&2
        exit 1
    fi
    if identity_source_is_generated "$expected_did"; then
        case "$prepared_did" in
            did:*) ;;
            *)
                echo "prepared PLC DID does not match the owner-only bootstrap identity" >&2
                exit 1
                ;;
        esac
    elif [ "$prepared_did" != "$expected_did" ]; then
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

authority_identity="$(read_secret authority.did)"
member_identity="$(read_secret member.did)"
require_identity_source authority "$authority_identity"
require_identity_source member "$member_identity"

ensure_account \
    authority \
    "$(read_secret authority.handle)" \
    "$authority_identity" \
    "${empty_revision}" \
    "${SECRETS_DIR}/authority.password"

ensure_account \
    member \
    "$(read_secret member.handle)" \
    "$member_identity" \
    "${empty_revision}" \
    "${SECRETS_DIR}/member.password"

echo "interop bootstrap complete"
