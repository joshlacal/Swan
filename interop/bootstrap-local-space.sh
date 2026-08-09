#!/usr/bin/env sh
set -eu
umask 077

SWAN_BIN="${SWAN_BIN:-/usr/local/bin/swan}"
DATA_DIRECTORY="${DATA_DIRECTORY:-/var/lib/swan/data}"
SECRETS_DIR="${SWAN_INTEROP_SECRETS_DIR:?set SWAN_INTEROP_SECRETS_DIR to an ignored directory of interop secrets}"

fail_input() {
    echo "$1" >&2
    exit 64
}

canonical_directory() {
    CDPATH='' cd -- "$1" 2>/dev/null && pwd -P
}

portable_mode() {
    if stat -c '%a' "$1" >/dev/null 2>&1; then
        stat -c '%a' "$1"
    else
        stat -f '%Lp' "$1"
    fi
}

portable_owner_id() {
    if stat -c '%u' "$1" >/dev/null 2>&1; then
        stat -c '%u' "$1"
    else
        stat -f '%u' "$1"
    fi
}

require_owner_only_directory() {
    directory="$1"
    diagnostic="$2"
    if [ ! -d "$directory" ] || [ -L "$directory" ] \
        || [ "$(portable_owner_id "$directory")" != "$(id -u)" ] \
        || [ "$(portable_mode "$directory")" != 700 ]; then
        fail_input "$diagnostic"
    fi
}

require_explicit_password_file() {
    candidate="$1"
    case "$candidate" in
        /*) ;;
        *) fail_input "explicit password file must use an absolute path" ;;
    esac
    if [ -L "$candidate" ]; then
        fail_input "explicit password file must not be a symlink"
    fi
    if [ ! -f "$candidate" ]; then
        fail_input "explicit password file is missing"
    fi
    if [ "$(portable_owner_id "$candidate")" != "$(id -u)" ]; then
        fail_input "explicit password file must be owner-only"
    fi
    mode="$(portable_mode "$candidate")"
    case "$mode" in
        400|600) ;;
        *) fail_input "explicit password file must be owner-only" ;;
    esac
    secret_root="$(canonical_directory "$SECRETS_DIR")" \
        || fail_input "explicit secret root is unavailable"
    candidate_parent="$(canonical_directory "$(dirname -- "$candidate")")" \
        || fail_input "explicit password file parent is unavailable"
    canonical_candidate="${candidate_parent}/$(basename -- "$candidate")"
    case "$canonical_candidate" in
        "${secret_root}"/*) ;;
        *) fail_input "explicit password file escapes the secret root" ;;
    esac
}

require_explicit_identity_file() {
    candidate="$1"
    case "$candidate" in
        /*) ;;
        *) fail_input "explicit identity file must use an absolute path" ;;
    esac
    if [ -L "$candidate" ] || [ -L "${candidate}.tmp" ]; then
        fail_input "explicit identity file must not be a symlink"
    fi
    data_root="$(canonical_directory "$DATA_DIRECTORY")" \
        || fail_input "explicit data root is unavailable"
    candidate_parent="$(canonical_directory "$(dirname -- "$candidate")")" \
        || fail_input "explicit identity file parent is unavailable"
    require_owner_only_directory "$candidate_parent" \
        "explicit identity file parent must be owner-only"
    canonical_candidate="${candidate_parent}/$(basename -- "$candidate")"
    case "$canonical_candidate" in
        "${data_root}"/*) ;;
        *) fail_input "explicit identity file escapes the data root" ;;
    esac
    if [ -e "$candidate" ]; then
        if [ ! -f "$candidate" ] \
            || [ "$(portable_owner_id "$candidate")" != "$(id -u)" ] \
            || [ "$(portable_mode "$candidate")" != 600 ]; then
            fail_input "explicit identity file must be owner-only"
        fi
    fi
    if [ -e "${candidate}.tmp" ]; then
        fail_input "explicit identity temporary file already exists"
    fi
}

validate_explicit_inputs() {
    case "$explicit_request_id" in
        ''|*[!A-Za-z0-9._:-]*) fail_input "explicit request ID is malformed" ;;
    esac
    if [ "${#explicit_request_id}" -gt 128 ]; then
        fail_input "explicit request ID is malformed"
    fi
    case "$explicit_handle" in
        ''|*[!a-z0-9.-]*|.*|*..*|*.) fail_input "explicit handle is malformed" ;;
    esac
    if [ "${#explicit_handle}" -gt 253 ]; then
        fail_input "explicit handle is malformed"
    fi
    case "$explicit_account_label" in
        ''|*[!A-Za-z0-9._-]*) fail_input "explicit account label is malformed" ;;
    esac
    if [ "${#explicit_account_label}" -gt 64 ]; then
        fail_input "explicit account label is malformed"
    fi
    require_owner_only_directory "$SECRETS_DIR" \
        "explicit secret root must be owner-only"
    require_explicit_password_file "$explicit_password_file"
    require_explicit_identity_file "$explicit_identity_file"
}

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
    request_id="$6"
    identity_file="$7"
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

explicit_mode=0
explicit_request_id=""
explicit_handle=""
explicit_password_file=""
explicit_account_label=""
explicit_identity_file=""
if [ "$#" -gt 0 ]; then
    explicit_mode=1
    while [ "$#" -gt 0 ]; do
        option="$1"
        if [ "$#" -lt 2 ]; then
            fail_input "explicit fresh-account inputs must be provided together"
        fi
        value="$2"
        shift 2
        case "$option" in
            --request-id)
                [ -z "$explicit_request_id" ] \
                    || fail_input "explicit request ID was provided more than once"
                explicit_request_id="$value"
                ;;
            --handle)
                [ -z "$explicit_handle" ] \
                    || fail_input "explicit handle was provided more than once"
                explicit_handle="$value"
                ;;
            --password-file)
                [ -z "$explicit_password_file" ] \
                    || fail_input "explicit password file was provided more than once"
                explicit_password_file="$value"
                ;;
            --account-label)
                [ -z "$explicit_account_label" ] \
                    || fail_input "explicit account label was provided more than once"
                explicit_account_label="$value"
                ;;
            --identity-file)
                [ -z "$explicit_identity_file" ] \
                    || fail_input "explicit identity file was provided more than once"
                explicit_identity_file="$value"
                ;;
            *) fail_input "unknown explicit fresh-account input" ;;
        esac
    done
    if [ -z "$explicit_request_id" ] || [ -z "$explicit_handle" ] \
        || [ -z "$explicit_password_file" ] || [ -z "$explicit_account_label" ] \
        || [ -z "$explicit_identity_file" ]; then
        fail_input "explicit fresh-account inputs must be provided together"
    fi
    validate_explicit_inputs
fi

empty_revision="$(read_secret "public-repo-revision")"
if [ -z "${empty_revision}" ]; then
    echo "interop bootstrap secret public-repo-revision is empty" >&2
    exit 1
fi

if [ "$explicit_mode" -eq 1 ]; then
    ensure_account \
        "$explicit_account_label" \
        "$explicit_handle" \
        generate \
        "$empty_revision" \
        "$explicit_password_file" \
        "$explicit_request_id" \
        "$explicit_identity_file"
else
    authority_identity="$(read_secret authority.did)"
    member_identity="$(read_secret member.did)"
    require_identity_source authority "$authority_identity"
    require_identity_source member "$member_identity"

    ensure_account \
        authority \
        "$(read_secret authority.handle)" \
        "$authority_identity" \
        "${empty_revision}" \
        "${SECRETS_DIR}/authority.password" \
        interop-authority-plc \
        "${DATA_DIRECTORY}/interop-authority-identity.json"

    ensure_account \
        member \
        "$(read_secret member.handle)" \
        "$member_identity" \
        "${empty_revision}" \
        "${SECRETS_DIR}/member.password" \
        interop-member-plc \
        "${DATA_DIRECTORY}/interop-member-identity.json"
fi

echo "interop bootstrap complete"
