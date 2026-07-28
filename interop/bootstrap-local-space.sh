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
    revision="$3"
    password_file="$4"
    request_id="interop-${label}-plc"
    identity_file="${DATA_DIRECTORY}/interop-${label}-identity.json"
    if "${SWAN_BIN}" account show --data-directory "${DATA_DIRECTORY}" --handle "${handle}" >/dev/null 2>&1; then
        return 0
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
    "${empty_revision}" \
    "${SECRETS_DIR}/authority.password"

ensure_account \
    member \
    "$(read_secret member.handle)" \
    "${empty_revision}" \
    "${SECRETS_DIR}/member.password"

echo "interop bootstrap complete"
