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
    did="$1"
    handle="$2"
    revision="$3"
    password_file="$4"
    if "${SWAN_BIN}" account show --data-directory "${DATA_DIRECTORY}" --did "${did}" >/dev/null 2>&1; then
        return 0
    fi
    "${SWAN_BIN}" account install-local \
        --data-directory "${DATA_DIRECTORY}" \
        --did "${did}" \
        --handle "${handle}" \
        --revision "${revision}" \
        --password-file "${password_file}" \
        --operator-secret-file "${SECRETS_DIR}/operator-secret" \
        --account-kek-file "${SECRETS_DIR}/account-kek"
}

empty_revision="$(read_secret "public-repo-revision")"
if [ -z "${empty_revision}" ]; then
    echo "interop bootstrap secret public-repo-revision is empty" >&2
    exit 1
fi

ensure_account \
    "$(read_secret authority.did)" \
    "$(read_secret authority.handle)" \
    "${empty_revision}" \
    "${SECRETS_DIR}/authority.password"

ensure_account \
    "$(read_secret member.did)" \
    "$(read_secret member.handle)" \
    "${empty_revision}" \
    "${SECRETS_DIR}/member.password"

echo "interop bootstrap complete"
