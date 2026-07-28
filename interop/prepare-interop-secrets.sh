#!/usr/bin/env sh
set -eu

external_directory="${EXTERNAL_SECRETS_DIR:-/external-secrets}"
runtime_directory="${SWAN_RUNTIME_SECRETS_DIR:-/prepared/swan-runtime}"
bootstrap_directory="${SWAN_BOOTSTRAP_SECRETS_DIR:-/prepared/swan-bootstrap}"
pds_directory="${REFERENCE_PDS_SECRETS_DIR:-/prepared/reference-pds}"

prepare_directory() {
    directory="$1"
    owner="$2"
    group="$3"
    install -d -o "$owner" -g "$group" -m 0700 "$directory"
    find "$directory" -mindepth 1 -maxdepth 1 -type f -delete
}

copy_secret() {
    name="$1"
    destination_directory="$2"
    owner="$3"
    group="$4"
    source="${external_directory}/${name}"

    if [ -L "$source" ] || [ ! -f "$source" ] || [ ! -s "$source" ] || [ ! -r "$source" ]; then
        echo "interop secret source is missing or unsafe" >&2
        exit 1
    fi
    if find "$source" -perm /077 -print -quit | grep -q .; then
        echo "interop secret source permissions are unsafe" >&2
        exit 1
    fi
    install -o "$owner" -g "$group" -m 0400 "$source" "${destination_directory}/${name}"
}

prepare_directory "$runtime_directory" swan swan
prepare_directory "$bootstrap_directory" swan swan
prepare_directory "$pds_directory" 1000 1000

for name in oauth-server-key account-kek; do
    copy_secret "$name" "$runtime_directory" swan swan
done

for name in \
    account-kek \
    operator-secret \
    authority.did \
    authority.handle \
    authority.password \
    member.did \
    member.handle \
    member.password \
    public-repo-revision
do
    copy_secret "$name" "$bootstrap_directory" swan swan
done

for name in \
    pds-dpop-secret \
    pds-jwt-secret \
    pds-admin-password \
    pds-repo-signing-key \
    pds-plc-rotation-key
do
    copy_secret "$name" "$pds_directory" 1000 1000
done

echo "interop secret copies prepared"
