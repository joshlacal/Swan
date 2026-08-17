#!/bin/sh
set -eu

# This drill intentionally creates its own disposable root. It accepts no
# production data, credentials, or deployment paths.
root="$(mktemp -d "${TMPDIR:-/tmp}/swan-task8-drill.XXXXXX")"
cleanup() { rm -rf "$root"; }
trap cleanup EXIT INT TERM

mkdir -p "$root/source" "$root/archive" "$root/restore"
printf '%s\n' '{"kind":"task8-disposable-account","version":1}' > "$root/source/manifest.json"
printf '%s\n' '{"operation":"backup","status":"deferred","reason":"storage-integrated-drill-not-assembled"}' > "$root/archive/evidence.json"
cp "$root/source/manifest.json" "$root/restore/manifest.json"
cmp -s "$root/source/manifest.json" "$root/restore/manifest.json"

printf '%s\n' '{"drill":"backup-restore","status":"deferred","credentials":"omitted","root":"disposable"}'
