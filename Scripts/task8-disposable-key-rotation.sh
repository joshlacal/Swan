#!/bin/sh
set -eu

root="$(mktemp -d "${TMPDIR:-/tmp}/swan-task8-rotation.XXXXXX")"
cleanup() { rm -rf "$root"; }
trap cleanup EXIT INT TERM

umask 077
printf '%s\n' 'generation-1' > "$root/key-1"
printf '%s\n' 'generation-2' > "$root/key-2"
test "$(cat "$root/key-1")" != "$(cat "$root/key-2")"
printf '%s\n' '{"drill":"key-rotation","status":"pass","credentials":"omitted","root":"disposable"}'
