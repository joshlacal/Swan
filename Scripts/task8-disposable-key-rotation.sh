#!/bin/sh
set -eu

root="$(mktemp -d "${TMPDIR:-/tmp}/swan-task8-rotation.XXXXXX")"
cleanup() { rm -rf "$root"; }
trap cleanup EXIT INT TERM

umask 077
printf '%s\n' '{"drill":"key-rotation","status":"deferred","reason":"storage-integrated-drill-not-assembled","credentials":"omitted","root":"disposable"}'
