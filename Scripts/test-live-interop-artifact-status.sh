#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
temporary_directory="$(mktemp -d "${TMPDIR:-/tmp}/swan-artifact-status.XXXXXX")"
trap 'rm -rf "$temporary_directory"' EXIT

printf '%s\n' '{"status":"passed","recovery":{"status":"passed"}}' \
  >"${temporary_directory}/passed.json"
python3 "${root}/Scripts/validate-live-interop-artifact.py" \
  "${temporary_directory}/passed.json"

printf '%s\n' '{"status":"failed","recovery":{"status":"passed"}}' \
  >"${temporary_directory}/nested-pass.json"
if python3 "${root}/Scripts/validate-live-interop-artifact.py" \
  "${temporary_directory}/nested-pass.json"
then
  echo "root failure was authorized by a nested passed status" >&2
  exit 1
fi

printf '%s\n' '{"status":"passed"}{"status":"passed"}' \
  >"${temporary_directory}/trailing-document.json"
if python3 "${root}/Scripts/validate-live-interop-artifact.py" \
  "${temporary_directory}/trailing-document.json"
then
  echo "multiple JSON documents were accepted" >&2
  exit 1
fi

echo "LIVE INTEROP ARTIFACT ROOT STATUS VALIDATION OK"
