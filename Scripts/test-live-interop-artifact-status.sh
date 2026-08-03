#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
temporary_directory="$(mktemp -d "${TMPDIR:-/tmp}/swan-artifact-status.XXXXXX")"
trap 'rm -rf "$temporary_directory"' EXIT

printf '%s\n' '{"scenario":"baseline","status":"passed","recovery":{"status":"passed"}}' \
  >"${temporary_directory}/passed.json"
python3 "${root}/Scripts/validate-live-interop-artifact.py" \
  "${temporary_directory}/passed.json"

printf '%s\n' '{"status":"passed"}' \
  >"${temporary_directory}/status-only.json"
if python3 "${root}/Scripts/validate-live-interop-artifact.py" \
  "${temporary_directory}/status-only.json"
then
  echo "status-only artifact was accepted without scenario evidence" >&2
  exit 1
fi

printf '%s\n' '{"scenario":"duplicated","status":"passed","faultWitness":{"mode":"duplicated","before":{"generation":1,"revision":"222222222222a","commitment":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"intended":{"generation":1,"revision":"222222222222b","commitment":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},"afterFault":{"generation":1,"revision":"222222222222b","commitment":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},"afterHeal":{"generation":1,"revision":"222222222222b","commitment":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},"faultObserved":true,"invalidDeliveryRejected":false}}' \
  >"${temporary_directory}/false-fault-witness.json"
if python3 "${root}/Scripts/validate-live-interop-artifact.py" \
  "${temporary_directory}/false-fault-witness.json"
then
  echo "false duplicated-mode witness was accepted" >&2
  exit 1
fi

sed 's/"invalidDeliveryRejected":false/"invalidDeliveryRejected":true/' \
  "${temporary_directory}/false-fault-witness.json" \
  >"${temporary_directory}/valid-fault-witness.json"
python3 "${root}/Scripts/validate-live-interop-artifact.py" \
  "${temporary_directory}/valid-fault-witness.json"

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
