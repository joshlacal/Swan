#!/usr/bin/env bash
set -euo pipefail

# Run the seven semantic fault cells against fresh TypeScript-member /
# Swan-receiver repositories in an already-running disposable, recovery-
# qualified Compose project. Each child run restores Swan and Toxiproxy.

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

project_name="${SWAN_STATEFUL_FAULT_PROJECT:-}"
compose_file="${SWAN_STATEFUL_FAULT_COMPOSE_FILE:-}"
output_path="${SWAN_STATEFUL_FAULT_OUTPUT:-${root}/artifacts/live/stateful-cross-host-fault-matrix.json}"
skip_build="${SWAN_STATEFUL_FAULT_NO_BUILD:-0}"

[[ "$project_name" =~ ^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$ ]] || {
  echo "SWAN_STATEFUL_FAULT_PROJECT must name a running disposable Compose project" >&2
  exit 64
}
[[ "$compose_file" = /* && -f "$compose_file" ]] || {
  echo "SWAN_STATEFUL_FAULT_COMPOSE_FILE must be an absolute Compose override" >&2
  exit 64
}
[[ "$output_path" = /* ]] || {
  echo "SWAN_STATEFUL_FAULT_OUTPUT must be absolute" >&2
  exit 64
}
[[ -n "${SWAN_INTEROP_SECRETS_DIR:-}" ]] || {
  echo "SWAN_INTEROP_SECRETS_DIR is required" >&2
  exit 64
}
case "$skip_build" in
  0|1) ;;
  *) echo "SWAN_STATEFUL_FAULT_NO_BUILD must be 0 or 1" >&2; exit 64 ;;
esac

temporary_root="${root}/.interop-live"
mkdir -p "$temporary_root"
chmod 700 "$temporary_root"
temporary_directory="$(mktemp -d "${temporary_root}/stateful-fault-matrix.XXXXXX")"
cleanup() {
  local result=$?
  trap - EXIT INT TERM HUP
  if ((result != 0)); then
    failed_output="${output_path}.failed"
    mkdir -p "$(dirname "$failed_output")"
    if [[ -f "${runner_output:-}" ]]; then
      install -m 0600 "$runner_output" "$failed_output"
    elif [[ -f "${witness_input:-}" ]]; then
      install -m 0600 "$witness_input" "${failed_output}.witnesses"
    else
      child_failed="$(find "$temporary_directory" -maxdepth 1 -type f -name '*.failed' -print -quit)"
      if [[ -n "$child_failed" ]]; then
        install -m 0600 "$child_failed" "${failed_output}.child"
      fi
    fi
  fi
  rm -rf "$temporary_directory"
  exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

modes=(normal offline disconnected delayed duplicated reordered corrupted)
first=1
for mode in "${modes[@]}"; do
  mode_output="${temporary_directory}/${mode}.json"
  if ((first)) && [[ "$skip_build" == "0" ]]; then
    no_build=0
    first=0
  else
    no_build=1
  fi
  SWAN_DYNAMIC_DELEGATION_PROJECT="$project_name" \
  SWAN_DYNAMIC_DELEGATION_COMPOSE_FILE="$compose_file" \
  SWAN_DYNAMIC_DELEGATION_OUTPUT="$mode_output" \
  SWAN_DYNAMIC_DELEGATION_DIRECTION=member \
  SWAN_DYNAMIC_DELEGATION_STATEFUL=1 \
  SWAN_DYNAMIC_DELEGATION_RECOVERY=0 \
  SWAN_DYNAMIC_DELEGATION_FAULT_MODE="$mode" \
  SWAN_DYNAMIC_DELEGATION_NO_BUILD="$no_build" \
    ./Scripts/run-reference-member-dynamic-delegation-acceptance.sh
done

witness_input="${temporary_directory}/witness-input.json"
python3 - "$temporary_directory" "$witness_input" "${modes[@]}" <<'PY'
import json
import os
import sys

directory, output, *modes = sys.argv[1:]
cells = []
for mode in modes:
    path = os.path.join(directory, f"{mode}.json")
    with open(path, encoding="utf-8") as handle:
        artifact = json.load(handle)
    if artifact.get("status") != "passed":
        raise SystemExit(f"{mode} live prerequisite failed")
    witness = artifact.get("faultWitness")
    if not isinstance(witness, dict) or witness.get("mode") != mode:
        raise SystemExit(f"{mode} fault witness missing")
    cells.append(witness)
with open(output, "x", encoding="utf-8") as handle:
    json.dump(
        {"scenario": "typescript-member-swan-receiver-fault-matrix", "cells": cells},
        handle,
        sort_keys=True,
        separators=(",", ":"),
    )
    handle.write("\n")
os.chmod(output, 0o600)
PY

image="${project_name}-swan:latest"
docker image inspect "$image" >/dev/null
runner_output="${temporary_directory}/matrix.json"
docker run --rm \
  --read-only \
  --tmpfs /tmp:size=16m,mode=1777 \
  --mount "type=bind,src=${temporary_directory},dst=/run/matrix" \
  --entrypoint /usr/local/bin/swan \
  "$image" \
  lab stateful-fault-matrix \
  --input /run/matrix/witness-input.json \
  --output /run/matrix/matrix.json

mkdir -p "$(dirname "$output_path")"
install -m 0600 "$runner_output" "$output_path"
echo "STATEFUL CROSS-HOST FAULT MATRIX OK: artifact=${output_path}"
