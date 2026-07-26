#!/usr/bin/env bash
set -euo pipefail

# The generator prerequisite is intentionally a separately reviewable Petrel
# jj change. Set PETREL_GENERATOR_ROOT to that checkout until it is accepted.
readonly generator_root="${PETREL_GENERATOR_ROOT:-../Petrel}"
readonly generator="${generator_root}/generator/main.py"

if [[ ! -f "${generator}" ]]; then
  echo "missing Petrel generator at ${generator}" >&2
  exit 1
fi

python3 "${generator}" --manifest PetrelManifest.json swift
if ! rg --quiet 'protocol ServerHandler' Sources/SwanSpacesWire/Generated; then
  echo "Petrel generator lacks the required emit_server_contracts support" >&2
  exit 1
fi
