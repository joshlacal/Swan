#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${root}"

source "${root}/Scripts/wire-generation-common.sh"

# This command never points Petrel at checked-in output. It is suitable for CI
# after it has materialized the profile's reference archive and pinned Petrel
# workspace locally: all generated files live under this private temp tree.
wire_generation_verify_profile_lexicons
wire_generation_require_pinned_generator
wire_generation_verify_checked_in_manifest

temporary_root="$(mktemp -d "${TMPDIR:-/tmp}/swan-wire-generation.XXXXXX")"
trap 'rm -rf "${temporary_root}"' EXIT
temporary_manifest="${temporary_root}/PetrelManifest.json"
temporary_output="${temporary_root}/Generated"
python3 - \
  "${root}/PetrelManifest.json" \
  "${root}" \
  "${temporary_manifest}" \
  "${temporary_output}" <<'PY'
import json
import os
import sys

source, swan_root, destination, output = sys.argv[1:]
with open(source, encoding="utf-8") as file:
    manifest = json.load(file)

workspace_prefix = "../Swan/"
interop_root = os.path.join(swan_root, ".interop-cache")
for key in ("emit", "reference"):
    paths = manifest.get("lexicons", {}).get(key)
    if not isinstance(paths, list) or not paths:
        raise SystemExit(f"wire generation: manifest has no {key} lexicon inputs")

    staged_paths = []
    for path in paths:
        if not isinstance(path, str) or not path.startswith(workspace_prefix):
            raise SystemExit(
                f"wire generation: {key} lexicon input is not rooted in Swan: {path!r}"
            )
        staged_path = os.path.normpath(
            os.path.join(swan_root, path[len(workspace_prefix):])
        )
        if os.path.commonpath((interop_root, staged_path)) != interop_root:
            raise SystemExit(
                f"wire generation: {key} lexicon input escapes .interop-cache: {path}"
            )
        if not os.path.isdir(staged_path):
            raise SystemExit(
                "wire generation: required active-workspace lexicon directory "
                f"is missing: {staged_path}"
            )
        staged_paths.append(staged_path)
    manifest["lexicons"][key] = staged_paths

manifest["swift"]["output"] = output
with open(destination, "w", encoding="utf-8") as file:
    json.dump(manifest, file, indent=2, sort_keys=True)
    file.write("\n")
PY

(
  cd "${PETREL_GENERATOR_ROOT}"
  PYTHONDONTWRITEBYTECODE=1 python3 "${PETREL_GENERATOR_ENTRYPOINT}" \
    --manifest "${temporary_manifest}" \
    --language swift
)

wire_generation_assert_server_contracts "${temporary_output}"

if ! diff -ru "${root}/Sources/SwanSpacesWire/Generated" "${temporary_output}"; then
  echo "wire generation: pinned regeneration differs from checked-in Swift sources" >&2
  exit 1
fi

echo "pinned Swan wire generation verified without worktree mutation"
