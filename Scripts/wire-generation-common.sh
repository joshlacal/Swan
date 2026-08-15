#!/usr/bin/env bash
# Shared, read-only preflight for both the mutating regeneration command and
# the disposable-output deterministic verifier. This file is sourced, not run.

wire_generation_die() {
  echo "wire generation: $*" >&2
  exit 1
}

wire_generation_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
wire_generation_profile="${wire_generation_root}/Profiles/permissioned-data-0016-2026-08-15.json"
readonly wire_generation_expected_petrel_generator_commit="710ecb0af23f07737c5c9b60eeed24092cb3aa3c"
readonly wire_generation_sha256="${wire_generation_root}/Scripts/sha256.sh"
readonly wire_generation_expected_profile_sha256="7c4733fdfb19246de785e7090b420b5cdfd95e2c9129de69625b860c35c11977"
readonly wire_generation_expected_petrel_manifest_sha256="70fa60badb45cfd17a261d3395b6c4ef80d94bf2d951034359ed1df93adad9ca"

wire_generation_profile_value() {
  local key="$1"
  python3 - "${wire_generation_profile}" "${key}" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    profile = json.load(source)
value = profile.get(sys.argv[2])
if not isinstance(value, str) or not value:
    raise SystemExit(f"profile is missing string key {sys.argv[2]!r}")
print(value)
PY
}

wire_generation_verify_profile_lexicons() {
  wire_generation_verify_successor_profile
  "${wire_generation_root}/Scripts/verify-profile.sh"
}

wire_generation_verify_successor_profile() {
  local actual
  [[ -f "${wire_generation_profile}" && ! -L "${wire_generation_profile}" ]] || wire_generation_die \
    "successor profile is missing or symlinked"
  actual="$("${wire_generation_sha256}" "${wire_generation_profile}" | awk '{print $1}')"
  [[ "${actual}" == "${wire_generation_expected_profile_sha256}" ]] || wire_generation_die \
    "successor profile checksum mismatch"
  [[ "$(wire_generation_profile_value petrelGeneratorCommit)" == \
      "${wire_generation_expected_petrel_generator_commit}" ]] || wire_generation_die \
    "successor profile generator pin mismatch"
  [[ "$(wire_generation_profile_value petrelManifest)" == "PetrelManifest.json" ]] || wire_generation_die \
    "successor profile Petrel manifest name mismatch"
  actual="$("${wire_generation_sha256}" "${wire_generation_root}/PetrelManifest.json" | awk '{print $1}')"
  [[ "${actual}" == "${wire_generation_expected_petrel_manifest_sha256}" ]] || wire_generation_die \
    "Petrel manifest checksum mismatch"
  [[ "$(wire_generation_profile_value petrelManifestSHA256)" == "${actual}" ]] || wire_generation_die \
    "successor profile Petrel manifest pin mismatch"
}

wire_generation_verify_legacy_profile_immutable() {
  local relative expected actual
  while read -r relative expected; do
    [[ -f "${wire_generation_root}/${relative}" ]] || wire_generation_die \
      "legacy profile artifact is missing: ${relative}"
    [[ ! -L "${wire_generation_root}/${relative}" ]] || wire_generation_die \
      "legacy profile artifact may not be a symlink: ${relative}"
    actual="$("${wire_generation_sha256}" "${wire_generation_root}/${relative}" | awk '{print $1}')"
    [[ "${actual}" == "${expected}" ]] || wire_generation_die \
      "legacy profile artifact changed: ${relative}"
  done <<EOF
Profiles/permissioned-data-0016-2026-07-03.json 30a696e78f62b11f22dd669f6ebb9f7e08d6c1d3346ebd71ad5cf0cd49b3f4d0
Profiles/permissioned-data-0016-2026-07-03.lexicons.sha256 9d36b3bf54e8c307b460dabaf93411bd75be44ba1737f29b13592b4b997b899f
Profiles/permissioned-data-0016-2026-07-03.generated-wire.sha256 c1d5697f351a4209c7f8a9faaf460d423f9f44f37845ae2c92e150e78c552609
Profiles/permissioned-data-0016-2026-07-30.json 431294d96a4a82f15fe5cd0807d89dbcd76d1768a1762d2a0c6a5905e8083988
Profiles/permissioned-data-0016-2026-07-30.lexicons.sha256 9d36b3bf54e8c307b460dabaf93411bd75be44ba1737f29b13592b4b997b899f
Profiles/permissioned-data-0016-2026-07-30.generated-wire.sha256 80f9f7b93127826d95d516a4a9d18b7ca245d82fc74f8fa484bbf3423d1f51db
EOF
}

wire_generation_verify_checked_in_manifest() {
  local output_root="${1:-${wire_generation_root}}" manifest manifest_hash
  wire_generation_verify_legacy_profile_immutable
  manifest="${wire_generation_root}/Profiles/permissioned-data-0016-2026-08-15.generated-wire.sha256"
  manifest_hash="$("${wire_generation_sha256}" "${manifest}" | awk '{print $1}')"
  [[ "$(wire_generation_profile_value generatedWireManifestSHA256)" == "${manifest_hash}" ]] || \
    wire_generation_die "successor generated-wire manifest pin mismatch"
  wire_generation_assert_exact_generated_file_set "${output_root}" "${manifest}"
  (
    cd "${output_root}"
    "${wire_generation_sha256}" --check "${manifest}"
  )
}

wire_generation_assert_exact_generated_file_set() {
  local output_root="$1" manifest="$2"
  (
  local expected actual
  expected="$(mktemp "${TMPDIR:-/tmp}/swan-wire-expected.XXXXXX")"
  actual="$(mktemp "${TMPDIR:-/tmp}/swan-wire-actual.XXXXXX")"
  trap "rm -f '${expected}' '${actual}'" EXIT
  awk '{print $2}' "${manifest}" | LC_ALL=C sort >"${expected}"
  (
    cd "${output_root}"
    find Sources/SwanSpacesWire -type f -name '*.swift' -print | LC_ALL=C sort
  ) >"${actual}"
  if ! diff -u "${expected}" "${actual}"; then
    wire_generation_die "generated Swift file-set differs from the immutable profile manifest"
  fi
  )
}

wire_generation_materialize_manifest() {
  local destination="$1" output="$2"
  python3 - "${wire_generation_root}/PetrelManifest.json" "${wire_generation_root}" "${destination}" "${output}" <<'PY'
import json
import os
import sys

source, swan_root, destination, output = sys.argv[1:]
with open(source, encoding="utf-8") as file:
    manifest = json.load(file)

for key in ("emit", "reference"):
    manifest["lexicons"][key] = [
        path if os.path.isabs(path) else os.path.normpath(os.path.join(swan_root, path))
        for path in manifest["lexicons"][key]
    ]
manifest["swift"]["output"] = output

with open(destination, "w", encoding="utf-8") as file:
    json.dump(manifest, file, indent=2, sort_keys=True)
    file.write("\n")
PY
}

wire_generation_require_pinned_generator() {
  local requested_root profile_commit parent_commit worktree_parent diff_summary

  [[ -n "${PETREL_GENERATOR_ROOT:-}" ]] || wire_generation_die \
    "PETREL_GENERATOR_ROOT is required; refusing to fall back to ../Petrel"
  [[ -d "${PETREL_GENERATOR_ROOT}" ]] || wire_generation_die \
    "PETREL_GENERATOR_ROOT is not a directory: ${PETREL_GENERATOR_ROOT}"

  requested_root="$(cd -P "${PETREL_GENERATOR_ROOT}" && pwd)"
  profile_commit="$(wire_generation_profile_value petrelGeneratorCommit)" || wire_generation_die \
    "could not read the pinned Petrel generator revision"
  [[ "${profile_commit}" == "${wire_generation_expected_petrel_generator_commit}" ]] || wire_generation_die \
    "profile Petrel generator revision ${profile_commit:-<none>} does not match immutable ${wire_generation_expected_petrel_generator_commit}"

  command -v jj >/dev/null 2>&1 || wire_generation_die "jj is required to validate Petrel's pinned revision"
  [[ -d "${requested_root}/.jj" ]] || wire_generation_die \
    "PETREL_GENERATOR_ROOT must be a jj workspace: ${requested_root}"
  [[ -f "${requested_root}/run.py" && -f "${requested_root}/generator/main.py" ]] || wire_generation_die \
    "Petrel generator entrypoint is missing under ${requested_root}"

  # The isolated workspace intentionally has an empty @ child whose parent is
  # the successor profile's pinned generator. Reject source edits or a
  # different parent before generation.
  parent_commit="$(jj -R "${requested_root}" log -r '@-' --no-graph -T 'commit_id' | tr -d '\n')"
  [[ "${parent_commit}" == "${wire_generation_expected_petrel_generator_commit}" ]] || wire_generation_die \
    "Petrel generator parent ${parent_commit:-<none>} does not match pinned ${wire_generation_expected_petrel_generator_commit}"
  worktree_parent="$(jj -R "${requested_root}" log -r '@' --no-graph -T 'parents.map(|p| p.commit_id()).join(" ")' | tr -d '\n')"
  [[ "${worktree_parent}" == "${wire_generation_expected_petrel_generator_commit}" ]] || wire_generation_die \
    "Petrel working-copy child must be empty and directly parented by ${wire_generation_expected_petrel_generator_commit}"
  diff_summary="$(jj -R "${requested_root}" diff -r @ --summary)"
  [[ -z "${diff_summary}" ]] || wire_generation_die \
    "Petrel working-copy child has source changes; refusing unpinned generation"

  # Validate the actual opt-in server-contract path and importable CLI without
  # executing generation or creating __pycache__ in the read-only source.
  rg --quiet 'emit_server_contracts' "${requested_root}/generator/main.py" || wire_generation_die \
    "Petrel generator lacks emit_server_contracts support"
  rg --quiet 'ServerHandler' "${requested_root}/generator" || wire_generation_die \
    "Petrel generator lacks ServerHandler contract templates"
  PYTHONDONTWRITEBYTECODE=1 python3 "${requested_root}/run.py" --help >/dev/null || wire_generation_die \
    "Petrel generator entrypoint is not runnable"

  readonly PETREL_GENERATOR_ROOT="${requested_root}"
  readonly PETREL_GENERATOR_ENTRYPOINT="${requested_root}/run.py"
  readonly PETREL_GENERATOR_COMMIT="${wire_generation_expected_petrel_generator_commit}"
}

wire_generation_assert_server_contracts() {
  local output="$1"
  [[ -d "${output}" ]] || wire_generation_die "generator did not create Swift output at ${output}"
  rg --quiet 'protocol ServerHandler' "${output}" || wire_generation_die \
    "generated output lacks required ServerHandler contracts"
  rg --quiet 'XRPCMethodDescriptor' "${output}" || wire_generation_die \
    "generated output lacks required endpoint descriptors"
}
