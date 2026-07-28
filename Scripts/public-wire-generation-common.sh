#!/usr/bin/env bash
# Shared closed-profile preflight for public wire regeneration and verification.
# This file is sourced by commands that set `set -euo pipefail`.

public_wire_die() {
  echo "public wire generation: $*" >&2
  exit 1
}

public_wire_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
public_wire_profile="${public_wire_root}/Profiles/public-data-testing-2026-07-27.json"
public_wire_lexicon_manifest="${public_wire_root}/Profiles/public-data-testing-2026-07-27.lexicons.sha256"
public_wire_generated_manifest="${public_wire_root}/Profiles/public-data-testing-2026-07-27.generated-wire.sha256"
public_wire_reference_root="${PUBLIC_WIRE_REFERENCE_ROOT:-${public_wire_root}/.interop-cache/atproto-3f6c96d5d2d25438bd40fa89d6ecc37865f8e354}"
public_wire_sha256="${public_wire_root}/Scripts/sha256.sh"
readonly public_wire_expected_generator_commit="d011ccf0029457434e659ec48c8024baa7b5c4e4"
readonly public_wire_expected_lexicon_manifest_sha256="bd94660a2c2c05fc23185059329194ff6c29635f74ce2efcf97351c1be98fe97"

public_wire_profile_value() {
  python3 - "${public_wire_profile}" "$1" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as source:
    value = json.load(source).get(sys.argv[2])
if not isinstance(value, str) or not value:
    raise SystemExit("missing profile string")
print(value)
PY
}

public_wire_verify_source_manifest() {
  local actual count expected relative
  [[ -d "${public_wire_reference_root}/lexicons" ]] || public_wire_die "pinned reference lexicons are unavailable"
  [[ ! -L "${public_wire_lexicon_manifest}" ]] || public_wire_die "lexicon manifest may not be a symlink"
  actual="$("${public_wire_sha256}" "${public_wire_lexicon_manifest}" | awk '{print $1}')"
  [[ "${actual}" == "${public_wire_expected_lexicon_manifest_sha256}" ]] || public_wire_die "lexicon manifest checksum mismatch"
  count="$(wc -l <"${public_wire_lexicon_manifest}" | tr -d ' ')"
  [[ "${count}" == "14" ]] || public_wire_die "lexicon manifest must contain exactly 14 entries"
  expected="$(mktemp "${TMPDIR:-/tmp}/swan-public-selected.XXXXXX")"
  awk '{print $2}' "${public_wire_lexicon_manifest}" | LC_ALL=C sort >"${expected}"
  [[ "$(LC_ALL=C sort "${expected}" | uniq | wc -l | tr -d ' ')" == "14" ]] || public_wire_die "lexicon paths must be unique"
  while read -r _ relative; do
    case "${relative}" in
      com/atproto/repo/*.json|com/atproto/sync/*.json) ;;
      *) public_wire_die "lexicon path is outside the finite public namespaces" ;;
    esac
    [[ -f "${public_wire_reference_root}/lexicons/${relative}" ]] || public_wire_die "selected lexicon is missing"
    [[ ! -L "${public_wire_reference_root}/lexicons/${relative}" ]] || public_wire_die "selected lexicon may not be a symlink"
  done <"${public_wire_lexicon_manifest}"
  (
    cd "${public_wire_reference_root}/lexicons"
    "${public_wire_sha256}" --check "${public_wire_lexicon_manifest}"
  ) >/dev/null
}

public_wire_stage_lexicons() {
  local destination="$1" relative
  mkdir -p "${destination}/com/atproto/repo" "${destination}/com/atproto/sync"
  while read -r _ relative; do
    cp "${public_wire_reference_root}/lexicons/${relative}" "${destination}/${relative}"
  done <"${public_wire_lexicon_manifest}"
  local actual
  actual="$(find "${destination}/com/atproto/repo" "${destination}/com/atproto/sync" -type f -name '*.json' | wc -l | tr -d ' ')"
  [[ "${actual}" == "14" ]] || public_wire_die "staged lexicon inventory is not exactly 14 files"
}

public_wire_require_pinned_generator() {
  [[ -n "${PETREL_GENERATOR_ROOT:-}" ]] || public_wire_die "PETREL_GENERATOR_ROOT is required"
  [[ -d "${PETREL_GENERATOR_ROOT}" ]] || public_wire_die "PETREL_GENERATOR_ROOT is not a directory"
  local requested parent worktree_parent diff_summary
  requested="$(cd -P "${PETREL_GENERATOR_ROOT}" && pwd)"
  [[ -d "${requested}/.jj" && -f "${requested}/run.py" && -f "${requested}/generator/main.py" ]] || public_wire_die "Petrel generator workspace is incomplete"
  [[ "$(public_wire_profile_value petrelGeneratorCommit)" == "${public_wire_expected_generator_commit}" ]] || public_wire_die "profile generator pin drifted"
  parent="$(jj -R "${requested}" log -r '@-' --no-graph -T 'commit_id' | tr -d '\n')"
  worktree_parent="$(jj -R "${requested}" log -r '@' --no-graph -T 'parents.map(|p| p.commit_id()).join(" ")' | tr -d '\n')"
  diff_summary="$(jj -R "${requested}" diff -r @ --summary)"
  [[ "${parent}" == "${public_wire_expected_generator_commit}" ]] || public_wire_die "Petrel generator parent is not pinned"
  [[ "${worktree_parent}" == "${public_wire_expected_generator_commit}" ]] || public_wire_die "Petrel workspace is not a direct empty child"
  [[ -z "${diff_summary}" ]] || public_wire_die "Petrel generator workspace has source changes"
  rg --quiet 'emit_server_contracts' "${requested}/generator/main.py" || public_wire_die "server-contract capability is absent"
  rg --quiet 'ServerHandler' "${requested}/generator" || public_wire_die "server-contract templates are absent"
  PYTHONDONTWRITEBYTECODE=1 python3 "${requested}/run.py" --help >/dev/null || public_wire_die "Petrel generator is not runnable"
  PETREL_GENERATOR_ROOT="${requested}"
  PETREL_GENERATOR_ENTRYPOINT="${requested}/run.py"
}

public_wire_materialize_manifest() {
  local staged="$1" output="$2" destination="$3"
  python3 - "${public_wire_root}/PublicPetrelManifest.json" "${staged}" \
    "${public_wire_reference_root}/lexicons" "${output}" "${destination}" <<'PY'
import json
import sys
source, staged, reference, output, destination = sys.argv[1:]
with open(source, encoding="utf-8") as file:
    manifest = json.load(file)
manifest["lexicons"]["emit"] = [
    staged + "/com/atproto/repo",
    staged + "/com/atproto/sync",
]
manifest["lexicons"]["reference"] = [reference]
manifest["swift"]["output"] = output
with open(destination, "w", encoding="utf-8") as file:
    json.dump(manifest, file, indent=2, sort_keys=True)
    file.write("\n")
PY
}

public_wire_verify_checked_in_manifest() {
  local source_root="${1:-${public_wire_root}}"
  local expected actual
  expected="$(mktemp "${TMPDIR:-/tmp}/swan-public-expected.XXXXXX")"
  actual="$(mktemp "${TMPDIR:-/tmp}/swan-public-actual.XXXXXX")"
  awk '{print $2}' "${public_wire_generated_manifest}" | LC_ALL=C sort >"${expected}"
  (
    cd "${source_root}"
    find Sources/SwanPublicWire -type f -name '*.swift' -print | LC_ALL=C sort
  ) >"${actual}"
  diff -u "${expected}" "${actual}" >/dev/null || public_wire_die "generated Swift file-set differs from the immutable profile"
  (
    cd "${source_root}"
    "${public_wire_sha256}" --check "${public_wire_generated_manifest}"
  ) >/dev/null || public_wire_die "generated Swift checksum differs from the immutable profile"
}

public_wire_assert_contracts() {
  local output="$1"
  [[ "$(rg -l 'protocol ServerHandler' "${output}" | wc -l | tr -d ' ')" == "12" ]] || public_wire_die "all twelve ServerHandler contracts were not generated"
  [[ "$(rg -l 'XRPCMethodDescriptor' "${output}" | wc -l | tr -d ' ')" == "12" ]] || public_wire_die "all twelve endpoint descriptors were not generated"
}

public_wire_normalize_generated_sources() {
  local output="$1"
  # Petrel's pinned templates preserve horizontal whitespace on otherwise
  # empty lines. The checked-in overlay applies this deterministic,
  # semantics-preserving normalization after every generation.
  find "${output}" -type f -name '*.swift' -exec perl -pi -e 's/[ \t]+$//' {} +
  find "${output}" -type f -name '*.swift' -exec perl -0777 -pi -e 's/\n+\z/\n/' {} +
}
