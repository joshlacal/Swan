#!/usr/bin/env bash
# Shared closed-profile preflight for public wire regeneration and verification.
# This file is sourced by commands that set `set -euo pipefail`.

public_wire_die() {
  echo "public wire generation: $*" >&2
  exit 1
}

public_wire_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
public_wire_profile="${public_wire_root}/Profiles/public-data-testing-2026-08-05.json"
public_wire_petrel_manifest="${public_wire_root}/PublicPetrelManifest.json"
public_wire_lexicon_manifest="${public_wire_root}/Profiles/public-data-testing-2026-08-05.lexicons.sha256"
public_wire_generated_manifest="${public_wire_root}/Profiles/public-data-testing-2026-08-05.generated-wire.sha256"
public_wire_reference_root="${PUBLIC_WIRE_REFERENCE_ROOT:-${public_wire_root}/.interop-cache/atproto-3f6c96d5d2d25438bd40fa89d6ecc37865f8e354}"
public_wire_sha256="${public_wire_root}/Scripts/sha256.sh"
readonly public_wire_expected_profile_id="public-data-testing-2026-08-05"
readonly public_wire_expected_reference_commit="3f6c96d5d2d25438bd40fa89d6ecc37865f8e354"
readonly public_wire_expected_generator_commit="c2a1cdbee8c621c7682416114700f032cc7e2b37"
readonly public_wire_expected_profile_sha256="98bb8609b6dc2dfde2db34fb4f6ee1f56d18dab584fa7987b3d259f151f96121"
readonly public_wire_expected_petrel_manifest_sha256="cb39d0c4264d02540b67adbe668a1224753b507e35e11f19ba97879931804068"
readonly public_wire_expected_lexicon_manifest_sha256="2f14fbc29b2c3414baca5e659fb8dbe85f6b5a5252e13ff677b5b19d4309374d"
readonly public_wire_expected_generated_manifest_sha256="80a03ee8bcaed70008b74556add80108f5cf64d96932b21df60e2d18e247dcc7"
readonly public_wire_expected_legacy_profile_sha256="6effa7604b1c2613f6819a6c4bb7d21874bd5073db23556089060c495a3c91bf"
readonly public_wire_expected_legacy_lexicon_manifest_sha256="bd94660a2c2c05fc23185059329194ff6c29635f74ce2efcf97351c1be98fe97"
readonly public_wire_expected_legacy_generated_manifest_sha256="c68177a315f6a3d6f01419f48be5e0beedf76d1e4ae21ebe5de52ac49ad80d3b"
readonly public_wire_expected_frozen_profile_sha256="7d1a3046825aec4cd83a03fd43c48f305738172fd9c462822e0833977f9c7cf8"
readonly public_wire_expected_frozen_lexicon_manifest_sha256="fa89a31b4ac6421ebcacdd6a66de77ff191497f19361d41141f538477638bd75"
readonly public_wire_expected_frozen_generated_manifest_sha256="4703b4096dbf5dbc83e19d30c15539f426b73ebaca57c26bf82b5774440f2898"

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

public_wire_verify_legacy_profile_immutable() {
  local relative expected actual
  while read -r relative expected; do
    [[ -f "${public_wire_root}/${relative}" ]] || public_wire_die "legacy profile artifact is missing: ${relative}"
    [[ ! -L "${public_wire_root}/${relative}" ]] || public_wire_die "legacy profile artifact may not be a symlink: ${relative}"
    actual="$("${public_wire_sha256}" "${public_wire_root}/${relative}" | awk '{print $1}')"
    [[ "${actual}" == "${expected}" ]] || public_wire_die "legacy profile artifact changed: ${relative}"
  done <<EOF
Profiles/public-data-testing-2026-07-27.json ${public_wire_expected_legacy_profile_sha256}
Profiles/public-data-testing-2026-07-27.lexicons.sha256 ${public_wire_expected_legacy_lexicon_manifest_sha256}
Profiles/public-data-testing-2026-07-27.generated-wire.sha256 ${public_wire_expected_legacy_generated_manifest_sha256}
Profiles/public-data-testing-2026-07-30.json ${public_wire_expected_frozen_profile_sha256}
Profiles/public-data-testing-2026-07-30.lexicons.sha256 ${public_wire_expected_frozen_lexicon_manifest_sha256}
Profiles/public-data-testing-2026-07-30.generated-wire.sha256 ${public_wire_expected_frozen_generated_manifest_sha256}
EOF
}

public_wire_write_expected_lexicon_paths() {
  local destination="$1"
  python3 - "${destination}" <<'PY'
import sys

paths = [
    "com/atproto/repo/applyWrites.json",
    "com/atproto/repo/createRecord.json",
    "com/atproto/repo/defs.json",
    "com/atproto/repo/deleteRecord.json",
    "com/atproto/repo/describeRepo.json",
    "com/atproto/repo/getRecord.json",
    "com/atproto/repo/listRecords.json",
    "com/atproto/repo/putRecord.json",
    "com/atproto/repo/uploadBlob.json",
    "com/atproto/server/confirmEmail.json",
    "com/atproto/server/requestEmailConfirmation.json",
    "com/atproto/server/requestEmailUpdate.json",
    "com/atproto/server/requestPasswordReset.json",
    "com/atproto/server/resetPassword.json",
    "com/atproto/server/updateEmail.json",
    "com/atproto/sync/defs.json",
    "com/atproto/sync/getBlob.json",
    "com/atproto/sync/getLatestCommit.json",
    "com/atproto/sync/getRepo.json",
    "com/atproto/sync/getRepoStatus.json",
    "com/atproto/sync/subscribeRepos.json",
]
with open(sys.argv[1], "w", encoding="utf-8") as output:
    output.write("\n".join(paths) + "\n")
PY
}

public_wire_verify_profile_inventory() {
  python3 - "${public_wire_profile}" \
    "${public_wire_expected_profile_id}" \
    "${public_wire_expected_reference_commit}" \
    "${public_wire_expected_generator_commit}" \
    "${public_wire_expected_lexicon_manifest_sha256}" <<'PY'
import json
import sys

profile_path, expected_id, reference_commit, generator_commit, lexicon_hash = sys.argv[1:]
with open(profile_path, encoding="utf-8") as source:
    profile = json.load(source)

lexicons = [
    "com.atproto.repo.applyWrites",
    "com.atproto.repo.createRecord",
    "com.atproto.repo.defs",
    "com.atproto.repo.deleteRecord",
    "com.atproto.repo.describeRepo",
    "com.atproto.repo.getRecord",
    "com.atproto.repo.listRecords",
    "com.atproto.repo.putRecord",
    "com.atproto.repo.uploadBlob",
    "com.atproto.server.confirmEmail",
    "com.atproto.server.requestEmailConfirmation",
    "com.atproto.server.requestEmailUpdate",
    "com.atproto.server.requestPasswordReset",
    "com.atproto.server.resetPassword",
    "com.atproto.server.updateEmail",
    "com.atproto.sync.defs",
    "com.atproto.sync.getBlob",
    "com.atproto.sync.getLatestCommit",
    "com.atproto.sync.getRepo",
    "com.atproto.sync.getRepoStatus",
    "com.atproto.sync.subscribeRepos",
]
endpoints = [identifier for identifier in lexicons if not identifier.endswith(".defs")]

expected = {
    "id": expected_id,
    "referenceImplementationCommit": reference_commit,
    "petrelGeneratorCommit": generator_commit,
    "petrelManifest": "PublicPetrelManifest.json",
    "petrelManifestSHA256": "cb39d0c4264d02540b67adbe668a1224753b507e35e11f19ba97879931804068",
    "lexiconManifest": f"{expected_id}.lexicons.sha256",
    "lexiconManifestSHA256": lexicon_hash,
    "generatedWireManifest": f"{expected_id}.generated-wire.sha256",
}
for field, value in expected.items():
    if profile.get(field) != value:
        raise SystemExit(f"profile {field} drifted")
if profile.get("lexicons") != lexicons:
    raise SystemExit("profile lexicon inventory must be the exact ordered 21-file set")
if profile.get("endpoints") != endpoints:
    raise SystemExit("profile endpoint inventory must be the exact ordered 19-method set")
if len(set(lexicons)) != 21 or len(set(endpoints)) != 19:
    raise SystemExit("profile inventory contains duplicate identifiers")
PY
}

public_wire_verify_source_manifest() {
  local actual count expected actual_paths relative
  public_wire_verify_legacy_profile_immutable
  [[ -d "${public_wire_reference_root}/lexicons" ]] || public_wire_die "pinned reference lexicons are unavailable"
  [[ ! -L "${public_wire_profile}" ]] || public_wire_die "successor profile may not be a symlink"
  [[ ! -L "${public_wire_petrel_manifest}" ]] || public_wire_die "Petrel manifest may not be a symlink"
  [[ ! -L "${public_wire_lexicon_manifest}" ]] || public_wire_die "lexicon manifest may not be a symlink"
  actual="$("${public_wire_sha256}" "${public_wire_profile}" | awk '{print $1}')"
  [[ "${actual}" == "${public_wire_expected_profile_sha256}" ]] || public_wire_die "successor profile checksum mismatch"
  public_wire_verify_profile_inventory
  actual="$("${public_wire_sha256}" "${public_wire_petrel_manifest}" | awk '{print $1}')"
  [[ "${actual}" == "${public_wire_expected_petrel_manifest_sha256}" ]] || public_wire_die "Petrel manifest checksum mismatch"
  [[ "$(public_wire_profile_value petrelManifestSHA256)" == "${actual}" ]] || public_wire_die "profile Petrel manifest checksum drifted"

  actual="$("${public_wire_sha256}" "${public_wire_lexicon_manifest}" | awk '{print $1}')"
  [[ "${actual}" == "${public_wire_expected_lexicon_manifest_sha256}" ]] || public_wire_die "lexicon manifest checksum mismatch"
  [[ "$(public_wire_profile_value lexiconManifestSHA256)" == "${actual}" ]] || public_wire_die "profile lexicon manifest checksum drifted"
  count="$(wc -l <"${public_wire_lexicon_manifest}" | tr -d ' ')"
  [[ "${count}" == "21" ]] || public_wire_die "lexicon manifest must contain exactly 21 entries"

  expected="$(mktemp "${TMPDIR:-/tmp}/swan-public-expected-lexicons.XXXXXX")"
  actual_paths="$(mktemp "${TMPDIR:-/tmp}/swan-public-actual-lexicons.XXXXXX")"
  public_wire_write_expected_lexicon_paths "${expected}"
  awk '{print $2}' "${public_wire_lexicon_manifest}" >"${actual_paths}"
  diff -u "${expected}" "${actual_paths}" >/dev/null || public_wire_die "lexicon manifest is not the exact ordered 21-file set"
  [[ "$(LC_ALL=C sort "${actual_paths}" | uniq | wc -l | tr -d ' ')" == "21" ]] || public_wire_die "lexicon paths must be unique"

  while read -r _ relative; do
    [[ -f "${public_wire_reference_root}/lexicons/${relative}" ]] || public_wire_die "selected lexicon is missing"
    [[ ! -L "${public_wire_reference_root}/lexicons/${relative}" ]] || public_wire_die "selected lexicon may not be a symlink"
  done <"${public_wire_lexicon_manifest}"
  (
    cd "${public_wire_reference_root}/lexicons"
    "${public_wire_sha256}" --check "${public_wire_lexicon_manifest}"
  ) >/dev/null || public_wire_die "selected source lexicon checksum mismatch"
  rm -f "${expected}" "${actual_paths}"
}

public_wire_stage_lexicons() {
  local destination="$1" relative actual expected
  mkdir -p \
    "${destination}/com/atproto/repo" \
    "${destination}/com/atproto/server" \
    "${destination}/com/atproto/sync"
  while read -r _ relative; do
    cp "${public_wire_reference_root}/lexicons/${relative}" "${destination}/${relative}"
  done <"${public_wire_lexicon_manifest}"
  [[ -z "$(find "${destination}" -type l -print -quit)" ]] || public_wire_die "staged lexicons contain a symlink"
  actual="$(mktemp "${TMPDIR:-/tmp}/swan-public-staged-actual.XXXXXX")"
  expected="$(mktemp "${TMPDIR:-/tmp}/swan-public-staged-expected.XXXXXX")"
  (
    cd "${destination}" || public_wire_die "unable to inspect staged lexicons"
    find com -type f -name '*.json' -print | LC_ALL=C sort
  ) >"${actual}"
  public_wire_write_expected_lexicon_paths "${expected}"
  diff -u "${expected}" "${actual}" >/dev/null || public_wire_die "staged lexicon inventory is not the exact 21-file set"
  rm -f "${actual}" "${expected}"
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
  export PETREL_GENERATOR_ENTRYPOINT
}

public_wire_materialize_manifest() {
  local staged="$1" output="$2" destination="$3"
  python3 - "${public_wire_petrel_manifest}" "${staged}" \
    "${public_wire_reference_root}/lexicons" "${output}" "${destination}" <<'PY'
import json
import sys
source, staged, reference, output, destination = sys.argv[1:]
with open(source, encoding="utf-8") as file:
    manifest = json.load(file)
manifest["lexicons"]["emit"] = [
    staged + "/com/atproto/repo",
    staged + "/com/atproto/server",
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
  local expected actual manifest_hash line_count
  [[ ! -L "${public_wire_generated_manifest}" ]] || public_wire_die "generated manifest may not be a symlink"
  manifest_hash="$("${public_wire_sha256}" "${public_wire_generated_manifest}" | awk '{print $1}')"
  [[ "${manifest_hash}" == "${public_wire_expected_generated_manifest_sha256}" ]] || public_wire_die "generated manifest checksum mismatch"
  [[ "$(public_wire_profile_value generatedWireManifestSHA256)" == "${manifest_hash}" ]] || public_wire_die "profile generated manifest checksum drifted"
  line_count="$(wc -l <"${public_wire_generated_manifest}" | tr -d ' ')"
  [[ "${line_count}" == "24" ]] || public_wire_die "generated manifest must contain exactly 24 Swift sources"
  expected="$(mktemp "${TMPDIR:-/tmp}/swan-public-expected-generated.XXXXXX")"
  actual="$(mktemp "${TMPDIR:-/tmp}/swan-public-actual-generated.XXXXXX")"
  awk '{print $2}' "${public_wire_generated_manifest}" | LC_ALL=C sort >"${expected}"
  [[ "$(uniq "${expected}" | wc -l | tr -d ' ')" == "24" ]] || public_wire_die "generated manifest paths must be unique"
  (
    cd "${source_root}" || public_wire_die "unable to inspect generated source root"
    find Sources/SwanPublicWire -type f -name '*.swift' -print | LC_ALL=C sort
  ) >"${actual}"
  diff -u "${expected}" "${actual}" >/dev/null || public_wire_die "generated Swift file-set differs from the immutable profile"
  (
    cd "${source_root}"
    "${public_wire_sha256}" --check "${public_wire_generated_manifest}"
  ) >/dev/null || public_wire_die "generated Swift checksum differs from the immutable profile"
  rm -f "${expected}" "${actual}"
}

public_wire_assert_contracts() {
  local output="$1"
  [[ "$(rg -l 'protocol ServerHandler' "${output}" | wc -l | tr -d ' ')" == "19" ]] || public_wire_die "all nineteen ServerHandler contracts were not generated"
  [[ "$(rg -l 'XRPCMethodDescriptor' "${output}" | wc -l | tr -d ' ')" == "19" ]] || public_wire_die "all nineteen endpoint descriptors were not generated"
  [[ ! -e "${output}/Sources/Petrel" ]] || public_wire_die "Petrel core contracts were generated unexpectedly"
}

public_wire_normalize_generated_sources() {
  local output="$1"
  # Petrel's pinned templates preserve horizontal whitespace on otherwise
  # empty lines. The checked-in overlay applies this deterministic,
  # semantics-preserving normalization after every generation.
  find "${output}" -type f -name '*.swift' -exec perl -pi -e 's/[ \t]+$//' {} +
  find "${output}" -type f -name '*.swift' -exec perl -0777 -pi -e 's/\n+\z/\n/' {} +
}
