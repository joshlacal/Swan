#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

readonly commit="8b43a326dbbb394f63b6d68761553cdfe25532de"
readonly archive_sha256="bc6f57e6211560220ac49dc7d6b55c5a43291f1e1193113ce413ffe4478fdd0b"
readonly verifier="./interop/verify-reference-indigo.sh"
readonly source_cache="${SWAN_REFERENCE_INDIGO_CACHE_DIR:-.interop-cache}"

temporary_directory="$(mktemp -d "${TMPDIR:-/tmp}/swan-indigo-verifier.XXXXXX")"
trap 'rm -rf "$temporary_directory"' EXIT

if [[ ! -x "$verifier" ]]; then
  echo "reference Indigo verifier is missing or not executable" >&2
  exit 1
fi

if [[ ! -f "${source_cache}/indigo-${commit}.tar.gz" ]] \
  || [[ ! -d "${source_cache}/indigo-${commit}" ]]
then
  echo "pinned Indigo mutation fixture is unavailable; run interop/fetch-reference-indigo.sh" >&2
  exit 1
fi

new_fixture() {
  name="$1"
  fixture="${temporary_directory}/${name}"
  mkdir -p "$fixture"
  cp "${source_cache}/indigo-${commit}.tar.gz" "$fixture/"
  cp -R "${source_cache}/indigo-${commit}" "$fixture/"
  printf '%s\n' "$fixture"
}

require_rejection() {
  name="$1"
  expected="$2"
  shift 2

  output=""
  if output="$("$@" 2>&1)"; then
    echo "Indigo verifier accepted unsafe mutation: ${name}" >&2
    exit 1
  fi
  if [[ "$output" != *"$expected"* ]]; then
    echo "Indigo verifier rejected ${name} for the wrong reason" >&2
    echo "expected diagnostic: ${expected}" >&2
    printf '%s\n' "$output" >&2
    exit 1
  fi
}

rewrite_verifier_constant() {
  source="$1"
  destination="$2"
  old="$3"
  new="$4"
  cp "$source" "$destination"
  python3 - "$destination" "$old" "$new" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
old, new = sys.argv[2:]
contents = path.read_text(encoding="utf-8")
if contents.count(old) != 1:
    raise SystemExit(
        f"constant mutation expected exactly one occurrence, found {contents.count(old)}"
    )
path.write_text(contents.replace(old, new, 1), encoding="utf-8")
PY
  chmod 0755 "$destination"
}

baseline_fixture="$(new_fixture baseline)"
baseline_output="$($verifier --cache-dir "$baseline_fixture")"
if [[ "$baseline_output" != "REFERENCE INDIGO CACHE OK: ${commit}" ]]; then
  echo "Indigo verifier baseline did not report the pinned commit" >&2
  printf '%s\n' "$baseline_output" >&2
  exit 1
fi

wrong_commit_verifier="${temporary_directory}/verify-wrong-commit.sh"
rewrite_verifier_constant \
  "$verifier" \
  "$wrong_commit_verifier" \
  "$commit" \
  "0000000000000000000000000000000000000000"
require_rejection \
  wrong-commit \
  "pinned Indigo reference cache is unavailable" \
  "$wrong_commit_verifier" --cache-dir "$baseline_fixture"

wrong_checksum_verifier="${temporary_directory}/verify-wrong-checksum.sh"
rewrite_verifier_constant \
  "$verifier" \
  "$wrong_checksum_verifier" \
  "$archive_sha256" \
  "0000000000000000000000000000000000000000000000000000000000000000"
require_rejection \
  wrong-checksum \
  "pinned Indigo archive checksum mismatch" \
  "$wrong_checksum_verifier" --cache-dir "$baseline_fixture"

missing_archive_fixture="$(new_fixture missing-archive)"
rm "${missing_archive_fixture}/indigo-${commit}.tar.gz"
require_rejection \
  missing-archive \
  "pinned Indigo reference cache is unavailable" \
  "$verifier" --cache-dir "$missing_archive_fixture"

corrupt_archive_fixture="$(new_fixture corrupt-archive)"
printf 'not a gzip archive\n' >"${corrupt_archive_fixture}/indigo-${commit}.tar.gz"
require_rejection \
  corrupt-archive \
  "pinned Indigo archive checksum mismatch" \
  "$verifier" --cache-dir "$corrupt_archive_fixture"

missing_source_fixture="$(new_fixture missing-source)"
rm "${missing_source_fixture}/indigo-${commit}/cmd/relay/relay/slurper.go"
require_rejection \
  missing-required-relay-source \
  "pinned Indigo source is incomplete" \
  "$verifier" --cache-dir "$missing_source_fixture"

symlink_fixture="$(new_fixture symlink-source)"
rm "${symlink_fixture}/indigo-${commit}/cmd/relay/main.go"
ln -s README.md "${symlink_fixture}/indigo-${commit}/cmd/relay/main.go"
require_rejection \
  symlink-source \
  "pinned Indigo source contains a symlink" \
  "$verifier" --cache-dir "$symlink_fixture"

mismatch_fixture="$(new_fixture archive-tree-mismatch)"
printf '\n// mutation\n' >>"${mismatch_fixture}/indigo-${commit}/cmd/relay/main.go"
require_rejection \
  archive-tree-mismatch \
  "pinned Indigo source does not match its archive" \
  "$verifier" --cache-dir "$mismatch_fixture"

unexpected_cache_fixture="$(new_fixture unexpected-cache-layout)"
mkdir "${unexpected_cache_fixture}/.indigo-unexpected.staging"
require_rejection \
  unexpected-cache-layout \
  "unexpected Indigo cache entry" \
  "$verifier" --cache-dir "$unexpected_cache_fixture"

unexpected_archive_fixture="$(new_fixture unexpected-archive-layout)"
python3 - \
  "${unexpected_archive_fixture}/indigo-${commit}.tar.gz" \
  "${unexpected_archive_fixture}/unexpected-layout.tar.gz" <<'PY'
import pathlib
import tarfile
import sys

source = pathlib.Path(sys.argv[1])
destination = pathlib.Path(sys.argv[2])
with tarfile.open(source, "r:gz") as input_archive:
    with tarfile.open(destination, "w:gz") as output_archive:
        for member in input_archive.getmembers():
            member.name = member.name.replace("indigo-", "unexpected-", 1)
            extracted = input_archive.extractfile(member) if member.isfile() else None
            output_archive.addfile(member, extracted)
destination.replace(source)
PY
unexpected_sha256="$(shasum -a 256 "${unexpected_archive_fixture}/indigo-${commit}.tar.gz" | awk '{print $1}')"
unexpected_archive_verifier="${temporary_directory}/verify-unexpected-archive.sh"
rewrite_verifier_constant \
  "$verifier" \
  "$unexpected_archive_verifier" \
  "$archive_sha256" \
  "$unexpected_sha256"
require_rejection \
  unexpected-archive-layout \
  "pinned Indigo archive has unexpected layout" \
  "$unexpected_archive_verifier" --cache-dir "$unexpected_archive_fixture"

echo "REFERENCE INDIGO VERIFIER MUTATIONS OK"
