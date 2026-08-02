#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
preparer="${script_dir}/prepare-disposable-interop-secrets.sh"
test_root="$(mktemp -d)"
test_root="$(cd "$test_root" && pwd -P)"
trap 'rm -rf -- "$test_root"' EXIT

direct_target="${test_root}/direct-secrets"
reported_target="$($preparer "$direct_target")"
[[ "$reported_target" == "$direct_target" ]]
[[ "$(stat -f '%Lp' "$direct_target" 2>/dev/null || stat -c '%a' "$direct_target")" == "700" ]]
[[ "$(find "$direct_target" -type f | wc -l | tr -d ' ')" == "16" ]]
if find "$direct_target" -type f ! -perm 0600 | grep -q .; then
  echo "generated secret files must be owner-only" >&2
  exit 1
fi

mkdir "${test_root}/real-parent"
ln -s "${test_root}/real-parent" "${test_root}/linked-parent"
redirected_target="${test_root}/linked-parent/redirected-secrets"
if "$preparer" "$redirected_target" >/dev/null 2>&1; then
  echo "symlinked ancestor unexpectedly accepted" >&2
  exit 1
fi
if [[ -e "${test_root}/real-parent/redirected-secrets" ]]; then
  echo "rejected symlink path still created secret files" >&2
  exit 1
fi

ln -s "${test_root}/missing-target" "${test_root}/dangling-target"
if "$preparer" "${test_root}/dangling-target" >/dev/null 2>&1; then
  echo "dangling final symlink unexpectedly accepted" >&2
  exit 1
fi
[[ -L "${test_root}/dangling-target" ]]

if "$preparer" "$direct_target" >/dev/null 2>&1; then
  echo "existing target unexpectedly overwritten" >&2
  exit 1
fi

printf '%s\n' "disposable interop secret preparation tests passed"
