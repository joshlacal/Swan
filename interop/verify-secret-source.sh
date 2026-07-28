#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -ne 2 ]]; then
  echo "usage: verify-secret-source.sh REPOSITORY_ROOT SECRET_DIRECTORY" >&2
  exit 2
fi

repository_root="$(cd "$1" && pwd -P)"
secret_directory="$2"
if [[ ! -d "$secret_directory" ]] || [[ -L "$secret_directory" ]]; then
  echo "interop secret directory is missing or unsafe" >&2
  exit 1
fi
secret_directory="$(cd "$secret_directory" && pwd -P)"
case "$secret_directory/" in
  "$repository_root/"*)
    echo "interop secret directory must be outside the repository" >&2
    exit 1
    ;;
esac
if [[ "$secret_directory" == *:* ]] || [[ "$secret_directory" == *$'\n'* ]]; then
  echo "interop secret directory path is unsafe for a Compose mount" >&2
  exit 1
fi

stat_mode() {
  path="$1"
  if stat -f '%Lp' "$path" >/dev/null 2>&1; then
    stat -f '%Lp' "$path"
  else
    stat -c '%a' "$path"
  fi
}

stat_uid() {
  path="$1"
  if stat -f '%u' "$path" >/dev/null 2>&1; then
    stat -f '%u' "$path"
  else
    stat -c '%u' "$path"
  fi
}

require_private_owner_file() {
  name="$1"
  path="${secret_directory}/${name}"
  if [[ -L "$path" ]] || [[ ! -f "$path" ]] || [[ ! -s "$path" ]] || [[ ! -r "$path" ]]; then
    echo "interop secret file is missing or unsafe" >&2
    exit 1
  fi
  mode="$(stat_mode "$path")"
  if (( (8#${mode} & 077) != 0 )); then
    echo "interop secret file permissions are unsafe" >&2
    exit 1
  fi
  if [[ "$(stat_uid "$path")" -ne "$(id -u)" ]]; then
    echo "interop secret file owner is unsafe" >&2
    exit 1
  fi
}

directory_mode="$(stat_mode "$secret_directory")"
if (( (8#${directory_mode} & 077) != 0 )) \
  || [[ "$(stat_uid "$secret_directory")" -ne "$(id -u)" ]]; then
  echo "interop secret directory owner or permissions are unsafe" >&2
  exit 1
fi

for name in \
  oauth-server-key \
  account-kek \
  operator-secret \
  authority.did \
  authority.handle \
  authority.password \
  member.did \
  member.handle \
  member.password \
  public-repo-revision \
  pds-dpop-secret \
  pds-jwt-secret \
  pds-admin-password \
  pds-repo-signing-key \
  pds-plc-rotation-key
do
  require_private_owner_file "$name"
done

printf '%s\n' "$secret_directory"
