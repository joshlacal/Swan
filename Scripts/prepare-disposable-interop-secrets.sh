#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -ne 1 ]]; then
  echo "usage: prepare-disposable-interop-secrets.sh EXTERNAL_DIRECTORY" >&2
  exit 2
fi

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
repository_root="$(cd "${script_dir}/.." && pwd -P)"
target="$1"
if [[ "$target" != /* || "$target" == *$'\n'* || "$target" == *:* ]]; then
  echo "secret directory must be an absolute, mount-safe path" >&2
  exit 1
fi
if [[ -e "$target" ]]; then
  echo "refusing to overwrite an existing secret directory" >&2
  exit 1
fi
case "$target/" in
  "$repository_root/"*)
    echo "secret directory must be outside the repository" >&2
    exit 1
    ;;
esac

umask 077
mkdir -m 0700 "$target"
trap 'rm -rf -- "$target"' ERR HUP INT TERM

write_random_b64() {
  name="$1"
  openssl rand -base64 32 \
    | tr -d '\r\n=' \
    | tr '+/' '-_' \
    > "${target}/${name}"
}

write_random_hex() {
  name="$1"
  openssl rand -hex 32 > "${target}/${name}"
}

write_literal() {
  name="$1"
  value="$2"
  printf '%s\n' "$value" > "${target}/${name}"
}

for name in oauth-server-key account-kek email-proof-key; do
  write_random_b64 "$name"
done
write_random_hex operator-secret
write_random_hex pds-dpop-secret
write_random_hex pds-jwt-secret
write_random_hex pds-admin-password
write_random_hex pds-repo-signing-key
write_random_hex pds-plc-rotation-key

write_literal authority.did generate
write_literal authority.handle authority.test
write_literal authority.password "swan-authority-$(openssl rand -hex 16)"
write_literal member.did generate
write_literal member.handle member.test
write_literal member.password "swan-member-$(openssl rand -hex 16)"
# A valid empty repository-v3 revision used by the pinned genesis path.
write_literal public-repo-revision 3jzfcijpj2z2a

chmod 0600 "$target"/*
trap - ERR HUP INT TERM
printf '%s\n' "$target"
