#!/usr/bin/env sh
set -eu

script_directory="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
bootstrap_script="${script_directory}/../interop/bootstrap-local-space.sh"
test_root="$(mktemp -d /tmp/swan-bootstrap-review.XXXXXX)"
trap 'rm -rf "$test_root"' EXIT HUP INT TERM

secrets_directory="${test_root}/secrets"
data_directory="${test_root}/data"
mkdir -p "$secrets_directory" "$data_directory"
printf '%s\n' 'authority.test' > "${secrets_directory}/authority.handle"
printf '%s\n' 'member.test' > "${secrets_directory}/member.handle"
printf '%s\n' 'did:plc:aaaaaaaaaaaaaaaaaaaaaaaa' > "${secrets_directory}/authority.did"
printf '%s\n' 'did:plc:bbbbbbbbbbbbbbbbbbbbbbbb' > "${secrets_directory}/member.did"
printf '%s\n' 'authority-password' > "${secrets_directory}/authority.password"
printf '%s\n' 'member-password' > "${secrets_directory}/member.password"
printf '%s\n' 'operator-secret' > "${secrets_directory}/operator-secret"
printf '%s\n' 'account-kek' > "${secrets_directory}/account-kek"
printf '%s\n' 'revision-cid' > "${secrets_directory}/public-repo-revision"

stub="${test_root}/swan-stub"
cat > "$stub" <<'STUB'
#!/usr/bin/env sh
set -eu

command="${1:-}"
subcommand="${2:-}"
shift 2 || true
handle=""
while [ "$#" -gt 0 ]; do
    if [ "$1" = '--handle' ] && [ "$#" -ge 2 ]; then
        shift
        handle="$1"
    fi
    shift
done

case "${command} ${subcommand}" in
    'account show')
        if [ "${STUB_MODE:-missing}" = 'missing' ]; then
            echo 'Error: account not found' >&2
        else
            echo 'Error: unable to open Swan control database' >&2
        fi
        exit 64
        ;;
    'account prepare-plc')
        : > "${STUB_PREPARE_MARKER:?}"
        case "$handle" in
            authority.test) printf '%s\n' '{"did":"did:plc:aaaaaaaaaaaaaaaaaaaaaaaa"}' ;;
            member.test) printf '%s\n' '{"did":"did:plc:bbbbbbbbbbbbbbbbbbbbbbbb"}' ;;
            *) exit 1 ;;
        esac
        ;;
    'account activate-plc')
        ;;
    *)
        exit 1
        ;;
esac
STUB
chmod 0700 "$stub"

success_marker="${test_root}/success-prepare-called"
STUB_MODE=missing \
STUB_PREPARE_MARKER="$success_marker" \
SWAN_BIN="$stub" \
DATA_DIRECTORY="$data_directory" \
SWAN_INTEROP_SECRETS_DIR="$secrets_directory" \
    "$bootstrap_script" >/dev/null
test -e "$success_marker"
test -s "${data_directory}/interop-authority-identity.json"
test -s "${data_directory}/interop-member-identity.json"

failure_data_directory="${test_root}/failure-data"
mkdir -p "$failure_data_directory"
failure_marker="${test_root}/failure-prepare-called"
set +e
STUB_MODE=storage-failure \
STUB_PREPARE_MARKER="$failure_marker" \
SWAN_BIN="$stub" \
DATA_DIRECTORY="$failure_data_directory" \
SWAN_INTEROP_SECRETS_DIR="$secrets_directory" \
    "$bootstrap_script" >"${test_root}/failure-output" 2>&1
status="$?"
set -e
test "$status" -ne 0
test ! -e "$failure_marker"
test ! -e "${failure_data_directory}/interop-authority-identity.json.tmp"
test ! -e "${failure_data_directory}/interop-authority-identity.json"

echo 'BOOTSTRAP LOOKUP FAIL-CLOSED TESTS OK'
