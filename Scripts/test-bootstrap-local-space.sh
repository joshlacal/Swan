#!/usr/bin/env sh
set -eu

script_directory="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
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
expected_did=""
request_id=""
password_file=""
identity_data_directory=""
while [ "$#" -gt 0 ]; do
    if [ "$1" = '--handle' ] && [ "$#" -ge 2 ]; then
        shift
        handle="$1"
    elif [ "$1" = '--expected-did' ] && [ "$#" -ge 2 ]; then
        shift
        expected_did="$1"
    elif [ "$1" = '--request-id' ] && [ "$#" -ge 2 ]; then
        shift
        request_id="$1"
    elif [ "$1" = '--password-file' ] && [ "$#" -ge 2 ]; then
        shift
        password_file="$1"
    elif [ "$1" = '--data-directory' ] && [ "$#" -ge 2 ]; then
        shift
        identity_data_directory="$1"
    fi
    shift
done

if [ -n "${STUB_ANY_MARKER:-}" ]; then
    : > "$STUB_ANY_MARKER"
fi
if [ -n "${STUB_INVOCATIONS:-}" ]; then
    printf '%s|%s|%s|%s|%s|%s\n' \
        "$command" "$subcommand" "$handle" "$request_id" \
        "$password_file" "$identity_data_directory" >> "$STUB_INVOCATIONS"
fi

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
            authority.test)
                if [ "${STUB_GENERATED:-0}" = '1' ]; then
                    test -z "$expected_did"
                    printf '%s\n' '{"did":"did:plc:cccccccccccccccccccccccc"}'
                else
                    test "$expected_did" = 'did:plc:aaaaaaaaaaaaaaaaaaaaaaaa'
                    printf '%s\n' '{"did":"did:plc:aaaaaaaaaaaaaaaaaaaaaaaa"}'
                fi
                ;;
            member.test)
                if [ "${STUB_GENERATED:-0}" = '1' ]; then
                    test -z "$expected_did"
                    printf '%s\n' '{"did":"did:plc:dddddddddddddddddddddddd"}'
                else
                    test "$expected_did" = 'did:plc:bbbbbbbbbbbbbbbbbbbbbbbb'
                    printf '%s\n' '{"did":"did:plc:bbbbbbbbbbbbbbbbbbbbbbbb"}'
                fi
                ;;
            fresh.test)
                test "${STUB_GENERATED:-0}" = '1'
                test -z "$expected_did"
                printf '%s\n' '{"did":"did:plc:eeeeeeeeeeeeeeeeeeeeeeee"}'
                ;;
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

# Fresh disposable labs may opt into generated PLC identities. The bootstrap
# must omit --expected-did, persist the generated identity, and bind a later
# restart to that durable DID rather than accepting an arbitrary account row.
generated_secrets_directory="${test_root}/generated-secrets"
generated_data_directory="${test_root}/generated-data"
mkdir -p "$generated_secrets_directory" "$generated_data_directory"
cp "${secrets_directory}/"* "$generated_secrets_directory/"
printf '%s\n' generate > "${generated_secrets_directory}/authority.did"
printf '%s\n' generate > "${generated_secrets_directory}/member.did"
generated_marker="${test_root}/generated-prepare-called"
STUB_MODE=missing \
STUB_GENERATED=1 \
STUB_PREPARE_MARKER="$generated_marker" \
SWAN_BIN="$stub" \
DATA_DIRECTORY="$generated_data_directory" \
SWAN_INTEROP_SECRETS_DIR="$generated_secrets_directory" \
    "$bootstrap_script" >/dev/null
test -e "$generated_marker"
test "$(sed -n 's/.*\"did\":\"\([^\"]*\)\".*/\1/p' "${generated_data_directory}/interop-authority-identity.json")" = 'did:plc:cccccccccccccccccccccccc'
test "$(sed -n 's/.*\"did\":\"\([^\"]*\)\".*/\1/p' "${generated_data_directory}/interop-member-identity.json")" = 'did:plc:dddddddddddddddddddddddd'

# The Phase 5 runner can request exactly one fresh generated account without
# changing the no-argument authority/member bootstrap contract. Every caller-
# selected value reaches the existing prepare/activate workflow verbatim, and
# the durable generated identity remains owner-only at the selected path.
explicit_data_directory="${test_root}/explicit-data"
explicit_identity_directory="${explicit_data_directory}/evidence"
mkdir -p "$explicit_identity_directory"
chmod 0700 "$secrets_directory" "$explicit_data_directory" "$explicit_identity_directory"
explicit_password_file="${secrets_directory}/fresh.password"
printf '%s\n' 'fresh-password-never-print' > "$explicit_password_file"
chmod 0600 "$explicit_password_file"
explicit_identity_file="${explicit_identity_directory}/fresh-identity.json"
explicit_invocations="${test_root}/explicit-invocations"
explicit_output="${test_root}/explicit-output"
STUB_MODE=missing \
STUB_GENERATED=1 \
STUB_PREPARE_MARKER="${test_root}/explicit-prepare-called" \
STUB_INVOCATIONS="$explicit_invocations" \
SWAN_BIN="$stub" \
DATA_DIRECTORY="$explicit_data_directory" \
SWAN_INTEROP_SECRETS_DIR="$secrets_directory" \
    "$bootstrap_script" \
    --request-id relay-fresh-001 \
    --handle fresh.test \
    --password-file "$explicit_password_file" \
    --account-label relay-fresh \
    --identity-file "$explicit_identity_file" \
    >"$explicit_output" 2>&1
test -s "$explicit_identity_file"
test "$(stat -f '%Lp' "$explicit_identity_file" 2>/dev/null || stat -c '%a' "$explicit_identity_file")" = 600
grep -Fq "account|prepare-plc|fresh.test|relay-fresh-001||${explicit_data_directory}" "$explicit_invocations"
grep -Fq "account|activate-plc||relay-fresh-001|${explicit_password_file}|${explicit_data_directory}" "$explicit_invocations"
if grep -Fq 'fresh-password-never-print' "$explicit_output"; then
    echo "explicit bootstrap printed password material" >&2
    exit 1
fi

require_explicit_rejection() {
    name="$1"
    expected="$2"
    shift 2
    marker="${test_root}/${name}-swan-called"
    output="${test_root}/${name}-output"
    set +e
    STUB_ANY_MARKER="$marker" \
    STUB_PREPARE_MARKER="${test_root}/${name}-prepare-called" \
    SWAN_BIN="$stub" \
    DATA_DIRECTORY="$explicit_data_directory" \
    SWAN_INTEROP_SECRETS_DIR="$secrets_directory" \
        "$bootstrap_script" "$@" >"$output" 2>&1
    status="$?"
    set -e
    test "$status" -ne 0
    test ! -e "$marker"
    grep -Fq "$expected" "$output"
    if grep -Fq 'fresh-password-never-print' "$output"; then
        echo "rejected explicit bootstrap printed password material" >&2
        exit 1
    fi
}

outside_password="${test_root}/outside.password"
printf '%s\n' 'outside-password' > "$outside_password"
chmod 0600 "$outside_password"
require_explicit_rejection malformed-request-id 'explicit request ID is malformed' \
    --request-id 'relay fresh' --handle fresh.test \
    --password-file "$explicit_password_file" --account-label relay-fresh \
    --identity-file "${explicit_identity_directory}/malformed-request.json"
require_explicit_rejection escaping-password 'explicit password file escapes the secret root' \
    --request-id relay-fresh-escape --handle fresh.test \
    --password-file "${secrets_directory}/../outside.password" --account-label relay-fresh \
    --identity-file "${explicit_identity_directory}/escaping-password.json"
unsafe_password="${secrets_directory}/unsafe.password"
printf '%s\n' 'unsafe-password' > "$unsafe_password"
chmod 0644 "$unsafe_password"
require_explicit_rejection non-owner-only-password 'explicit password file must be owner-only' \
    --request-id relay-fresh-mode --handle fresh.test \
    --password-file "$unsafe_password" --account-label relay-fresh \
    --identity-file "${explicit_identity_directory}/unsafe-password.json"
require_explicit_rejection missing-password 'explicit password file is missing' \
    --request-id relay-fresh-missing --handle fresh.test \
    --password-file "${secrets_directory}/missing.password" --account-label relay-fresh \
    --identity-file "${explicit_identity_directory}/missing-password.json"
password_symlink="${secrets_directory}/linked.password"
ln -s "$explicit_password_file" "$password_symlink"
require_explicit_rejection symlink-password 'explicit password file must not be a symlink' \
    --request-id relay-fresh-link --handle fresh.test \
    --password-file "$password_symlink" --account-label relay-fresh \
    --identity-file "${explicit_identity_directory}/symlink-password.json"
require_explicit_rejection escaping-identity 'explicit identity file escapes the data root' \
    --request-id relay-fresh-identity-escape --handle fresh.test \
    --password-file "$explicit_password_file" --account-label relay-fresh \
    --identity-file "${explicit_data_directory}/../outside-identity.json"
unsafe_identity="${explicit_identity_directory}/unsafe-identity.json"
printf '%s\n' '{"did":"did:plc:eeeeeeeeeeeeeeeeeeeeeeee"}' > "$unsafe_identity"
chmod 0644 "$unsafe_identity"
require_explicit_rejection non-owner-only-identity 'explicit identity file must be owner-only' \
    --request-id relay-fresh-identity-mode --handle fresh.test \
    --password-file "$explicit_password_file" --account-label relay-fresh \
    --identity-file "$unsafe_identity"
require_explicit_rejection incomplete-inputs 'explicit fresh-account inputs must be provided together' \
    --request-id relay-fresh-partial

echo 'BOOTSTRAP LOOKUP FAIL-CLOSED TESTS OK'
