#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIRECTORY=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
WATCHDOG="$SCRIPT_DIRECTORY/run-swift-tests-with-watchdog.sh"
TEST_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/swan-watchdog-test.XXXXXX")
chmod 700 "$TEST_ROOT"
SENTINEL_PID=

cleanup() {
    if [ -n "$SENTINEL_PID" ] && kill -0 "$SENTINEL_PID" 2>/dev/null; then
        kill "$SENTINEL_PID" 2>/dev/null || true
        wait "$SENTINEL_PID" 2>/dev/null || true
    fi
    rm -rf "$TEST_ROOT"
}
trap cleanup EXIT HUP INT TERM

fail() {
    printf 'watchdog self-test: FAIL: %s\n' "$1" >&2
    exit 1
}

assert_status() {
    expected=$1
    actual=$2
    label=$3
    if [ "$actual" -ne "$expected" ]; then
        fail "$label returned $actual, expected $expected"
    fi
}

assert_contains() {
    path=$1
    expected=$2
    label=$3
    if ! grep -F -- "$expected" "$path" >/dev/null 2>&1; then
        fail "$label did not contain: $expected"
    fi
}

capture_status() {
    destination=$1
    shift
    set +e
    "$@" >"$destination" 2>&1
    CAPTURED_STATUS=$?
    set -e
}

if [ ! -x "$WATCHDOG" ]; then
    fail "watchdog runner is missing or not executable: $WATCHDOG"
fi

capture_status "$TEST_ROOT/usage.out" \
    "$WATCHDOG" --deadline-seconds 0 -- /bin/true
assert_status 64 "$CAPTURED_STATUS" "invalid deadline"

pass_artifacts="$TEST_ROOT/pass-artifacts"
capture_status "$TEST_ROOT/pass.out" \
    "$WATCHDOG" --deadline-seconds 5 \
    --artifacts-directory "$pass_artifacts" -- \
    /bin/sh -c 'printf "watchdog-pass-stdout\n"; printf "watchdog-pass-stderr\n" >&2'
assert_status 0 "$CAPTURED_STATUS" "passing command"
assert_contains "$TEST_ROOT/pass.out" "watchdog-pass-stdout" "streamed stdout"
assert_contains "$TEST_ROOT/pass.out" "watchdog-pass-stderr" "streamed stderr"
assert_contains "$pass_artifacts/command.log" "watchdog-pass-stdout" "retained stdout"
assert_contains "$pass_artifacts/command.log" "watchdog-pass-stderr" "retained stderr"
assert_contains "$pass_artifacts/watchdog-status.txt" "command_status=0" "pass receipt"

exit_artifacts="$TEST_ROOT/exit-artifacts"
capture_status "$TEST_ROOT/exit.out" \
    "$WATCHDOG" --deadline-seconds 5 \
    --artifacts-directory "$exit_artifacts" -- \
    /bin/sh -c 'printf "watchdog-exit-23\n"; exit 23'
assert_status 23 "$CAPTURED_STATUS" "exit-23 command"
assert_contains "$exit_artifacts/command.log" "watchdog-exit-23" "exit-23 log"
assert_contains "$exit_artifacts/watchdog-status.txt" "command_status=23" "exit-23 receipt"

/usr/bin/perl -e '$SIG{TERM} = sub {}; sleep 30' &
SENTINEL_PID=$!
if ! kill -0 "$SENTINEL_PID" 2>/dev/null; then
    fail "unrelated sentinel did not start"
fi

timeout_artifacts="$TEST_ROOT/timeout-artifacts"
timeout_state="$TEST_ROOT/timeout-state"
mkdir -m 700 "$timeout_state"
capture_status "$TEST_ROOT/timeout.out" \
    "$WATCHDOG" --deadline-seconds 1 \
    --artifacts-directory "$timeout_artifacts" -- \
    /bin/sh -c '
        state_directory=$1
        /usr/bin/perl -e '\''
            $SIG{TERM} = sub {};
            open(my $handle, ">", $ARGV[0]) or die $!;
            print {$handle} "$$\n";
            close($handle) or die $!;
            sleep 30;
        '\'' "$state_directory/background-child.pid" &
        child=$!
        printf "%s\n" "$child" >"$state_directory/shell-child.pid"
        wait "$child"
    ' watchdog-timeout-command "$timeout_state"
assert_status 124 "$CAPTURED_STATUS" "timed-out command"
assert_contains "$TEST_ROOT/timeout.out" "watchdog: deadline exceeded" "timeout stream"
assert_contains "$timeout_artifacts/watchdog-status.txt" "timed_out=true" "timeout receipt"
assert_contains "$timeout_artifacts/watchdog-status.txt" "command_status=124" "timeout status"
test -s "$timeout_artifacts/process-group.txt" || fail "timeout process-group diagnostic is empty"
test -s "$timeout_artifacts/processes.txt" || fail "timeout process diagnostic is empty"

test -s "$timeout_state/background-child.pid" || fail "background child PID was not recorded"
background_child_pid=$(sed -n '1p' "$timeout_state/background-child.pid")
case "$background_child_pid" in
    ''|*[!0-9]*) fail "background child PID is not numeric" ;;
esac
assert_contains "$timeout_artifacts/processes.txt" "$background_child_pid" \
    "background child process diagnostic"
if grep -F -- "$SENTINEL_PID" "$timeout_artifacts/processes.txt" >/dev/null 2>&1; then
    fail "timeout diagnostics included an unrelated process group"
fi
recorded_leader=$(sed -n 's/^leader_pid=//p' "$timeout_artifacts/process-group.txt")
recorded_pgid=$(sed -n 's/^resolved_pgid=//p' "$timeout_artifacts/process-group.txt")
[ "$recorded_leader" = "$recorded_pgid" ] \
    || fail "verified leader $recorded_leader does not equal PGID $recorded_pgid"
attempt=0
while kill -0 "$background_child_pid" 2>/dev/null && [ "$attempt" -lt 50 ]; do
    sleep 0.1
    attempt=$((attempt + 1))
done
if kill -0 "$background_child_pid" 2>/dev/null; then
    fail "timed-out background child survived process-group termination"
fi
if ! kill -0 "$SENTINEL_PID" 2>/dev/null; then
    fail "watchdog terminated an unrelated sentinel"
fi

case $(uname -s) in
    Darwin)
        artifact_mode=$(stat -f '%Lp' "$timeout_artifacts")
        log_mode=$(stat -f '%Lp' "$timeout_artifacts/command.log")
        ;;
    Linux)
        artifact_mode=$(stat -c '%a' "$timeout_artifacts")
        log_mode=$(stat -c '%a' "$timeout_artifacts/command.log")
        ;;
    *)
        fail "unsupported self-test platform"
        ;;
esac
[ "$artifact_mode" = 700 ] || fail "artifact directory mode is $artifact_mode, expected 700"
[ "$log_mode" = 600 ] || fail "command log mode is $log_mode, expected 600"

kill "$SENTINEL_PID" 2>/dev/null || true
wait "$SENTINEL_PID" 2>/dev/null || true
SENTINEL_PID=
printf 'watchdog self-test: PASS\n'
