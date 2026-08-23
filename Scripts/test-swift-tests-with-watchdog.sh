#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIRECTORY=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
WATCHDOG="$SCRIPT_DIRECTORY/run-swift-tests-with-watchdog.sh"
TEST_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/swan-watchdog-test.XXXXXX")
chmod 700 "$TEST_ROOT"
SENTINEL_PID=
SUBORDINATE_PROBE_PID=
SUBORDINATE_PROBE_IDENTITY=
SWIFTPM_PROBE_PID=
SWIFTPM_PROBE_IDENTITY=
IDENTITY_REJECTION_PROBE_PID=
IDENTITY_REJECTION_PROBE_IDENTITY=
SIGNAL_PROBE_PID=
SIGNAL_PROBE_IDENTITY=

process_start_identity() {
    process_pid=$1
    /bin/ps -o lstart= -p "$process_pid" 2>/dev/null \
        | awk '{$1=$1; print}'
}

terminate_exact_probe() {
    probe_pid=$1
    expected_identity=$2
    case "$probe_pid" in
        ''|*[!0-9]*) return 0 ;;
    esac
    [ -n "$expected_identity" ] || return 0
    current_identity=$(process_start_identity "$probe_pid" || true)
    [ "$current_identity" = "$expected_identity" ] || return 0
    kill -KILL "$probe_pid" 2>/dev/null || true
    probe_attempt=0
    while [ "$(process_start_identity "$probe_pid")" = "$expected_identity" ] \
        && [ "$probe_attempt" -lt 50 ]; do
        sleep 0.1
        probe_attempt=$((probe_attempt + 1))
    done
}

cleanup() {
    terminate_exact_probe \
        "$SUBORDINATE_PROBE_PID" "$SUBORDINATE_PROBE_IDENTITY"
    terminate_exact_probe \
        "$SWIFTPM_PROBE_PID" "$SWIFTPM_PROBE_IDENTITY"
    terminate_exact_probe \
        "$IDENTITY_REJECTION_PROBE_PID" "$IDENTITY_REJECTION_PROBE_IDENTITY"
    terminate_exact_probe \
        "$SIGNAL_PROBE_PID" "$SIGNAL_PROBE_IDENTITY"
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

adversarial_failures=0
descendant_artifacts="$TEST_ROOT/descendant-artifacts"
descendant_state="$TEST_ROOT/descendant-state"
mkdir -m 700 "$descendant_state"
capture_status "$TEST_ROOT/descendant.out" \
    "$WATCHDOG" --deadline-seconds 1 \
    --artifacts-directory "$descendant_artifacts" -- \
    /usr/bin/perl -MPOSIX -e '
        use strict;
        use warnings;
        my $state_directory = shift @ARGV;
        sub record_pid {
            my ($path) = @_;
            open(my $handle, ">", $path) or die $!;
            print {$handle} "$$\n";
            close($handle) or die $!;
        }
        sub become_subordinate_probe {
            my ($path) = @_;
            $! = 0;
            POSIX::setpgid(0, 0);
            die "setpgid failed: $!\n" if $!;
            $SIG{TERM} = sub {};
            record_pid($path);
            open(STDIN, "<", "/dev/null") or die $!;
            open(STDOUT, ">", "/dev/null") or die $!;
            open(STDERR, ">", "/dev/null") or die $!;
            sleep 30;
            exit 0;
        }
        $SIG{TERM} = sub {};
        my $intermediate = fork();
        die "fork intermediate failed: $!\n" unless defined $intermediate;
        if ($intermediate == 0) {
            my $subordinate = fork();
            die "fork subordinate failed: $!\n" unless defined $subordinate;
            if ($subordinate == 0) {
                become_subordinate_probe("$state_directory/subordinate.pid");
            }
            waitpid($subordinate, 0);
            exit 0;
        }
        my $swiftpm_child = fork();
        die "fork SwiftPM-shaped child failed: $!\n"
            unless defined $swiftpm_child;
        if ($swiftpm_child == 0) {
            become_subordinate_probe("$state_directory/swiftpm-child.pid");
        }
        waitpid($intermediate, 0);
        waitpid($swiftpm_child, 0);
    ' "$descendant_state"
assert_status 124 "$CAPTURED_STATUS" "subordinate-process-group timeout"
test -s "$descendant_state/subordinate.pid" \
    || fail "subordinate descendant PID was not recorded"
test -s "$descendant_state/swiftpm-child.pid" \
    || fail "SwiftPM-shaped child PID was not recorded"
SUBORDINATE_PROBE_PID=$(sed -n '1p' "$descendant_state/subordinate.pid")
SWIFTPM_PROBE_PID=$(sed -n '1p' "$descendant_state/swiftpm-child.pid")
case "$SUBORDINATE_PROBE_PID:$SWIFTPM_PROBE_PID" in
    *[!0-9:]*) fail "subordinate process-group probe PID is not numeric" ;;
esac
SUBORDINATE_PROBE_IDENTITY=$(
    process_start_identity "$SUBORDINATE_PROBE_PID" || true
)
SWIFTPM_PROBE_IDENTITY=$(
    process_start_identity "$SWIFTPM_PROBE_PID" || true
)

if ! grep -F -- "$SUBORDINATE_PROBE_PID" \
    "$descendant_artifacts/processes.txt" >/dev/null 2>&1; then
    printf 'watchdog self-test: FAIL: recursive diagnostics omitted subordinate PID %s\n' \
        "$SUBORDINATE_PROBE_PID" >&2
    adversarial_failures=$((adversarial_failures + 1))
fi
if ! grep -F -- "$SWIFTPM_PROBE_PID" \
    "$descendant_artifacts/processes.txt" >/dev/null 2>&1; then
    printf 'watchdog self-test: FAIL: recursive diagnostics omitted SwiftPM-shaped PID %s\n' \
        "$SWIFTPM_PROBE_PID" >&2
    adversarial_failures=$((adversarial_failures + 1))
fi
if [ -n "$SUBORDINATE_PROBE_IDENTITY" ]; then
    printf 'watchdog self-test: FAIL: TERM-ignoring subordinate PID %s survived\n' \
        "$SUBORDINATE_PROBE_PID" >&2
    adversarial_failures=$((adversarial_failures + 1))
fi
if [ -n "$SWIFTPM_PROBE_IDENTITY" ]; then
    printf 'watchdog self-test: FAIL: SwiftPM-shaped PID %s survived\n' \
        "$SWIFTPM_PROBE_PID" >&2
    adversarial_failures=$((adversarial_failures + 1))
fi
if ! kill -0 "$SENTINEL_PID" 2>/dev/null; then
    fail "descendant cleanup terminated the unrelated sentinel"
fi
terminate_exact_probe \
    "$SUBORDINATE_PROBE_PID" "$SUBORDINATE_PROBE_IDENTITY"
terminate_exact_probe \
    "$SWIFTPM_PROBE_PID" "$SWIFTPM_PROBE_IDENTITY"
SUBORDINATE_PROBE_PID=
SUBORDINATE_PROBE_IDENTITY=
SWIFTPM_PROBE_PID=
SWIFTPM_PROBE_IDENTITY=

signal_artifacts="$TEST_ROOT/signal-artifacts"
signal_state="$TEST_ROOT/signal-state"
mkdir -m 700 "$signal_state"
"$WATCHDOG" --deadline-seconds 30 \
    --artifacts-directory "$signal_artifacts" -- \
    /usr/bin/perl -MPOSIX -e '
        use strict;
        use warnings;
        my $pid_path = shift @ARGV;
        my $child = fork();
        die "fork failed: $!\n" unless defined $child;
        if ($child == 0) {
            $! = 0;
            POSIX::setpgid(0, 0);
            die "setpgid failed: $!\n" if $!;
            $SIG{TERM} = sub {};
            open(my $handle, ">", $pid_path) or die $!;
            print {$handle} "$$\n";
            close($handle) or die $!;
            open(STDIN, "<", "/dev/null") or die $!;
            open(STDOUT, ">", "/dev/null") or die $!;
            open(STDERR, ">", "/dev/null") or die $!;
            sleep 30;
            exit 0;
        }
        waitpid($child, 0);
    ' "$signal_state/probe.pid" \
    >"$TEST_ROOT/signal.out" 2>&1 &
signal_wrapper_pid=$!
signal_ready_attempt=0
while { [ ! -s "$signal_state/probe.pid" ] \
    || [ ! -s "$signal_artifacts/process-group.txt" ]; } \
    && [ "$signal_ready_attempt" -lt 100 ]; do
    sleep 0.05
    signal_ready_attempt=$((signal_ready_attempt + 1))
done
test -s "$signal_state/probe.pid" \
    || fail "external-TERM descendant PID was not recorded"
SIGNAL_PROBE_PID=$(sed -n '1p' "$signal_state/probe.pid")
case "$SIGNAL_PROBE_PID" in
    ''|*[!0-9]*) fail "external-TERM descendant PID is not numeric" ;;
esac
SIGNAL_PROBE_IDENTITY=$(process_start_identity "$SIGNAL_PROBE_PID" || true)
[ -n "$SIGNAL_PROBE_IDENTITY" ] \
    || fail "external-TERM descendant exited before the signal"
kill -TERM "$signal_wrapper_pid"
set +e
wait "$signal_wrapper_pid"
signal_wrapper_status=$?
set -e
assert_status 143 "$signal_wrapper_status" "externally terminated wrapper"

observed_signal_probe_identity=$(
    process_start_identity "$SIGNAL_PROBE_PID" || true
)
if [ "$observed_signal_probe_identity" = "$SIGNAL_PROBE_IDENTITY" ]; then
    printf 'watchdog self-test: FAIL: external TERM left subordinate PID %s alive\n' \
        "$SIGNAL_PROBE_PID" >&2
    adversarial_failures=$((adversarial_failures + 1))
fi
if [ ! -s "$signal_artifacts/descendant-identities.txt" ] \
    || ! grep -F -- "$SIGNAL_PROBE_PID|$SIGNAL_PROBE_IDENTITY" \
        "$signal_artifacts/descendant-identities.txt" >/dev/null 2>&1; then
    printf 'watchdog self-test: FAIL: external TERM did not identity-bind PID %s\n' \
        "$SIGNAL_PROBE_PID" >&2
    adversarial_failures=$((adversarial_failures + 1))
fi
if ! kill -0 "$SENTINEL_PID" 2>/dev/null; then
    fail "external-TERM cleanup terminated the unrelated sentinel"
fi
terminate_exact_probe "$SIGNAL_PROBE_PID" "$SIGNAL_PROBE_IDENTITY"
SIGNAL_PROBE_PID=
SIGNAL_PROBE_IDENTITY=

identity_artifacts="$TEST_ROOT/identity-artifacts"
identity_state="$TEST_ROOT/identity-state"
fake_ps_directory="$TEST_ROOT/fake-ps"
mkdir -m 700 "$identity_state" "$fake_ps_directory"
fake_ps="$fake_ps_directory/ps"
cat >"$fake_ps" <<'FAKE_PS'
#!/bin/sh
set -eu
if [ "$#" -eq 4 ] \
    && [ "$1" = "-o" ] \
    && [ "$2" = "lstart=" ] \
    && [ "$3" = "-p" ] \
    && [ -s "$SWAN_TEST_IDENTITY_TARGET_FILE" ]; then
    target_pid=$(sed -n '1p' "$SWAN_TEST_IDENTITY_TARGET_FILE")
    if [ "$4" = "$target_pid" ]; then
        identity_count=0
        if [ -s "$SWAN_TEST_IDENTITY_COUNT_FILE" ]; then
            identity_count=$(sed -n '1p' "$SWAN_TEST_IDENTITY_COUNT_FILE")
        fi
        identity_count=$((identity_count + 1))
        printf '%s\n' "$identity_count" >"$SWAN_TEST_IDENTITY_COUNT_FILE"
        if [ "$identity_count" -gt 1 ]; then
            printf '%s\n' 'Thu Jan  1 00:00:00 1970'
            exit 0
        fi
    fi
fi
exec "$SWAN_TEST_REAL_PS" "$@"
FAKE_PS
chmod 700 "$fake_ps"
capture_status "$TEST_ROOT/identity.out" \
    env PATH="$fake_ps_directory:$PATH" \
    SWAN_TEST_REAL_PS=/bin/ps \
    SWAN_TEST_IDENTITY_TARGET_FILE="$identity_state/probe.pid" \
    SWAN_TEST_IDENTITY_COUNT_FILE="$identity_state/identity-count" \
    "$WATCHDOG" --deadline-seconds 1 \
    --artifacts-directory "$identity_artifacts" -- \
    /usr/bin/perl -MPOSIX -e '
        use strict;
        use warnings;
        my $pid_path = shift @ARGV;
        $SIG{TERM} = sub {};
        my $child = fork();
        die "fork failed: $!\n" unless defined $child;
        if ($child == 0) {
            $! = 0;
            POSIX::setpgid(0, 0);
            die "setpgid failed: $!\n" if $!;
            $SIG{TERM} = sub {};
            open(my $handle, ">", $pid_path) or die $!;
            print {$handle} "$$\n";
            close($handle) or die $!;
            open(STDIN, "<", "/dev/null") or die $!;
            open(STDOUT, ">", "/dev/null") or die $!;
            open(STDERR, ">", "/dev/null") or die $!;
            sleep 30;
            exit 0;
        }
        waitpid($child, 0);
    ' "$identity_state/probe.pid"
assert_status 124 "$CAPTURED_STATUS" "identity-rejection timeout"
test -s "$identity_state/probe.pid" \
    || fail "identity-rejection probe PID was not recorded"
IDENTITY_REJECTION_PROBE_PID=$(sed -n '1p' "$identity_state/probe.pid")
case "$IDENTITY_REJECTION_PROBE_PID" in
    ''|*[!0-9]*) fail "identity-rejection probe PID is not numeric" ;;
esac
IDENTITY_REJECTION_PROBE_IDENTITY=$(
    process_start_identity "$IDENTITY_REJECTION_PROBE_PID" || true
)
if [ -z "$IDENTITY_REJECTION_PROBE_IDENTITY" ]; then
    printf 'watchdog self-test: FAIL: stale-identity probe was signaled\n' >&2
    adversarial_failures=$((adversarial_failures + 1))
fi
if [ ! -s "$identity_artifacts/identity-rejections.txt" ]; then
    printf 'watchdog self-test: FAIL: identity mismatch had no rejection receipt\n' >&2
    adversarial_failures=$((adversarial_failures + 1))
elif ! grep -F -- "pid=$IDENTITY_REJECTION_PROBE_PID" \
    "$identity_artifacts/identity-rejections.txt" >/dev/null 2>&1; then
    printf 'watchdog self-test: FAIL: identity receipt omitted probe PID %s\n' \
        "$IDENTITY_REJECTION_PROBE_PID" >&2
    adversarial_failures=$((adversarial_failures + 1))
fi
if ! kill -0 "$SENTINEL_PID" 2>/dev/null; then
    fail "identity rejection terminated the unrelated sentinel"
fi
terminate_exact_probe \
    "$IDENTITY_REJECTION_PROBE_PID" "$IDENTITY_REJECTION_PROBE_IDENTITY"
IDENTITY_REJECTION_PROBE_PID=
IDENTITY_REJECTION_PROBE_IDENTITY=

if [ "$adversarial_failures" -ne 0 ]; then
    fail "$adversarial_failures adversarial watchdog assertions failed"
fi

kill "$SENTINEL_PID" 2>/dev/null || true
wait "$SENTINEL_PID" 2>/dev/null || true
SENTINEL_PID=
printf 'watchdog self-test: PASS\n'
