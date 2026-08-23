#!/usr/bin/env bash
set -euo pipefail

export LC_ALL=C
umask 077

usage() {
    printf '%s\n' \
        'usage: run-swift-tests-with-watchdog.sh --deadline-seconds POSITIVE_INTEGER [--artifacts-directory PATH] -- COMMAND [ARG...]' >&2
    exit 64
}

if [ "$#" -lt 4 ] || [ "$1" != "--deadline-seconds" ]; then
    usage
fi
deadline_seconds=$2
shift 2
case "$deadline_seconds" in
    ''|*[!0-9]*) usage ;;
esac
if ! [ "$deadline_seconds" -gt 0 ] 2>/dev/null; then
    usage
fi

artifacts_directory=
if [ "$#" -ge 2 ] && [ "$1" = "--artifacts-directory" ]; then
    artifacts_directory=$2
    shift 2
    [ -n "$artifacts_directory" ] || usage
fi
if [ "$#" -lt 2 ] || [ "$1" != "--" ]; then
    usage
fi
shift
[ "$#" -gt 0 ] || usage

platform=$(uname -s)
case "$platform" in
    Darwin)
        [ -x /usr/bin/perl ] || {
            printf 'watchdog: Darwin requires /usr/bin/perl for POSIX::setpgid\n' >&2
            exit 70
        }
        ;;
    Linux)
        setsid_path=$(command -v setsid 2>/dev/null || true)
        [ -n "$setsid_path" ] || {
            printf 'watchdog: Linux requires setsid\n' >&2
            exit 70
        }
        ;;
    *)
        printf 'watchdog: unsupported platform: %s\n' "$platform" >&2
        exit 70
        ;;
esac

if [ -n "$artifacts_directory" ]; then
    if [ -e "$artifacts_directory" ] || [ -L "$artifacts_directory" ]; then
        printf 'watchdog: artifacts directory must not already exist: %s\n' \
            "$artifacts_directory" >&2
        exit 64
    fi
    if ! mkdir -m 700 -- "$artifacts_directory"; then
        printf 'watchdog: could not create artifacts directory: %s\n' \
            "$artifacts_directory" >&2
        exit 70
    fi
else
    artifacts_directory=$(mktemp -d \
        "${TMPDIR:-/tmp}/swan-swift-test-watchdog.XXXXXX")
    chmod 700 "$artifacts_directory"
fi
if [ -L "$artifacts_directory" ] || [ ! -d "$artifacts_directory" ]; then
    printf 'watchdog: artifacts path is not a real directory\n' >&2
    exit 70
fi

command_log="$artifacts_directory/command.log"
status_receipt="$artifacts_directory/watchdog-status.txt"
process_group_receipt="$artifacts_directory/process-group.txt"
output_fifo="$artifacts_directory/.command-output.fifo"
ready_file="$artifacts_directory/.leader-ready"
go_file="$artifacts_directory/.leader-go"
mkfifo -m 600 "$output_fifo"
: >"$process_group_receipt"
chmod 600 "$process_group_receipt"

leader_pid=
verified_pgid=
group_verified=false
target_active=false
tee_pid=

cleanup_internal_files() {
    rm -f -- "$output_fifo" "$ready_file" "$go_file"
}
trap cleanup_internal_files EXIT

group_is_alive() {
    [ "$group_verified" = true ] || return 1
    kill -0 -- "-$verified_pgid" 2>/dev/null
}

terminate_verified_group() {
    [ "$group_verified" = true ] || return 0
    if group_is_alive; then
        kill -TERM -- "-$verified_pgid" 2>/dev/null || true
    fi
    grace_started=$SECONDS
    while group_is_alive && [ $((SECONDS - grace_started)) -lt 2 ]; do
        sleep 0.1
    done
    if group_is_alive; then
        kill -KILL -- "-$verified_pgid" 2>/dev/null || true
    fi
}

handle_signal() {
    signal_status=$1
    trap - HUP INT TERM
    if [ "$target_active" = true ]; then
        terminate_verified_group
        set +e
        wait "$leader_pid" 2>/dev/null
        set -e
        target_active=false
    fi
    exit "$signal_status"
}
trap 'handle_signal 129' HUP
trap 'handle_signal 130' INT
trap 'handle_signal 143' TERM

tee "$command_log" <"$output_fifo" &
tee_pid=$!

case "$platform" in
    Darwin)
        /usr/bin/perl -MPOSIX -e '
            use strict;
            use warnings;
            my ($ready, $go, @command) = @ARGV;
            die "missing command\n" unless @command;
            $! = 0;
            POSIX::setpgid(0, 0);
            die "setpgid failed: $!\n" if $!;
            open(my $ready_handle, ">", $ready)
                or die "open ready file failed: $!\n";
            print {$ready_handle} "$$\n";
            close($ready_handle) or die "close ready file failed: $!\n";
            my $released = 0;
            for (1 .. 1000) {
                if (-e $go) {
                    $released = 1;
                    last;
                }
                select(undef, undef, undef, 0.01);
            }
            die "leader handshake timed out\n" unless $released;
            exec { $command[0] } @command;
            die "exec failed: $!\n";
        ' "$ready_file" "$go_file" "$@" >"$output_fifo" 2>&1 &
        ;;
    Linux)
        "$setsid_path" /bin/sh -c '
            ready=$1
            go=$2
            shift 2
            umask 077
            printf "%s\n" "$$" >"$ready"
            attempt=0
            while [ ! -f "$go" ] && [ "$attempt" -lt 1000 ]; do
                sleep 0.01
                attempt=$((attempt + 1))
            done
            [ -f "$go" ] || {
                printf "leader handshake timed out\n" >&2
                exit 70
            }
            exec "$@"
        ' swan-watchdog-leader "$ready_file" "$go_file" "$@" \
            >"$output_fifo" 2>&1 &
        ;;
esac
leader_pid=$!
target_active=true

ready_attempt=0
while [ ! -s "$ready_file" ] && [ "$ready_attempt" -lt 500 ]; do
    if ! kill -0 "$leader_pid" 2>/dev/null; then
        break
    fi
    sleep 0.01
    ready_attempt=$((ready_attempt + 1))
done

reported_leader=
if [ -s "$ready_file" ]; then
    reported_leader=$(tr -d '[:space:]' <"$ready_file")
fi
resolved_pgid=$(ps -o pgid= -p "$leader_pid" 2>/dev/null \
    | tr -d '[:space:]' || true)
case "$leader_pid:$reported_leader:$resolved_pgid" in
    *[!0-9:]*) verification_error='non-numeric leader or process group' ;;
    "$leader_pid:$leader_pid:$leader_pid") verification_error= ;;
    *) verification_error='leader PID and process group did not match' ;;
esac
if [ -n "$verification_error" ]; then
    printf 'watchdog: process-group verification failed: %s\n' \
        "$verification_error" >&2
    set +e
    wait "$leader_pid"
    wait "$tee_pid"
    set -e
    target_active=false
    exit 70
fi

verified_pgid=$resolved_pgid
group_verified=true
{
    printf 'platform=%s\n' "$platform"
    printf 'leader_pid=%s\n' "$leader_pid"
    printf 'reported_leader_pid=%s\n' "$reported_leader"
    printf 'resolved_pgid=%s\n' "$verified_pgid"
    printf 'process_group_verified=true\n'
} >"$process_group_receipt"
chmod 600 "$process_group_receipt"
: >"$go_file"
chmod 600 "$go_file"

capture_timeout_diagnostics() {
    processes_path="$artifacts_directory/processes.txt"
    members_path="$artifacts_directory/group-members.txt"
    {
        printf 'watchdog timeout process snapshot\n'
        printf 'leader_pid=%s verified_pgid=%s\n' \
            "$leader_pid" "$verified_pgid"
        ps -axo pid=,ppid=,pgid=,stat=,etime=,command= \
            | awk -v target="$verified_pgid" '$3 == target { print }'
    } >"$processes_path" 2>&1
    ps -axo pid=,pgid= 2>/dev/null \
        | awk -v target="$verified_pgid" '$2 == target { print $1 }' \
        >"$members_path"
    chmod 600 "$processes_path" "$members_path"

    case "$platform" in
        Darwin)
            samples_directory="$artifacts_directory/samples"
            mkdir -m 700 "$samples_directory"
            sampler_pids="$artifacts_directory/.sampler-pids"
            : >"$sampler_pids"
            while IFS= read -r member_pid; do
                case "$member_pid" in
                    ''|*[!0-9]*) continue ;;
                esac
                if kill -0 "$member_pid" 2>/dev/null; then
                    /usr/bin/sample "$member_pid" 1 1 \
                        -file "$samples_directory/$member_pid.sample.txt" \
                        >"$samples_directory/$member_pid.sample-command.txt" \
                        2>&1 &
                    printf '%s\n' "$!" >>"$sampler_pids"
                fi
            done <"$members_path"

            sample_started=$SECONDS
            samplers_alive=true
            while [ "$samplers_alive" = true ] \
                && [ $((SECONDS - sample_started)) -lt 5 ]; do
                samplers_alive=false
                while IFS= read -r sampler_pid; do
                    if kill -0 "$sampler_pid" 2>/dev/null; then
                        samplers_alive=true
                        break
                    fi
                done <"$sampler_pids"
                if [ "$samplers_alive" = true ]; then
                    sleep 0.1
                fi
            done
            while IFS= read -r sampler_pid; do
                if kill -0 "$sampler_pid" 2>/dev/null; then
                    kill -TERM "$sampler_pid" 2>/dev/null || true
                fi
                set +e
                wait "$sampler_pid" 2>/dev/null
                set -e
            done <"$sampler_pids"
            rm -f -- "$sampler_pids"
            ;;
        Linux)
            stacks_directory="$artifacts_directory/proc-stacks"
            mkdir -m 700 "$stacks_directory"
            while IFS= read -r member_pid; do
                case "$member_pid" in
                    ''|*[!0-9]*) continue ;;
                esac
                member_directory="$stacks_directory/$member_pid"
                mkdir -m 700 "$member_directory"
                for task_directory in /proc/"$member_pid"/task/*; do
                    [ -d "$task_directory" ] || continue
                    task_id=${task_directory##*/}
                    cat "$task_directory/stack" \
                        >"$member_directory/$task_id.stack.txt" 2>&1 || true
                done
            done <"$members_path"

            diagnostic_tool=
            if command -v pstack >/dev/null 2>&1; then
                diagnostic_tool=pstack
            elif command -v gdb >/dev/null 2>&1; then
                diagnostic_tool=gdb
            fi
            if [ -n "$diagnostic_tool" ]; then
                tool_pids="$artifacts_directory/.diagnostic-tool-pids"
                : >"$tool_pids"
                while IFS= read -r member_pid; do
                    case "$member_pid" in
                        ''|*[!0-9]*) continue ;;
                    esac
                    if [ "$diagnostic_tool" = pstack ]; then
                        pstack "$member_pid" \
                            >"$stacks_directory/$member_pid.pstack.txt" \
                            2>&1 &
                    else
                        gdb -batch -nx \
                            -ex 'set pagination off' \
                            -ex 'thread apply all backtrace' \
                            -p "$member_pid" \
                            >"$stacks_directory/$member_pid.gdb.txt" \
                            2>&1 &
                    fi
                    printf '%s\n' "$!" >>"$tool_pids"
                done <"$members_path"
                tool_started=$SECONDS
                tools_alive=true
                while [ "$tools_alive" = true ] \
                    && [ $((SECONDS - tool_started)) -lt 5 ]; do
                    tools_alive=false
                    while IFS= read -r tool_pid; do
                        if kill -0 "$tool_pid" 2>/dev/null; then
                            tools_alive=true
                            break
                        fi
                    done <"$tool_pids"
                    if [ "$tools_alive" = true ]; then
                        sleep 0.1
                    fi
                done
                while IFS= read -r tool_pid; do
                    if kill -0 "$tool_pid" 2>/dev/null; then
                        kill -TERM "$tool_pid" 2>/dev/null || true
                    fi
                    set +e
                    wait "$tool_pid" 2>/dev/null
                    set -e
                done <"$tool_pids"
                rm -f -- "$tool_pids"
            fi
            ;;
    esac
}

watch_started=$SECONDS
timed_out=false
while kill -0 "$leader_pid" 2>/dev/null; do
    if [ $((SECONDS - watch_started)) -ge "$deadline_seconds" ]; then
        timed_out=true
        break
    fi
    sleep 0.1
done

target_wait_status=0
if [ "$timed_out" = true ]; then
    printf 'watchdog: deadline exceeded after %ss; capturing diagnostics in %s\n' \
        "$deadline_seconds" "$artifacts_directory" >&2
    capture_timeout_diagnostics
    terminate_verified_group
    set +e
    wait "$leader_pid"
    target_wait_status=$?
    set -e
    target_active=false
    command_status=124
else
    set +e
    wait "$leader_pid"
    target_wait_status=$?
    set -e
    target_active=false
    command_status=$target_wait_status
fi

set +e
wait "$tee_pid"
tee_status=$?
set -e
if [ "$tee_status" -ne 0 ] && [ "$command_status" -ne 124 ]; then
    printf 'watchdog: output retention failed with status %s\n' "$tee_status" >&2
    command_status=70
fi

{
    printf 'deadline_seconds=%s\n' "$deadline_seconds"
    printf 'leader_pid=%s\n' "$leader_pid"
    printf 'verified_pgid=%s\n' "$verified_pgid"
    printf 'process_group_verified=true\n'
    printf 'timed_out=%s\n' "$timed_out"
    printf 'target_wait_status=%s\n' "$target_wait_status"
    printf 'tee_status=%s\n' "$tee_status"
    printf 'command_status=%s\n' "$command_status"
} >"$status_receipt"
chmod 600 "$status_receipt" "$command_log"

printf 'watchdog: artifacts retained at %s\n' "$artifacts_directory" >&2
exit "$command_status"
