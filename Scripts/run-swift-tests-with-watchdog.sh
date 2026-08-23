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
identity_rejections_path="$artifacts_directory/identity-rejections.txt"
descendant_identities_path="$artifacts_directory/descendant-identities.txt"
descendant_members_path="$artifacts_directory/descendant-members.txt"
process_snapshot_path="$artifacts_directory/.process-snapshot"
descendant_candidates_path="$artifacts_directory/.descendant-candidates"
descendant_seeds_path="$artifacts_directory/.descendant-seeds"
output_fifo="$artifacts_directory/.command-output.fifo"
ready_file="$artifacts_directory/.leader-ready"
go_file="$artifacts_directory/.leader-go"
mkfifo -m 600 "$output_fifo"
: >"$process_group_receipt"
chmod 600 "$process_group_receipt"

leader_pid=
leader_start_identity=
verified_pgid=
group_verified=false
target_active=false
tee_pid=
descendant_cleanup_ready=false
descendant_tracking_initialized=false
deferred_signal_status=

process_start_identity() {
    identity_pid=$1
    case "$identity_pid" in
        ''|*[!0-9]*) return 1 ;;
    esac
    identity_started=$(ps -o lstart= -p "$identity_pid" 2>/dev/null \
        | awk '{$1=$1; print}' || true)
    [ -n "$identity_started" ] || return 1
    case "$platform" in
        Darwin)
            printf '%s\n' "$identity_started"
            ;;
        Linux)
            [ -r "/proc/$identity_pid/stat" ] || return 1
            identity_stat_tail=$(sed 's/^.*) //' "/proc/$identity_pid/stat" \
                2>/dev/null || true)
            identity_start_ticks=$(printf '%s\n' "$identity_stat_tail" \
                | awk '{print $20}' || true)
            [ -n "$identity_start_ticks" ] || return 1
            printf '%s;%s\n' "$identity_started" "$identity_start_ticks"
            ;;
    esac
}

record_identity_rejection() {
    rejection_phase=$1
    rejection_pid=$2
    rejection_expected=$3
    rejection_observed=$4
    [ -n "$rejection_observed" ] || rejection_observed='<missing>'
    printf 'phase=%s pid=%s expected=%s observed=%s\n' \
        "$rejection_phase" "$rejection_pid" \
        "$rejection_expected" "$rejection_observed" \
        >>"$identity_rejections_path"
}

identity_is_current() {
    identity_phase=$1
    identity_pid=$2
    expected_identity=$3
    observed_identity=$(process_start_identity "$identity_pid" || true)
    if [ "$observed_identity" != "$expected_identity" ]; then
        record_identity_rejection \
            "$identity_phase" "$identity_pid" \
            "$expected_identity" "$observed_identity"
        return 1
    fi
    return 0
}

leader_identity_is_current() {
    [ -n "$leader_start_identity" ] || return 1
    observed_leader_identity=$(process_start_identity "$leader_pid" || true)
    [ "$observed_leader_identity" = "$leader_start_identity" ]
}

cleanup_internal_files() {
    rm -f -- \
        "$output_fifo" "$ready_file" "$go_file" \
        "$process_snapshot_path" "$descendant_candidates_path" \
        "$descendant_seeds_path"
}
trap cleanup_internal_files EXIT

group_is_alive() {
    [ "$group_verified" = true ] || return 1
    kill -0 -- "-$verified_pgid" 2>/dev/null
}

handle_signal() {
    signal_status=$1
    if [ "$descendant_cleanup_ready" != true ]; then
        deferred_signal_status=$signal_status
        return
    fi
    trap - HUP INT TERM
    signal_target_wait_status=0
    if [ "$target_active" = true ]; then
        initialize_descendant_tracking
        discover_descendants signal-initial
        terminate_verified_tree
        set +e
        wait "$leader_pid" 2>/dev/null
        signal_target_wait_status=$?
        set -e
        target_active=false
    fi

    set +e
    wait "$tee_pid" 2>/dev/null
    signal_tee_status=$?
    set -e
    {
        printf 'deadline_seconds=%s\n' "$deadline_seconds"
        printf 'leader_pid=%s\n' "$leader_pid"
        printf 'verified_pgid=%s\n' "$verified_pgid"
        printf 'process_group_verified=true\n'
        printf 'timed_out=false\n'
        printf 'externally_signaled=true\n'
        printf 'target_wait_status=%s\n' "$signal_target_wait_status"
        printf 'tee_status=%s\n' "$signal_tee_status"
        printf 'command_status=%s\n' "$signal_status"
    } >"$status_receipt"
    chmod 600 "$status_receipt" "$command_log"
    printf 'watchdog: artifacts retained at %s\n' \
        "$artifacts_directory" >&2
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
leader_start_identity=$(process_start_identity "$leader_pid" || true)
if [ -z "$leader_start_identity" ]; then
    printf 'watchdog: could not bind leader PID %s to a start identity\n' \
        "$leader_pid" >&2
    : >"$go_file"
    set +e
    wait "$leader_pid"
    wait "$tee_pid"
    set -e
    target_active=false
    exit 70
fi

ready_attempt=0
while [ ! -s "$ready_file" ] && [ "$ready_attempt" -lt 500 ]; do
    if ! leader_identity_is_current; then
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
    printf 'leader_start_identity=%s\n' "$leader_start_identity"
    printf 'process_group_verified=true\n'
} >"$process_group_receipt"
chmod 600 "$process_group_receipt"
: >"$go_file"
chmod 600 "$go_file"

initialize_descendant_tracking() {
    if [ "$descendant_tracking_initialized" = true ]; then
        return
    fi
    : >"$identity_rejections_path"
    : >"$descendant_identities_path"
    : >"$descendant_members_path"
    chmod 600 \
        "$identity_rejections_path" \
        "$descendant_identities_path" \
        "$descendant_members_path"
    printf '%s|%s\n' "$leader_pid" "$leader_start_identity" \
        >>"$descendant_identities_path"
    descendant_tracking_initialized=true
}

discover_descendants() {
    discovery_phase=$1
    ps -axo pid=,ppid=,pgid=,stat=,etime=,command= \
        >"$process_snapshot_path"
    : >"$descendant_seeds_path"
    while IFS='|' read -r tracked_pid tracked_identity; do
        case "$tracked_pid" in
            ''|*[!0-9]*) continue ;;
        esac
        if identity_is_current \
            "$discovery_phase-seed" "$tracked_pid" "$tracked_identity"; then
            printf '%s\n' "$tracked_pid" >>"$descendant_seeds_path"
        fi
    done <"$descendant_identities_path"

    awk '
        NR == FNR {
            seed[$1] = 1
            next
        }
        {
            pid = $1
            parent[pid] = $2
            order[++count] = pid
        }
        END {
            for (pid in seed) {
                included[pid] = 1
            }
            changed = 1
            while (changed) {
                changed = 0
                for (position = 1; position <= count; position++) {
                    pid = order[position]
                    if (!included[pid] && included[parent[pid]]) {
                        included[pid] = 1
                        changed = 1
                    }
                }
            }
            for (position = 1; position <= count; position++) {
                pid = order[position]
                if (included[pid]) {
                    print pid
                }
            }
        }
    ' "$descendant_seeds_path" "$process_snapshot_path" \
        >"$descendant_candidates_path"

    while IFS= read -r candidate_pid; do
        case "$candidate_pid" in
            ''|*[!0-9]*) continue ;;
        esac
        existing_identity=$(awk -F'|' -v candidate="$candidate_pid" \
            '$1 == candidate { print substr($0, index($0, "|") + 1); exit }' \
            "$descendant_identities_path")
        if [ -n "$existing_identity" ]; then
            identity_is_current \
                "$discovery_phase-existing" \
                "$candidate_pid" "$existing_identity" || true
            continue
        fi
        candidate_identity=$(process_start_identity "$candidate_pid" || true)
        if [ -n "$candidate_identity" ]; then
            printf '%s|%s\n' "$candidate_pid" "$candidate_identity" \
                >>"$descendant_identities_path"
        fi
    done <"$descendant_candidates_path"
}

write_verified_process_diagnostics() {
    diagnostic_phase=$1
    processes_path="$artifacts_directory/processes.txt"
    : >"$descendant_members_path"
    {
        printf 'watchdog timeout recursive process snapshot\n'
        printf 'leader_pid=%s verified_pgid=%s\n' \
            "$leader_pid" "$verified_pgid"
        while IFS='|' read -r diagnostic_pid diagnostic_identity; do
            case "$diagnostic_pid" in
                ''|*[!0-9]*) continue ;;
            esac
            if identity_is_current \
                "$diagnostic_phase" "$diagnostic_pid" "$diagnostic_identity"; then
                printf '%s\n' "$diagnostic_pid" \
                    >>"$descendant_members_path"
                printf 'pid=%s start_identity=%s\n' \
                    "$diagnostic_pid" "$diagnostic_identity"
                diagnostic_row=$(awk -v candidate="$diagnostic_pid" \
                    '$1 == candidate { print; exit }' \
                    "$process_snapshot_path")
                if [ -n "$diagnostic_row" ]; then
                    printf '%s\n' "$diagnostic_row"
                else
                    printf 'pid=%s process_snapshot=<missing>\n' \
                        "$diagnostic_pid"
                fi
            fi
        done <"$descendant_identities_path"
    } >"$processes_path" 2>&1
    chmod 600 "$processes_path" "$descendant_members_path"
}

signal_tracked_descendants() {
    tree_signal=$1
    tree_phase=$2
    while IFS='|' read -r tree_pid tree_identity; do
        case "$tree_pid" in
            ''|*[!0-9]*) continue ;;
        esac
        [ "$tree_pid" != "$leader_pid" ] || continue
        if identity_is_current "$tree_phase" "$tree_pid" "$tree_identity"; then
            kill "-$tree_signal" "$tree_pid" 2>/dev/null || true
        fi
    done <"$descendant_identities_path"
}

tracked_descendant_is_alive() {
    alive_phase=$1
    while IFS='|' read -r alive_pid alive_identity; do
        case "$alive_pid" in
            ''|*[!0-9]*) continue ;;
        esac
        [ "$alive_pid" != "$leader_pid" ] || continue
        if identity_is_current "$alive_phase" "$alive_pid" "$alive_identity"; then
            return 0
        fi
    done <"$descendant_identities_path"
    return 1
}

terminate_verified_tree() {
    [ "$group_verified" = true ] || return 0
    if group_is_alive; then
        kill -TERM -- "-$verified_pgid" 2>/dev/null || true
    fi
    signal_tracked_descendants TERM term-initial

    tree_grace_started=$SECONDS
    while [ $((SECONDS - tree_grace_started)) -lt 2 ]; do
        if leader_identity_is_current; then
            discover_descendants term-rescan
            signal_tracked_descendants TERM term-rescan
        fi
        if ! group_is_alive \
            && ! tracked_descendant_is_alive term-grace; then
            break
        fi
        sleep 0.1
    done

    if leader_identity_is_current; then
        discover_descendants term-final-rescan
        signal_tracked_descendants TERM term-final-rescan
    fi
    if group_is_alive; then
        kill -KILL -- "-$verified_pgid" 2>/dev/null || true
    fi
    signal_tracked_descendants KILL kill-survivor

    kill_wait_started=$SECONDS
    while tracked_descendant_is_alive kill-wait \
        && [ $((SECONDS - kill_wait_started)) -lt 2 ]; do
        sleep 0.1
    done
}

descendant_cleanup_ready=true
if [ -n "$deferred_signal_status" ]; then
    handle_signal "$deferred_signal_status"
fi

capture_timeout_diagnostics() {
    initialize_descendant_tracking
    discover_descendants timeout-initial
    write_verified_process_diagnostics timeout-diagnostic
    members_path=$descendant_members_path

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
                member_identity=$(awk -F'|' -v candidate="$member_pid" \
                    '$1 == candidate { print substr($0, index($0, "|") + 1); exit }' \
                    "$descendant_identities_path")
                if [ -n "$member_identity" ] \
                    && identity_is_current \
                        sample "$member_pid" "$member_identity"; then
                    /usr/bin/sample "$member_pid" 1 1 \
                        -file "$samples_directory/$member_pid.sample.txt" \
                        >"$samples_directory/$member_pid.sample-command.txt" \
                        2>&1 &
                    sampler_pid=$!
                    sampler_identity=$(process_start_identity "$sampler_pid" || true)
                    printf '%s|%s\n' "$sampler_pid" "$sampler_identity" \
                        >>"$sampler_pids"
                fi
            done <"$members_path"

            sample_started=$SECONDS
            samplers_alive=true
            while [ "$samplers_alive" = true ] \
                && [ $((SECONDS - sample_started)) -lt 5 ]; do
                samplers_alive=false
                while IFS='|' read -r sampler_pid sampler_identity; do
                    observed_sampler_identity=$(
                        process_start_identity "$sampler_pid" || true
                    )
                    if [ -n "$sampler_identity" ] \
                        && [ "$observed_sampler_identity" = "$sampler_identity" ]; then
                        samplers_alive=true
                        break
                    fi
                done <"$sampler_pids"
                if [ "$samplers_alive" = true ]; then
                    sleep 0.1
                fi
            done
            while IFS='|' read -r sampler_pid sampler_identity; do
                observed_sampler_identity=$(
                    process_start_identity "$sampler_pid" || true
                )
                if [ -n "$sampler_identity" ] \
                    && [ "$observed_sampler_identity" = "$sampler_identity" ]; then
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
                member_identity=$(awk -F'|' -v candidate="$member_pid" \
                    '$1 == candidate { print substr($0, index($0, "|") + 1); exit }' \
                    "$descendant_identities_path")
                if [ -z "$member_identity" ] \
                    || ! identity_is_current \
                        proc-stack "$member_pid" "$member_identity"; then
                    continue
                fi
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
                    member_identity=$(awk -F'|' -v candidate="$member_pid" \
                        '$1 == candidate { print substr($0, index($0, "|") + 1); exit }' \
                        "$descendant_identities_path")
                    if [ -z "$member_identity" ] \
                        || ! identity_is_current \
                            diagnostic-tool "$member_pid" "$member_identity"; then
                        continue
                    fi
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
                    tool_pid=$!
                    tool_identity=$(process_start_identity "$tool_pid" || true)
                    printf '%s|%s\n' "$tool_pid" "$tool_identity" \
                        >>"$tool_pids"
                done <"$members_path"
                tool_started=$SECONDS
                tools_alive=true
                while [ "$tools_alive" = true ] \
                    && [ $((SECONDS - tool_started)) -lt 5 ]; do
                    tools_alive=false
                    while IFS='|' read -r tool_pid tool_identity; do
                        observed_tool_identity=$(
                            process_start_identity "$tool_pid" || true
                        )
                        if [ -n "$tool_identity" ] \
                            && [ "$observed_tool_identity" = "$tool_identity" ]; then
                            tools_alive=true
                            break
                        fi
                    done <"$tool_pids"
                    if [ "$tools_alive" = true ]; then
                        sleep 0.1
                    fi
                done
                while IFS='|' read -r tool_pid tool_identity; do
                    observed_tool_identity=$(
                        process_start_identity "$tool_pid" || true
                    )
                    if [ -n "$tool_identity" ] \
                        && [ "$observed_tool_identity" = "$tool_identity" ]; then
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
while leader_identity_is_current; do
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
    terminate_verified_tree
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
