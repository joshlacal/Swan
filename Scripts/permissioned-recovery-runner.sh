#!/usr/bin/env bash
set -euo pipefail

# This script is copied into the harness's owner-only temporary directory and
# mounted into the named runner. It accepts no credentials as arguments or
# files: passwords are read only from the runner's read-only bootstrap-secret
# mount and remain in its tmpfs environment.
umask 077
export HOME=/tmp
export SSL_CERT_FILE=/etc/ssl/certs/caddy-local-root.crt

space_uri="$1"
member_did="$2"
collection="$3"
client_id="$4"
member_handle="$5"
authority_handle="$6"
authority_did="$7"
space_skey="$8"
run_selector="$9"
case "$run_selector" in
  [a-z2-7][a-z2-7][a-z2-7][a-z2-7][a-z2-7][a-z2-7][a-z2-7][a-z2-7][a-z2-7][a-z2-7][a-z2-7][a-z2-7][a-z2-7][a-z2-7][a-z2-7][a-z2-7]) ;;
  *) echo "permissioned recovery run selector is invalid" >&2; exit 64 ;;
esac
read_scope="space:app.bsky.bookmarks?authority=${authority_did}&skey=${space_skey}&action=read"
create_scope="space:app.bsky.bookmarks?authority=${authority_did}&skey=${space_skey}&action=create&collection=${collection}"
export SWAN_LAB_PRODUCER_HANDLE="$member_handle"
stage() { printf '%s\n' "$1" > /run/acceptance/stage.txt; }
stage key-derivation-start
SWAN_LAB_PERMISSIONED_COMMIT_KEY="$(/usr/local/bin/swan account recovery-commit-key \
  --data-directory /var/lib/swan/data --did "$member_did")"
case "$SWAN_LAB_PERMISSIONED_COMMIT_KEY" in ES256:*) ;; *) exit 1;; esac
export SWAN_LAB_PERMISSIONED_COMMIT_KEY
stage key-derived

provision_space() {
  # Setup is deliberately outside the write-only advancement primitive. The
  # advancement invocations below never construct an authority/consumer or
  # read an authority password; this one-time bootstrap creates the fresh
  # disposable space and membership before the retention proof begins.
  local private_value
  private_value="$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')"
  SWAN_LAB_CONSUMER_HANDLE="$authority_handle"
  export SWAN_LAB_CONSUMER_HANDLE
  # shellcheck disable=SC2016 # `$type` is a literal AT Protocol record key.
  printf '{"space":"%s","repo":"%s","collection":"%s","rkey":"%s-setup","record":{"$type":"app.bsky.feed.post","text":"%s"}}\n' \
    "$space_uri" "$member_did" "$collection" "$run_selector" "$private_value" >/tmp/provision-record.json
  stage provision-start
  if ! /usr/local/bin/swan lab live \
    --mode permissioned --name "${run_selector}-provision" \
    --producer-url https://swan.test --consumer-url https://swan.test \
    --producer-auth oauth --consumer-auth oauth \
    --producer-password-file /run/secrets/swan-bootstrap/member.password \
    --consumer-password-file /run/secrets/swan-bootstrap/authority.password \
    --producer-client-id "$client_id" --producer-redirect-uri http://127.0.0.1/callback \
    --consumer-client-id "$client_id" --consumer-redirect-uri http://127.0.0.1/callback \
    --scope atproto --scope "$read_scope" --scope "$create_scope" \
    --space "$space_uri" --body-file /tmp/provision-record.json \
    --read-query "space=$space_uri" "repo=$member_did" "collection=$collection" "rkey=${run_selector}-setup" \
    --provision-space --output /tmp/provision.json >/tmp/provision.log 2>&1
  then
    stage provision-failed
    exit 1
  fi
  grep -q '"status":"passed"' /tmp/provision.json
  if grep -F -- "$private_value" /tmp/provision.json >/dev/null; then
    exit 1
  fi
  unset SWAN_LAB_CONSUMER_HANDLE
  stage provision-passed
}

write_batch() {
  local phase="$1"
  local private_value
  private_value="$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')"
  # shellcheck disable=SC2016 # `$type` is a literal AT Protocol record key.
  printf '{"space":"%s","repo":"%s","writes":[{"$type":"com.atproto.space.applyWrites#create","collection":"%s","rkey":"%s-%s-1","value":{"$type":"app.bsky.feed.post","text":"%s"}},{"$type":"com.atproto.space.applyWrites#create","collection":"%s","rkey":"%s-%s-2","value":{"$type":"app.bsky.feed.post","text":"%s"}},{"$type":"com.atproto.space.applyWrites#create","collection":"%s","rkey":"%s-%s-3","value":{"$type":"app.bsky.feed.post","text":"%s"}}]}\n' \
    "$space_uri" "$member_did" "$collection" "$run_selector" "$phase" "$private_value" \
    "$collection" "$run_selector" "$phase" "$private_value" \
    "$collection" "$run_selector" "$phase" "$private_value" >/tmp/apply-writes.json
  local -a command=(
    /usr/local/bin/swan lab live
    --mode permissioned --permissioned-write-only-apply-writes
    --name "${run_selector}-${phase}-advance"
    --producer-url https://swan.test --producer-auth oauth
    --producer-password-file /run/secrets/swan-bootstrap/member.password
    --producer-client-id "$client_id" --producer-redirect-uri http://127.0.0.1/callback
    --scope atproto --scope "$read_scope" --scope "$create_scope"
    --space "$space_uri" --repository "$member_did" --body-file /tmp/apply-writes.json
    --output "/tmp/${phase}-advance.json"
  )
  stage "${phase}-advance-start"
  if ! "${command[@]}" >/tmp/live.log 2>&1; then
    error_code="$(python3 /run/acceptance/extract-permissioned-recovery-error-code.py "/tmp/${phase}-advance.json" || true)"
    if [[ -n "$error_code" ]]; then
      stage "${phase}-advance-failed-${error_code}"
    elif grep -q 'OAuth' /tmp/live.log; then
      stage "${phase}-advance-failed-oauth"
    else
      stage "${phase}-advance-failed-pre-artifact"
    fi
    exit 1
  fi
  grep -q '"status":"passed"' "/tmp/${phase}-advance.json"
  if grep -F -- "$private_value" "/tmp/${phase}-advance.json" >/dev/null; then
    exit 1
  fi
  stage "${phase}-advance-passed"
}

wire_tid() {
  python3 - "$1" <<'PY'
import json
import re
import sys

value = json.load(open(sys.argv[1], encoding="utf-8")).get("terminalRevision")
if not isinstance(value, str) or not re.fullmatch(r"[a-z2-7]{13}", value):
    raise SystemExit(1)
print(value)
PY
}

run_recovery() {
  local phase="$1"
  local since="$2"
  local output="$3"
  local require_prior="$4"
  local -a command=(
    /usr/local/bin/swan lab recover-permissioned
    --receiver-did "$authority_did" --repository "$member_did" --space "$space_uri"
    --data-directory /var/lib/swan/data --name permissioned-retention-recovery
    --source-url https://swan.test --authority-url https://swan.test
    --source-auth oauth --source-password-file /run/secrets/swan-bootstrap/member.password
    --source-client-id "$client_id"
    --source-redirect-uri http://127.0.0.1/callback
    --scope atproto --scope "$read_scope" --scope "$create_scope"
    --since "$since" --request-id "${run_selector}-${phase}-recovery" --output "$output"
    --request-timeout-seconds 20 --no-fail-on-failure
  )
  if [[ "$require_prior" == true ]]; then
    command+=(--require-prior-head)
  fi
  stage "${phase}-recovery-start"
  if ! "${command[@]}" >/tmp/recovery.log 2>&1; then
    if grep -q 'OAuth' /tmp/recovery.log; then
      stage "${phase}-recovery-command-failed-oauth"
    elif grep -q 'permissioned commit public key' /tmp/recovery.log; then
      stage "${phase}-recovery-command-failed-key"
    elif grep -q 'receiver account' /tmp/recovery.log; then
      stage "${phase}-recovery-command-failed-receiver"
    else
      stage "${phase}-recovery-command-failed-pre-artifact"
    fi
    exit 1
  fi
  grep -q '"status":"passed"' "$output" || {
    stage "${phase}-recovery-artifact-failed"
    exit 1
  }
  stage "${phase}-recovery-passed"
}

# Phase one is deliberately a generic first install. It makes the receiver's
# durable base observable before phase two asks the recovery CLI to enforce a
# generation-advancing replacement from that exact base.
provision_space
write_batch seed
# A canonical TID older than every just-created operation forces the retention
# gap. It is deliberately not harvested from an artifact or peer response.
seed_gap_tid="2222222222222"
case "$seed_gap_tid" in [a-z2-7][a-z2-7][a-z2-7][a-z2-7][a-z2-7][a-z2-7][a-z2-7][a-z2-7][a-z2-7][a-z2-7][a-z2-7][a-z2-7][a-z2-7]) ;; *) exit 1;; esac
run_recovery seed "$seed_gap_tid" /tmp/seed-recovery.json false
seed_terminal_tid="$(wire_tid /tmp/seed-advance.json)"
case "$seed_terminal_tid" in [a-z2-7][a-z2-7][a-z2-7][a-z2-7][a-z2-7][a-z2-7][a-z2-7][a-z2-7][a-z2-7][a-z2-7][a-z2-7][a-z2-7][a-z2-7]) ;; *) exit 1;; esac

# The saved retained cursor becomes stale only after the independent
# acceptance prefix advances the source past retention. This isolates replay
# keys and keeps a retained-volume rerun deterministic through the fresh
# selector created by the host harness.
write_batch acceptance
run_recovery acceptance "$seed_terminal_tid" /run/acceptance/artifact.json true

chmod 0600 /run/acceptance/artifact.json
stage "$(python3 - /run/acceptance/artifact.json <<'PY'
import json
import sys

allowed = {
    "CARBlockCIDMismatch", "RecoveryFailed", "RecoveryInvalidBinding",
    "RecoveryInvalidTimestamp", "RecoveryReceiverMismatch",
    "RecoveryUnknownSession", "RecoveryExpiredSession",
    "RecoveryImportInProgress", "RecoveryPoisonedSession",
    "RecoveryConflictingRequestReuse", "RecoveryBindingMismatch",
    "RecoveryVerificationRequired", "RecoveryInvalidStatus",
    "RetentionGapMissing", "PriorHeadRequired", "CorruptRecoveryAccepted",
}
artifact = json.load(open(sys.argv[1], encoding="utf-8"))
if artifact.get("status") == "passed":
    print("recovery-artifact-passed")
else:
    code = artifact.get("errorCode")
    print("recovery-artifact-failed-" + (code if code in allowed else "unknown"))
PY
)"
unset seed_gap_tid seed_terminal_tid SWAN_LAB_PERMISSIONED_COMMIT_KEY
