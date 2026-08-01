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
read_scope="space:app.bsky.bookmarks?authority=${authority_did}&skey=${space_skey}&action=read"
create_scope="space:app.bsky.bookmarks?authority=${authority_did}&skey=${space_skey}&action=create&collection=${collection}"
export SWAN_LAB_PRODUCER_HANDLE="$member_handle"
export SWAN_LAB_CONSUMER_HANDLE="$authority_handle"
SWAN_LAB_PRODUCER_PASSWORD="$(tr -d '\r\n' < /run/secrets/swan-bootstrap/member.password)"
SWAN_LAB_CONSUMER_PASSWORD="$(tr -d '\r\n' < /run/secrets/swan-bootstrap/authority.password)"
export SWAN_LAB_PRODUCER_PASSWORD SWAN_LAB_CONSUMER_PASSWORD
stage() { printf '%s\n' "$1" > /run/acceptance/stage.txt; }
diagnostic_code() {
  case "$1" in
    HTTP[1-5][0-9][0-9]|InvalidURL|ResponseTooLarge|UnexpectedRedirect|UnexpectedContentType|TransportFailure|FileFailure|InteropFailure|UnknownError)
      printf '%s\n' "$1"
      ;;
    *)
      printf '%s\n' unknown
      ;;
  esac
}
stage key-derivation-start
SWAN_LAB_PERMISSIONED_COMMIT_KEY="$(/usr/local/bin/swan account recovery-commit-key \
  --data-directory /var/lib/swan/data --did "$member_did")"
case "$SWAN_LAB_PERMISSIONED_COMMIT_KEY" in ES256:*) ;; *) exit 1;; esac
export SWAN_LAB_PERMISSIONED_COMMIT_KEY
stage key-derived

write_one() {
  local index="$1"
  local rkey="retention-${index}"
  local private_value
  private_value="$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')"
  # shellcheck disable=SC2016 # `$type` is a literal AT Protocol record key.
  printf '{"space":"%s","repo":"%s","collection":"%s","rkey":"%s","record":{"$type":"app.bsky.feed.post","text":"%s"}}\n' \
    "$space_uri" "$member_did" "$collection" "$rkey" "$private_value" >/tmp/record.json
  local -a command=(
    /usr/local/bin/swan lab live
    --mode permissioned --name "retention-write-${index}"
    --producer-url https://swan.test --consumer-url https://swan.test
    --producer-auth oauth --consumer-auth oauth
    --producer-client-id "$client_id" --producer-redirect-uri http://127.0.0.1/callback
    --consumer-client-id "$client_id" --consumer-redirect-uri http://127.0.0.1/callback
    --scope atproto --scope "$read_scope" --scope "$create_scope"
    --space "$space_uri" --body-file /tmp/record.json
    --read-query "space=$space_uri" "repo=$member_did" "collection=$collection" "rkey=$rkey"
    --output "/tmp/write-${index}.json"
  )
  if [[ "$index" == 1 ]]; then
    command+=(--provision-space --permissioned-list-ops --permissioned-list-ops-exclude-values)
  fi
  stage "write-${index}-start"
  if ! "${command[@]}" >/tmp/live.log 2>&1; then
    error_code="$(sed -n 's/.*"errorCode":"\([A-Za-z0-9_]*\)".*/\1/p' "/tmp/write-${index}.json" || true)"
    if [[ -n "$error_code" ]]; then
      stage "write-${index}-failed-$(diagnostic_code "$error_code")"
    elif grep -q 'permissioned space creation failed' /tmp/live.log; then
      stage "write-${index}-failed-space-create"
    elif grep -q 'permissioned space membership failed' /tmp/live.log; then
      stage "write-${index}-failed-space-member"
    elif grep -q 'OAuth' /tmp/live.log; then
      stage "write-${index}-failed-oauth"
    else
      stage "write-${index}-failed-pre-artifact"
    fi
    exit 1
  fi
  grep -q '"status":"passed"' "/tmp/write-${index}.json"
  if grep -F -- "$private_value" "/tmp/write-${index}.json" >/dev/null; then
    exit 1
  fi
  stage "write-${index}-passed"
}

write_one 1
earliest_tid="$(python3 - /tmp/write-1.json <<'PY'
import json
import re
import sys

value = json.load(open(sys.argv[1], encoding="utf-8")).get("syncOperationRevision")
if not isinstance(value, str) or not re.fullmatch(r"[a-z2-7]{13}", value):
    raise SystemExit(1)
print(value)
PY
)"
case "$earliest_tid" in [a-z2-7][a-z2-7][a-z2-7][a-z2-7][a-z2-7][a-z2-7][a-z2-7][a-z2-7][a-z2-7][a-z2-7][a-z2-7][a-z2-7][a-z2-7]) ;; *) exit 1;; esac
stage earliest-tid-pruned
write_one 2
write_one 3
echo "permissioned recovery acceptance: earliest wire TID was pruned"

stage recovery-start
if ! /usr/local/bin/swan lab recover-permissioned \
  --receiver-did "$authority_did" --repository "$member_did" --space "$space_uri" \
  --data-directory /var/lib/swan/data --name permissioned-retention-recovery \
  --source-url https://swan.test --authority-url https://swan.test \
  --source-auth oauth --source-client-id "$client_id" \
  --source-redirect-uri http://127.0.0.1/callback \
  --scope atproto --scope "$read_scope" --scope "$create_scope" \
  --since "$earliest_tid" --output /run/acceptance/artifact.json \
  --request-timeout-seconds 20 --no-fail-on-failure >/tmp/recovery.log 2>&1
then
  if grep -q 'OAuth' /tmp/recovery.log; then
    stage recovery-command-failed-oauth
  elif grep -q 'permissioned commit public key' /tmp/recovery.log; then
    stage recovery-command-failed-key
  elif grep -q 'receiver account' /tmp/recovery.log; then
    stage recovery-command-failed-receiver
  else
    stage recovery-command-failed-pre-artifact
  fi
  exit 1
fi
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
    "RetentionGapMissing", "CorruptRecoveryAccepted",
}
artifact = json.load(open(sys.argv[1], encoding="utf-8"))
if artifact.get("status") == "passed":
    print("recovery-artifact-passed")
else:
    code = artifact.get("errorCode")
    print("recovery-artifact-failed-" + (code if code in allowed else "unknown"))
PY
)"
unset earliest_tid SWAN_LAB_PERMISSIONED_COMMIT_KEY SWAN_LAB_PRODUCER_PASSWORD SWAN_LAB_CONSUMER_PASSWORD
