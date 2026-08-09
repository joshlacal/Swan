#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
validator="${root}/Scripts/validate-reference-relay-artifact.py"
runner="${root}/Scripts/run-reference-relay-acceptance.sh"
bootstrap_helper="${root}/interop/bootstrap-local-space.sh"
secrets_helper="${root}/interop/prepare-interop-secrets.sh"
capture_helper="${root}/interop/reference-relay-capture.go"
relay_compose="${root}/interop/docker-compose.reference-relay.yml"
serve_command="${root}/Sources/swan/SwanCommand.swift"
temporary_directory="$(mktemp -d "${TMPDIR:-/tmp}/swan-reference-relay-test.XXXXXX")"
trap 'rm -rf "$temporary_directory"' EXIT

bash -n "$runner"
python3 - "$runner" <<'PY'
import pathlib
import sys

source = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
crawl = source.index("com.atproto.sync.requestCrawl")
live_open = source.index("poll_until 'Swan live subscribeRepos observation'", crawl)
seed = source.index("seed_relay_host_admission", live_open)
host_entry = source.index("poll_until 'relay host entry'", seed)
capture = source.index('capture_container=', host_entry)
capture_ready = source.index("poll_until 'relay capture readiness'", capture)
fresh_account = source.index('run_nonce=', capture_ready)
assert crawl < live_open < seed < host_entry < capture < capture_ready < fresh_account
assert '"${root}/.reference-relay-live.XXXXXX"' in source
assert '"${root}/.reference-relay-secrets.XXXXXX"' in source
assert '.reference-relay-live.*' in source
assert '.reference-relay-secrets.*' in source
assert 'compose run --rm --no-deps' not in source
prepare = source.index("management_post '/v1/accounts/plc/prepare'", fresh_account)
handle = source.index('task6c-handle', prepare)
activate = source.index("management_post '/v1/accounts/plc/activate'", handle)
lifecycle = source.index("poll_until 'identity-account-sync lifecycle'", activate)
assert fresh_account < prepare < handle < activate < lifecycle
proxy = source.index('--serve-plc-loopback-proxy', fresh_account, prepare)
assert fresh_account < proxy < prepare
assert '--network "container:${swan_id}"' in source
assert '"plcOrigin":"http://127.0.0.1:2582"' in source
assert '"handleLaboratoryOrigin":"http://127.0.0.1:2583"' in source
assert 'swan-interop-bootstrap' not in source
assert 'Authorization: Bearer' in source
assert 'authorization="$(mktemp /tmp/task6c-management-authorization.XXXXXX)"' in source
assert '--header @"$authorization"' in source
write_start = source.index('write_public_record()')
write = source[write_start:source.index('temporary_directory="$(mktemp', write_start)]
assert '"createdAt":' in write
assert 'case "$(tr -d "\\r\\n"' in write
assert '*\\"status\\":\\"passed\\"*)' in write
assert 'docker exec "$toxiproxy_id" curl' not in source
toggle = source.index('set_toxiproxy_enabled()')
toggle_body = source[toggle:source.index('\n}', toggle) + 2]
assert '--network "$network_name"' in toggle_body
assert '--entrypoint curl "$swan_image"' in toggle_body
assert 'http://toxiproxy:8474/proxies/reference-relay-swan' in toggle_body
assert 'set_toxiproxy_enabled true' in source[source.index('cleanup()'):source.index('poll_until()')]
assert 'docker exec "$swan_id" /usr/local/bin/swan firehose force-sync' not in source
assert 'offline_force_sync' not in source
assert 'compose stop' not in source
assert 'docker start "$swan_id"' not in source
sync = source.index('management_firehose_sync()')
sync_body = source[sync:source.index('\n}', sync) + 2]
assert "management_post '/v1/firehose/sync'" in sync_body
assert 'requestId' in sync_body
seed_body_start = source.index('seed_relay_host_admission()')
seed_body = source[seed_body_start:source.index('\n}', seed_body_start) + 2]
assert 'management_firehose_sync "$bootstrap_did"' in seed_body
manual = source.index('management_firehose_sync "$fresh_did"', lifecycle)
manual_sync = source.index("poll_until 'manual sync relay event'", manual)
assert manual < manual_sync
cleanup_body = source[source.index('cleanup()'):source.index('poll_until()')]
assert 'swan_running' not in cleanup_body
assert 'finalize_artifact_after_cleanup' in cleanup_body
assert 'disposable_container_count' in cleanup_body
assert "printf '%s\\n' 'REFERENCE RELAY ACCEPTANCE OK'" in source
assert source.index('compose down --remove-orphans', source.index('cleanup()')) < source.index('finalize_artifact_after_cleanup', source.index('cleanup()'))
assert 'capture_container_is_running' in source
PY
python3 - "$relay_compose" <<'PY'
import pathlib
import sys

source = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
for required in [
    '--management-port', '--management-operator-secret-file',
    '--enable-management-plc-provisioning', '--management-account-kek-file',
    '--management-account-kek-id', '--enable-management-firehose-sync',
]:
    assert required in source
PY
python3 - "$serve_command" <<'PY'
import pathlib
import sys

source = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
assert '.customLong("enable-management-firehose-sync")' in source
assert '--enable-management-firehose-sync requires --management-port' in source
assert '--enable-management-firehose-sync requires --enable-public-firehose' in source
assert 'firehoseSync: managementFirehoseSync' in source
PY
python3 - "$capture_helper" <<'PY'
import pathlib
import sys

source = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
dial = source.index("websocket.DefaultDialer.DialContext")
ready = source.index('filepath.Join(outputDirectory, "ready")', dial)
read = source.index("connection.ReadMessage()", ready)
assert dial < ready < read
assert "os.O_CREATE|os.O_EXCL|os.O_WRONLY" in source[ready:read]
assert '"/.well-known/atproto-did"' in source
assert 'serve-handle-did-file' in source
assert 'serve-plc-loopback-proxy' in source
PY
python3 - "$bootstrap_helper" <<'PY'
import pathlib
import sys

source = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
assert "if stat -c '%a' \"$1\" >/dev/null 2>&1; then" in source
assert "if stat -c '%u' \"$1\" >/dev/null 2>&1; then" in source
PY
python3 - "$secrets_helper" <<'PY'
import pathlib
import sys

source = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
assert 'copy_secret "operator-secret" "$runtime_directory" swan swan' in source
PY
python3 - "$validator" <<'PY'
import ast
import pathlib
import sys
ast.parse(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
PY

good="${temporary_directory}/good.json"
python3 - "$good" <<'PY'
import json, os, sys
artifact = {
  "schemaVersion": 2,
  "scenario": "swan-reference-relay-phase5",
  "status": "passed",
  "swanHead": "e" * 40,
  "indigo": {
    "commit": "8b43a326dbbb394f63b6d68761553cdfe25532de",
    "sourceSHA256": "b" * 64,
    "vendorSHA256": "8" * 64,
    "imageID": "c" * 64,
  },
  "freshState": {
    "volume": "swan-interop-alpha_reference-relay-data",
    "removed": True,
    "listHostsCount": 0,
  },
  "orderedSteps": [
    "fresh_state", "crawl", "subscription_open", "admission_sync",
    "public_host_entry", "account_activation",
    "activation_lifecycle", "first_commit", "offline_five_commit_recovery",
    "manual_sync",
  ],
  "admission": {"syncEmissionCount": 1, "publicHostObserved": True},
  "connectionObservations": [
    {"ordinal": 1, "cursorMode": "live", "upstreamCursor": None},
    {"ordinal": 2, "cursorMode": "backfill", "upstreamCursor": 104},
  ],
  "account": {"didDigest": "d" * 64, "fresh": True},
  "lifecycleKinds": ["identity", "account", "sync"],
  "eventCensus": {
    "identity": 1, "account": 1, "activationSync": 1,
    "commit": 6, "manualSync": 1,
    "orderedKinds": ["identity", "account", "sync", "commit", "commit",
                     "commit", "commit", "commit", "commit", "sync"],
  },
  "captureHelper": {
    "runningThroughFinalFrame": True,
    "terminalStatus": "removed_after_running",
  },
  "firstCommit": {"observed": True, "sequence": 4},
  "offlineRecovery": {
    "expectedCommitCount": 5, "observedCommitCount": 5,
    "relaySequenceStart": 5, "relaySequenceEnd": 9,
    "upstreamCursor": 104, "firstDeliveredRelaySequence": 5,
    "duplicateCount": 0, "gapCount": 0,
    "queryMode": "subscribe_repos_cursor_only",
  },
  "finalRepository": {
    "relayRevision": "222222222222a", "swanRevision": "222222222222a",
    "relayCommitCID": "bafyreiaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "swanCommitCID": "bafyreiaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "relayDataCID": "bafyreiebbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "swanDataCID": "bafyreiebbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "relayMSTDigest": "1" * 64, "swanMSTDigest": "1" * 64,
    "projectionDigest": "2" * 64, "equal": True,
  },
  "manualSync": {"observed": True, "clean": True},
  "verifier": {
    "status": "passed",
    "checks": [
      "canonical_frames", "ordered_lifecycle", "cursor_recovery",
      "repository_commits", "get_repo_mode", "final_mst_equality",
    ],
  },
  "cleanup": {"toxiproxyEnabled": True, "disposableContainersRemaining": 0},
  "artifactPolicy": "aggregate-digest-only",
  "successMarker": "REFERENCE RELAY ACCEPTANCE OK",
}
with open(sys.argv[1], "x", encoding="utf-8") as output:
    json.dump(artifact, output, separators=(",", ":"))
    output.write("\n")
os.chmod(sys.argv[1], 0o600)
PY

"$validator" "$good"

lagged="${temporary_directory}/lagged-checkpoint.json"
python3 - "$good" "$lagged" <<'PY'
import json,os,sys
with open(sys.argv[1],encoding="utf-8") as source:
  artifact=json.load(source)
artifact["connectionObservations"][1]["upstreamCursor"]=900
artifact["offlineRecovery"]["upstreamCursor"]=900
with open(sys.argv[2],"x",encoding="utf-8") as output:
  json.dump(artifact,output,separators=(",",":"))
  output.write("\n")
os.chmod(sys.argv[2],0o600)
PY
"$validator" "$lagged"

reject_mutation() {
  local name="$1"
  local mutation="$2"
  local candidate="${temporary_directory}/${name}.json"
  python3 - "$good" "$candidate" "$mutation" <<'PY'
import json, os, sys
source, destination, mutation = sys.argv[1:]
with open(source, encoding="utf-8") as handle:
    artifact = json.load(handle)
exec(mutation, {"artifact": artifact})
with open(destination, "x", encoding="utf-8") as output:
    json.dump(artifact, output, separators=(",", ":"))
    output.write("\n")
os.chmod(destination, 0o600)
PY
  if "$validator" "$candidate" >/dev/null 2>&1; then
    echo "validator accepted mutation: ${name}" >&2
    exit 1
  fi
}

reject_mutation missing-step 'artifact["orderedSteps"].pop(2)'
reject_mutation reordered-step 'artifact["orderedSteps"][1], artifact["orderedSteps"][2] = artifact["orderedSteps"][2], artifact["orderedSteps"][1]'
reject_mutation missing-admission-sync 'artifact["admission"]["syncEmissionCount"] = 0'
reject_mutation missing-public-host 'artifact["admission"]["publicHostObserved"] = False'
reject_mutation duplicate-lifecycle 'artifact["lifecycleKinds"].insert(1, "identity")'
reject_mutation late-duplicate-identity 'artifact["eventCensus"]["identity"] = 2; artifact["eventCensus"]["orderedKinds"].append("identity")'
reject_mutation late-duplicate-account 'artifact["eventCensus"]["account"] = 2; artifact["eventCensus"]["orderedKinds"].append("account")'
reject_mutation late-duplicate-sync 'artifact["eventCensus"]["manualSync"] = 2; artifact["eventCensus"]["orderedKinds"].append("sync")'
reject_mutation hidden-extra-kind 'artifact["eventCensus"]["orderedKinds"].append("commit")'
reject_mutation capture-not-running 'artifact["captureHelper"]["runningThroughFinalFrame"] = False'
reject_mutation capture-nonzero 'artifact["captureHelper"]["terminalStatus"] = "exited_1"'
reject_mutation wrong-offline-count 'artifact["offlineRecovery"]["observedCommitCount"] = 4'
reject_mutation cursor-gap 'artifact["offlineRecovery"]["firstDeliveredRelaySequence"] = 6'
reject_mutation missing-upstream-observation 'artifact["connectionObservations"][1]["upstreamCursor"] = 103'
reject_mutation conflated-cursor-schema 'artifact["offlineRecovery"]["reconnectCursor"] = artifact["offlineRecovery"].pop("upstreamCursor")'
reject_mutation wrong-query-mode 'artifact["offlineRecovery"]["queryMode"] = "get_repo_since"'
reject_mutation final-revision-mismatch 'artifact["finalRepository"]["relayRevision"] = "222222222222b"'
reject_mutation final-mst-mismatch 'artifact["finalRepository"]["relayMSTDigest"] = "3" * 64'
reject_mutation missing-verifier-check 'artifact["verifier"]["checks"].pop()'
reject_mutation missing-marker 'artifact.pop("successMarker")'
reject_mutation secret-bearing-field 'artifact["oauthToken"] = "secret"'
reject_mutation raw-private-log 'artifact["debug"] = {"rawLogs": ["private"]}'

bad_mode="${temporary_directory}/bad-mode.json"
cp "$good" "$bad_mode"
chmod 0644 "$bad_mode"
if "$validator" "$bad_mode" >/dev/null 2>&1; then
  echo "validator accepted a non-0600 artifact" >&2
  exit 1
fi

if SWAN_REFERENCE_RELAY_PROJECT='INVALID/PROJECT' \
  SWAN_REFERENCE_RELAY_OUTPUT="${temporary_directory}/out.json" \
  "$runner" >/dev/null 2>&1; then
  echo "runner accepted an unsafe Compose project" >&2
  exit 1
fi

if SWAN_REFERENCE_RELAY_PROJECT='swan-interop-alpha' \
  SWAN_REFERENCE_RELAY_OUTPUT='relative.json' \
  "$runner" >/dev/null 2>&1; then
  echo "runner accepted a relative artifact path" >&2
  exit 1
fi

echo "REFERENCE RELAY ACCEPTANCE MUTATION TESTS OK"
