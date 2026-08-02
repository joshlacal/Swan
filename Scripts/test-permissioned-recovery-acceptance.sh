#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
runner="${root}/Scripts/run-permissioned-recovery-acceptance.sh"
runner_body="${root}/Scripts/permissioned-recovery-runner.sh"
validator="${root}/Scripts/validate-permissioned-recovery-artifact.py"
error_extractor="${root}/Scripts/extract-permissioned-recovery-error-code.py"
temporary_directory="$(mktemp -d "${TMPDIR:-/tmp}/permissioned-recovery-harness.XXXXXX")"
trap 'rm -rf "$temporary_directory"' EXIT

bash -n "$runner"
bash -n "$runner_body"
python3 - "$validator" <<'PY'
import ast
import pathlib
import sys

ast.parse(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
PY
python3 - "${temporary_directory}/formatted-error.json" <<'PY'
import json
import pathlib
import sys

artifact = {"status": "failed", "errorCode": "OperationMismatch"}
path = pathlib.Path(sys.argv[1])
path.write_text(json.dumps(artifact, indent=2) + "\n", encoding="utf-8")
PY
[[ "$(python3 "$error_extractor" "${temporary_directory}/formatted-error.json")" == OperationMismatch ]] || {
  echo "formatted artifact error code was not extracted" >&2
  exit 1
}
rg -q 'SWAN_PERMISSIONED_RECOVERY_PROJECT' "$runner"
rg -q 'SWAN_INTEROP_SECRETS_DIR' "$runner"
rg -q 'verify-secret-source\.sh' "$runner"
rg -q -- '--space-oplog-retention 2' "$runner"
rg -q -- '--require-prior-head' "$runner_body"
rg -q -- '--permissioned-write-only-apply-writes' "$runner_body"
rg -q -- 'com.atproto.space.applyWrites#create' "$runner_body"
rg -q -- 'seed_gap_tid="2222222222222"' "$runner_body"
rg -Fq 'seed_terminal_tid="$(wire_tid /tmp/seed-advance.json)"' "$runner_body"
if rg -Fq '${index}' "$runner_body"; then
  echo "write-batch failure handling must not reference the removed per-write index" >&2
  exit 1
fi
rg -Fq 'stage "${phase}-advance-failed-pre-artifact"' "$runner_body"
rg -q -- 'run_recovery seed' "$runner_body"
rg -q -- 'run_recovery acceptance' "$runner_body"
rg -q -- 'run_selector' "$runner_body"
rg -q -- 'generate_run_selector' "$runner"
rg -q 'recover-permissioned' "$runner_body"
rg -q 'account recovery-commit-key' "$runner_body"
if rg -q 'reference-plc|member-plc\.json|verificationMethod|publicKeyMultibase|swift -' "$runner" "$runner_body"; then
  echo "the runner must derive its key only from verified durable Swan history" >&2
  exit 1
fi
awk '
  /normal_stopped=1/ { armed = 1 }
  /docker stop --time 10 "\$normal_swan_id"/ { found = 1; exit(armed ? 0 : 1) }
  END { if (!found) exit 1 }
' "$runner"
if rg -Fq 'docker run --name "$runner_container" -i' "$runner"; then
  echo "the legacy background docker-run path must not remain" >&2
  exit 1
fi
awk '
  /runner_container="\$\{project_name\}-permissioned-recovery-runner-/ { named = 1 }
  /runner_cleanup_armed=1/ { armed = 1 }
  /docker create --name "\$runner_container" -i/ { created = 1 }
  /> "\$runner_id_file"/ { captured = 1 }
  /docker start --attach --interactive "\$runner_id"/ { attached = 1 }
  /docker rm --force "\$runner_id"/ { exact_cleanup = 1 }
  /operation_deadline=\$\(\(SECONDS \+ wait_timeout\)\)/ { bounded = 1 }
  END { exit(named && armed && created && captured && attached && exact_cleanup && bounded ? 0 : 1) }
' "$runner"
awk '
  /remove_runner\(\)/ { in_remove = 1; next }
  in_remove && /^}/ { exit(waited ? 1 : 0) }
  in_remove && /wait "\$runner_pid"/ { waited = 1 }
  END { if (!in_remove) exit 1 }
' "$runner"
rg -Fq "trap '' INT TERM HUP" "$runner"
rg -Fq '((normal_stopped == 1))' "$runner"
if rg -n 'docker[[:space:]]+compose[[:space:]]+(up|down|stop|restart|rm|build)' "$runner"; then
  echo "the recovery harness must not use Compose lifecycle or build commands" >&2
  exit 1
fi

extract_function() {
  local function_name="$1"
  awk -v function_name="$function_name" '
    $0 ~ "^" function_name "\\(\\)" { printing = 1 }
    printing { print }
    printing && /^}/ { exit }
  ' "$runner"
}

capture_function="$(extract_function capture_runner_id)"
matcher_function="$(extract_function runner_id_matches_cleanup_nonce)"
selector_function="$(extract_function generate_run_selector)"
[[ -n "$capture_function" && -n "$matcher_function" && -n "$selector_function" ]] || {
  echo "runner ID capture functions were not found" >&2
  exit 1
}

# The host selector makes every live run's replay keys and rkeys fresh without
# placing that selector in the sanitized artifact. Exercise the generator
# directly, and reject malformed input before the runner can read any secret.
generated_selectors="$(bash -c "$selector_function; generate_run_selector; generate_run_selector")"
selector_one="$(printf '%s\n' "$generated_selectors" | sed -n '1p')"
selector_two="$(printf '%s\n' "$generated_selectors" | sed -n '2p')"
selector_extra="$(printf '%s\n' "$generated_selectors" | sed -n '3p')"
[[ -z "$selector_extra" ]] \
  && [[ "$selector_one" =~ ^[a-z2-7]{16}$ ]] \
  && [[ "$selector_two" =~ ^[a-z2-7]{16}$ ]] \
  && [[ "$selector_one" != "$selector_two" ]] || {
  echo "run selector generation was not canonical and unique" >&2
  exit 1
}
if invalid_selector_output="$(bash "$runner_body" x x x x x x x x invalid 2>&1)"; then
  echo "runner accepted a malformed run selector" >&2
  exit 1
fi
[[ "$invalid_selector_output" == *"run selector is invalid"* ]] || {
  echo "runner did not reject malformed selector before secret access" >&2
  exit 1
}
mock_docker_directory="${temporary_directory}/mock-docker"
mkdir -p "$mock_docker_directory"
python3 - "${mock_docker_directory}/docker" <<'PY'
import os
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
path.write_text("""#!/usr/bin/env bash
set -euo pipefail
case \"$1\" in
  inspect)
    printf '%s /%s %s\\n' \"${MOCK_ID}\" \"${RUNNER_CONTAINER}\" \"${MOCK_LABEL}\"
    ;;
  *) exit 64 ;;
esac
""", encoding="utf-8")
os.chmod(path, 0o700)
PY

assert_lost_stdout_capture() {
  local observed_label="$1"
  local expected_status="$2"
  local nonce="0123456789abcdef0123456789abcdef"
  local candidate="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  local result
  if result="$(
    MOCK_LABEL="$observed_label" \
    MOCK_ID="$candidate" \
    RUNNER_CAPTURE_FUNCTION="$capture_function" \
    RUNNER_MATCHER_FUNCTION="$matcher_function" \
    PATH="${mock_docker_directory}:$PATH" \
    bash -c '
      set -euo pipefail
      eval "$RUNNER_MATCHER_FUNCTION"
      eval "$RUNNER_CAPTURE_FUNCTION"
      runner_id=""
      runner_id_file="$1"
      runner_container="task47-lost-stdout-runner"
      runner_cleanup_nonce="$2"
      export RUNNER_CONTAINER="$runner_container"
      if capture_runner_id; then
        printf "%s" "$runner_id"
      else
        exit 1
      fi
    ' bash "${temporary_directory}/missing-runner.id" "$nonce"
  )"; then
    [[ "$expected_status" == accepted && "$result" == "$candidate" ]] || {
      echo "lost-stdout capture accepted an unexpected lifecycle object" >&2
      exit 1
    }
  else
    [[ "$expected_status" == rejected ]] || {
      echo "lost-stdout capture rejected its exact matching lifecycle object" >&2
      exit 1
    }
  fi
}

# Exercise the real capture functions with a missing stdout-ID file. The exact
# name plus matching label is accepted; a label mismatch fails closed. Docker
# container names are unique, so an exact-name inspect cannot be ambiguous.
assert_lost_stdout_capture 0123456789abcdef0123456789abcdef accepted
assert_lost_stdout_capture ffffffffffffffffffffffffffffffff rejected

good_artifact="${temporary_directory}/good.json"
python3 - "$good_artifact" <<'PY'
import json
import os
import sys

artifact = {
    "scenario": "permissioned-retention-recovery",
    "profileID": "permissioned-data-0016-2026-07-30",
    "gapStatus": 409,
    "gapErrorCode": "full_repo_recovery_required",
    "gapFallbackUsed": False,
    "priorHeadGeneration": 1,
    "priorHeadRevision": "3mrzdwwyosz22",
    "priorCommitment": "a" * 64,
    "replacementHeadGeneration": 2,
    "replacementHeadRevision": "3mrzdwwyosz23",
    "replacementCommitment": "b" * 64,
    "replacementRecordCount": 3,
    "replacementCASAdvanced": True,
    "corruptionRejected": True,
    "corruptErrorCode": "CARBlockCIDMismatch",
    "finalHeadGeneration": 2,
    "finalHeadRevision": "3mrzdwwyosz23",
    "finalCommitment": "b" * 64,
    "lastValidHeadPreserved": True,
    "status": "passed",
    "errorCode": None,
    "fixturePolicy": "semantic-summary-only; no DIDs, space URIs, paths, request identities, verifier material, credentials, tokens, DPoP proofs, record values, or raw LtHash state",
}
with open(sys.argv[1], "w", encoding="utf-8") as output:
    json.dump(artifact, output, sort_keys=True)
os.chmod(sys.argv[1], 0o600)
PY
"$validator" "$good_artifact"

reject_mutation() {
  local field="$1"
  local value_json="$2"
  local expected_code="$3"
  local mutated="${temporary_directory}/${field}.json"
  python3 - "$good_artifact" "$mutated" "$field" "$value_json" <<'PY'
import json
import os
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    artifact = json.load(source)
artifact[sys.argv[3]] = json.loads(sys.argv[4])
with open(sys.argv[2], "w", encoding="utf-8") as output:
    json.dump(artifact, output, sort_keys=True)
os.chmod(sys.argv[2], 0o600)
PY
  local output
  if output="$("$validator" "$mutated")"; then
    echo "validator accepted a mutated ${field}" >&2
    exit 1
  fi
  [[ "$output" == "$expected_code" ]] || {
    echo "validator reported ${output} instead of ${expected_code}" >&2
    exit 1
  }
}

reject_mutation scenario '"alternate-scenario"' scenario
reject_mutation profileID '"alternate-profile"' profile
reject_mutation gapStatus 200 status
reject_mutation gapFallbackUsed true gap-fallback
reject_mutation priorHeadGeneration 0 generation
reject_mutation replacementHeadGeneration 1 head
reject_mutation replacementCASAdvanced false replacement
reject_mutation finalHeadGeneration true generation

reject_coordinated_replacement_mutation() {
  local field="$1"
  local value_json="$2"
  local mutated="${temporary_directory}/replacement-${field}.json"
  python3 - "$good_artifact" "$mutated" "$field" "$value_json" <<'PY'
import json
import os
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    artifact = json.load(source)
field = sys.argv[3]
value = json.loads(sys.argv[4])
artifact[f"replacement{field}"] = value
artifact[f"final{field}"] = value
with open(sys.argv[2], "w", encoding="utf-8") as output:
    json.dump(artifact, output, sort_keys=True)
os.chmod(sys.argv[2], 0o600)
PY
  local output
  if output="$("$validator" "$mutated")"; then
    echo "validator accepted a non-advancing replacement ${field}" >&2
    exit 1
  fi
  [[ "$output" == replacement ]] || {
    echo "validator reported ${output} instead of replacement" >&2
    exit 1
  }
}

reject_coordinated_replacement_mutation HeadGeneration 1
reject_coordinated_replacement_mutation HeadRevision '"3mrzdwwyosz22"'
reject_coordinated_replacement_mutation Commitment '"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"'

echo "permissioned recovery acceptance harness checks passed"
