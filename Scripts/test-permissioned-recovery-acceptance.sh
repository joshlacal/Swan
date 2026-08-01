#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
runner="${root}/Scripts/run-permissioned-recovery-acceptance.sh"
validator="${root}/Scripts/validate-permissioned-recovery-artifact.py"
temporary_directory="$(mktemp -d "${TMPDIR:-/tmp}/permissioned-recovery-harness.XXXXXX")"
trap 'rm -rf "$temporary_directory"' EXIT

bash -n "$runner"
python3 - "$validator" <<'PY'
import ast
import pathlib
import sys

ast.parse(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
PY
rg -q 'SWAN_PERMISSIONED_RECOVERY_PROJECT' "$runner"
rg -q 'SWAN_INTEROP_SECRETS_DIR' "$runner"
rg -q 'verify-secret-source\.sh' "$runner"
rg -q -- '--space-oplog-retention 2' "$runner"
rg -q 'recover-permissioned' "$runner"
rg -q 'account recovery-commit-key' "$runner"
if rg -q 'reference-plc|member-plc\.json|verificationMethod|publicKeyMultibase|swift -' "$runner"; then
  echo "the runner must derive its key only from verified durable Swan history" >&2
  exit 1
fi
awk '
  /normal_stopped=1/ { armed = 1 }
  /docker stop --time 10 "\$normal_swan_id"/ { found = 1; exit(armed ? 0 : 1) }
  END { if (!found) exit 1 }
' "$runner"
awk '
  /runner_container="\$\{project_name\}-permissioned-recovery-runner-/ { named = 1 }
  /docker run --name "\$runner_container" -i/ { started = 1 }
  /docker rm --force "\$runner_container"/ { cleaned = 1 }
  /operation_deadline=\$\(\(SECONDS \+ wait_timeout\)\)/ { bounded = 1 }
  END { exit(named && started && cleaned && bounded ? 0 : 1) }
' "$runner"
rg -Fq "trap '' INT TERM HUP" "$runner"
if rg -n 'docker[[:space:]]+compose[[:space:]]+(up|down|stop|restart|rm|build)' "$runner"; then
  echo "the recovery harness must not use Compose lifecycle or build commands" >&2
  exit 1
fi

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
    "priorHeadPresent": False,
    "validHeadGeneration": 1,
    "validHeadRevision": "3mrzdwwyosz22",
    "validCommitment": "a" * 64,
    "validRecordCount": 3,
    "corruptionRejected": True,
    "corruptErrorCode": "CARBlockCIDMismatch",
    "finalHeadGeneration": 1,
    "finalHeadRevision": "3mrzdwwyosz22",
    "finalCommitment": "a" * 64,
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
  local value="$2"
  local expected_code="$3"
  local mutated="${temporary_directory}/${field}.json"
  python3 - "$good_artifact" "$mutated" "$field" "$value" <<'PY'
import json
import os
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    artifact = json.load(source)
artifact[sys.argv[3]] = sys.argv[4]
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

reject_mutation scenario alternate-scenario scenario
reject_mutation profileID alternate-profile profile
reject_mutation gapStatus 200 status

echo "permissioned recovery acceptance harness checks passed"
