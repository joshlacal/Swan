#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
runner="${root}/Scripts/run-permissioned-recovery-acceptance.sh"

bash -n "$runner"
rg -q 'SWAN_PERMISSIONED_RECOVERY_PROJECT' "$runner"
rg -q 'SWAN_INTEROP_SECRETS_DIR' "$runner"
rg -q 'verify-secret-source\.sh' "$runner"
rg -q -- '--space-oplog-retention 2' "$runner"
rg -q 'recover-permissioned' "$runner"
rg -q 'full_repo_recovery_required' "$runner"
rg -q 'CARBlockCIDMismatch' "$runner"
rg -q 'verificationMethod' "$runner"
rg -q 'publicKeyMultibase' "$runner"
rg -q 'docker start "\$normal_swan_id"' "$runner"
rg -q 'wait_for_caddy_health' "$runner"
awk '
  /normal_stopped=1/ { armed = 1 }
  /docker stop --time 10 "\$normal_swan_id"/ { found = 1; exit(armed ? 0 : 1) }
  END { if (!found) exit 1 }
' "$runner"
if rg -n 'docker[[:space:]]+compose[[:space:]]+(up|down|stop|restart|rm|build)' "$runner"; then
  echo "the recovery harness must not use Compose lifecycle or build commands" >&2
  exit 1
fi

echo "permissioned recovery acceptance harness static checks passed"
