#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

# Mutation coverage includes YAML values that only become dangerous after
# Compose resolves quoting, comments, aliases, and interpolation.
export SWAN_INTEROP_REQUIRE_EFFECTIVE_COMPOSE="${SWAN_INTEROP_REQUIRE_EFFECTIVE_COMPOSE:-1}"

temporary_directory="$(mktemp -d "${TMPDIR:-/tmp}/swan-interop-verifier.XXXXXX")"
trap 'rm -rf "$temporary_directory"' EXIT

baseline_output=""
if ! baseline_output="$(./Scripts/verify-interop-lab.sh 2>&1)"; then
  echo "interop verifier baseline failed before mutations:" >&2
  printf '%s\n' "$baseline_output" >&2
  exit 1
fi
if [[ "$baseline_output" != *"INTEROP LAB STATIC INVARIANTS OK"* ]]; then
  echo "interop verifier baseline did not report success" >&2
  exit 1
fi

override_output=""
if override_output="$(
  SWAN_INTEROP_NOTIFICATION_CONFIG_FILE="interop/notification-config.json" \
    ./Scripts/verify-interop-lab.sh 2>&1
)"; then
  echo "interop verifier accepted a production input override" >&2
  exit 1
fi
if [[ "$override_output" != *"verifier input overrides require mutation-test mode"* ]]; then
  echo "interop verifier rejected a production input override for the wrong reason" >&2
  printf '%s\n' "$override_output" >&2
  exit 1
fi

export SWAN_INTEROP_VERIFIER_TEST_MODE=1

mutate_and_require_rejection() {
  name="$1"
  old="$2"
  new="$3"
  expected="$4"
  candidate="${temporary_directory}/${name}.yml"
  cp docker-compose.yml "$candidate"

  python3 - "$candidate" "$old" "$new" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
old = sys.argv[2]
new = sys.argv[3]
contents = path.read_text(encoding="utf-8")
if contents.count(old) != 1:
    raise SystemExit(
        f"mutation fixture expected exactly one occurrence, found {contents.count(old)}"
    )
path.write_text(contents.replace(old, new, 1), encoding="utf-8")
PY

  output=""
  if output="$(SWAN_INTEROP_COMPOSE_FILE="$candidate" ./Scripts/verify-interop-lab.sh 2>&1)"; then
    echo "verifier accepted unsafe mutation: ${name}" >&2
    exit 1
  fi
  if [[ "$output" != *"$expected"* ]]; then
    echo "verifier rejected ${name} for the wrong reason" >&2
    echo "expected diagnostic: ${expected}" >&2
    printf '%s\n' "$output" >&2
    exit 1
  fi
}

mutate_json_and_require_rejection() {
  name="$1"
  path_expression="$2"
  encoded_value="$3"
  expected="$4"
  candidate="${temporary_directory}/${name}.json"
  cp interop/notification-config.json "$candidate"

  python3 - "$candidate" "$path_expression" "$encoded_value" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
segments = sys.argv[2].split("/")
value = json.loads(sys.argv[3])
document = json.loads(path.read_text(encoding="utf-8"))
target = document
for segment in segments[:-1]:
    target = target[int(segment)] if isinstance(target, list) else target[segment]
last = segments[-1]
if isinstance(target, list):
    target[int(last)] = value
else:
    target[last] = value
path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
PY

  output=""
  if output="$(
    SWAN_INTEROP_NOTIFICATION_CONFIG_FILE="$candidate" \
      ./Scripts/verify-interop-lab.sh 2>&1
  )"; then
    echo "verifier accepted unsafe notification mutation: ${name}" >&2
    exit 1
  fi
  if [[ "$output" != *"$expected"* ]]; then
    echo "verifier rejected notification mutation ${name} for the wrong reason" >&2
    echo "expected diagnostic: ${expected}" >&2
    printf '%s\n' "$output" >&2
    exit 1
  fi
}

mutate_file_and_require_rejection() {
  name="$1"
  source_file="$2"
  old="$3"
  new="$4"
  override_name="$5"
  expected="$6"
  candidate="${temporary_directory}/${name}"
  cp "$source_file" "$candidate"
  if [[ -x "$source_file" ]]; then
    chmod 0755 "$candidate"
  fi

  python3 - "$candidate" "$old" "$new" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
old = sys.argv[2]
new = sys.argv[3]
contents = path.read_text(encoding="utf-8")
if contents.count(old) != 1:
    raise SystemExit(
        f"mutation fixture expected exactly one occurrence, found {contents.count(old)}"
    )
path.write_text(contents.replace(old, new, 1), encoding="utf-8")
PY

  output=""
  if output="$(env "$override_name=$candidate" ./Scripts/verify-interop-lab.sh 2>&1)"; then
    echo "verifier accepted unsafe file mutation: ${name}" >&2
    exit 1
  fi
  if [[ "$output" != *"$expected"* ]]; then
    echo "verifier rejected file mutation ${name} for the wrong reason" >&2
    echo "expected diagnostic: ${expected}" >&2
    printf '%s\n' "$output" >&2
    exit 1
  fi
}

require_acceptance_preflight_rejection() {
  name="$1"
  expected="$2"
  shift 2

  output=""
  if output="$("$@" 2>&1)"; then
    echo "clean-cache runner accepted unsafe preflight: ${name}" >&2
    exit 1
  fi
  if [[ "$output" != *"$expected"* ]]; then
    echo "clean-cache runner rejected ${name} for the wrong reason" >&2
    echo "expected diagnostic: ${expected}" >&2
    printf '%s\n' "$output" >&2
    exit 1
  fi
}

require_acceptance_preflight_rejection \
  scratch-inside-workspace \
  'scratch path must be outside the source workspace' \
  ./Scripts/run-clean-cache-acceptance.sh \
    --mode macos \
    --scratch-path "$root/Scripts"

secret_fixture="$temporary_directory/external-secrets"
mkdir -p "$secret_fixture/already-present"
require_acceptance_preflight_rejection \
  scratch-inside-secret-source \
  'scratch path must be outside the interop secret directory' \
  env SWAN_INTEROP_SECRETS_DIR="$secret_fixture" \
    ./Scripts/run-clean-cache-acceptance.sh \
      --mode linux \
      --scratch-path "$secret_fixture/already-present"

require_acceptance_preflight_rejection \
  ambient-compose-file \
  'COMPOSE_FILE must be unset for clean-cache acceptance' \
  env COMPOSE_FILE=/tmp/untrusted-compose.yml \
    ./Scripts/run-clean-cache-acceptance.sh --mode macos

require_acceptance_preflight_rejection \
  invalid-reference-variant \
  'usage: Scripts/run-clean-cache-acceptance.sh' \
  ./Scripts/run-clean-cache-acceptance.sh \
    --mode macos \
    --reference-variant unsupported

rg -Fq -- '--reference-variant pinned|recovery' Scripts/run-clean-cache-acceptance.sh
rg -Fq -- 'reference-pds-recovery' Scripts/run-clean-cache-acceptance.sh

require_acceptance_preflight_rejection \
  invalid-dynamic-direction \
  'SWAN_DYNAMIC_DELEGATION_DIRECTION must be member or authority' \
  env SWAN_DYNAMIC_DELEGATION_DIRECTION=unsupported \
    SWAN_DYNAMIC_DELEGATION_PROJECT=preflight-only \
    ./Scripts/run-reference-member-dynamic-delegation-acceptance.sh

rg -Fq -- 'credentialKeyPLC' Scripts/run-reference-member-dynamic-delegation-acceptance.sh
rg -Fq -- 'reference-authority-dynamic-credential' Scripts/run-reference-member-dynamic-delegation-acceptance.sh
rg -Fq -- 'sanitized semantic artifact for a failed run' \
  Scripts/run-reference-member-dynamic-delegation-acceptance.sh
rg -Fq -- 'reference-member-dynamic-failed.XXXXXX' \
  Scripts/run-reference-member-dynamic-delegation-acceptance.sh

require_acceptance_preflight_rejection \
  caller-selected-notification-project \
  'SWAN_NOTIFICATION_RESTART_PROJECT is not accepted' \
  env SWAN_NOTIFICATION_RESTART_PROJECT=existing-lab \
    ./Scripts/run-notification-restart-acceptance.sh

# The restart runner may coexist with another lab project. Its topology
# override must be generated from Docker's live subnet inventory, must carry
# the same trusted Caddy peer relationship, and must not publish the host 443
# port that belongs to another disposable project.
notification_runner="Scripts/run-notification-restart-acceptance.sh"
rg -Fq 'docker network inspect' "$notification_runner"
rg -Fq 'compose_override="${temporary_directory}/compose-network-override.yml"' "$notification_runner"
rg -Fq '      - "${network_prefix}.2"' "$notification_runner"
rg -Fq '    ports: !override []' "$notification_runner"
rg -Fq -- '--file "$compose_override"' "$notification_runner"

mutate_and_require_rejection \
  root-swan-runtime \
  $'  swan:\n    build:' \
  $'  swan:\n    user: root\n    build:' \
  'Swan runtime must not run as root'

mutate_and_require_rejection \
  writable-runtime-secret \
  '/run/secrets/swan-runtime:ro' \
  '/run/secrets/swan-runtime:rw' \
  'runtime secrets must use the read-only prepared volume'

mutate_and_require_rejection \
  writable-swan-root-filesystem \
  '    read_only: true' \
  '    read_only: false' \
  'Swan runtime root filesystem must be read-only'

mutate_and_require_rejection \
  missing-bootstrap-success-dependency \
  $'      swan-bootstrap:\n        condition: service_completed_successfully' \
  $'      swan-bootstrap:\n        condition: service_started' \
  'Swan must wait for successful bootstrap'

mutate_and_require_rejection \
  compose-secret-environment-value \
  $'      PDS_HOSTNAME: pds.test' \
  $'      PDS_HOSTNAME: pds.test\n      PDS_JWT_SECRET: ${PDS_JWT_SECRET}' \
  'Compose interpolation is limited to the external secret directory path'

mutate_and_require_rejection \
  live-scenario-command \
  'echo "planned-not-executed: CA trust prepared; no probes or faults were run"' \
  '/usr/local/bin/swan lab matrix --fail-on-failure' \
  'runner planned status is missing'

mutate_and_require_rejection \
  root-scenario-runner \
  $'  scenario-runner:\n    profiles:' \
  $'  scenario-runner:\n    user: root\n    profiles:' \
  'scenario runner must not run as root'

mutate_and_require_rejection \
  caddy-started-not-ready \
  $'      caddy-ca-ready:\n        condition: service_completed_successfully' \
  $'      caddy:\n        condition: service_started' \
  'runner must wait for prepared CA trust'

mutate_and_require_rejection \
  swan-executable-only-healthcheck \
  'curl --fail --silent --show-error --max-time 2 http://127.0.0.1:3000/health >/dev/null' \
  'test -x /usr/local/bin/swan' \
  'Swan healthcheck must probe the live HTTP listener'

mutate_and_require_rejection \
  reference-pds-started-only \
  $'      reference-plc:\n        condition: service_healthy\n    healthcheck:' \
  $'      reference-plc:\n        condition: service_started\n    healthcheck:' \
  'reference PDS must wait for a healthy PLC'

mutate_and_require_rejection \
  caddy-started-only-swan \
  $'      swan:\n        condition: service_healthy' \
  $'      swan:\n        condition: service_started' \
  'Caddy must wait for a healthy Swan listener'

# shellcheck disable=SC2016 # Pass a literal unsafe Compose interpolation.
mutate_and_require_rejection \
  overbroad-runtime-secret-source \
  'swan-runtime-secrets:/run/secrets/swan-runtime:ro' \
  '${SWAN_INTEROP_SECRETS_DIR}:/run/secrets/swan-runtime:ro' \
  'Compose interpolation is limited to the external secret directory path'

mutate_and_require_rejection \
  missing-lab-notification-config \
  $'      - --notification-config\n      - /etc/swan/interop/notification-config.json\n' \
  '' \
  'Compose must load the checked-in lab notification configuration'

mutate_and_require_rejection \
  missing-notification-delivery \
  $'      - --enable-notification-delivery\n' \
  '' \
  'Compose must enable durable notification delivery and restart recovery'

mutate_and_require_rejection \
  missing-caddy-config-image \
  '    dockerfile: Swan/interop/Dockerfile.caddy' \
  '    dockerfile: Dockerfile' \
  'Caddy must use the pinned checked-in config image'

mutate_and_require_rejection \
  missing-login-trusted-proxy \
  $'      - --login-trusted-proxy-peer\n      - "172.30.0.2"\n' \
  '' \
  'Compose must declare its exact login trusted proxy'

mutate_and_require_rejection \
  floating-caddy-login-peer \
  '        ipv4_address: 172.30.0.2' \
  '        ipv4_address: 172.30.0.3' \
  'Caddy must have the fixed login-proxy peer address'

mutate_and_require_rejection \
  floating-toxiproxy-address \
  '        ipv4_address: 172.30.0.8' \
  '        ipv4_address: 172.30.0.2' \
  'Toxiproxy must reserve an address distinct from Caddy'

mutate_and_require_rejection \
  floating-login-proxy-subnet \
  '        - subnet: 172.30.0.0/24' \
  '        - subnet: 172.31.0.0/24' \
  'interop network must use the fixed login-proxy subnet'

if [[ "$SWAN_INTEROP_REQUIRE_EFFECTIVE_COMPOSE" == "1" ]]; then
  mutate_and_require_rejection \
    effective-root-hidden-by-comment \
    $'    user: swan\n    read_only: true\n    tmpfs:' \
    $'    user: "root" # user: swan\n    read_only: true\n    tmpfs:' \
    'effective Compose Swan runtime must run as swan'
fi

mutate_file_and_require_rejection \
  caddy-adds-forged-client-ip \
  interop/Caddyfile \
  $'\t\theader_up X-Swan-Client-IP {http.request.remote.host}\n' \
  $'\t\theader_up +X-Swan-Client-IP {http.request.remote.host}\n' \
  SWAN_INTEROP_CADDYFILE \
  'Caddy must set the login client identity from its direct peer exactly once'

mutate_file_and_require_rejection \
  caddy-trusts-forwarded-client-ip \
  interop/Caddyfile \
  '{http.request.remote.host}' \
  '{http.request.header.X-Forwarded-For}' \
  SWAN_INTEROP_CADDYFILE \
  'Caddy must set the login client identity from its direct peer exactly once'

mutate_json_and_require_rejection \
  nested-private-key \
  'authorityDestinations/0/privateKey' \
  '"opaque-private-material"' \
  'checked-in notification configuration contains a secret-like field'

mutate_json_and_require_rejection \
  nested-unknown-field \
  'credentialKeyPLC/unexpected' \
  'true' \
  'checked-in notification configuration has unknown fields'

mutate_json_and_require_rejection \
  notification-audience-not-authority \
  'authorityDestinations/0/audience' \
  '"did:web:interop-swan-managing-service"' \
  'checked-in notification authority route is not the fixed restart laboratory'

mutate_file_and_require_rejection \
  duplicate-notification-field \
  interop/notification-config.json \
  $'{\n  "credentialPublicKeys": [],' \
  $'{\n  "managingServiceAudience": "did:web:interop-swan-managing-service",\n  "credentialPublicKeys": [],' \
  SWAN_INTEROP_NOTIFICATION_CONFIG_FILE \
  'checked-in notification configuration has a duplicate field'

mutate_file_and_require_rejection \
  missing-notification-receipt-proof \
  Scripts/run-notification-restart-acceptance.sh \
  'event_id = ?' \
  'event_id IS NOT NULL' \
  SWAN_INTEROP_NOTIFICATION_RESTART_SCENARIO \
  'notification restart scenario is missing its durable convergence contract'

mutate_file_and_require_rejection \
  reference-checksum-build-argument \
  interop/Dockerfile.reference-pds \
  $'WORKDIR /app\n' \
  $'ARG REFERENCE_ARCHIVE_SHA256\nWORKDIR /app\n' \
  SWAN_INTEROP_REFERENCE_PDS_DOCKERFILE \
  'reference image Dockerfiles must not accept an archive checksum build argument'

mutate_file_and_require_rejection \
  mutable-reference-node-image \
  interop/Dockerfile.reference-pds \
  'FROM node:24.15-alpine3.23@sha256:d1b3b4da11eefd5941e7f0b9cf17783fc99d9c6fc34884a665f40a06dbdfc94f AS build' \
  'FROM node:24.15-alpine3.23 AS build' \
  SWAN_INTEROP_REFERENCE_PDS_DOCKERFILE \
  'reference image Dockerfiles must use the exact pinned Node digest in both stages'

mutate_file_and_require_rejection \
  altered-pnpm-bootstrap-digest \
  interop/Dockerfile.reference-pds \
  '71c631e382066efc25625d5cf029075de07b61b37f6e27350fbd84b1bda5864c8c1967adc280776b45c30a715c0359a3be08fef42d5bb09e2b99029979692916' \
  '81c631e382066efc25625d5cf029075de07b61b37f6e27350fbd84b1bda5864c8c1967adc280776b45c30a715c0359a3be08fef42d5bb09e2b99029979692916' \
  SWAN_INTEROP_REFERENCE_PDS_DOCKERFILE \
  'reference image Dockerfiles must verify the pinned pnpm bootstrap'

mutate_file_and_require_rejection \
  swan-reference-cache-exception \
  Dockerfile.dockerignore \
  $'Swan/.interop-cache/**\n' \
  $'Swan/.interop-cache/**\n!Swan/.interop-cache/atproto-unsafe.tar.gz\n' \
  SWAN_INTEROP_SWAN_DOCKERIGNORE \
  'the Swan image build context must not expose a reference-source cache exception'

./Scripts/test-bootstrap-local-space.sh
echo "INTEROP LAB VERIFIER MUTATION TESTS OK"
