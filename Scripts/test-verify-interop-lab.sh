#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

fail() {
  echo "$*" >&2
  exit 1
}

# Mutation coverage includes YAML values that only become dangerous after
# Compose resolves quoting, comments, aliases, and interpolation.
export SWAN_INTEROP_REQUIRE_EFFECTIVE_COMPOSE="${SWAN_INTEROP_REQUIRE_EFFECTIVE_COMPOSE:-1}"

temporary_directory="$(mktemp -d "${TMPDIR:-/tmp}/swan-interop-verifier.XXXXXX")"
docker_temporary_directory="$(mktemp -d "${root}/.reference-relay-live.XXXXXX")"
trap 'rm -rf "$temporary_directory" "$docker_temporary_directory"' EXIT

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

# Phase 5 is intentionally a second Compose file. The normal lab must stay
# relay-free; this suite makes the optional topology and all of its custody
# inputs explicit before any Docker or Compose production changes are made.
relay_compose_file="interop/docker-compose.reference-relay.yml"
relay_compose_script="interop/compose-reference-relay.sh"
relay_dockerfile="interop/Dockerfile.reference-relay"
relay_dockerignore="interop/Dockerfile.reference-relay.dockerignore"
relay_overlay_profile="interop/reference-relay-overlay/profile.json"
relay_overlay_patch="interop/reference-relay-overlay/reference-relay-private-upstream.patch"
relay_overlay_apply="interop/reference-relay-overlay/apply-reference-relay-overlay.sh"
relay_caddyfile="interop/Caddyfile.reference-relay"
relay_caddy_dockerfile="interop/Dockerfile.caddy.reference-relay"
relay_toxiproxy_config="interop/toxiproxy.reference-relay.json"
relay_toxiproxy_dockerfile="interop/Dockerfile.toxiproxy.reference-relay"

for required_relay_input in \
  "$relay_compose_file" \
  "$relay_compose_script" \
  "$relay_dockerfile" \
  "$relay_dockerignore" \
  "$relay_overlay_profile" \
  "$relay_overlay_patch" \
  "$relay_overlay_apply" \
  "$relay_caddyfile" \
  "$relay_caddy_dockerfile" \
  "$relay_toxiproxy_config" \
  "$relay_toxiproxy_dockerfile"
do
  [[ -f "$required_relay_input" ]] || fail "reference relay topology input is missing: ${required_relay_input}"
done
for executable_relay_input in "$relay_compose_script" "$relay_overlay_apply"; do
  [[ -x "$executable_relay_input" ]] \
    || fail "reference relay topology script is not executable: ${executable_relay_input}"
done

# The lab-only overlay must cover the real WebSocket subscriber, not merely
# host probing. This is deliberately exercised before its static mutation
# cases so a retained PublicOnlyDialer is a hard RED.
overlay_subscription_probe="${temporary_directory}/relay-overlay-subscription"
./"$relay_overlay_apply" "$overlay_subscription_probe" >/dev/null
if rg -q 'ssrf\.PublicOnlyDialer' "$overlay_subscription_probe/cmd/relay/relay/slurper.go"; then
  fail "reference relay overlay leaves the Slurper private-upstream dialer enabled"
fi

# Break caught: a literal unified-diff context line is itself an added line in
# the branch's outer diff, so tabs/blank context become branch whitespace
# errors. The shipped overlay must use only zero-context additions/deletions.
python3 - "$relay_overlay_patch" <<'PY'
import pathlib,sys
lines=pathlib.Path(sys.argv[1]).read_text(encoding="utf-8").splitlines()
if any(line.startswith(" ") for line in lines):
  raise SystemExit("reference relay overlay patch contains context lines")
if any(line.startswith("+") and not line[1:].strip() for line in lines if not line.startswith("+++")):
  raise SystemExit("reference relay overlay patch contains a whitespace-only addition")
PY

branch_base="a9bbd311b3f3d59e0b8fba851eecb949052e1ade"
branch_head="$(jj log -r '@' --no-graph -T 'commit_id')"
branch_whitespace="${temporary_directory}/branch-whitespace.log"
if ! git --git-dir="$(jj git root)" diff --check "${branch_base}..${branch_head}" \
  >"$branch_whitespace" 2>&1; then
  cat "$branch_whitespace" >&2
  fail "Task 7 branch diff contains whitespace errors"
fi
[[ ! -s "$branch_whitespace" ]] || fail "Task 7 branch diff emitted whitespace diagnostics"

# Break caught: reducing hunks to zero context must not change either Indigo
# source file produced by the already-reviewed private-upstream overlay.
custom_overlay="${docker_temporary_directory}/relay-overlay-custom"
mkdir "$custom_overlay"
cp -R ".interop-cache/indigo-8b43a326dbbb394f63b6d68761553cdfe25532de/source/." "$custom_overlay"
tar -xzf ".interop-cache/indigo-vendor-8b43a326dbbb394f63b6d68761553cdfe25532de/indigo-8b43a326dbbb394f63b6d68761553cdfe25532de.vendor.tar.gz" \
  -C "$custom_overlay"
docker run --rm --network none --user "$(id -u):$(id -g)" \
  --read-only --tmpfs /tmp:rw,exec,size=512m,mode=1777 \
  -e GOCACHE=/tmp/go-build \
  --mount "type=bind,src=${root},dst=/workspace,readonly" \
  --mount "type=bind,src=${custom_overlay},dst=/overlay" \
  --entrypoint /usr/local/go/bin/go \
  'docker.io/library/golang@sha256:b305420a68d0f229d91eb3b3ed9e519fcf2cf5461da4bef997bf927e8c0bfd2b' \
  run /workspace/interop/apply-reference-relay-overlay.go /overlay \
    /workspace/interop/reference-relay-overlay/reference-relay-private-upstream.patch
cmp "$overlay_subscription_probe/cmd/relay/relay/host_checker.go" \
  "$custom_overlay/cmd/relay/relay/host_checker.go"
cmp "$overlay_subscription_probe/cmd/relay/relay/slurper.go" \
  "$custom_overlay/cmd/relay/relay/slurper.go"
[[ "$(shasum -a 256 "$custom_overlay/cmd/relay/relay/host_checker.go" | awk '{print $1}')" \
  == "17897e3a2a869b38cbd709b7bb04339742e8a7f9db98f10f81ac1ce5d3e44f98" ]] \
  || fail "reference relay host checker overlay output changed"
[[ "$(shasum -a 256 "$custom_overlay/cmd/relay/relay/slurper.go" | awk '{print $1}')" \
  == "29d57bfdc78a16ff5218bbc34efccc20c112ea294eb2d904c45fbd2b5fc39389" ]] \
  || fail "reference relay Slurper overlay output changed"

mutate_relay_and_require_rejection() {
  name="$1"
  old="$2"
  new="$3"
  expected="$4"
  candidate="${temporary_directory}/${name}.yml"
  cp "$relay_compose_file" "$candidate"

  python3 - "$candidate" "$old" "$new" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
old, new = sys.argv[2:]
contents = path.read_text(encoding="utf-8")
if contents.count(old) != 1:
    raise SystemExit(
        f"relay mutation fixture expected exactly one occurrence, found {contents.count(old)}"
    )
path.write_text(contents.replace(old, new, 1), encoding="utf-8")
PY

  output=""
  if output="$(
    SWAN_INTEROP_REFERENCE_RELAY_COMPOSE_FILE="$candidate" \
      ./Scripts/verify-interop-lab.sh 2>&1
  )"; then
    fail "interop verifier accepted unsafe relay mutation: ${name}"
  fi
  if [[ "$output" != *"$expected"* ]]; then
    echo "interop verifier rejected relay mutation ${name} for the wrong reason" >&2
    echo "expected diagnostic: ${expected}" >&2
    printf '%s\n' "$output" >&2
    exit 1
  fi
}

mutate_relay_file_and_require_rejection() {
  name="$1"
  source_file="$2"
  old="$3"
  new="$4"
  override_name="$5"
  expected="$6"
  candidate="${temporary_directory}/${name}"
  cp "$source_file" "$candidate"
  [[ ! -x "$source_file" ]] || chmod 0755 "$candidate"

  python3 - "$candidate" "$old" "$new" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
old, new = sys.argv[2:]
contents = path.read_text(encoding="utf-8")
if contents.count(old) != 1:
    raise SystemExit(
        f"relay file mutation expected exactly one occurrence, found {contents.count(old)}"
    )
path.write_text(contents.replace(old, new, 1), encoding="utf-8")
PY

  output=""
  if output="$(env "$override_name=$candidate" ./Scripts/verify-interop-lab.sh 2>&1)"; then
    fail "interop verifier accepted unsafe relay file mutation: ${name}"
  fi
  if [[ "$output" != *"$expected"* ]]; then
    echo "interop verifier rejected relay file mutation ${name} for the wrong reason" >&2
    echo "expected diagnostic: ${expected}" >&2
    printf '%s\n' "$output" >&2
    exit 1
  fi
}

mutate_relay_and_require_rejection \
  relay-without-caddy-trust \
  'caddy-trust:/etc/ssl/certs:ro' \
  'caddy-trust:/etc/ssl/certs:rw' \
  'reference relay must mount the Caddy private CA read-only'

mutate_relay_and_require_rejection \
  relay-without-public-firehose \
  $'      - --enable-public-firehose\n' \
  '' \
  'relay topology must explicitly enable the public firehose'

mutate_relay_and_require_rejection \
  relay-bypasses-toxiproxy \
  '      - "swan.test:172.30.0.8"' \
  '      - "swan.test:172.30.0.2"' \
  'reference relay must resolve swan.test through the fixed Toxiproxy address'

mutate_relay_and_require_rejection \
  relay-publishes-direct-port \
  $'    volumes:\n      - reference-relay-data:/data' \
  $'    ports:\n      - "2470:2470"\n    volumes:\n      - reference-relay-data:/data' \
  'reference relay must not publish a host port'

mutate_relay_and_require_rejection \
  relay-parent-workspace-context \
  $'      context: .\n      dockerfile: interop/Dockerfile.reference-relay' \
  $'      context: ..\n      dockerfile: interop/Dockerfile.reference-relay' \
  'reference relay must build from its workspace root'

mutate_relay_file_and_require_rejection \
  relay-overlay-without-private-upstream-opt-in \
  "$relay_overlay_apply" \
  'Transport: ssrf.PublicOnlyTransport(),' \
  'Transport: http.DefaultTransport,' \
  SWAN_INTEROP_REFERENCE_RELAY_OVERLAY_APPLY \
  'reference relay overlay must use the dedicated lab-only private upstream transport'

mutate_relay_file_and_require_rejection \
  relay-overlay-without-slurper-private-upstream-opt-in \
  "$relay_overlay_patch" \
  'netDialer := ssrf.PublicOnlyDialer()' \
  'netDialer := (&net.Dialer{}).DialContext' \
  SWAN_INTEROP_REFERENCE_RELAY_OVERLAY_PATCH \
  'reference relay overlay must replace both private-upstream SSRF guards'

# Phase 5's CGO builder must be a separate immutable Bookworm tuple. The
# existing Alpine vendor materializer pin is intentionally not a substitute.
mutate_relay_file_and_require_rejection \
  relay-builder-digest-mismatch \
  "$relay_dockerfile" \
  'FROM docker.io/library/golang@sha256:b305420a68d0f229d91eb3b3ed9e519fcf2cf5461da4bef997bf927e8c0bfd2b AS build' \
  'FROM docker.io/library/golang@sha256:0000000000000000000000000000000000000000000000000000000000000000 AS build' \
  SWAN_INTEROP_REFERENCE_RELAY_DOCKERFILE \
  'reference relay Dockerfile must use the checksum-pinned Bookworm builder and static offline CGO recipe'

mutate_relay_file_and_require_rejection \
  relay-builder-without-static-recipe \
  "$relay_dockerfile" \
  "go build -tags 'timetzdata netgo osusergo sqlite_omit_load_extension' -ldflags '-linkmode external -extldflags \"-static\"' -o /out/reference-relay ./cmd/relay" \
  "go build -tags timetzdata -o /out/reference-relay ./cmd/relay" \
  SWAN_INTEROP_REFERENCE_RELAY_DOCKERFILE \
  'reference relay Dockerfile must use the checksum-pinned Bookworm builder and static offline CGO recipe'

mutate_relay_file_and_require_rejection \
  relay-runtime-image-drift \
  "$relay_dockerfile" \
  'FROM docker.io/library/golang@sha256:727cfc3c40be55cd1bc9a4a059406b28a059857e3be752aa9d09531e12c20c56' \
  'FROM docker.io/library/golang@sha256:0000000000000000000000000000000000000000000000000000000000000000' \
  SWAN_INTEROP_REFERENCE_RELAY_DOCKERFILE \
  'reference relay Dockerfile must use the pinned Alpine runtime image'

mutate_relay_file_and_require_rejection \
  relay-toxiproxy-without-tls-listener \
  "$relay_toxiproxy_config" \
  $'  },\n  {\n    "name": "reference-relay-swan",\n    "listen": "0.0.0.0:443",\n    "upstream": "caddy:443",\n    "enabled": true\n  }\n' \
  '  }' \
  SWAN_INTEROP_REFERENCE_RELAY_TOXIPROXY_CONFIG_FILE \
  'reference relay Toxiproxy config must contain the dedicated TLS listener'

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

require_acceptance_preflight_rejection \
  invalid-dynamic-fault-mode \
  'SWAN_DYNAMIC_DELEGATION_FAULT_MODE is invalid' \
  env SWAN_DYNAMIC_DELEGATION_FAULT_MODE=time-travel \
    SWAN_DYNAMIC_DELEGATION_PROJECT=preflight-only \
    ./Scripts/run-reference-member-dynamic-delegation-acceptance.sh

require_acceptance_preflight_rejection \
  dynamic-fault-requires-stateful-member \
  'SWAN_DYNAMIC_DELEGATION_FAULT_MODE requires member direction and stateful mode' \
  env SWAN_DYNAMIC_DELEGATION_FAULT_MODE=normal \
    SWAN_DYNAMIC_DELEGATION_DIRECTION=authority \
    SWAN_DYNAMIC_DELEGATION_STATEFUL=1 \
    SWAN_DYNAMIC_DELEGATION_PROJECT=preflight-only \
    ./Scripts/run-reference-member-dynamic-delegation-acceptance.sh

rg -Fq -- 'credentialKeyPLC' Scripts/run-reference-member-dynamic-delegation-acceptance.sh
rg -Fq -- 'reference-authority-dynamic-credential' Scripts/run-reference-member-dynamic-delegation-acceptance.sh
rg -Fq -- 'sanitized semantic artifact for a failed run' \
  Scripts/run-reference-member-dynamic-delegation-acceptance.sh
rg -Fq -- 'reference-member-dynamic-failed.XXXXXX' \
  Scripts/run-reference-member-dynamic-delegation-acceptance.sh

require_acceptance_preflight_rejection \
  missing-stateful-fault-project \
  'SWAN_STATEFUL_FAULT_PROJECT must name a running disposable Compose project' \
  ./Scripts/run-stateful-cross-host-fault-matrix.sh

rg -Fq -- 'modes=(normal offline disconnected delayed duplicated reordered corrupted)' \
  Scripts/run-stateful-cross-host-fault-matrix.sh
rg -Fq -- 'lab stateful-fault-matrix' \
  Scripts/run-stateful-cross-host-fault-matrix.sh
rg -Fq -- 'lab permissioned-replica-head' \
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

rg -Fq -- \
  'COPY Swan/Scripts/project-corruption-recovery-witness.py /usr/local/bin/swan-project-corruption-recovery-witness' \
  Dockerfile || fail 'runtime image must install the corruption witness projector'
rg -Fq -- '/usr/local/bin/swan-project-corruption-recovery-witness' \
  Scripts/run-reference-member-dynamic-delegation-acceptance.sh \
  || fail 'corruption recovery must invoke the installed witness projector'

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
  'FROM node:24.22.1-alpine3.23@sha256:0468540aa58203ff9e40c2aab3907c52644ab818af6176b1c70a026137dc92a2 AS build' \
  'FROM node:24.22.1-alpine3.23 AS build' \
  SWAN_INTEROP_REFERENCE_PDS_DOCKERFILE \
  'reference image Dockerfiles must use the exact pinned Node digest in both stages'

mutate_file_and_require_rejection \
  altered-pnpm-bootstrap-digest \
  interop/Dockerfile.reference-pds \
  'b3951d6d6ff4a9f13dc7cf56cd28d2b8eb37dbcc9c68e52e1e1191873ea9f82a017287ab50baadc5ccc494f036c67c0e47eb13608c2fa36f47711b61ea128e61' \
  '81c631e382066efc25625d5cf029075de07b61b37f6e27350fbd84b1bda5864c8c1967adc280776b45c30a715c0359a3be08fef42d5bb09e2b99029979692916' \
  SWAN_INTEROP_REFERENCE_PDS_DOCKERFILE \
  'reference image Dockerfiles must verify the pinned pnpm bootstrap'

mutate_file_and_require_rejection \
  unpinned-swan-reference-cache-exception \
  Dockerfile.dockerignore \
  '!Swan/.interop-cache/indigo-8b43a326dbbb394f63b6d68761553cdfe25532de/indigo-8b43a326dbbb394f63b6d68761553cdfe25532de.tar.gz' \
  $'!Swan/.interop-cache/indigo-8b43a326dbbb394f63b6d68761553cdfe25532de/indigo-8b43a326dbbb394f63b6d68761553cdfe25532de.tar.gz\n!Swan/.interop-cache/atproto-unsafe.tar.gz' \
  SWAN_INTEROP_SWAN_DOCKERIGNORE \
  'the Swan image build context must allow only the pinned Indigo source and vendor archives'

mutate_file_and_require_rejection \
  wrong-indigo-source-archive-pin \
  Dockerfile.dockerignore \
  '!Swan/.interop-cache/indigo-8b43a326dbbb394f63b6d68761553cdfe25532de/indigo-8b43a326dbbb394f63b6d68761553cdfe25532de.tar.gz' \
  '!Swan/.interop-cache/indigo-0000000000000000000000000000000000000000/indigo-0000000000000000000000000000000000000000.tar.gz' \
  SWAN_INTEROP_SWAN_DOCKERIGNORE \
  'the Swan image build context must allow only the pinned Indigo source and vendor archives'

mutate_file_and_require_rejection \
  broad-late-swan-cache-reinclude \
  Dockerfile.dockerignore \
  '!Swan/.interop-cache/indigo-8b43a326dbbb394f63b6d68761553cdfe25532de/indigo-8b43a326dbbb394f63b6d68761553cdfe25532de.tar.gz' \
  $'!Swan/.interop-cache/indigo-8b43a326dbbb394f63b6d68761553cdfe25532de/indigo-8b43a326dbbb394f63b6d68761553cdfe25532de.tar.gz\n!Swan/**' \
  SWAN_INTEROP_SWAN_DOCKERIGNORE \
  'the Swan image build context must allow only the pinned Indigo source and vendor archives'

mutate_file_and_require_rejection \
  missing-indigo-bundle-traversal \
  Dockerfile.dockerignore \
  $'!Swan/.interop-cache/indigo-8b43a326dbbb394f63b6d68761553cdfe25532de\n' \
  $'# removed pinned Indigo bundle traversal\n' \
  SWAN_INTEROP_SWAN_DOCKERIGNORE \
  'the Swan image build context must allow only the pinned Indigo source and vendor archives'

mutate_file_and_require_rejection \
  wrong-indigo-vendor-archive-pin \
  Dockerfile.dockerignore \
  '!Swan/.interop-cache/indigo-vendor-8b43a326dbbb394f63b6d68761553cdfe25532de/indigo-8b43a326dbbb394f63b6d68761553cdfe25532de.vendor.tar.gz' \
  '!Swan/.interop-cache/indigo-vendor-0000000000000000000000000000000000000000/indigo-0000000000000000000000000000000000000000.vendor.tar.gz' \
  SWAN_INTEROP_SWAN_DOCKERIGNORE \
  'the Swan image build context must allow only the pinned Indigo source and vendor archives'

mutate_file_and_require_rejection \
  extracted-indigo-vendor-reinclude \
  Dockerfile.dockerignore \
  '!Swan/.interop-cache/indigo-vendor-8b43a326dbbb394f63b6d68761553cdfe25532de/indigo-8b43a326dbbb394f63b6d68761553cdfe25532de.vendor.tar.gz' \
  $'!Swan/.interop-cache/indigo-vendor-8b43a326dbbb394f63b6d68761553cdfe25532de/indigo-8b43a326dbbb394f63b6d68761553cdfe25532de.vendor.tar.gz\n!Swan/.interop-cache/indigo-vendor-8b43a326dbbb394f63b6d68761553cdfe25532de/vendor/**' \
  SWAN_INTEROP_SWAN_DOCKERIGNORE \
  'the Swan image build context must allow only the pinned Indigo source and vendor archives'

# Phase 5 acceptance must not silently regress to inferring a relay connection
# or reusing one of the two fixed bootstrap identities. These mutations guard
# only Task 6A's observation and fresh-account input prerequisites.
mutate_file_and_require_rejection \
  missing-relay-subscription-open-observation \
  Sources/SwanHTTP/PublicFirehoseStreamingRoute.swift \
  'swan.public_firehose.subscribe_repos.open' \
  'swan.public_firehose.subscribe_repos.open.disabled' \
  SWAN_INTEROP_PUBLIC_FIREHOSE_ROUTE \
  'relay subscription observation contract is missing'

mutate_file_and_require_rejection \
  missing-relay-subscription-close-observation \
  Sources/SwanHTTP/PublicFirehoseStreamingRoute.swift \
  'swan.public_firehose.subscribe_repos.close' \
  'swan.public_firehose.subscribe_repos.close.disabled' \
  SWAN_INTEROP_PUBLIC_FIREHOSE_ROUTE \
  'relay subscription observation contract is missing'

mutate_file_and_require_rejection \
  missing-fresh-account-request-id-input \
  interop/bootstrap-local-space.sh \
  '--request-id)' \
  '--request-id-disabled)' \
  SWAN_INTEROP_BOOTSTRAP_SCRIPT \
  'fresh-account bootstrap input contract is missing'

mutate_file_and_require_rejection \
  missing-fresh-account-identity-file-input \
  interop/bootstrap-local-space.sh \
  '--identity-file)' \
  '--identity-file-disabled)' \
  SWAN_INTEROP_BOOTSTRAP_SCRIPT \
  'fresh-account bootstrap input contract is missing'

./Scripts/test-bootstrap-local-space.sh
echo "INTEROP LAB VERIFIER MUTATION TESTS OK"
