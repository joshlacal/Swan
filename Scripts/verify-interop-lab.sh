#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

override_names=(
  SWAN_INTEROP_COMPOSE_FILE
  SWAN_INTEROP_NOTIFICATION_CONFIG_FILE
  SWAN_INTEROP_NOTIFICATION_RESTART_SCENARIO
  SWAN_INTEROP_REFERENCE_PDS_DOCKERFILE
  SWAN_INTEROP_REFERENCE_PLC_DOCKERFILE
  SWAN_INTEROP_CADDYFILE
  SWAN_INTEROP_SWAN_DOCKERIGNORE
  SWAN_INTEROP_REFERENCE_PDS_DOCKERIGNORE
  SWAN_INTEROP_REFERENCE_PLC_DOCKERIGNORE
  SWAN_INTEROP_REFERENCE_RELAY_COMPOSE_FILE
  SWAN_INTEROP_REFERENCE_RELAY_DOCKERFILE
  SWAN_INTEROP_REFERENCE_RELAY_OVERLAY_PATCH
  SWAN_INTEROP_REFERENCE_RELAY_OVERLAY_APPLY
  SWAN_INTEROP_REFERENCE_RELAY_TOXIPROXY_CONFIG_FILE
  SWAN_INTEROP_PUBLIC_FIREHOSE_ROUTE
  SWAN_INTEROP_BOOTSTRAP_SCRIPT
  SWAN_INTEROP_REFERENCE_RELAY_CAPTURE
  SWAN_INTEROP_REFERENCE_RELAY_ACCEPTANCE_RUNNER
  SWAN_INTEROP_REFERENCE_RELAY_ACCEPTANCE_VALIDATOR
)
for override_name in "${override_names[@]}"; do
  if [[ -n "${!override_name:-}" ]] \
    && [[ "${SWAN_INTEROP_VERIFIER_TEST_MODE:-0}" != "1" ]]
  then
    echo "verifier input overrides require mutation-test mode" >&2
    exit 64
  fi
done

compose_file="${SWAN_INTEROP_COMPOSE_FILE:-docker-compose.yml}"
notification_config_file="${SWAN_INTEROP_NOTIFICATION_CONFIG_FILE:-interop/notification-config.json}"
notification_restart_scenario="${SWAN_INTEROP_NOTIFICATION_RESTART_SCENARIO:-Scripts/run-notification-restart-acceptance.sh}"
reference_pds_dockerfile="${SWAN_INTEROP_REFERENCE_PDS_DOCKERFILE:-interop/Dockerfile.reference-pds}"
reference_plc_dockerfile="${SWAN_INTEROP_REFERENCE_PLC_DOCKERFILE:-interop/Dockerfile.reference-plc}"
toxiproxy_dockerfile="interop/Dockerfile.toxiproxy"
toxiproxy_config="interop/toxiproxy.json"
caddyfile="${SWAN_INTEROP_CADDYFILE:-interop/Caddyfile}"
swan_dockerignore="${SWAN_INTEROP_SWAN_DOCKERIGNORE:-Dockerfile.dockerignore}"
reference_pds_dockerignore="${SWAN_INTEROP_REFERENCE_PDS_DOCKERIGNORE:-interop/Dockerfile.reference-pds.dockerignore}"
reference_plc_dockerignore="${SWAN_INTEROP_REFERENCE_PLC_DOCKERIGNORE:-interop/Dockerfile.reference-plc.dockerignore}"
recovery_compose_file="interop/docker-compose.reference-recovery.yml"
recovery_compose_script="interop/compose-recovery.sh"
recovery_pds_dockerfile="interop/Dockerfile.reference-pds-recovery"
recovery_overlay_profile="interop/reference-pds-overlay/profile.json"
recovery_overlay_patch="interop/reference-pds-overlay/reference-pds-recovery.patch"
recovery_overlay_apply="interop/reference-pds-overlay/apply-reference-pds-overlay.sh"
recovery_overlay_test="interop/reference-pds-overlay/test-reference-pds-overlay.sh"
relay_compose_file="${SWAN_INTEROP_REFERENCE_RELAY_COMPOSE_FILE:-interop/docker-compose.reference-relay.yml}"
relay_compose_script="interop/compose-reference-relay.sh"
relay_dockerfile="${SWAN_INTEROP_REFERENCE_RELAY_DOCKERFILE:-interop/Dockerfile.reference-relay}"
relay_dockerignore="interop/Dockerfile.reference-relay.dockerignore"
relay_overlay_profile="interop/reference-relay-overlay/profile.json"
relay_overlay_patch="${SWAN_INTEROP_REFERENCE_RELAY_OVERLAY_PATCH:-interop/reference-relay-overlay/reference-relay-private-upstream.patch}"
relay_overlay_apply="${SWAN_INTEROP_REFERENCE_RELAY_OVERLAY_APPLY:-interop/reference-relay-overlay/apply-reference-relay-overlay.sh}"
relay_caddyfile="interop/Caddyfile.reference-relay"
relay_caddy_dockerfile="interop/Dockerfile.caddy.reference-relay"
relay_toxiproxy_config="${SWAN_INTEROP_REFERENCE_RELAY_TOXIPROXY_CONFIG_FILE:-interop/toxiproxy.reference-relay.json}"
relay_toxiproxy_dockerfile="interop/Dockerfile.toxiproxy.reference-relay"
public_firehose_route="${SWAN_INTEROP_PUBLIC_FIREHOSE_ROUTE:-Sources/SwanHTTP/PublicFirehoseStreamingRoute.swift}"
bootstrap_script="${SWAN_INTEROP_BOOTSTRAP_SCRIPT:-interop/bootstrap-local-space.sh}"
relay_capture="${SWAN_INTEROP_REFERENCE_RELAY_CAPTURE:-interop/reference-relay-capture.go}"
relay_acceptance_runner="${SWAN_INTEROP_REFERENCE_RELAY_ACCEPTANCE_RUNNER:-Scripts/run-reference-relay-acceptance.sh}"
relay_acceptance_validator="${SWAN_INTEROP_REFERENCE_RELAY_ACCEPTANCE_VALIDATOR:-Scripts/validate-reference-relay-artifact.py}"

for required_file in \
  "$compose_file" \
  "$notification_config_file" \
  "$notification_restart_scenario" \
  "$reference_pds_dockerfile" \
  "$reference_plc_dockerfile" \
  "$toxiproxy_dockerfile" \
  "$toxiproxy_config" \
  "$caddyfile" \
  "$swan_dockerignore" \
  "$reference_pds_dockerignore" \
  "$reference_plc_dockerignore" \
  "$recovery_compose_file" \
  "$recovery_compose_script" \
  "$recovery_pds_dockerfile" \
  "$recovery_overlay_profile" \
  "$recovery_overlay_patch" \
  "$recovery_overlay_apply" \
  "$recovery_overlay_test" \
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
  "$relay_toxiproxy_dockerfile" \
  "$public_firehose_route" \
  "$bootstrap_script" \
  "$relay_capture" \
  "$relay_acceptance_runner" \
  "$relay_acceptance_validator"
do
  if [[ ! -f "$required_file" ]]; then
    echo "interop verifier input is missing: ${required_file}" >&2
    exit 1
  fi
done
if [[ ! -x "$relay_acceptance_runner" || ! -x "$relay_acceptance_validator" ]]; then
  echo "reference relay acceptance runner and validator must be executable" >&2
  exit 1
fi
if [[ ! -x "$notification_restart_scenario" ]]; then
  echo "notification restart scenario must be executable" >&2
  exit 1
fi
if [[ ! -x "Scripts/test-bootstrap-local-space.sh" ]]; then
  echo "bootstrap fail-closed regression must be executable" >&2
  exit 1
fi
for recovery_script in \
  "$recovery_compose_script" \
  "$recovery_overlay_apply" \
  "$recovery_overlay_test" \
  "$relay_compose_script" \
  "$relay_overlay_apply"
do
  if [[ ! -x "$recovery_script" ]]; then
    echo "recovery overlay script must be executable: ${recovery_script}" >&2
    exit 1
  fi
done

# The recovery image is a qualified disposable variant, not an unpinned fork.
# Bind its Compose entry, source archive, and patch to the active immutable
# profile so a green stateful run cannot silently drift to another source.
python3 - \
  "$recovery_overlay_profile" \
  "Profiles/permissioned-data-0016-2026-07-30.json" \
  "$recovery_overlay_patch" <<'PY'
import hashlib
import json
import pathlib
import sys

overlay_path, active_path, patch_path = map(pathlib.Path, sys.argv[1:])
with overlay_path.open(encoding="utf-8") as handle:
    overlay = json.load(handle)
with active_path.open(encoding="utf-8") as handle:
    active = json.load(handle)

for key in ("referenceImplementationCommit", "referenceArchiveSHA256"):
    if overlay.get(key) != active.get(key):
        raise SystemExit(f"recovery overlay profile is not bound to active profile: {key}")
if overlay.get("overlayPatch") != patch_path.name:
    raise SystemExit("recovery overlay profile points to the wrong patch")
actual = hashlib.sha256(patch_path.read_bytes()).hexdigest()
if overlay.get("overlayPatchSHA256") != actual:
    raise SystemExit("recovery overlay patch checksum does not match its profile")
PY
rg -q '^  reference-pds:$' "$recovery_compose_file"
rg -q '^      context: \.\.$' "$recovery_compose_file"
rg -q '^      dockerfile: Swan/interop/Dockerfile\.reference-pds-recovery$' \
  "$recovery_compose_file"
rg -q -- 'docker-compose.reference-recovery.yml' "$recovery_compose_script"
rg -q -- './interop/verify-reference.sh' "$recovery_compose_script"
rg -q '^COPY Swan/\.interop-cache/atproto-3f6c96d5d2d25438bd40fa89d6ecc37865f8e354\.tar\.gz /tmp/reference\.tar\.gz$' \
  "$recovery_pds_dockerfile"
rg -q '^COPY Swan/interop/reference-pds-overlay/reference-pds-recovery\.patch /tmp/reference-pds-recovery\.patch$' \
  "$recovery_pds_dockerfile"
rg -q '^RUN apk add --no-cache patch' "$recovery_pds_dockerfile"
rg -q 'patch --batch --forward -p1' "$recovery_pds_dockerfile"
if rg -n '^[[:space:]]*RUN .*(curl|git clone|git fetch)' "$recovery_pds_dockerfile"; then
  echo "recovery reference image Dockerfile must not fetch source from the network" >&2
  exit 1
fi
rg -q 'overlay patch checksum mismatch' "$recovery_overlay_apply"
rg -q 'pinned reference checkout' "$recovery_overlay_test"

./interop/verify-reference.sh
./interop/verify-reference-indigo.sh \
  --bundle-dir ".interop-cache/indigo-8b43a326dbbb394f63b6d68761553cdfe25532de"
./interop/verify-reference-indigo-vendor.sh

service_block_from_file() {
  file="$1"
  service="$2"
  awk -v service="$service" '
    $0 == "  " service ":" { capture=1; next }
    capture && /^  [[:alnum:]][[:alnum:]-]*:/ { capture=0 }
    capture { print }
  ' "$file"
}

service_block() {
  service_block_from_file "$compose_file" "$1"
}

require_contains() {
  block="$1"
  expected="$2"
  message="$3"
  if [[ "$block" != *"$expected"* ]]; then
    echo "$message" >&2
    exit 1
  fi
}

reject_contains() {
  block="$1"
  forbidden="$2"
  message="$3"
  if [[ "$block" == *"$forbidden"* ]]; then
    echo "$message" >&2
    exit 1
  fi
}

require_exact_line() {
  block="$1"
  expected="$2"
  message="$3"
  if ! printf '%s\n' "$block" | rg -Fqx "$expected"; then
    echo "$message" >&2
    exit 1
  fi
}

# Prepared-secret custody, asserted from contents rather than from spelling.
#
# The previous version of this check was three `reject_contains` calls over the
# `swan` service block: no `operator-secret`, no `swan-bootstrap-secrets`, no
# `.password`. It passed for a year while the preparation script copied
# `operator-secret` straight into `$runtime_directory` — the very volume the
# `swan` service mounts — because the compose YAML never spells the filename;
# it spells the volume. A text search over YAML cannot see what is inside a
# volume, so it was reading the label on the box.
#
# This runs `interop/prepare-interop-secrets.sh` for real, with an `install`
# stub that reproduces its file/directory creation without the ownership
# changes that need root, and then asserts over the resulting trees:
#
#   1. every `--*-file` path in a Swan `command:` resolves to a file the
#      preparation script actually writes into a directory that service mounts;
#   2. the long-running public runtime reaches exactly the three runtime
#      secrets, and no operator secret or account password;
#   3. the operator secret is reachable only by the bootstrap job and by the
#      one overlay that passes `--management-port`.
#
# The inventory of external secret names is derived from the script's own
# `copy_secret` call sites; the *routing* — which prepared directory each name
# lands in — is decided by executing the script, which is the part that was
# wrong.
verify_prepared_secret_custody() {
  local scratch
  scratch="$(mktemp -d "${TMPDIR:-/tmp}/swan-prepared-secret-custody.XXXXXX")"

  mkdir -p "$scratch/bin"
  cat > "$scratch/bin/install" <<'INSTALL_STUB'
#!/usr/bin/env sh
set -eu
directory=0
mode=""
operands=""
while [ $# -gt 0 ]; do
  case "$1" in
    -d) directory=1; shift ;;
    -o|-g) shift 2 ;;
    -m) mode="$2"; shift 2 ;;
    --) shift; break ;;
    *) operands="$operands $1"; shift ;;
  esac
done
# shellcheck disable=SC2086 # Deliberate re-split of collected operands.
set -- $operands "$@"
if [ "$directory" -eq 1 ]; then
  mkdir -p "$1"
  chmod "${mode:-755}" "$1"
else
  cp "$1" "$2"
  chmod "${mode:-644}" "$2"
fi
INSTALL_STUB
  chmod +x "$scratch/bin/install"

  if ! python3 - "interop/prepare-interop-secrets.sh" "$scratch/external" <<'PY'
import pathlib
import re
import sys

script_path, external_path = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
text = script_path.read_text(encoding="utf-8")

names = set(re.findall(r'copy_secret\s+"([A-Za-z0-9._-]+)"', text))
collecting = False
for line in text.splitlines():
    stripped = line.strip()
    if stripped.startswith("for name in"):
        stripped = stripped[len("for name in"):]
        collecting = True
    elif not collecting:
        continue
    for token in stripped.replace(";", " ").replace("\\", " ").split():
        if token == "do":
            collecting = False
            continue
        if token.startswith(("$", "#")):
            continue
        names.add(token)

if not names:
    raise SystemExit("no external secret names could be derived from the preparation script")

external_path.mkdir(parents=True, exist_ok=True)
external_path.chmod(0o700)
for name in sorted(names):
    target = external_path / name
    target.write_text(f"{name}-verifier-placeholder\n", encoding="utf-8")
    target.chmod(0o400)
PY
  then
    rm -rf "$scratch"
    echo "prepared-secret inventory could not be derived" >&2
    exit 1
  fi

  # Diagnostics are held back until the run fails. The script's permission
  # guard uses GNU `find -perm /077`; BSD `find` rejects that mode string, so a
  # macOS verifier run prints one harmless error per copied secret and the
  # guard simply does not fire. The routing this check is about is unaffected,
  # and the real container run is Linux.
  if ! (
    PATH="$scratch/bin:$PATH" \
      EXTERNAL_SECRETS_DIR="$scratch/external" \
      SWAN_RUNTIME_SECRETS_DIR="$scratch/prepared/swan-runtime" \
      SWAN_OPERATOR_SECRETS_DIR="$scratch/prepared/swan-operator" \
      SWAN_BOOTSTRAP_SECRETS_DIR="$scratch/prepared/swan-bootstrap" \
      REFERENCE_PDS_SECRETS_DIR="$scratch/prepared/reference-pds" \
      sh interop/prepare-interop-secrets.sh \
      >/dev/null 2>"$scratch/prepare.stderr"
  ); then
    cat "$scratch/prepare.stderr" >&2 || true
    rm -rf "$scratch"
    echo "the interop secret preparation script did not run to completion" >&2
    exit 1
  fi

  if ! python3 - "$scratch/prepared" "$compose_file" "$relay_compose_file" <<'PY'
import pathlib
import sys

prepared_root, compose_path, relay_path = map(pathlib.Path, sys.argv[1:4])


def fail(message):
    raise SystemExit(message)


def parse_services(path):
    """Enough of Compose's block style for this laboratory: per service, the
    `environment` map and the `volumes` / `command` sequences. Deliberately not
    a general YAML parser and deliberately not PyYAML — the verifier's only
    Python dependency is the standard library."""
    services = {}
    service = None
    key = None
    in_services = False
    for raw in path.read_text(encoding="utf-8").splitlines():
        if not raw.strip() or raw.strip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        stripped = raw.strip()
        if indent == 0:
            in_services = stripped == "services:"
            service = key = None
            continue
        if not in_services:
            continue
        if indent == 2 and stripped.endswith(":"):
            service = stripped[:-1]
            services.setdefault(service, {"environment": {}, "volumes": [], "command": []})
            key = None
            continue
        if service is None:
            continue
        if indent == 4:
            if stripped.endswith(":"):
                key = stripped[:-1]
            else:
                key = None
            continue
        if key in ("volumes", "command") and stripped.startswith("- "):
            value = stripped[2:].strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                value = value[1:-1]
            services[service][key].append(value)
        elif key == "environment" and ":" in stripped and not stripped.startswith("- "):
            name, _, value = stripped.partition(":")
            services[service]["environment"][name.strip()] = value.strip()
    return services


def split_mount(entry):
    mode = None
    for suffix in (":ro", ":rw"):
        if entry.endswith(suffix):
            mode, entry = suffix[1:], entry[: -len(suffix)]
            break
    if ":" not in entry:
        return None, None, mode
    source, _, target = entry.rpartition(":")
    return source, target, mode


base = parse_services(compose_path)
overlay = parse_services(relay_path)

for required in ("swan-secrets-init", "swan", "swan-bootstrap"):
    if required not in base:
        fail(f"prepared-secret custody: {required} is missing from the base laboratory")

# Which prepared directory the executed script filled, per preparation env var.
executed = {
    "SWAN_RUNTIME_SECRETS_DIR": prepared_root / "swan-runtime",
    "SWAN_OPERATOR_SECRETS_DIR": prepared_root / "swan-operator",
    "SWAN_BOOTSTRAP_SECRETS_DIR": prepared_root / "swan-bootstrap",
    "REFERENCE_PDS_SECRETS_DIR": prepared_root / "reference-pds",
}
contents = {}
for variable, directory in executed.items():
    if not directory.is_dir():
        fail(
            "prepared-secret custody: the preparation script wrote no directory "
            f"for {variable}"
        )
    contents[variable] = {entry.name for entry in directory.iterdir() if entry.is_file()}

# Bind each prepared directory to the named volume the initializer publishes it
# through, using the container path the initializer is configured with.
initializer = base["swan-secrets-init"]
volume_contents = {}
for variable, files in contents.items():
    container_path = initializer["environment"].get(variable)
    if not container_path:
        fail(f"prepared-secret custody: swan-secrets-init does not set {variable}")
    matches = [
        source
        for source, target, _ in map(split_mount, initializer["volumes"])
        if target == container_path
    ]
    if len(matches) != 1:
        fail(
            "prepared-secret custody: swan-secrets-init publishes no single volume "
            f"at {container_path} ({variable})"
        )
    volume_contents[matches[0]] = files

if not volume_contents:
    fail("prepared-secret custody: no prepared volume could be bound to its contents")


def reachable(*services):
    """Every prepared secret file a service can open, keyed by container path."""
    files = {}
    for service in services:
        for entry in service.get("volumes", []):
            source, target, _ = split_mount(entry)
            for name in volume_contents.get(source, set()):
                files[f"{target}/{name}"] = name
    return files


runtime = reachable(base["swan"])
if set(runtime.values()) != {"oauth-server-key", "account-kek", "email-proof-key"}:
    fail(
        "prepared-secret custody: the long-running Swan runtime reaches "
        f"{sorted(set(runtime.values()))}, not exactly the three runtime secrets"
    )

relay_runtime = reachable(base["swan"], overlay.get("swan", {}))
for label, files in (("swan", runtime), ("reference-relay swan", relay_runtime)):
    passwords = sorted(name for name in files.values() if name.endswith(".password"))
    if passwords:
        fail(f"prepared-secret custody: {label} reaches account passwords {passwords}")

if "operator-secret" in runtime.values():
    fail(
        "prepared-secret custody: the base laboratory runtime reaches the "
        "operator secret; it must be prepared into a volume only the "
        "management topology mounts"
    )
if "operator-secret" not in relay_runtime.values():
    fail(
        "prepared-secret custody: the reference-relay runtime enables the "
        "management listener but cannot reach the operator secret"
    )
if "operator-secret" not in reachable(base["swan-bootstrap"]).values():
    fail("prepared-secret custody: bootstrap cannot reach the operator secret")

# Every file-backed CLI flag must name a file that actually gets written. This
# is the assertion the old text search could not make: a `--*-file` path under
# a mounted secret directory that the preparation script never fills is a
# startup failure the YAML looks perfectly fine about.
for label, service, mounts in (
    ("swan", base["swan"], runtime),
    ("reference-relay swan", overlay.get("swan", {}), relay_runtime),
):
    command = service.get("command", [])
    secret_roots = {path.rsplit("/", 1)[0] for path in mounts}
    for index, argument in enumerate(command):
        if not argument.startswith("--") or not argument.endswith("-file"):
            continue
        if index + 1 >= len(command):
            fail(f"prepared-secret custody: {label} passes {argument} with no path")
        path = command[index + 1]
        root = path.rsplit("/", 1)[0]
        if root not in secret_roots:
            continue
        if path not in mounts:
            fail(
                f"prepared-secret custody: {label} passes {argument} {path}, which "
                "the preparation script never writes into a mounted volume"
            )
PY
  then
    rm -rf "$scratch"
    exit 1
  fi
  rm -rf "$scratch"
}

# The normal laboratory deliberately remains relay-free. Phase 5's crawler
# and feature flag live only in the dedicated second Compose file.
if rg -n 'reference-relay|SWAN_PUBLIC_CRAWLERS|--enable-public-firehose|relay\.test' "$compose_file"; then
  echo "base interop laboratory must remain reference-relay-free" >&2
  exit 1
fi

relay_block="$(service_block_from_file "$relay_compose_file" reference-relay)"
relay_swan_block="$(service_block_from_file "$relay_compose_file" swan)"
relay_caddy_block="$(service_block_from_file "$relay_compose_file" caddy)"
relay_toxiproxy_block="$(service_block_from_file "$relay_compose_file" toxiproxy)"
relay_setup_block="$(service_block_from_file "$relay_compose_file" toxiproxy-setup)"
if [[ -z "$relay_block" ]]; then
  echo "reference relay service is missing from the dedicated override" >&2
  exit 1
fi
require_contains "$relay_block" 'dockerfile: interop/Dockerfile.reference-relay' "reference relay must use its pinned Dockerfile"
require_exact_line "$relay_block" '      context: .' "reference relay must build from its workspace root"
require_contains "$relay_block" 'reference-relay-data:/data' "reference relay must persist its data in the dedicated named volume"
require_contains "$relay_block" 'caddy-trust:/etc/ssl/certs:ro' "reference relay must mount the Caddy private CA read-only"
require_contains "$relay_block" 'SSL_CERT_FILE: /etc/ssl/certs/caddy-local-root.crt' "reference relay must use the Caddy private CA trust file"
require_contains "$relay_block" 'RELAY_PLC_HOST: http://reference-plc:2582' "reference relay must resolve PLC through the lab service"
require_contains "$relay_block" 'swan.test:172.30.0.8' "reference relay must resolve swan.test through the fixed Toxiproxy address"
require_contains "$relay_block" '/usr/local/bin/reference-relay-healthcheck' "reference relay healthcheck must probe the live HTTP listener"
require_contains "$relay_block" $'caddy-ca-ready:\n        condition: service_completed_successfully' "reference relay must wait for prepared Caddy trust"
require_contains "$relay_block" $'reference-plc:\n        condition: service_healthy' "reference relay must wait for a healthy PLC"
reject_contains "$relay_block" 'ports:' "reference relay must not publish a host port"
reject_contains "$relay_block" 'RELAY_ADMIN_' "reference relay must not inject admin credentials through Compose"
reject_contains "$relay_block" 'PASSWORD' "reference relay must not inject credentials through Compose"
reject_contains "$relay_block" 'TOKEN' "reference relay must not inject credentials through Compose"
for capture_contract in \
  'COPY interop/reference-relay-capture.go /tmp/reference-relay-capture.go' \
  '-o /out/reference-relay-capture /tmp/reference-relay-capture.go' \
  'COPY --from=build /out/reference-relay-capture /usr/local/bin/reference-relay-capture'
do
  if ! rg -Fq -- "$capture_contract" "$relay_dockerfile"; then
    echo "reference relay image must contain the offline frame capture helper" >&2
    exit 1
  fi
done
if ! rg -Fq '!interop/reference-relay-capture.go' "$relay_dockerignore"; then
  echo "reference relay Docker allowlist must contain only the capture helper source" >&2
  exit 1
fi
if ! rg -Fq 'reference-relay-swan' "$relay_acceptance_runner" \
  || ! rg -Fq 'REFERENCE RELAY ACCEPTANCE OK' "$relay_acceptance_validator"; then
  echo "reference relay ordered runner or aggregate validator is incomplete" >&2
  exit 1
fi
require_contains "$relay_swan_block" 'SWAN_PUBLIC_CRAWLERS: http://reference-relay:2470' "relay topology must wire Swan crawlers to the internal reference relay"
require_contains "$relay_swan_block" '--enable-public-firehose' "relay topology must explicitly enable the public firehose"
require_contains "$relay_caddy_block" 'dockerfile: interop/Dockerfile.caddy.reference-relay' "relay topology must use its Caddy route override"
require_exact_line "$relay_caddy_block" '      context: .' "relay topology Caddy must build from its workspace root"
require_contains "$relay_caddy_block" 'relay.test' "relay topology must give Caddy the relay.test alias"
require_contains "$relay_toxiproxy_block" 'dockerfile: interop/Dockerfile.toxiproxy.reference-relay' "relay topology must use its dedicated Toxiproxy listener config"
require_exact_line "$relay_toxiproxy_block" '      context: .' "relay topology Toxiproxy must build from its workspace root"
require_contains "$relay_setup_block" 'reference-relay-swan' "relay topology must provision the dedicated relay-to-Swan Toxiproxy listener"
require_contains "$relay_setup_block" '"listen":"0.0.0.0:443","upstream":"caddy:443"' "relay topology must route Toxiproxy TLS to Caddy"
if ! rg -q '^  reference-relay-data:$' "$relay_compose_file"; then
  echo "relay topology must declare the dedicated named data volume" >&2
  exit 1
fi

# The private-network exception is a checksum-qualified disposable overlay,
# never a mutation of the pinned source cache or an ambient relay setting.
for required_relay_overlay_line in \
  '--- a/cmd/relay/relay/host_checker.go' \
  'Transport: ssrf.PublicOnlyTransport(),' \
  '--- a/cmd/relay/relay/slurper.go' \
  'netDialer := ssrf.PublicOnlyDialer()'
do
  if ! rg -Fq -- "$required_relay_overlay_line" "$relay_overlay_patch"; then
    echo "reference relay overlay must replace both private-upstream SSRF guards" >&2
    exit 1
  fi
done
python3 - "$relay_overlay_profile" "$relay_overlay_patch" "interop/reference-indigo-vendor-pin.json" <<'PY'
import hashlib
import json
import pathlib
import sys

profile_path, patch_path, pin_path = map(pathlib.Path, sys.argv[1:])
profile = json.loads(profile_path.read_text(encoding="utf-8"))
pin = json.loads(pin_path.read_text(encoding="utf-8"))
expected = {
    "id",
    "indigoCommit",
    "sourceArchiveSHA256",
    "vendorArchiveSHA256",
    "toolchainImageDigest",
    "relayBuilderImageDigest",
    "relayBuilderManifestDigest",
    "relayBuilderPlatform",
    "relayBuilderGoVersion",
    "overlayPatch",
    "overlayPatchSHA256",
}
if set(profile) != expected or profile.get("id") != "reference-relay-private-upstream-overlay-2026-08-08":
    raise SystemExit("reference relay overlay profile has unexpected layout")
for key in (
    "indigoCommit", "sourceArchiveSHA256", "vendorArchiveSHA256", "toolchainImageDigest",
    "relayBuilderImageDigest", "relayBuilderManifestDigest", "relayBuilderPlatform",
    "relayBuilderGoVersion",
):
    if profile.get(key) != pin.get(key):
        raise SystemExit(f"reference relay overlay profile is not bound to the Indigo pin: {key}")
if profile.get("overlayPatch") != patch_path.name:
    raise SystemExit("reference relay overlay profile points to the wrong patch")
if profile.get("overlayPatchSHA256") != hashlib.sha256(patch_path.read_bytes()).hexdigest():
    raise SystemExit("reference relay overlay patch checksum does not match its profile")
PY
require_contains "$(<"$relay_overlay_apply")" 'required_patch_line='"'"'Transport: ssrf.PublicOnlyTransport(),'"'"'' "reference relay overlay must use the dedicated lab-only private upstream transport"
require_contains "$(<"$relay_overlay_apply")" 'required_subscription_patch_line='"'"'netDialer := ssrf.PublicOnlyDialer()'"'"'' "reference relay overlay must use the dedicated Slurper private upstream transport"
# shellcheck disable=SC2016 # Match the literal script contract, including variables.
require_contains "$(<"$relay_overlay_apply")" './interop/verify-reference-indigo.sh --bundle-dir "$source_bundle"' "reference relay overlay must verify the pinned Indigo source"
# shellcheck disable=SC2016 # Match the literal script contract, including variables.
require_contains "$(<"$relay_overlay_apply")" './interop/verify-reference-indigo-vendor.sh --bundle-dir "$vendor_bundle" --source-bundle "$source_bundle"' "reference relay overlay must verify the pinned Indigo vendor bundle"
if rg -n '^[[:space:]]*RUN .*(curl|wget|git clone|git fetch|go mod download)' "$relay_dockerfile"; then
  echo "reference relay Dockerfile must not fetch source from the network" >&2
  exit 1
fi
if ! rg -Fq 'FROM docker.io/library/golang@sha256:754d5200fc3edae76d3b6598a9a3fac7e74981ee6a5413ab955025f185753ef2' "$relay_dockerfile"; then
  echo "reference relay Dockerfile must use the pinned Alpine runtime image" >&2
  exit 1
fi
for required_relay_docker_line in \
  'FROM docker.io/library/golang@sha256:972b4110ba0f47539a975c31e52c64765e1ff19f2d74469ae4a595c6676e80a5 AS build' \
  'COPY .interop-cache/indigo-8b43a326dbbb394f63b6d68761553cdfe25532de/indigo-8b43a326dbbb394f63b6d68761553cdfe25532de.tar.gz /tmp/indigo.tar.gz' \
  'COPY .interop-cache/indigo-vendor-8b43a326dbbb394f63b6d68761553cdfe25532de/indigo-8b43a326dbbb394f63b6d68761553cdfe25532de.vendor.tar.gz /tmp/indigo.vendor.tar.gz' \
  'COPY interop/reference-relay-overlay/reference-relay-private-upstream.patch /tmp/reference-relay-private-upstream.patch' \
  'COPY interop/apply-reference-relay-overlay.go /tmp/apply-reference-relay-overlay.go' \
  'ENV CGO_ENABLED=1 GOPROXY=off GOTOOLCHAIN=local GOFLAGS=-mod=vendor' \
  'go run /tmp/apply-reference-relay-overlay.go /src /tmp/reference-relay-private-upstream.patch' \
  "go build -tags 'timetzdata netgo osusergo sqlite_omit_load_extension' -ldflags '-linkmode external -extldflags \"-static\"' -o /out/reference-relay ./cmd/relay" \
  "go build -tags 'timetzdata netgo osusergo sqlite_omit_load_extension' -ldflags '-linkmode external -extldflags \"-static\"' -o /out/reference-relay-healthcheck /tmp/reference-relay-healthcheck.go" \
  'ENV SSL_CERT_FILE=/etc/ssl/certs/caddy-local-root.crt GODEBUG=netdns=go' \
  'RUN --network=none'
do
  if ! rg -Fq "$required_relay_docker_line" "$relay_dockerfile"; then
    echo "reference relay Dockerfile must use the checksum-pinned Bookworm builder and static offline CGO recipe" >&2
    exit 1
  fi
done
if rg -n 'sed -i.*(host_checker|slurper)' "$relay_dockerfile"; then
  echo "reference relay Dockerfile must apply the checksum-verified overlay rather than reimplement it" >&2
  exit 1
fi
python3 - "$relay_dockerignore" <<'PY'
import pathlib
import sys

rules = {
    line.strip() for line in pathlib.Path(sys.argv[1]).read_text(encoding="utf-8").splitlines()
    if line.strip() and not line.lstrip().startswith("#")
}
required = {
    "**", ".interop-cache/**", "!.interop-cache/",
    "!.interop-cache/indigo-8b43a326dbbb394f63b6d68761553cdfe25532de/indigo-8b43a326dbbb394f63b6d68761553cdfe25532de.tar.gz",
    "!.interop-cache/indigo-vendor-8b43a326dbbb394f63b6d68761553cdfe25532de/indigo-8b43a326dbbb394f63b6d68761553cdfe25532de.vendor.tar.gz",
    "!interop/reference-relay-overlay/",
    "!interop/reference-relay-overlay/reference-relay-private-upstream.patch",
    "!interop/apply-reference-relay-overlay.go",
}
if not required <= rules:
    raise SystemExit("reference relay build context must allow only pinned archives and overlay material")
for forbidden in ("!.interop-cache/**", "!.interop-cache/indigo-8b43a326dbbb394f63b6d68761553cdfe25532de/source/**"):
    if forbidden in rules:
        raise SystemExit("reference relay build context must allow only pinned archives and overlay material")
PY
python3 - "$relay_toxiproxy_config" <<'PY'
import json
import sys
from pathlib import Path

configuration = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
expected = [
    {"name": "reference-pds", "listen": "0.0.0.0:8666", "upstream": "reference-pds:3000", "enabled": True},
    {"name": "reference-relay-swan", "listen": "0.0.0.0:443", "upstream": "caddy:443", "enabled": True},
]
if configuration != expected:
    raise SystemExit("reference relay Toxiproxy config must contain the dedicated TLS listener")
PY
for relay_preflight in './interop/verify-reference-indigo.sh' './interop/verify-reference-indigo-vendor.sh'; do
  if ! rg -Fq "$relay_preflight" "$relay_compose_script"; then
    echo "relay override Compose preflight must verify pinned Indigo source and vendor" >&2
    exit 1
  fi
done

public_firehose_route_contents="$(<"$public_firehose_route")"
for required_observation_event in \
  '"swan.public_firehose.subscribe_repos.open"' \
  '"swan.public_firehose.subscribe_repos.close"'
do
  require_contains \
    "$public_firehose_route_contents" \
    "$required_observation_event" \
    "relay subscription observation contract is missing"
done

bootstrap_script_contents="$(<"$bootstrap_script")"
for required_fresh_account_input in \
  '--request-id)' \
  '--handle)' \
  '--password-file)' \
  '--account-label)' \
  '--identity-file)'
do
  require_contains \
    "$bootstrap_script_contents" \
    "$required_fresh_account_input" \
    "fresh-account bootstrap input contract is missing"
done
for required_fresh_account_safety in \
  'require_explicit_password_file' \
  'require_explicit_identity_file' \
  'require_owner_only_directory'
do
  require_contains \
    "$bootstrap_script_contents" \
    "$required_fresh_account_safety" \
    "fresh-account bootstrap safety contract is missing"
done

for service in \
  swan-secrets-init \
  swan-notification-config-init \
  swan-data-init \
  swan-bootstrap \
  swan \
  reference-pds \
  reference-plc \
  caddy \
  caddy-ca-ready \
  mailpit \
  toxiproxy \
  toxiproxy-setup \
  scenario-runner
do
  if ! rg -q "^  ${service}:" "$compose_file"; then
    echo "required interop service is missing: ${service}" >&2
    exit 1
  fi
done

secrets_init_block="$(service_block swan-secrets-init)"
data_init_block="$(service_block swan-data-init)"
bootstrap_block="$(service_block swan-bootstrap)"
swan_block="$(service_block swan)"
reference_block="$(service_block reference-pds)"
caddy_block="$(service_block caddy)"
ca_ready_block="$(service_block caddy-ca-ready)"
mailpit_block="$(service_block mailpit)"
toxiproxy_block="$(service_block toxiproxy)"
runner_block="$(service_block scenario-runner)"

# Compose may interpolate the external directory path, never secret values.
interpolations="$(rg -o '\$\{[^}]+\}' "$compose_file" || true)"
interpolation_count="$(printf '%s\n' "$interpolations" | awk 'NF { count += 1 } END { print count + 0 }')"
# shellcheck disable=SC2016 # Compare the literal Compose interpolation form.
if [[ "$interpolation_count" -ne 1 ]] \
  || [[ "$interpolations" != '${SWAN_INTEROP_SECRETS_DIR:?set the owner-only lab interop secret directory path}' ]]; then
  echo "Compose interpolation is limited to the external secret directory path" >&2
  exit 1
fi
if rg -n '^[[:space:]]*(SWAN_OAUTH_SERVER_KEY|PDS_(DPOP_SECRET|JWT_SECRET|ADMIN_PASSWORD|REPO_SIGNING_KEY_K256_PRIVATE_KEY_HEX|PLC_ROTATION_KEY_K256_PRIVATE_KEY_HEX)):' "$compose_file"; then
  echo "Compose must not inject secret values through environment entries" >&2
  exit 1
fi

# A root-only copier handles host/container UID mismatch. It never invokes the
# Swan executable, has no network, and produces least-privilege named volumes.
require_contains "$secrets_init_block" 'user: root' "secret preparation must run as root"
require_contains "$secrets_init_block" 'entrypoint: ["/usr/local/bin/swan-interop-prepare-secrets"]' "secret preparation wrapper is missing"
require_contains "$secrets_init_block" ':/external-secrets:ro' "external secrets must be mounted read-only"
require_contains "$secrets_init_block" 'swan-runtime-secrets:/prepared/swan-runtime' "runtime secret output is missing"
require_contains "$secrets_init_block" 'swan-operator-secrets:/prepared/swan-operator' "operator secret output is missing"
require_contains "$secrets_init_block" 'SWAN_OPERATOR_SECRETS_DIR: /prepared/swan-operator' "operator secret output directory is not configured"
require_contains "$secrets_init_block" 'swan-bootstrap-secrets:/prepared/swan-bootstrap' "bootstrap secret output is missing"
require_contains "$secrets_init_block" 'reference-pds-secrets:/prepared/reference-pds' "PDS secret output is missing"
require_contains "$secrets_init_block" 'network_mode: "none"' "secret preparation must be network-isolated"
reject_contains "$secrets_init_block" 'entrypoint: ["/usr/local/bin/swan"]' "root secret preparation must not run Swan"
reject_contains "$secrets_init_block" 'privileged:' "secret preparation must not be privileged"

require_contains "$data_init_block" 'user: root' "data preparation must run as root"
require_contains "$data_init_block" 'network_mode: "none"' "data preparation must be network-isolated"
require_contains "$data_init_block" 'install -d -o swan -g swan -m 0700 /var/lib/swan/data' "data preparation ownership contract is missing"
reject_contains "$data_init_block" 'entrypoint: ["/usr/local/bin/swan"]' "root data preparation must not run Swan"
reject_contains "$data_init_block" 'privileged:' "data preparation must not be privileged"

require_contains "$bootstrap_block" 'user: swan' "bootstrap must run as swan"
require_contains "$bootstrap_block" 'entrypoint: ["/usr/local/bin/swan-interop-bootstrap"]' "bootstrap wrapper is missing"
require_contains "$bootstrap_block" 'swan-bootstrap-secrets:/run/secrets/swan-bootstrap:ro' "bootstrap secrets must be read-only"
require_contains "$bootstrap_block" $'swan-secrets-init:\n        condition: service_completed_successfully' "bootstrap must wait for prepared secrets"
require_contains "$bootstrap_block" $'swan-data-init:\n        condition: service_completed_successfully' "bootstrap must wait for prepared data"
reject_contains "$bootstrap_block" 'user: root' "bootstrap must not run as root"
reject_contains "$bootstrap_block" 'privileged:' "bootstrap must not be privileged"
# shellcheck disable=SC2016 # Reject the literal interpolation prefix.
reject_contains "$bootstrap_block" '${SWAN_INTEROP_SECRETS_DIR' "bootstrap must not mount host secrets directly"

# The long-running runtime is explicitly unprivileged and receives only the
# runtime secret volume, never bootstrap passwords/operator material.
require_contains "$swan_block" 'user: swan' "Swan runtime must explicitly run as swan"
require_contains "$swan_block" 'read_only: true' "Swan runtime root filesystem must be read-only"
require_contains "$swan_block" '/tmp:size=16m,mode=1777' "Swan runtime must have only a bounded writable temporary filesystem"
reject_contains "$swan_block" 'user: root' "Swan runtime must not run as root"
reject_contains "$swan_block" 'privileged:' "Swan runtime must not be privileged"
reject_contains "$swan_block" 'cap_add:' "Swan runtime must not add capabilities"
reject_contains "$swan_block" '/var/run/docker.sock' "Swan runtime must not mount the Docker socket"
require_contains "$swan_block" 'swan-runtime-secrets:/run/secrets/swan-runtime:ro' "runtime secrets must use the read-only prepared volume"
reject_contains "$swan_block" 'swan-bootstrap-secrets' "runtime must not receive bootstrap-only secrets"
# Custody is asserted from the files the preparation script actually writes,
# not from the spelling of this YAML — see verify_prepared_secret_custody.
verify_prepared_secret_custody
# shellcheck disable=SC2016 # Reject the literal interpolation prefix.
reject_contains "$swan_block" '${SWAN_INTEROP_SECRETS_DIR' "runtime must not mount host secrets directly"
require_contains "$swan_block" '--oauth-server-key-file' "file-backed OAuth server key flag is missing"
require_contains "$swan_block" '/run/secrets/swan-runtime/oauth-server-key' "OAuth server key path is wrong"
require_contains "$swan_block" '--enable-oauth-authorization-server' "Compose must enable the complete OAuth authorization server"
require_contains "$swan_block" '--oauth-allow-localhost-development-client' "Compose must declare its localhost client metadata exception"
require_contains "$swan_block" '--login-trusted-proxy-peer' "Compose must declare its exact login trusted proxy"
require_contains "$swan_block" '"172.30.0.2"' "Compose login trusted proxy must match Caddy's fixed peer"
require_contains "$swan_block" '--notification-config' "Compose must load the checked-in lab notification configuration"
require_contains "$swan_block" '/etc/swan/interop/notification-config.json' "Compose notification configuration path is wrong"
require_contains "$swan_block" '--enable-notification-delivery' "Compose must enable durable notification delivery and restart recovery"
require_contains "$swan_block" '--enable-email-recovery' "Compose must enable durable account-email recovery"
require_contains "$swan_block" '--email-proof-key-file' "Compose email proof key flag is missing"
require_contains "$swan_block" '/run/secrets/swan-runtime/email-proof-key' "Compose email proof key path is wrong"
require_contains "$swan_block" '--email-smtp-host' "Compose email SMTP host flag is missing"
require_contains "$swan_block" 'mailpit' "Compose email delivery must target the isolated Mailpit service"
reject_contains "$swan_block" './interop/notification-config.json:' "Compose must not use a host file bind for notification configuration"
# The laboratory notification configuration is no longer in the runtime image;
# it arrives through a named volume a network-isolated initializer publishes.
require_contains "$swan_block" 'swan-notification-config:/etc/swan/interop:ro' "Compose must mount the lab notification configuration read-only from its prepared volume"
require_contains "$swan_block" $'swan-notification-config-init:\n        condition: service_completed_successfully' "Swan must wait for the prepared notification configuration"
notification_config_init_block="$(service_block swan-notification-config-init)"
require_contains "$notification_config_init_block" 'target: interop-notification-config' "notification configuration must come from the lab-only image stage"
require_contains "$notification_config_init_block" 'swan-notification-config:/prepared/notification-config' "notification configuration output volume is missing"
require_contains "$notification_config_init_block" 'network_mode: "none"' "notification configuration preparation must be network-isolated"
require_contains "$notification_config_init_block" 'install -o swan -g swan -m 0444' "notification configuration must be published read-only to swan"
reject_contains "$notification_config_init_block" 'entrypoint: ["/usr/local/bin/swan"]' "notification configuration preparation must not run Swan"
reject_contains "$notification_config_init_block" 'privileged:' "notification configuration preparation must not be privileged"
# shellcheck disable=SC2016 # Reject the literal interpolation prefix.
reject_contains "$notification_config_init_block" '${' "notification configuration preparation must not interpolate environment values"
require_contains "$swan_block" '--managing-service-audience' "Compose must enable checkUserAccess service verification"
reject_contains "$swan_block" '--enable-localhost-oauth' "Compose must not use the narrower localhost-only OAuth bridge"
require_contains "$swan_block" '--enable-local-space-interop' "local-space interop flag is missing"
require_contains "$swan_block" '--space-account-kek-file' "account KEK file flag is missing"
require_contains "$swan_block" '/run/secrets/swan-runtime/account-kek' "account KEK path is wrong"
require_contains "$swan_block" '--enable-public-repository-mutations' "public mutation capability must be explicitly enabled"
require_contains "$swan_block" '--public-account-kek-file' "public mutation account KEK flag is missing"
require_contains "$swan_block" 'https://swan.test' "Swan public URL must use Caddy TLS"
require_contains "$swan_block" $'swan-bootstrap:\n        condition: service_completed_successfully' "Swan must wait for successful bootstrap"

# Reference PDS secrets are loaded from its read-only, UID-adjusted volume by
# an unprivileged wrapper. No secret value appears in Compose.
require_contains "$reference_block" 'reference-pds-secrets:/run/secrets/reference-pds:ro' "PDS secrets must use the read-only prepared volume"
require_contains "$reference_block" 'REFERENCE_PDS_SECRETS_DIR: /run/secrets/reference-pds' "PDS file-secret directory is missing"
require_contains "$reference_block" $'swan-secrets-init:\n        condition: service_completed_successfully' "PDS must wait for prepared secrets"
# shellcheck disable=SC2016 # Reject any literal Compose interpolation.
reject_contains "$reference_block" '${' "PDS must not interpolate environment values"
reject_contains "$reference_block" 'PDS_DPOP_SECRET:' "PDS DPoP secret must not be in Compose environment"
reject_contains "$reference_block" 'PDS_JWT_SECRET:' "PDS JWT secret must not be in Compose environment"
reject_contains "$reference_block" 'PDS_ADMIN_PASSWORD:' "PDS administrator password must not be in Compose environment"
reject_contains "$reference_block" 'PDS_REPO_SIGNING_KEY_K256_PRIVATE_KEY_HEX:' "PDS signing key must not be in Compose environment"
reject_contains "$reference_block" 'PDS_PLC_ROTATION_KEY_K256_PRIVATE_KEY_HEX:' "PDS rotation key must not be in Compose environment"

# Caddy is the only host ingress. Its health is the deterministic CA creation
# gate, and its upstream dependencies must be genuinely ready before TLS can
# report healthy. A root shell then copies only the public CA to an
# unprivileged volume.
require_contains "$swan_block" 'curl --fail --silent --show-error --max-time 2 http://127.0.0.1:3000/health' "Swan healthcheck must probe the live HTTP listener"
require_contains "$reference_block" "fetch('http://127.0.0.1:3000/xrpc/_health')" "reference PDS healthcheck must probe the live HTTP listener"
require_contains "$(service_block reference-plc)" "fetch('http://127.0.0.1:2582/_health')" "reference PLC healthcheck must probe the live HTTP listener"
require_contains "$(service_block reference-plc)" 'PLC_DATA_DIRECTORY: /plc' "reference PLC state directory is missing"
require_contains "$(service_block reference-plc)" 'reference-plc-data:/plc' "reference PLC state volume is missing"
rg -q '^COPY Swan/interop/reference-plc-server\.mjs /reference/reference-plc-server\.mjs$' \
  "$reference_plc_dockerfile" || {
  echo "reference PLC must use the persistent wrapper" >&2
  exit 1
}
rg -q '^CMD \["node", "/reference/reference-plc-server\.mjs"\]$' \
  "$reference_plc_dockerfile" || {
  echo "reference PLC command must use the persistent wrapper" >&2
  exit 1
}
test -x "${root}/interop/test-reference-plc-persistence.sh" || {
  echo "reference PLC persistence acceptance script is missing or not executable" >&2
  exit 1
}
require_contains "$reference_block" $'reference-plc:\n        condition: service_healthy' "reference PDS must wait for a healthy PLC"
require_contains "$(service_block toxiproxy-setup)" $'reference-pds:\n        condition: service_healthy' "Toxiproxy setup must wait for a healthy reference PDS"
require_contains "$caddy_block" $'swan:\n        condition: service_healthy' "Caddy must wait for a healthy Swan listener"
require_contains "$caddy_block" '"127.0.0.1:443:443"' "Caddy must be the loopback-only host ingress"
require_contains "$caddy_block" 'test -s /data/caddy/pki/authorities/local/root.crt' "Caddy CA healthcheck is missing"
require_contains "$caddy_block" 'aliases:' "Caddy TLS aliases are missing"
require_contains "$caddy_block" 'ipv4_address: 172.30.0.2' "Caddy must have the fixed login-proxy peer address"
require_contains "$toxiproxy_block" 'ipv4_address: 172.30.0.8' "Toxiproxy must reserve an address distinct from Caddy"
require_contains "$toxiproxy_block" 'dockerfile: Swan/interop/Dockerfile.toxiproxy' "Toxiproxy must use the pinned checked-in config image"
require_contains "$toxiproxy_block" '-config=/etc/toxiproxy/config.json' "Toxiproxy must load its restart-safe proxy configuration"
require_contains "$caddy_block" 'dockerfile: Swan/interop/Dockerfile.caddy' "Caddy must use the pinned checked-in config image"
reject_contains "$caddy_block" './interop/Caddyfile:' "Caddy must not use a host file bind"
require_contains "$caddy_block" 'swan.test' "Caddy must own the swan.test network alias"
require_contains "$caddy_block" 'pds.test' "Caddy must own the pds.test network alias"
reject_contains "$mailpit_block" 'ports:' "Mailpit must not publish a host port"
require_contains "$mailpit_block" 'healthcheck:' "Mailpit must expose a readiness healthcheck"
require_contains "$mailpit_block" '8025/api/v1/info' "Mailpit healthcheck must use its local HTTP API"
require_contains "$swan_block" $'mailpit:\n        condition: service_healthy' "Swan must wait for Mailpit readiness"
reject_contains "$toxiproxy_block" 'ports:' "Toxiproxy must not publish a host port"
if ! rg -q '^[[:space:]]+- subnet: 172\.30\.0\.0/24$' "$compose_file"; then
  echo "interop network must use the fixed login-proxy subnet" >&2
  exit 1
fi
published_port_count="$(rg -c '^[[:space:]]+ports:' "$compose_file" || true)"
if [[ "$published_port_count" -ne 1 ]]; then
  echo "Caddy must be the only service with a published host port" >&2
  exit 1
fi
require_contains "$ca_ready_block" 'user: root' "CA trust preparation ownership is missing"
require_contains "$ca_ready_block" 'entrypoint: ["/usr/local/bin/swan-interop-caddy-trust"]' "CA trust preparation wrapper is missing"
require_contains "$ca_ready_block" 'caddy-data:/caddy-data:ro' "CA source must be read-only"
require_contains "$ca_ready_block" 'caddy-trust:/prepared-trust' "CA trust destination is missing"
require_contains "$ca_ready_block" 'network_mode: "none"' "CA trust preparation must be network-isolated"
require_contains "$ca_ready_block" $'caddy:\n        condition: service_healthy' "CA trust preparation must wait for Caddy health"
reject_contains "$ca_ready_block" 'entrypoint: ["/usr/local/bin/swan"]' "root CA preparation must not run Swan"
reject_contains "$ca_ready_block" 'privileged:' "CA trust preparation must not be privileged"

# The Task 28 runner is genuinely inert: opt-in profile, no network, no Swan
# invocation, no probes/faults, and only a read-only prepared trust mount.
require_contains "$runner_block" 'profiles: ["planned-not-executed"]' "scenario runner must remain opt-in and planned"
require_contains "$runner_block" 'user: swan' "scenario runner must be unprivileged"
require_contains "$runner_block" 'network_mode: "none"' "planned runner must be network-isolated"
require_contains "$runner_block" 'caddy-trust:/etc/ssl/certs:ro' "runner trust mount must be read-only"
require_contains "$runner_block" 'SSL_CERT_FILE=/etc/ssl/certs/caddy-local-root.crt' "runner trust environment is missing"
require_contains "$runner_block" 'planned-not-executed: CA trust prepared; no probes or faults were run' "runner planned status is missing"
require_contains "$runner_block" $'caddy-ca-ready:\n        condition: service_completed_successfully' "runner must wait for prepared CA trust"
reject_contains "$runner_block" 'user: root' "scenario runner must not run as root"
reject_contains "$runner_block" '/usr/local/bin/swan' "planned runner must not invoke Swan"
reject_contains "$runner_block" 'lab matrix' "planned runner must not execute the matrix"
reject_contains "$runner_block" 'curl ' "planned runner must not send requests"
reject_contains "$runner_block" 'http://' "planned runner must not name a live endpoint"
reject_contains "$runner_block" 'https://' "planned runner must not name a live endpoint"
reject_contains "$runner_block" 'toxiproxy' "planned runner must not mutate Toxiproxy"
reject_contains "$runner_block" 'privileged:' "scenario runner must not be privileged"

rg -q 'permissioned-data-0016-2026-10-22' Sources/SwanInterop/SwanInterop.swift
rg -q 'e115236537041a900ec971be05185a70cca73e8a' Sources/SwanInterop/SwanInterop.swift
rg -q '3f6c96d5d2d25438bd40fa89d6ecc37865f8e354' "$reference_pds_dockerfile"
rg -q '1924ced5c07fb0ae5d8f13f0911bcbd2efc66e9460e463e9d8da10b94e8215ea' "$reference_pds_dockerfile"
rg -q 'tls internal' "$caddyfile"
rg -q 'reverse_proxy toxiproxy:8666' "$caddyfile"
delete_client_header_count="$(
  rg -c '^[[:space:]]*header_up -X-Swan-Client-IP$' "$caddyfile" || true
)"
if [[ "${delete_client_header_count:-0}" -ne 0 ]]; then
  echo "Caddy must not delete its replacement login client identity header" >&2
  exit 1
fi
set_client_header_count="$(
  rg -c '^[[:space:]]*header_up X-Swan-Client-IP \{http\.request\.remote\.host\}$' \
    "$caddyfile" || true
)"
if [[ "${set_client_header_count:-0}" -ne 1 ]]; then
  echo "Caddy must set the login client identity from its direct peer exactly once" >&2
  exit 1
fi
rg -q '^FROM caddy:2\.11\.7-alpine@sha256:504a44d7d74bd2bc28a66afc4774912fc21223ca8a67734af1c54ab2f999b489$' interop/Dockerfile.caddy
rg -q '^COPY Swan/interop/Caddyfile /etc/caddy/Caddyfile$' interop/Dockerfile.caddy
rg -q '^FROM ghcr\.io/shopify/toxiproxy:2\.13\.0@sha256:5d3dae09bc185dcc5ff6cf43abf6062a4a720aff0c4306a471e773acdcd107aa$' "$toxiproxy_dockerfile"
rg -q '^COPY Swan/interop/toxiproxy\.json /etc/toxiproxy/config\.json$' "$toxiproxy_dockerfile"
if rg -n '^[[:space:]]*RUN .*(curl|wget|git clone|git fetch)' "$toxiproxy_dockerfile"; then
  echo "Toxiproxy image Dockerfile must not fetch source from the network" >&2
  exit 1
fi
python3 - "$toxiproxy_config" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
configuration = json.loads(path.read_text(encoding="utf-8"))
if not isinstance(configuration, list) or len(configuration) != 1:
    raise SystemExit("Toxiproxy config must contain exactly one proxy")
proxy = configuration[0]
if not isinstance(proxy, dict) or set(proxy) != {"name", "listen", "upstream", "enabled"}:
    raise SystemExit("Toxiproxy config must contain only the reference-pds proxy")
if proxy != {
    "name": "reference-pds",
    "listen": "0.0.0.0:8666",
    "upstream": "reference-pds:3000",
    "enabled": True,
}:
    raise SystemExit("Toxiproxy reference-pds proxy is not the pinned topology")
PY

rg -qx 'FROM swift:6\.4\.1-jammy@sha256:51729e0f6ed2f477490cd1e1132e5eddbf011b81092f4998fc8d88e5435e33cb AS build' Dockerfile
rg -q 'libsodium-dev pkg-config' Dockerfile
# The runtime keeps the Swift 6.4.1 standard-library surface alongside the
# release executable. A minimal Ubuntu runtime would omit those libraries and
# fail only after the container passes image build.
rg -qx 'FROM swift:6\.4\.1-jammy@sha256:51729e0f6ed2f477490cd1e1132e5eddbf011b81092f4998fc8d88e5435e33cb AS runtime' Dockerfile
rg -q 'libsodium23' Dockerfile
# The laboratory notification configuration lives in a stage of its own and the
# default (last) stage is the clean runtime, so `docker build` with no
# `--target` cannot produce an image carrying a `laboratory: true` PLC policy.
rg -qx 'FROM runtime AS interop-notification-config' Dockerfile
rg -qx 'FROM runtime' Dockerfile
if [[ "$(rg -c '^COPY Swan/interop/notification-config\.json ' Dockerfile || true)" != "1" ]]; then
  echo "the lab notification configuration must be copied exactly once, into its own stage" >&2
  exit 1
fi
python3 - Dockerfile <<'PY'
import pathlib
import sys

lines = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8").splitlines()
stage = None
for line in lines:
    stripped = line.strip()
    if stripped.startswith("FROM "):
        stage = stripped.split(" AS ")[-1] if " AS " in stripped else "<default>"
        continue
    if "notification-config.json" in stripped and not stripped.startswith("#"):
        if stage != "interop-notification-config":
            raise SystemExit(
                "the lab notification configuration must not enter stage "
                f"{stage}; only interop-notification-config may carry it"
            )
    if "/etc/swan/interop" in stripped and not stripped.startswith("#"):
        raise SystemExit(
            "no image stage may create /etc/swan/interop; it is a mount point"
        )
if stage != "<default>":
    raise SystemExit(
        "the final Dockerfile stage must be the unnamed clean runtime, not "
        f"{stage}"
    )
PY
rg -q 'COPY Swan/interop/bootstrap-local-space\.sh /usr/local/bin/swan-interop-bootstrap' Dockerfile
rg -q 'COPY Swan/interop/prepare-interop-secrets\.sh /usr/local/bin/swan-interop-prepare-secrets' Dockerfile
rg -q 'COPY Swan/interop/prepare-caddy-trust\.sh /usr/local/bin/swan-interop-caddy-trust' Dockerfile
rg -q 'COPY Swan/interop/run-reference-pds\.sh /usr/local/bin/reference-pds-with-file-secrets' "$reference_pds_dockerfile"
rg -q '^CMD \["/usr/local/bin/reference-pds-with-file-secrets",' "$reference_pds_dockerfile"
node_image='node:24.22.1-alpine3.23@sha256:0468540aa58203ff9e40c2aab3907c52644ab818af6176b1c70a026137dc92a2'
pnpm_sha512='b3951d6d6ff4a9f13dc7cf56cd28d2b8eb37dbcc9c68e52e1e1191873ea9f82a017287ab50baadc5ccc494f036c67c0e47eb13608c2fa36f47711b61ea128e61'
for reference_dockerfile in \
  "$reference_pds_dockerfile" \
  "$reference_plc_dockerfile" \
  "$recovery_pds_dockerfile"; do
  node_from_count="$(rg -c "^FROM ${node_image}( AS build)?$" "$reference_dockerfile" || true)"
  if [[ "$node_from_count" != "2" ]]; then
    echo "reference image Dockerfiles must use the exact pinned Node digest in both stages" >&2
    exit 1
  fi
  if rg -q '^FROM node:[^@[:space:]]+( AS build)?$' "$reference_dockerfile"; then
    echo "reference image Dockerfiles must pin Node by digest" >&2
    exit 1
  fi
  if ! rg -q "${pnpm_sha512}  /tmp/pnpm-12\\.15\\.0\\.tgz" "$reference_dockerfile" \
      || ! rg -q 'npm install --global /tmp/pnpm-12\.15\.0\.tgz' "$reference_dockerfile" \
      || ! rg -q 'test "\$\(pnpm --version\)" = "12\.15\.0"' "$reference_dockerfile"; then
    echo "reference image Dockerfiles must verify the pinned pnpm bootstrap" >&2
    exit 1
  fi
done
rg -q 'account show' interop/bootstrap-local-space.sh
rg -q 'account not found' interop/bootstrap-local-space.sh
rg -q 'could not inspect existing account' interop/bootstrap-local-space.sh
rg -q 'expected_did' interop/bootstrap-local-space.sh
rg -q 'authority\.did' interop/bootstrap-local-space.sh
rg -q 'member\.did' interop/bootstrap-local-space.sh
rg -q 'prepared PLC DID does not match' interop/bootstrap-local-space.sh
rg -q 'find "\$source" -perm /077' interop/prepare-interop-secrets.sh
rg -q 'install -o "\$owner" -g "\$group" -m 0400' interop/prepare-interop-secrets.sh
rg -q 'prepare_directory "\$runtime_directory" swan swan' interop/prepare-interop-secrets.sh
rg -q 'prepare_directory "\$operator_directory" swan swan' interop/prepare-interop-secrets.sh
rg -q 'prepare_directory "\$pds_directory" 1000 1000' interop/prepare-interop-secrets.sh
rg -q 'source_certificate="/caddy-data/caddy/pki/authorities/local/root\.crt"' interop/prepare-caddy-trust.sh
rg -q 'install -d -o root -g root -m 0755 "\$trust_directory"' interop/prepare-caddy-trust.sh
rg -q 'install -o swan -g swan -m 0444' interop/prepare-caddy-trust.sh
rg -q 'verify-secret-source\.sh "\$root" "\$SWAN_INTEROP_SECRETS_DIR"' interop/compose.sh

# The checked-in notification configuration is intentionally lab-only public
# material. It must not be a hidden private-key or secret input channel.
python3 - "$notification_config_file" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])


class DuplicateField(ValueError):
    pass


def reject_duplicate_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateField(key)
        result[key] = value
    return result


try:
    configuration = json.loads(
        path.read_text(encoding="utf-8"),
        object_pairs_hook=reject_duplicate_pairs,
    )
except DuplicateField as error:
    raise SystemExit(
        "checked-in notification configuration has a duplicate field: "
        f"{error}"
    ) from error

secret_field_tokens = ("private", "secret", "password", "token")


def reject_secret_fields(value, location="$"):
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str):
                raise SystemExit(
                    f"checked-in notification configuration has a non-string field at {location}"
                )
            child_location = f"{location}.{key}"
            if any(token in key.lower() for token in secret_field_tokens):
                raise SystemExit(
                    "checked-in notification configuration contains a "
                    f"secret-like field: {child_location}"
                )
            reject_secret_fields(child, child_location)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            reject_secret_fields(child, f"{location}[{index}]")


def require_object(value, location, allowed, required):
    if not isinstance(value, dict):
        raise SystemExit(
            f"checked-in notification configuration expected an object at {location}"
        )
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise SystemExit(
            "checked-in notification configuration has unknown fields "
            f"at {location}: {', '.join(unknown)}"
        )
    missing = sorted(required - set(value))
    if missing:
        raise SystemExit(
            "checked-in notification configuration is missing fields "
            f"at {location}: {', '.join(missing)}"
        )


def require_array(value, location):
    if not isinstance(value, list):
        raise SystemExit(
            f"checked-in notification configuration expected an array at {location}"
        )
    if len(value) > 128:
        raise SystemExit(
            f"checked-in notification configuration has too many entries at {location}"
        )


def require_string(value, location):
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > 2_048:
        raise SystemExit(
            f"checked-in notification configuration expected a bounded string at {location}"
        )


reject_secret_fields(configuration)
required_root = {
    "credentialPublicKeys",
    "servicePublicKeys",
    "authorityDestinations",
    "registrationDestinations",
    "recipientServiceBindings",
    "managingServiceAudience",
    "credentialKeyPLC",
}
allowed_root = required_root | {"delegationPublicKeys", "delegationKeyPLC"}
require_object(configuration, "$", allowed_root, required_root)

credential_fields = {
    "issuer",
    "keyID",
    "generation",
    "algorithm",
    "publicKey",
    "p256X963",
    "secp256k1",
}
service_fields = credential_fields - {"keyID"}
string_key_fields = {
    "issuer",
    "keyID",
    "algorithm",
    "publicKey",
    "p256X963",
    "secp256k1",
}

for collection_name in ("credentialPublicKeys", "delegationPublicKeys"):
    entries = configuration.get(collection_name, [])
    require_array(entries, f"$.{collection_name}")
    for index, entry in enumerate(entries):
        location = f"$.{collection_name}[{index}]"
        require_object(entry, location, credential_fields, {"issuer", "generation"})
        for field in string_key_fields & set(entry):
            require_string(entry[field], f"{location}.{field}")
        generation = entry["generation"]
        if isinstance(generation, bool) or not isinstance(generation, int) or generation < 0:
            raise SystemExit(
                f"checked-in notification configuration has an invalid generation at {location}"
            )
        if not any(entry.get(field) for field in ("publicKey", "p256X963", "secp256k1")):
            raise SystemExit(
                f"checked-in notification configuration has no public key at {location}"
            )

service_entries = configuration["servicePublicKeys"]
require_array(service_entries, "$.servicePublicKeys")
for index, entry in enumerate(service_entries):
    location = f"$.servicePublicKeys[{index}]"
    require_object(entry, location, service_fields, {"issuer", "generation"})
    for field in string_key_fields & set(entry):
        require_string(entry[field], f"{location}.{field}")
    generation = entry["generation"]
    if isinstance(generation, bool) or not isinstance(generation, int) or generation < 0:
        raise SystemExit(
            f"checked-in notification configuration has an invalid generation at {location}"
        )
    if not any(entry.get(field) for field in ("publicKey", "p256X963", "secp256k1")):
        raise SystemExit(
            f"checked-in notification configuration has no public key at {location}"
        )

destination_fields = {"key", "endpoint", "audience", "finalPeer"}
for collection_name in ("authorityDestinations", "registrationDestinations"):
    destinations = configuration[collection_name]
    require_array(destinations, f"$.{collection_name}")
    for index, destination in enumerate(destinations):
        location = f"$.{collection_name}[{index}]"
        require_object(
            destination,
            location,
            destination_fields,
            destination_fields,
        )
        for field in destination_fields:
            require_string(destination[field], f"{location}.{field}")
        if (
            destination["endpoint"] != "http://localhost:3001"
            or destination["finalPeer"] != "127.0.0.1"
        ):
            raise SystemExit(
                "checked-in notification destination is not loopback-lab-only"
            )

expected_authority = "did:plc:abcdefghijklmnopqrstuvwx"
if configuration["authorityDestinations"] != [
    {
        "key": expected_authority,
        "endpoint": "http://localhost:3001",
        "audience": expected_authority,
        "finalPeer": "127.0.0.1",
    }
]:
    raise SystemExit(
        "checked-in notification authority route is not the fixed restart laboratory"
    )
if configuration["registrationDestinations"]:
    raise SystemExit(
        "checked-in notification configuration must not contain registration routes"
    )

bindings = configuration["recipientServiceBindings"]
require_array(bindings, "$.recipientServiceBindings")
binding_fields = {"serviceIdentity", "recipientAccount"}
for index, binding in enumerate(bindings):
    location = f"$.recipientServiceBindings[{index}]"
    require_object(binding, location, binding_fields, binding_fields)
    for field in binding_fields:
        require_string(binding[field], f"{location}.{field}")
if bindings:
    raise SystemExit(
        "checked-in notification configuration must not contain recipient bindings"
    )
if (
    configuration["credentialPublicKeys"]
    or configuration.get("delegationPublicKeys", [])
    or configuration["servicePublicKeys"]
):
    raise SystemExit(
        "checked-in notification configuration must not contain static key material"
    )

require_string(configuration["managingServiceAudience"], "$.managingServiceAudience")
if configuration["managingServiceAudience"] != "did:web:interop-swan-managing-service":
    raise SystemExit("checked-in notification configuration is not lab-scoped")
plc = configuration["credentialKeyPLC"]
plc_fields = {"origin", "laboratory", "allowlistedHost"}
require_object(plc, "$.credentialKeyPLC", plc_fields, plc_fields)
if plc != {
    "origin": "http://reference-plc:2582",
    "laboratory": True,
    "allowlistedHost": "reference-plc",
}:
    raise SystemExit("checked-in notification PLC resolver is not the pinned lab origin")

if "delegationKeyPLC" in configuration:
    delegation_plc = configuration["delegationKeyPLC"]
    delegation_plc_fields = {
        "origin",
        "laboratory",
        "allowlistedHost",
        "allowedIssuers",
    }
    require_object(
        delegation_plc,
        "$.delegationKeyPLC",
        delegation_plc_fields,
        delegation_plc_fields,
    )
    if delegation_plc["origin"] != "http://reference-plc:2582":
        raise SystemExit(
            "checked-in notification delegation PLC is not the pinned lab origin"
        )
    if delegation_plc["laboratory"] is not True or delegation_plc["allowlistedHost"] != "reference-plc":
        raise SystemExit(
            "checked-in notification delegation PLC is not loopback-lab-only"
        )
    issuers = delegation_plc["allowedIssuers"]
    require_array(issuers, "$.delegationKeyPLC.allowedIssuers")
    if not issuers:
        raise SystemExit(
            "checked-in notification delegation PLC issuer allowlist is empty"
        )
    for index, issuer in enumerate(issuers):
        require_string(issuer, f"$.delegationKeyPLC.allowedIssuers[{index}]")
        if not issuer.startswith("did:plc:"):
            raise SystemExit(
                "checked-in notification delegation PLC issuer is not a PLC DID"
            )
    if len(set(issuers)) != len(issuers):
        raise SystemExit(
            "checked-in notification delegation PLC issuer allowlist has duplicates"
        )
PY

# The live closure is opt-in, but its proof contract is checked offline. It
# must crash the delivery-disabled seed, make the proxy ready before recovery,
# force a lost acknowledgement, start normal Compose after convergence, and
# correlate one durable receipt without reading a record table or retaining the
# generated permissioned value.
bash -n "$notification_restart_scenario"
for required_contract in \
  'docker kill --signal KILL' \
  'permissioned_space_outbox' \
  'permissioned_space_notification_receipts' \
  'WHERE issuer = ? AND event_id = ? AND space_uri = ?' \
  'readonly: true' \
  'successfulForwards' \
  'uniqueRequestDigests' \
  'droppedAcknowledgements' \
  'returnedAcknowledgements' \
  'NOTIFICATION RESTART OUTBOX CONVERGENCE OK: successful_forwards=2 receiver_effects=1'
do
  if ! rg -Fq "$required_contract" "$notification_restart_scenario"; then
    echo "notification restart scenario is missing its durable convergence contract" >&2
    exit 1
  fi
done
python3 - "$notification_restart_scenario" <<'PY'
import sys
from pathlib import Path

scenario = Path(sys.argv[1]).read_text(encoding="utf-8")
anchors = (
    'proxy_id="$(',
    'until [[ -f "$temporary_directory/ready" ]]',
    'recovery_id="$(',
    'wait_for_swan_http "$recovery_container" "recovery-enabled Swan"',
)
positions = [scenario.find(anchor) for anchor in anchors]
if any(position < 0 for position in positions) or positions != sorted(positions):
    raise SystemExit(
        "notification restart scenario must make the loopback proxy ready "
        "before recovery starts"
    )
PY
if rg -n \
  'set[[:space:]]+-x|docker[[:space:]]+logs|cat[[:space:]].*permissioned-record|tee[[:space:]].*permissioned-record' \
  "$notification_restart_scenario"
then
  echo "notification restart scenario contains a value-bearing log path" >&2
  exit 1
fi

for reference_dockerfile in "$reference_pds_dockerfile" "$reference_plc_dockerfile"; do
  if rg -q '^ARG[[:space:]]+REFERENCE_ARCHIVE_SHA256' "$reference_dockerfile"; then
    echo "reference image Dockerfiles must not accept an archive checksum build argument" >&2
    exit 1
  fi
  rg -q '^RUN echo "1924ced5c07fb0ae5d8f13f0911bcbd2efc66e9460e463e9d8da10b94e8215ea  /tmp/reference\.tar\.gz" \| sha256sum -c -' "$reference_dockerfile"
done

# Every build context is an allowlist and excludes secret/state paths. The
# pinned reference builds expose only the verified archive exception.
for ignore_file in \
  "$swan_dockerignore" \
  "$reference_pds_dockerignore" \
  "$reference_plc_dockerignore"
do
  rg -qx '\*\*' "$ignore_file"
  rg -qx '!Swan/' "$ignore_file"
  rg -qx '!Petrel/' "$ignore_file"
  rg -qx '\*\*/\.env\*' "$ignore_file"
  rg -qx '\*\*/\.swan-data/' "$ignore_file"
  rg -qx '\*\*/\*\.sqlite' "$ignore_file"
  rg -qx '\*\*/\*\.key' "$ignore_file"
  rg -qx '\.swan-interop-secrets/' "$ignore_file"
  rg -qx '\*\*/\.swan-interop-secrets/' "$ignore_file"
  rg -qx '\*\*/\.swan-interop-secrets/\*\*' "$ignore_file"
done
rg -qx 'Swan/web/node_modules' "$swan_dockerignore"
rg -qx 'Swan/web/node_modules/\*\*' "$swan_dockerignore"
rg -qx 'Swan/web/\.svelte-kit' "$swan_dockerignore"
rg -qx 'Swan/web/\.svelte-kit/\*\*' "$swan_dockerignore"
rg -qx 'Swan/web/build' "$swan_dockerignore"
rg -qx 'Swan/web/build/\*\*' "$swan_dockerignore"
rg -qx 'Swan/web/test-results' "$swan_dockerignore"
rg -qx 'Swan/web/test-results/\*\*' "$swan_dockerignore"
rg -qx 'Swan/web/playwright-report' "$swan_dockerignore"
rg -qx 'Swan/web/playwright-report/\*\*' "$swan_dockerignore"
rg -qx 'Swan/\.interop-cache/\*\*' "$swan_dockerignore"
python3 - "$swan_dockerignore" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
allowed_source_parent = (
    "!Swan/.interop-cache/"
    "indigo-8b43a326dbbb394f63b6d68761553cdfe25532de"
)
allowed_source_archive = (
    "!Swan/.interop-cache/"
    "indigo-8b43a326dbbb394f63b6d68761553cdfe25532de/"
    "indigo-8b43a326dbbb394f63b6d68761553cdfe25532de.tar.gz"
)
allowed_vendor_parent = (
    "!Swan/.interop-cache/"
    "indigo-vendor-8b43a326dbbb394f63b6d68761553cdfe25532de"
)
allowed_vendor_archive = (
    "!Swan/.interop-cache/"
    "indigo-vendor-8b43a326dbbb394f63b6d68761553cdfe25532de/"
    "indigo-8b43a326dbbb394f63b6d68761553cdfe25532de.vendor.tar.gz"
)
rules = [
    line.strip()
    for line in path.read_text(encoding="utf-8").splitlines()
    if line.strip() and not line.lstrip().startswith("#")
]
exceptions = {
    line for line in rules if line.startswith("!") and "/.interop-cache/" in line
}
allowed = {
    allowed_source_parent,
    allowed_source_archive,
    allowed_vendor_parent,
    allowed_vendor_archive,
}
if exceptions != allowed:
    raise SystemExit(
        "the Swan image build context must allow only the pinned Indigo source and vendor archives"
    )
if rules[-4:] != [
    allowed_source_parent,
    allowed_source_archive,
    allowed_vendor_parent,
    allowed_vendor_archive,
]:
    raise SystemExit(
        "the Swan image build context must allow only the pinned Indigo source and vendor archives"
    )

# Evaluate ordered membership for the exact allowed archive and representative
# forbidden cache paths. A later broad negation such as !Swan/** must not undo
# the cache exclusion without naming .interop-cache itself.
import fnmatch

def is_ignored(candidate):
    ignored = False
    for rule in rules:
        negated = rule.startswith("!")
        pattern = rule[1:] if negated else rule
        pattern = pattern.lstrip("/")
        if pattern.endswith("/"):
            pattern += "**"
        if fnmatch.fnmatchcase(candidate, pattern):
            ignored = not negated
    return ignored

pinned_source_parent = allowed_source_parent[1:]
pinned_source = allowed_source_archive[1:]
pinned_vendor_parent = allowed_vendor_parent[1:]
pinned_vendor = allowed_vendor_archive[1:]
for candidate, expected_ignored in (
    (pinned_source_parent, False),
    (pinned_source, False),
    (pinned_vendor_parent, False),
    (pinned_vendor, False),
    (
        "Swan/.interop-cache/indigo-8b43a326dbbb394f63b6d68761553cdfe25532de/"
        "source/go.mod",
        True,
    ),
    (
        "Swan/.interop-cache/indigo-vendor-8b43a326dbbb394f63b6d68761553cdfe25532de/"
        "vendor/modules.txt",
        True,
    ),
    (
        "Swan/.interop-cache/indigo-vendor-8b43a326dbbb394f63b6d68761553cdfe25532de/"
        "metadata.json",
        True,
    ),
    ("Swan/.interop-cache/atproto-unpinned.tar.gz", True),
    ("Swan/.interop-cache/indigo-unpinned/archive.tar.gz", True),
):
    if is_ignored(candidate) != expected_ignored:
        raise SystemExit(
            "the Swan image build context must allow only the pinned Indigo source and vendor archives"
        )
PY
for ignore_file in "$reference_pds_dockerignore" "$reference_plc_dockerignore"; do
  rg -qx 'Swan/\.interop-cache/\*\*' "$ignore_file"
  rg -qx '!Swan/\.interop-cache/atproto-3f6c96d5d2d25438bd40fa89d6ecc37865f8e354\.tar\.gz' "$ignore_file"
done

if rg -n '^[[:space:]]*RUN .*\b(curl|git clone|git fetch)\b' \
  "$reference_pds_dockerfile" "$reference_plc_dockerfile"
then
  echo "reference image Dockerfiles must not fetch source from the network" >&2
  exit 1
fi

verify_effective_compose() {
  local effective_secret_source="/var/empty/swan-interop-verifier-secrets"
  local effective_json=""
  effective_json="$(mktemp "${TMPDIR:-/tmp}/swan-effective-compose.XXXXXX")"

  if ! SWAN_INTEROP_SECRETS_DIR="$effective_secret_source" \
    docker compose \
      --profile planned-not-executed \
      -f "$compose_file" \
      config --format json >"$effective_json"
  then
    rm -f "$effective_json"
    echo "effective Compose configuration could not be rendered" >&2
    exit 1
  fi

  if python3 - "$effective_json" "$effective_secret_source" <<'PY'
import json
import sys
from pathlib import Path

configuration = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
effective_secret_source = sys.argv[2]


def fail(message):
    raise SystemExit(message)


services = configuration.get("services")
if not isinstance(services, dict):
    fail("effective Compose configuration has no service map")

required_services = {
    "swan-secrets-init",
    "swan-notification-config-init",
    "swan-data-init",
    "swan-bootstrap",
    "swan",
    "reference-pds",
    "reference-plc",
    "caddy",
    "caddy-ca-ready",
    "mailpit",
    "toxiproxy",
    "toxiproxy-setup",
    "scenario-runner",
}
if set(services) != required_services:
    fail("effective Compose service set does not match the laboratory profile")

swan = services["swan"]
if swan.get("user") != "swan":
    fail("effective Compose Swan runtime must run as swan")
if swan.get("read_only") is not True:
    fail("effective Compose Swan runtime root filesystem must be read-only")
if swan.get("privileged") not in (None, False):
    fail("effective Compose Swan runtime must not be privileged")
if swan.get("cap_add"):
    fail("effective Compose Swan runtime must not add capabilities")
if swan.get("depends_on", {}).get("swan-bootstrap", {}).get("condition") != (
    "service_completed_successfully"
):
    fail("effective Compose Swan runtime must wait for successful bootstrap")
command = swan.get("command", [])
if (
    not isinstance(command, list)
    or command.count("--enable-notification-delivery") != 1
    or command.count("--notification-config") != 1
    or command.count("/etc/swan/interop/notification-config.json") != 1
):
    fail("effective Compose Swan runtime must enable pinned notification recovery")
if (
    command.count("--enable-email-recovery") != 1
    or command.count("--email-proof-key-file") != 1
    or command.count("/run/secrets/swan-runtime/email-proof-key") != 1
    or command.count("--email-smtp-host") != 1
    or command.count("mailpit") != 1
):
    fail("effective Compose Swan runtime must enable Mailpit account-email recovery")
if swan.get("depends_on", {}).get("mailpit", {}).get("condition") != "service_healthy":
    fail("effective Compose Swan runtime must wait for healthy Mailpit")
mailpit = services["mailpit"]
if "healthcheck" not in mailpit or "8025/api/v1/info" not in str(mailpit["healthcheck"]):
    fail("effective Compose Mailpit readiness healthcheck is missing")
if (
    command.count("--login-trusted-proxy-peer") != 1
    or command.count("172.30.0.2") != 1
):
    fail("effective Compose Swan runtime must trust only the fixed Caddy login peer")

runtime_secret_mounts = [
    volume
    for volume in swan.get("volumes", [])
    if volume.get("target") == "/run/secrets/swan-runtime"
]
if (
    len(runtime_secret_mounts) != 1
    or runtime_secret_mounts[0].get("type") != "volume"
    or runtime_secret_mounts[0].get("source") != "swan-runtime-secrets"
    or runtime_secret_mounts[0].get("read_only") is not True
):
    fail("effective Compose Swan runtime secret mount is not least privilege")

# The base laboratory enables no management listener, so the resolved model
# must give its runtime no path to the operator secret volume at all.
if any(
    volume.get("source") == "swan-operator-secrets"
    for volume in swan.get("volumes", [])
):
    fail("effective Compose Swan runtime mounts the operator secret volume")

notification_config_mounts = [
    volume
    for volume in swan.get("volumes", [])
    if volume.get("target") == "/etc/swan/interop"
]
if (
    len(notification_config_mounts) != 1
    or notification_config_mounts[0].get("type") != "volume"
    or notification_config_mounts[0].get("source") != "swan-notification-config"
    or notification_config_mounts[0].get("read_only") is not True
):
    fail(
        "effective Compose lab notification configuration must be a read-only "
        "prepared volume, never a host bind or an image path"
    )
if services["swan-notification-config-init"].get("network_mode") != "none":
    fail("effective Compose notification configuration preparation is not isolated")

secret_init = services["swan-secrets-init"]
if secret_init.get("user") != "root" or secret_init.get("network_mode") != "none":
    fail("effective Compose secret preparation boundary is invalid")
external_mounts = [
    volume
    for volume in secret_init.get("volumes", [])
    if volume.get("target") == "/external-secrets"
]
if (
    len(external_mounts) != 1
    or external_mounts[0].get("type") != "bind"
    or external_mounts[0].get("source") != effective_secret_source
    or external_mounts[0].get("read_only") is not True
):
    fail("effective Compose external secret mount is not read-only and isolated")

safe_secret_directory_variables = {
    "EXTERNAL_SECRETS_DIR",
    "REFERENCE_PDS_SECRETS_DIR",
    "SWAN_BOOTSTRAP_SECRETS_DIR",
    "SWAN_INTEROP_SECRETS_DIR",
    "SWAN_OPERATOR_SECRETS_DIR",
    "SWAN_RUNTIME_SECRETS_DIR",
}
for service_name, service in services.items():
    if service.get("privileged") not in (None, False):
        fail(f"effective Compose service is privileged: {service_name}")
    if service.get("cap_add"):
        fail(f"effective Compose service adds capabilities: {service_name}")
    for environment_key in service.get("environment", {}):
        lowered_key = environment_key.lower()
        if (
            any(
                token in lowered_key
                for token in ("private", "secret", "password", "token")
            )
            and environment_key not in safe_secret_directory_variables
        ):
            fail(
                "effective Compose contains a secret-like environment key: "
                f"{service_name}.{environment_key}"
            )
    for volume in service.get("volumes", []):
        if volume.get("type") != "bind":
            continue
        if (
            service_name != "swan-secrets-init"
            or volume.get("target") != "/external-secrets"
        ):
            fail("effective Compose exposes an unexpected host bind mount")

published = []
for service_name, service in services.items():
    for port in service.get("ports", []):
        published.append((service_name, port))
if len(published) != 1:
    fail("effective Compose Caddy ingress is not the sole loopback publication")
published_service, published_port = published[0]
if (
    published_service != "caddy"
    or published_port.get("host_ip") != "127.0.0.1"
    or published_port.get("target") != 443
    or str(published_port.get("published")) != "443"
    or published_port.get("protocol") != "tcp"
):
    fail("effective Compose Caddy ingress is not the sole loopback publication")

caddy = services["caddy"]
if caddy.get("depends_on", {}).get("swan", {}).get("condition") != "service_healthy":
    fail("effective Compose Caddy must wait for a healthy Swan listener")
caddy_network = caddy.get("networks", {}).get("swan", {})
if caddy_network.get("ipv4_address") != "172.30.0.2":
    fail("effective Compose Caddy must use the fixed login-proxy peer address")
aliases = caddy_network.get("aliases", [])
if set(aliases) != {"swan.test", "pds.test"}:
    fail("effective Compose Caddy aliases do not match the laboratory hosts")
network = configuration.get("networks", {}).get("swan", {})
ipam_config = network.get("ipam", {}).get("config", [])
if (
    not isinstance(ipam_config, list)
    or len(ipam_config) != 1
    or ipam_config[0].get("subnet") != "172.30.0.0/24"
):
    fail("effective Compose interop network must use the fixed login-proxy subnet")

reference = services["reference-pds"]
if reference.get("depends_on", {}).get("reference-plc", {}).get("condition") != (
    "service_healthy"
):
    fail("effective Compose reference PDS must wait for a healthy PLC")
for forbidden in (
    "PDS_DPOP_SECRET",
    "PDS_JWT_SECRET",
    "PDS_ADMIN_PASSWORD",
    "PDS_REPO_SIGNING_KEY_K256_PRIVATE_KEY_HEX",
    "PDS_PLC_ROTATION_KEY_K256_PRIVATE_KEY_HEX",
):
    if forbidden in reference.get("environment", {}):
        fail("effective Compose reference PDS contains a secret environment key")

runner = services["scenario-runner"]
if runner.get("profiles") != ["planned-not-executed"]:
    fail("effective Compose scenario runner profile is not inert")
if runner.get("user") != "swan" or runner.get("network_mode") != "none":
    fail("effective Compose scenario runner privilege boundary is invalid")
if runner.get("depends_on", {}).get("caddy-ca-ready", {}).get("condition") != (
    "service_completed_successfully"
):
    fail("effective Compose scenario runner must wait for prepared CA trust")
runner_trust = [
    volume
    for volume in runner.get("volumes", [])
    if volume.get("target") == "/etc/ssl/certs"
]
if len(runner_trust) != 1 or runner_trust[0].get("read_only") is not True:
    fail("effective Compose scenario runner trust mount must be read-only")
PY
  then
    :
  else
    rm -f "$effective_json"
    exit 1
  fi
  rm -f "$effective_json"
  echo "INTEROP LAB EFFECTIVE COMPOSE INVARIANTS OK"
}

verify_effective_relay_compose() {
  local effective_secret_source="/var/empty/swan-interop-verifier-secrets"
  local effective_json=""
  effective_json="$(mktemp "${TMPDIR:-/tmp}/swan-effective-relay-compose.XXXXXX")"

  if ! SWAN_INTEROP_SECRETS_DIR="$effective_secret_source" docker compose \
    --profile planned-not-executed -f "$compose_file" -f "$relay_compose_file" \
    config --format json >"$effective_json"; then
    rm -f "$effective_json"
    echo "effective reference relay Compose configuration could not be rendered" >&2
    exit 1
  fi

  if python3 - "$effective_json" <<'PY'
import json
import sys
from pathlib import Path

configuration = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
services = configuration.get("services")
if not isinstance(services, dict) or "reference-relay" not in services:
    raise SystemExit("effective reference relay Compose service is missing")
swan = services["swan"]
if swan.get("environment", {}).get("SWAN_PUBLIC_CRAWLERS") != "http://reference-relay:2470":
    raise SystemExit("effective relay topology must wire Swan crawlers internally")
if swan.get("command", []).count("--enable-public-firehose") != 1:
    raise SystemExit("effective relay topology must explicitly enable public firehose once")
relay = services["reference-relay"]
if relay.get("ports"):
    raise SystemExit("effective reference relay must not publish a host port")
if relay.get("environment", {}).get("RELAY_PLC_HOST") != "http://reference-plc:2582":
    raise SystemExit("effective reference relay PLC origin is not pinned")
if relay.get("environment", {}).get("SSL_CERT_FILE") != "/etc/ssl/certs/caddy-local-root.crt":
    raise SystemExit("effective reference relay Caddy trust file is missing")
trust_mounts = [volume for volume in relay.get("volumes", []) if volume.get("target") == "/etc/ssl/certs"]
if len(trust_mounts) != 1 or trust_mounts[0].get("source") != "caddy-trust" or trust_mounts[0].get("read_only") is not True:
    raise SystemExit("effective reference relay Caddy trust mount is not read-only")
data_mounts = [volume for volume in relay.get("volumes", []) if volume.get("target") == "/data"]
if len(data_mounts) != 1 or data_mounts[0].get("source") != "reference-relay-data":
    raise SystemExit("effective reference relay data volume is missing")
if not {"swan.test:172.30.0.8", "swan.test=172.30.0.8"} & set(relay.get("extra_hosts", [])):
    raise SystemExit("effective reference relay must resolve swan.test through Toxiproxy")
if relay.get("depends_on", {}).get("caddy-ca-ready", {}).get("condition") != "service_completed_successfully":
    raise SystemExit("effective reference relay must wait for prepared Caddy trust")
if relay.get("depends_on", {}).get("reference-plc", {}).get("condition") != "service_healthy":
    raise SystemExit("effective reference relay must wait for healthy PLC")
for key in relay.get("environment", {}):
    if any(token in key.lower() for token in ("password", "secret", "token")):
        raise SystemExit("effective reference relay contains a secret-like environment key")
caddy_aliases = services["caddy"].get("networks", {}).get("swan", {}).get("aliases", [])
if set(caddy_aliases) != {"swan.test", "pds.test", "relay.test"}:
    raise SystemExit("effective relay topology Caddy aliases do not include relay.test exactly")
if services["toxiproxy"].get("build", {}).get("dockerfile") != "interop/Dockerfile.toxiproxy.reference-relay":
    raise SystemExit("effective relay topology Toxiproxy listener image is not pinned")
PY
  then
    :
  else
    rm -f "$effective_json"
    exit 1
  fi
  rm -f "$effective_json"
  echo "REFERENCE RELAY EFFECTIVE COMPOSE INVARIANTS OK"
}

if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
  verify_effective_compose
  verify_effective_relay_compose
elif [[ "${SWAN_INTEROP_REQUIRE_EFFECTIVE_COMPOSE:-0}" == "1" ]]; then
  echo "Docker Compose is required for effective interop verification" >&2
  exit 1
else
  echo "INTEROP LAB EFFECTIVE COMPOSE INVARIANTS SKIPPED: Docker Compose unavailable" >&2
fi

echo "INTEROP LAB STATIC INVARIANTS OK"
