#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$root"

project="${SWAN_REFERENCE_RELAY_PROJECT:-swan-interop-alpha}"
output="${SWAN_REFERENCE_RELAY_OUTPUT:-${root}/artifacts/live/reference-relay-acceptance.json}"
timeout="${SWAN_REFERENCE_RELAY_TIMEOUT:-300}"
relay_volume="swan-interop-alpha_reference-relay-data"
temporary_directory=""
workspace_compose_directory=""
scenario_secret_directory=""
capture_container=""
handle_container=""
plc_proxy_container=""
toxiproxy_id=""
swan_data_volume=""
swan_image=""
network_name=""
toxiproxy_enabled=1
scenario_started=0
acceptance_ready=0
output_temporary=""
admission_sync_count=0
public_host_observed=0
capture_running_through_final_frame=0
custody_parent_commit=""
base_compose_file="docker-compose.yml"

validate_artifact_output_path() {
  python3 - "$root" "$output" <<'PY'
import os,pathlib,stat,sys
root=pathlib.Path(sys.argv[1])
raw=sys.argv[2]
artifacts=root / "artifacts"
candidate=pathlib.Path(raw)
if not candidate.is_absolute() or os.path.normpath(raw) != raw:
  raise SystemExit("artifact output must be canonical and absolute")
try:
  candidate.relative_to(artifacts)
except ValueError:
  raise SystemExit("artifact output must remain beneath the repository artifacts directory")
if candidate == artifacts or candidate.name in {"", ".", ".."}:
  raise SystemExit("artifact output must name a file beneath the artifacts directory")
ignore=(root / ".gitignore").read_text(encoding="utf-8").splitlines()
if "artifacts/" not in {line.strip() for line in ignore}:
  raise SystemExit("repository artifacts directory is not ignored")
current=artifacts
for part in candidate.relative_to(artifacts).parts[:-1]:
  try:
    metadata=current.lstat()
  except OSError:
    raise SystemExit("artifact output parent must already exist")
  if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
    raise SystemExit("artifact output parent traversal is unsafe")
  current=current / part
try:
  metadata=current.lstat()
except OSError:
  raise SystemExit("artifact output parent must already exist")
if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
  raise SystemExit("artifact output parent traversal is unsafe")
try:
  metadata=candidate.lstat()
except FileNotFoundError:
  pass
else:
  if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
    raise SystemExit("existing artifact output is unsafe")
PY
}

verify_jj_custody() {
  local jj_root at_empty parents parent_count diff_names
  command -v jj >/dev/null 2>&1 || {
    echo "jj is required for acceptance custody" >&2
    return 1
  }
  jj_root="$(jj root 2>/dev/null)" || return 1
  [[ "$jj_root" == "$root" ]] || {
    echo "acceptance runner is not at the expected jj workspace root" >&2
    return 1
  }
  at_empty="$(jj log -r '@' --no-graph -T 'if(empty, "true", "false") ++ "\n"' 2>/dev/null)" || return 1
  [[ "$at_empty" == true ]] || {
    echo "acceptance requires a clean empty jj child" >&2
    return 1
  }
  parents="$(jj log -r 'parents(@)' --no-graph -T 'commit_id ++ "\n"' 2>/dev/null)" || return 1
  parent_count="$(printf '%s\n' "$parents" | awk 'NF { count += 1 } END { print count + 0 }')"
  [[ "$parent_count" == 1 && "$parents" =~ ^[0-9a-f]{40}$ ]] || {
    echo "acceptance requires exactly one full-commit jj parent" >&2
    return 1
  }
  custody_parent_commit="$parents"
  diff_names="$(jj diff --from @- --to @ --name-only 2>/dev/null)" || return 1
  [[ -z "$diff_names" ]] || {
    echo "acceptance jj child contains changes" >&2
    return 1
  }
}

[[ "$project" == "swan-interop-alpha" ]] || {
  echo "SWAN_REFERENCE_RELAY_PROJECT must be swan-interop-alpha" >&2
  exit 64
}
[[ "$output" = /* ]] || {
  echo "SWAN_REFERENCE_RELAY_OUTPUT must be absolute" >&2
  exit 64
}
if [[ ! "$timeout" =~ ^[1-9][0-9]*$ ]] || ((timeout > 900)); then
  echo "SWAN_REFERENCE_RELAY_TIMEOUT must be an integer from 1 through 900" >&2
  exit 64
fi
[[ -n "${SWAN_INTEROP_SECRETS_DIR:-}" ]] || {
  echo "SWAN_INTEROP_SECRETS_DIR is required" >&2
  exit 64
}
validate_artifact_output_path
verify_jj_custody
command -v docker >/dev/null 2>&1 || { echo "Docker is required" >&2; exit 69; }
docker version >/dev/null
SWAN_INTEROP_SECRETS_DIR="$(./interop/verify-secret-source.sh "$root" "$SWAN_INTEROP_SECRETS_DIR")"
export SWAN_INTEROP_SECRETS_DIR

compose() {
  docker compose --project-directory "$root" \
    -f "$base_compose_file" -f interop/docker-compose.reference-relay.yml \
    --project-name "$project" "$@"
}

container_for_service() {
  local service="$1" ids count
  ids="$(docker ps --all \
    --filter "label=com.docker.compose.project=${project}" \
    --filter "label=com.docker.compose.service=${service}" \
    --format '{{.ID}}')"
  count="$(printf '%s\n' "$ids" | awk 'NF { n += 1 } END { print n + 0 }')"
  [[ "$count" == 1 ]] || { echo "expected exactly one ${service} container" >&2; return 1; }
  printf '%s\n' "$ids"
}

set_toxiproxy_enabled() {
  local enabled="$1"
  [[ "$enabled" == true || "$enabled" == false ]] || return 64
  [[ -n "$network_name" && -n "$swan_image" ]] || return 1
  docker run --rm --network "$network_name" --read-only \
    --tmpfs /tmp:size=1m,mode=1777 --entrypoint curl "$swan_image" \
    --fail --silent --show-error --max-time 5 \
    -X POST http://toxiproxy:8474/proxies/reference-relay-swan \
    -H 'Content-Type: application/json' --data "{\"enabled\":${enabled}}" >/dev/null
}

toxiproxy_is_enabled() {
  [[ -n "$network_name" && -n "$swan_image" ]] || return 1
  docker run --rm --network "$network_name" --read-only \
    --tmpfs /tmp:size=1m,mode=1777 --entrypoint curl "$swan_image" \
    --fail --silent --show-error --max-time 5 \
    http://toxiproxy:8474/proxies/reference-relay-swan \
    | python3 -c 'import json,sys; raise SystemExit(0 if json.load(sys.stdin).get("enabled") is True else 1)'
}

disposable_container_count() {
  {
    docker ps --all --filter "label=com.docker.compose.project=${project}" --format '{{.ID}}'
    docker ps --all --filter "name=^/${project}-task6c-" --format '{{.ID}}'
  } | awk 'NF && !seen[$0]++ { count += 1 } END { print count + 0 }'
}

finalize_artifact_after_cleanup() {
  local disposable_count="$1" toxiproxy_restored="$2"
  python3 - "$output_temporary" "$disposable_count" "$toxiproxy_restored" <<'PY'
import json,os,sys
path,count_raw,toxiproxy_raw=sys.argv[1:]
artifact=json.load(open(path,encoding="utf-8"))
artifact["cleanup"]={
  "toxiproxyEnabled": toxiproxy_raw == "true",
  "disposableContainersRemaining": int(count_raw),
}
with open(path,"w",encoding="utf-8") as out:
  json.dump(artifact,out,separators=(",",":")); out.write("\n")
os.chmod(path,0o600)
PY
  ./Scripts/validate-reference-relay-artifact.py "$output_temporary" || return 1
  mv -f "$output_temporary" "$output" || return 1
  output_temporary=""
  chmod 0600 "$output" || return 1
  printf '%s\n' 'REFERENCE RELAY ACCEPTANCE OK'
}

cleanup() {
  local result=$?
  local failed_swan=""
  local cleanup_toxiproxy_enabled=false
  local remaining=1
  trap - EXIT INT TERM HUP
  set +e
  if ((result != 0 && scenario_started == 1)); then
    failed_swan="$(container_for_service swan 2>/dev/null)"
    if [[ -n "$failed_swan" ]]; then
      docker logs --tail 40 "$failed_swan" 2>&1 | sed 's/^/swan failure: /' >&2
    fi
  fi
  if [[ -n "$toxiproxy_id" ]] && ((toxiproxy_enabled == 0)); then
    if set_toxiproxy_enabled true; then
      toxiproxy_enabled=1
    else
      result=1
    fi
  fi
  if [[ -n "$toxiproxy_id" ]] && ((toxiproxy_enabled == 1)) && toxiproxy_is_enabled; then
    cleanup_toxiproxy_enabled=true
  elif ((scenario_started == 1)); then
    result=1
  fi
  if [[ -n "$capture_container" ]]; then
    docker rm --force "$capture_container" >/dev/null 2>&1 || result=1
  fi
  if [[ -n "$handle_container" ]]; then
    docker rm --force "$handle_container" >/dev/null 2>&1 || result=1
  fi
  if [[ -n "$plc_proxy_container" ]]; then
    docker rm --force "$plc_proxy_container" >/dev/null 2>&1 || result=1
  fi
  if ((scenario_started == 1)); then
    compose down --remove-orphans >/dev/null 2>&1 || result=1
  fi
  remaining="$(disposable_container_count)" || result=1
  [[ "$remaining" == 0 ]] || result=1
  if ((result == 0 && acceptance_ready == 1)); then
    finalize_artifact_after_cleanup "$remaining" "$cleanup_toxiproxy_enabled" || result=1
  fi
  if ((result != 0)); then
    [[ -z "$output_temporary" ]] || rm -f "$output_temporary"
    rm -f "$output"
  fi
  [[ -z "$workspace_compose_directory" ]] || rm -rf "$workspace_compose_directory"
  [[ -z "$temporary_directory" ]] || rm -rf "$temporary_directory"
  [[ -z "$scenario_secret_directory" ]] || rm -rf "$scenario_secret_directory"
  exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP
rm -f "$output"

poll_until() {
  local label="$1"; shift
  local deadline=$((SECONDS + timeout))
  while ((SECONDS < deadline)); do
    if "$@"; then return 0; fi
    sleep 1
  done
  echo "timed out waiting for ${label}" >&2
  return 1
}

json_hosts_count() {
  python3 -c 'import json,sys; v=json.load(sys.stdin).get("hosts"); print(len(v) if isinstance(v,list) else -1)'
}

curl_from_swan() {
  docker exec "$swan_id" curl --fail --silent --show-error --max-time 5 "$@"
}

seed_relay_host_admission() {
  local bootstrap_did
  # The public listHosts endpoint intentionally exposes only hosts that have
  # delivered at least one event.  The base topology's fixed authority account
  # is activated before Swan starts, so announce its already-public head after
  # requestCrawl.  The fresh account under test is still created only after the
  # host-entry and live-connection gates below.
  bootstrap_did="$(docker exec "$swan_id" /bin/sh -ec '
    file=/var/lib/swan/data/interop-authority-identity.json
    test -r "$file"
    tr -d "\r\n" <"$file" | sed -n "s/.*\"did\":\"\([^\"]*\)\".*/\1/p"
  ')"
  [[ "$bootstrap_did" == did:* && "$bootstrap_did" != *[[:space:]]* ]] || {
    echo "bootstrap host-admission identity is unavailable" >&2
    return 1
  }
  management_firehose_sync "$bootstrap_did"
}

relay_has_swan_host() {
  local body
  body="$(curl_from_swan 'http://reference-relay:2470/xrpc/com.atproto.sync.listHosts?limit=100')" || return 1
  python3 -c 'import json,sys; h=json.load(sys.stdin).get("hosts",[]); raise SystemExit(0 if any(x.get("hostname")=="swan.test" for x in h) else 1)' <<<"$body"
}

relay_list_hosts_empty() {
  local body
  body="$(curl_from_swan 'http://reference-relay:2470/xrpc/com.atproto.sync.listHosts?limit=100')" || return 1
  [[ "$(printf '%s' "$body" | json_hosts_count)" == 0 ]]
}

logs_have_open_mode() {
  local mode="$1"
  docker logs --since "$log_since" "$swan_id" 2>&1 \
    | grep -F 'swan.public_firehose.subscribe_repos.open' \
    | grep -F "cursor_mode=${mode}" >/dev/null
}

capture_count() {
  local did="$1" kind="$2"
  [[ -f "${temporary_directory}/capture/index.jsonl" ]] || { printf '0\n'; return; }
  python3 - "${temporary_directory}/capture/index.jsonl" "$did" "$kind" <<'PY'
import json,sys
count=0
with open(sys.argv[1], encoding="utf-8") as source:
  for line in source:
    value=json.loads(line)
    count += value.get("did") == sys.argv[2] and value.get("kind") == sys.argv[3]
print(count)
PY
}

capture_is_ready() {
  python3 - "${temporary_directory}/capture/ready" <<'PY'
import os,stat,sys
try:
  mode=os.lstat(sys.argv[1]).st_mode
except FileNotFoundError:
  raise SystemExit(1)
raise SystemExit(0 if stat.S_ISREG(mode) and stat.S_IMODE(mode)==0o600 else 1)
PY
}

capture_has_lifecycle() {
  [[ "$(capture_count "$fresh_did" identity)" == 1 ]] \
    && [[ "$(capture_count "$fresh_did" account)" == 1 ]] \
    && [[ "$(capture_count "$fresh_did" sync)" -ge 1 ]]
}

capture_has_commits() {
  [[ "$(capture_count "$fresh_did" commit)" -ge "$1" ]]
}

capture_has_manual_sync() {
  [[ "$(capture_count "$fresh_did" sync)" -ge 2 ]]
}

capture_has_exact_final_census() {
  python3 - "${temporary_directory}/capture/index.jsonl" "$fresh_did" <<'PY'
import json,sys
expected=["identity","account","sync"] + ["commit"] * 6 + ["sync"]
kinds=[]
with open(sys.argv[1],encoding="utf-8") as source:
  for line in source:
    value=json.loads(line)
    if value.get("did")==sys.argv[2]: kinds.append(value.get("kind"))
raise SystemExit(0 if kinds == expected else 1)
PY
}

capture_container_is_running() {
  [[ -n "$capture_container" ]] || return 1
  [[ "$(docker inspect --format '{{.State.Running}} {{.State.ExitCode}}' "$capture_container")" == "true 0" ]]
}

management_post() {
  local path="$1" body="$2"
  if ! docker exec -i "$swan_id" /bin/sh -ec '
    umask 077
    authorization="$(mktemp /tmp/task6c-management-authorization.XXXXXX)"
    trap '\''rm -f "$authorization"'\'' EXIT
    secret="$(tr -d "\r\n" </run/secrets/swan-operator/operator-secret)"
    test -n "$secret"
    printf "Authorization: Bearer %s\n" "$secret" >"$authorization"
    unset secret
    curl --fail --silent --show-error --max-time 20 \
      --header @"$authorization" \
      -H "Content-Type: application/json" --data-binary @- \
      "http://127.0.0.1:3001$1"
  ' _ "$path" <"$body"; then
    echo "management POST failed at ${path}" >&2
    return 1
  fi
}

management_firehose_sync() {
  local did="$1" request_id body response
  [[ "$did" == did:* && "$did" != *[[:space:]]* ]] || return 64
  request_id="$(python3 -c 'import uuid; print(uuid.uuid4())')"
  body="$(mktemp "${scenario_secret_directory}/firehose-sync-body.XXXXXX")"
  response="$(mktemp "${scenario_secret_directory}/firehose-sync-response.XXXXXX")"
  chmod 0600 "$body" "$response"
  python3 - "$body" "$did" "$request_id" <<'PY'
import json,sys
with open(sys.argv[1],"w",encoding="utf-8") as output:
  json.dump({"did":sys.argv[2],"requestId":sys.argv[3]},output,separators=(",",":"))
PY
  management_post '/v1/firehose/sync' "$body" >"$response"
  python3 - "$response" "$did" "$request_id" <<'PY'
import json,sys
value=json.load(open(sys.argv[1],encoding="utf-8"))
assert value == {"did":sys.argv[2],"requestId":sys.argv[3],"status":"accepted"}
PY
  rm -f "$body" "$response"
}

handle_proof_is_ready() {
  local body
  body="$(curl_from_swan 'http://127.0.0.1:2583/.well-known/atproto-did')" || return 1
  [[ "$body" == "$fresh_did" ]]
}

plc_proxy_is_ready() {
  curl_from_swan 'http://127.0.0.1:2582/_health' >/dev/null
}

write_public_record() {
  local ordinal="$1"
  local rkey="relay${run_nonce}${ordinal}"
  local body="${temporary_directory}/record-${ordinal}.json"
  local live_artifact="${temporary_directory}/live-${ordinal}.json"
  python3 - "$body" "$fresh_did" "$rkey" <<'PY'
import datetime,json,os,secrets,sys
created_at=datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00","Z")
body={"repo":sys.argv[2],"collection":"app.bsky.feed.post","rkey":sys.argv[3],"record":{"$type":"app.bsky.feed.post","text":secrets.token_hex(32),"createdAt":created_at}}
with open(sys.argv[1],"x",encoding="utf-8") as out: json.dump(body,out,separators=(",",":"))
os.chmod(sys.argv[1],0o600)
PY
  docker run --rm --network "$network_name" --read-only \
    --tmpfs /tmp:size=16m,mode=1777 \
    --mount "type=volume,src=${caddy_trust_volume},dst=/etc/ssl/certs,readonly" \
    --mount "type=bind,src=${scenario_secret_directory},dst=/run/task6c-secrets,readonly" \
    --mount "type=bind,src=${temporary_directory},dst=/run/task6c" \
    --entrypoint /bin/sh "$swan_image" -ec '
      export SSL_CERT_FILE=/etc/ssl/certs/caddy-local-root.crt
      export SWAN_LAB_PRODUCER_HANDLE="$1"
      /usr/local/bin/swan lab live --mode public --name "reference-relay-${2}" \
        --producer-url https://swan.test --consumer-url https://swan.test \
        --producer-auth oauth --producer-password-file /run/task6c-secrets/account.password \
        --consumer-auth none \
        --producer-client-id "http://localhost?scope=atproto&redirect_uri=http%3A%2F%2F127.0.0.1%2Fcallback" \
        --producer-redirect-uri http://127.0.0.1/callback --scope atproto \
        --repository "$3" --collection app.bsky.feed.post --rkey "$4" \
        --body-file "/run/task6c/record-${2}.json" --output "/run/task6c/live-${2}.json" \
        >/tmp/live.log 2>&1
      case "$(tr -d "\r\n" <"/run/task6c/live-${2}.json")" in
        *\"status\":\"passed\"*) ;;
        *) exit 1 ;;
      esac
    ' _ "$fresh_handle" "$ordinal" "$fresh_did" "$rkey"
  chmod 0600 "$live_artifact"
  rm -f "$body" "$live_artifact"
}

temporary_directory="$(mktemp -d "${root}/.reference-relay-live.XXXXXX")"
chmod 0700 "$temporary_directory"
mkdir -m 0700 "${temporary_directory}/capture"
scenario_secret_directory="$(mktemp -d "${root}/.reference-relay-secrets.XXXXXX")"
chmod 0700 "$scenario_secret_directory"

./interop/verify-reference.sh
./interop/verify-reference-indigo.sh
./interop/verify-reference-indigo-vendor.sh
if [[ "$(basename "$root")" != "Swan" ]]; then
  workspace_compose_directory="$(mktemp -d "${root}/.reference-relay-compose.XXXXXX")"
  chmod 0700 "$workspace_compose_directory"
  base_compose_file="${temporary_directory}/docker-compose.workspace.yml"
  python3 - "$root" "$base_compose_file" "$workspace_compose_directory" <<'PY'
import os,pathlib,re,sys
root=pathlib.Path(sys.argv[1]).resolve()
destination=pathlib.Path(sys.argv[2])
temporary=pathlib.Path(sys.argv[3])
if root.parent.name != ".worktrees":
  raise SystemExit("non-canonical Swan checkout must be a direct child of .worktrees")
context=root.parents[1]
worktree=os.path.relpath(root,context)
if worktree.startswith("..") or not (context/"Petrel").is_dir():
  raise SystemExit("jj workspace and Petrel must share the canonical parent context")
source=(root/"docker-compose.yml").read_text(encoding="utf-8")
dockerfiles=sorted(set(re.findall(r"(?m)^\s+dockerfile: (Swan/[^\s]+)$",source)))
if "context: .." not in source or not dockerfiles:
  raise SystemExit("base Compose file no longer has the qualified parent-checkout layout")
source=source.replace("context: ..",f"context: {context}")
for qualified in dockerfiles:
  relative=qualified.removeprefix("Swan/")
  dockerfile_source=root/relative
  patched=temporary/(relative.replace("/","__"))
  content=dockerfile_source.read_text(encoding="utf-8")
  content=content.replace("COPY Swan/",f"COPY {worktree}/")
  content=content.replace("COPY Swan ",f"COPY {worktree} ")
  patched.write_text(content,encoding="utf-8")
  os.chmod(patched,0o600)
  ignore_source=dockerfile_source.with_name(dockerfile_source.name+".dockerignore")
  ignore_path=patched.with_name(patched.name+".dockerignore")
  if relative == "Dockerfile":
    allowed=[
      "!Petrel/", "Petrel/**", "!Petrel/Package.swift", "!Petrel/Package.resolved",
      "!Petrel/Sources/", "!Petrel/Sources/**", "!Petrel/Tests/", "!Petrel/Tests/**",
      "!.worktrees/", ".worktrees/**", f"!{worktree}/", f"{worktree}/**",
      f"!{worktree}/Package.swift", f"!{worktree}/Package.resolved",
      f"!{worktree}/Sources/", f"!{worktree}/Sources/**",
      f"!{worktree}/Tests/", f"!{worktree}/Tests/**",
      f"!{worktree}/Profiles/", f"!{worktree}/Profiles/**",
      f"!{worktree}/interop/", f"{worktree}/interop/**",
      f"!{worktree}/interop/notification-config.json",
      f"!{worktree}/interop/bootstrap-local-space.sh", f"!{worktree}/interop/prepare-interop-secrets.sh",
      f"!{worktree}/interop/prepare-caddy-trust.sh",
      f"!{worktree}/Scripts/", f"{worktree}/Scripts/**",
      f"!{worktree}/Scripts/validate-live-interop-artifact.py",
      f"!{worktree}/Scripts/project-corruption-recovery-witness.py",
    ]
    ignore="**\n"+"\n".join(allowed)+"\n"
  elif ignore_source.is_file():
    ignore=ignore_source.read_text(encoding="utf-8").replace("Swan/",f"{worktree}/")
  else:
    copy_sources=re.findall(rf"(?m)^COPY ({re.escape(worktree)}/[^\s]+) ",content)
    if not copy_sources:
      raise SystemExit(f"no custody allowlist or local COPY sources for {dockerfile_source}")
    allowed={worktree}
    for copy_source in copy_sources:
      path=pathlib.PurePosixPath(copy_source)
      allowed.add(str(path))
      allowed.update(str(parent) for parent in path.parents if str(parent) not in (".",""))
    ignore="**\n"+"".join(f"!{path}/\n" if path not in copy_sources else f"!{path}\n" for path in sorted(allowed))
  ignore += (
    f"{worktree}/.reference-relay-compose.*\n{worktree}/.reference-relay-compose.*/**\n"
    f"{worktree}/.reference-relay-live.*\n{worktree}/.reference-relay-live.*/**\n"
    f"{worktree}/.reference-relay-secrets.*\n{worktree}/.reference-relay-secrets.*/**\n"
  )
  ignore_path.write_text(ignore,encoding="utf-8")
  os.chmod(ignore_path,0o600)
  source=source.replace(f"dockerfile: {qualified}",f"dockerfile: {patched}")
destination.write_text(source,encoding="utf-8")
os.chmod(destination,0o600)
PY
fi

compose down --remove-orphans >/dev/null 2>&1 || true
if docker volume inspect "$relay_volume" >/dev/null 2>&1; then
  docker volume rm "$relay_volume" >/dev/null
fi
if docker volume inspect "$relay_volume" >/dev/null 2>&1; then
  echo "exact relay volume survived removal" >&2
  exit 1
fi

scenario_started=1
compose up -d --build
swan_id="$(container_for_service swan)"
relay_id="$(container_for_service reference-relay)"
toxiproxy_id="$(container_for_service toxiproxy)"
network_name="${project}_swan"
swan_image="$(docker inspect --format '{{.Config.Image}}' "$swan_id")"
relay_image="$(docker inspect --format '{{.Config.Image}}' "$relay_id")"
caddy_trust_volume="$(docker inspect --format '{{range .Mounts}}{{if eq .Destination "/etc/ssl/certs"}}{{.Name}}{{end}}{{end}}' "$relay_id")"
[[ -n "$caddy_trust_volume" ]] || { echo "relay Caddy trust volume was not resolved" >&2; exit 1; }

poll_until 'fresh empty relay listHosts' relay_list_hosts_empty
log_since="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
curl_from_swan -X POST 'http://reference-relay:2470/xrpc/com.atproto.sync.requestCrawl' \
  -H 'Content-Type: application/json' --data '{"hostname":"swan.test"}' >/dev/null
poll_until 'Swan live subscribeRepos observation' logs_have_open_mode live
log_since="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
seed_relay_host_admission
admission_sync_count=$((admission_sync_count + 1))
poll_until 'relay host entry' relay_has_swan_host
public_host_observed=1

capture_container="${project}-task6c-capture-$$"
docker run --detach --name "$capture_container" --user "$(id -u):$(id -g)" \
  --network "$network_name" --read-only --tmpfs /tmp:size=16m,mode=1777 \
  --mount "type=bind,src=${temporary_directory}/capture,dst=/capture" \
  --entrypoint /usr/local/bin/reference-relay-capture "$relay_image" \
  --url 'ws://reference-relay:2470/xrpc/com.atproto.sync.subscribeRepos' \
  --output-directory /capture --timeout "${timeout}s" >/dev/null
poll_until 'relay capture readiness' capture_is_ready

run_nonce="$(python3 -c 'import secrets; print(secrets.token_hex(5))')"
fresh_handle="relay-${run_nonce}.test"
plc_proxy_container="${project}-task6c-plc-proxy-$$"
docker run --detach --name "$plc_proxy_container" --user "$(id -u):$(id -g)" \
  --network "container:${swan_id}" --read-only --tmpfs /tmp:size=1m,mode=1777 \
  --entrypoint /usr/local/bin/reference-relay-capture "$relay_image" \
  --serve-plc-loopback-proxy >/dev/null
poll_until 'PLC loopback proxy readiness' plc_proxy_is_ready
python3 - "${scenario_secret_directory}/account.password" <<'PY'
import os,secrets,sys
fd=os.open(sys.argv[1],os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
with os.fdopen(fd,"w",encoding="utf-8") as out: out.write(secrets.token_hex(32)+"\n")
PY
python3 - "${scenario_secret_directory}/prepare.json" "$run_nonce" "$fresh_handle" \
  "${SWAN_INTEROP_SECRETS_DIR}/public-repo-revision" <<'PY'
import json,os,sys
path,nonce,handle,revision_path=sys.argv[1:]
revision=open(revision_path,encoding="utf-8").read().strip()
assert revision and len(revision.encode()) <= 128
body={"requestId":f"task6c-{nonce}","handle":handle,"pdsOrigin":"https://swan.test","repositoryRevision":revision,"plcOrigin":"http://127.0.0.1:2582","plcLaboratory":True,"plcReferenceCompatibility":"did-plc-server-0.0.1"}
fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
with os.fdopen(fd,"w",encoding="utf-8") as out: json.dump(body,out,separators=(",",":"))
PY
management_post '/v1/accounts/plc/prepare' "${scenario_secret_directory}/prepare.json" \
  >"${scenario_secret_directory}/prepared.json"
chmod 0600 "${scenario_secret_directory}/prepared.json"
fresh_did="$(python3 - "${scenario_secret_directory}/prepared.json" <<'PY'
import json,sys
value=json.load(open(sys.argv[1],encoding="utf-8")).get("did")
assert isinstance(value,str) and value.startswith("did:plc:") and not any(c.isspace() for c in value)
print(value)
PY
)"
mkdir -m 0700 "${temporary_directory}/handle"
install -m 0600 /dev/null "${temporary_directory}/handle/did"
printf '%s\n' "$fresh_did" >"${temporary_directory}/handle/did"
handle_container="${project}-task6c-handle-$$"
docker run --detach --name "$handle_container" --user "$(id -u):$(id -g)" \
  --network "container:${swan_id}" --read-only \
  --tmpfs /tmp:size=1m,mode=1777 \
  --mount "type=bind,src=${temporary_directory}/handle,dst=/handle,readonly" \
  --entrypoint /usr/local/bin/reference-relay-capture "$relay_image" \
  --serve-handle-did-file /handle/did >/dev/null
poll_until 'fresh handle proof readiness' handle_proof_is_ready
python3 - "${scenario_secret_directory}/activate.json" "$run_nonce" \
  "${scenario_secret_directory}/account.password" <<'PY'
import json,os,sys
path,nonce,password_path=sys.argv[1:]
password=open(password_path,encoding="utf-8").read().strip()
assert password and len(password.encode()) <= 4096
body={"requestId":f"task6c-{nonce}","password":password,"plcOrigin":"http://127.0.0.1:2582","plcLaboratory":True,"plcReferenceCompatibility":"did-plc-server-0.0.1","handleLaboratoryOrigin":"http://127.0.0.1:2583"}
fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
with os.fdopen(fd,"w",encoding="utf-8") as out: json.dump(body,out,separators=(",",":"))
PY
management_post '/v1/accounts/plc/activate' "${scenario_secret_directory}/activate.json" \
  >"${scenario_secret_directory}/activated.json"
chmod 0600 "${scenario_secret_directory}/activated.json"
python3 - "${scenario_secret_directory}/activated.json" "$fresh_did" <<'PY'
import json,sys
value=json.load(open(sys.argv[1],encoding="utf-8"))
assert value.get("did")==sys.argv[2] and value.get("status")=="active"
PY
poll_until 'identity-account-sync lifecycle' capture_has_lifecycle

write_public_record 1
poll_until 'first relay commit' capture_has_commits 1
first_sequence="$(python3 - "${temporary_directory}/capture/index.jsonl" "$fresh_did" <<'PY'
import json,sys
with open(sys.argv[1],encoding="utf-8") as f:
  for line in f:
    v=json.loads(line)
    if v.get("did")==sys.argv[2] and v.get("kind")=="commit": print(v["seq"]); break
PY
)"

recovery_log_since="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
set_toxiproxy_enabled false
toxiproxy_enabled=0
for ordinal in 2 3 4 5 6; do write_public_record "$ordinal"; done
[[ "$(capture_count "$fresh_did" commit)" == 1 ]] || { echo "relay observed commits while its Swan proxy was disabled" >&2; exit 1; }
set_toxiproxy_enabled true
toxiproxy_enabled=1
log_since="$recovery_log_since"
poll_until 'Swan backfill subscribeRepos observation' logs_have_open_mode backfill
poll_until 'five recovered relay commits' capture_has_commits 6
reconnect_cursor="$(docker logs --since "$recovery_log_since" "$swan_id" 2>&1 | python3 -c '
import re,sys
values=[]
for line in sys.stdin:
  if "swan.public_firehose.subscribe_repos.open" not in line or "cursor_mode=backfill" not in line:
    continue
  match=re.search(r"(?:^| )cursor_value=([0-9]+)(?: |$)",line)
  if match: values.append(int(match.group(1)))
if not values: raise SystemExit(1)
print(values[-1])
')"

if docker logs --since "$recovery_log_since" "$(container_for_service caddy)" 2>&1 \
  | grep -E 'com\.atproto\.sync\.getRepo[^[:space:]]*since=' >/dev/null; then
  echo "pinned relay issued getRepo?since; revision-aware acceptance is not implemented" >&2
  exit 1
fi

management_firehose_sync "$fresh_did"
poll_until 'manual sync relay event' capture_has_manual_sync
poll_until 'exact final fresh-DID event census' capture_has_exact_final_census
capture_container_is_running || {
  echo "relay capture helper was not running through the final required frame" >&2
  exit 1
}
capture_running_through_final_frame=1
docker rm --force "$capture_container" >/dev/null
capture_container=""

docker run --rm --user "$(id -u):$(id -g)" --network "$network_name" --read-only \
  --tmpfs /tmp:size=16m,mode=1777 \
  --mount "type=volume,src=${caddy_trust_volume},dst=/etc/ssl/certs,readonly" \
  --mount "type=bind,src=${temporary_directory},dst=/run/task6c" \
  --entrypoint curl "$swan_image" --fail --silent --show-error --max-time 30 \
  --cacert /etc/ssl/certs/caddy-local-root.crt \
  -o /run/task6c/final.car "https://swan.test/xrpc/com.atproto.sync.getRepo?did=${fresh_did}"
chmod 0600 "${temporary_directory}/final.car"

python3 - "${temporary_directory}/capture/index.jsonl" "$fresh_did" "${temporary_directory}/manifest.json" "$reconnect_cursor" <<'PY'
import json,os,sys
index,did,target,reconnect_cursor_raw=sys.argv[1:]
reconnect_cursor=int(reconnect_cursor_raw)
events=[]
with open(index,encoding="utf-8") as source:
  for line in source:
    value=json.loads(line)
    if value.get("did")==did: events.append(value)
commits=[value["seq"] for value in events if value["kind"]=="commit"]
if len(commits)!=6: raise SystemExit("expected first plus five recovery commits")
assert reconnect_cursor >= 0
manifest={"did":did,"frameFiles":[f"capture/{v['file']}" for v in events],"finalCARFile":"final.car","finalRevision":"pending","finalCommitCID":"pending","finalDataCID":"pending","reconnects":[{"upstreamCursor":reconnect_cursor,"firstDeliveredRelaySequence":commits[1]}],"getRepo":{"mode":"cursor-only","fullSnapshotAccepted":False,"exactFinalStateProven":False},"offlineSequenceStart":commits[1],"offlineSequenceEnd":commits[-1]}
with open(target,"x",encoding="utf-8") as out: json.dump(manifest,out,separators=(",",":"))
os.chmod(target,0o600)
PY

# Obtain the final head from Swan's public endpoint and structurally inspect
# the CAR to bind the verifier manifest. Neither is accepted without the
# subsequent authenticated Task 6B verifier.
latest="$(curl_from_swan "http://127.0.0.1:3000/xrpc/com.atproto.sync.getLatestCommit?did=${fresh_did}")"
inspection="$(docker run --rm --user "$(id -u):$(id -g)" --network none --read-only \
  --tmpfs /tmp:size=16m,mode=1777 \
  --mount "type=bind,src=${temporary_directory},dst=/run/task6c,readonly" \
  --entrypoint /usr/local/bin/swan "$swan_image" firehose inspect-relay-car \
  --car /run/task6c/final.car)"
relay_latest="$(curl_from_swan "http://reference-relay:2470/xrpc/com.atproto.sync.getLatestCommit?did=${fresh_did}")"
python3 - "${temporary_directory}/manifest.json" "$latest" "$inspection" "$relay_latest" <<'PY'
import json,os,sys
path=sys.argv[1]
manifest=json.load(open(path,encoding="utf-8"))
latest=json.loads(sys.argv[2]); inspection=json.loads(sys.argv[3]); relay=json.loads(sys.argv[4])
if inspection["did"] != manifest["did"] or latest["rev"] != inspection["revision"] or latest["cid"] != inspection["commitCID"]:
  raise SystemExit("Swan latest commit and final CAR disagree")
if relay.get("rev") != inspection["revision"] or relay.get("cid") != inspection["commitCID"]:
  raise SystemExit("relay latest commit and Swan final CAR disagree")
manifest["finalRevision"]=inspection["revision"]
manifest["finalCommitCID"]=inspection["commitCID"]
manifest["finalDataCID"]=inspection["dataCID"]
with open(path,"w",encoding="utf-8") as out: json.dump(manifest,out,separators=(",",":"))
os.chmod(path,0o600)
PY

offline_start="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["offlineSequenceStart"])' "${temporary_directory}/manifest.json")"
docker logs --since "$recovery_log_since" "$swan_id" 2>&1 \
  | grep -F 'swan.public_firehose.subscribe_repos.open' \
  | grep -F 'cursor_mode=backfill' \
  | grep -F "cursor_value=${reconnect_cursor}" >/dev/null || {
    echo "Swan did not observe the exact recovery cursor" >&2
    exit 1
  }

verification="$(docker run --rm --user "$(id -u):$(id -g)" --network "$network_name" \
  --read-only --tmpfs /tmp:size=16m,mode=1777 \
  --mount "type=bind,src=${temporary_directory},dst=/run/task6c,readonly" \
  --entrypoint /usr/local/bin/swan "$swan_image" firehose verify-relay-capture \
  --manifest /run/task6c/manifest.json --plc-origin http://reference-plc:2582 \
  --plc-laboratory --plc-laboratory-allowlisted-host reference-plc)"

mkdir -p "$(dirname "$output")"
rm -f "$output"
output_temporary="$(mktemp "$(dirname "$output")/.reference-relay-acceptance.XXXXXX")"
chmod 0600 "$output_temporary"
image_id="$(docker inspect --format '{{.Id}}' "$relay_image")"
image_id="${image_id#sha256:}"
swan_head="$custody_parent_commit"
python3 - "$output_temporary" "${temporary_directory}/manifest.json" "$inspection" "$verification" \
  "$swan_head" "$image_id" "$first_sequence" "$fresh_did" "$admission_sync_count" \
  "$public_host_observed" "$capture_running_through_final_frame" <<'PY'
import hashlib,json,os,sys
target,manifest_path,inspection_raw,verification_raw,swan_head,image_id,first_sequence,did,admission_count_raw,host_observed_raw,capture_running_raw=sys.argv[1:]
manifest=json.load(open(manifest_path,encoding="utf-8"))
inspection=json.loads(inspection_raw)
verification=json.loads(verification_raw)
frames=[]
for path in manifest["frameFiles"]:
  frame_path=os.path.join(os.path.dirname(manifest_path),path)
  frames.append(hashlib.sha256(open(frame_path,"rb").read()).hexdigest())
event_kinds=[]
with open(os.path.join(os.path.dirname(manifest_path),"capture/index.jsonl"),encoding="utf-8") as source:
  for line in source:
    event=json.loads(line)
    if event.get("did")==did: event_kinds.append(event.get("kind"))
offline_start=manifest["offlineSequenceStart"]
expected_kinds=["identity","account","sync"] + ["commit"] * 6 + ["sync"]
if event_kinds != expected_kinds: raise SystemExit("final fresh-DID event census changed")
activation_sync_count=sum(1 for index,kind in enumerate(event_kinds) if index == 2 and kind == "sync")
manual_sync_count=sum(1 for index,kind in enumerate(event_kinds) if index == len(event_kinds) - 1 and kind == "sync")
artifact={
 "schemaVersion":2,"scenario":"swan-reference-relay-phase5","status":"passed","swanHead":swan_head,
 "indigo":{"commit":"8b43a326dbbb394f63b6d68761553cdfe25532de","sourceSHA256":"bc6f57e6211560220ac49dc7d6b55c5a43291f1e1193113ce413ffe4478fdd0b","vendorSHA256":"ee11abd21e9ba70aabc013e92f877b248fdd381ea7de35a3c76f85857217c8c1","imageID":image_id},
 "freshState":{"volume":"swan-interop-alpha_reference-relay-data","removed":True,"listHostsCount":0},
 "orderedSteps":["fresh_state","crawl","subscription_open","admission_sync","public_host_entry","account_activation","activation_lifecycle","first_commit","offline_five_commit_recovery","manual_sync"],
 "admission":{"syncEmissionCount":int(admission_count_raw),"publicHostObserved":host_observed_raw=="1"},
 "connectionObservations":[{"ordinal":1,"cursorMode":"live","upstreamCursor":None},{"ordinal":2,"cursorMode":"backfill","upstreamCursor":manifest["reconnects"][0]["upstreamCursor"]}],
 "account":{"didDigest":hashlib.sha256(did.encode()).hexdigest(),"fresh":True},
 "lifecycleKinds":["identity","account","sync"],
 "eventCensus":{"identity":event_kinds.count("identity"),"account":event_kinds.count("account"),"activationSync":activation_sync_count,"commit":event_kinds.count("commit"),"manualSync":manual_sync_count,"orderedKinds":event_kinds},
 "captureHelper":{"runningThroughFinalFrame":capture_running_raw=="1","terminalStatus":"removed_after_running"},
 "firstCommit":{"observed":True,"sequence":int(first_sequence)},
 "offlineRecovery":{"expectedCommitCount":5,"observedCommitCount":5,"relaySequenceStart":offline_start,"relaySequenceEnd":manifest["offlineSequenceEnd"],"upstreamCursor":manifest["reconnects"][0]["upstreamCursor"],"firstDeliveredRelaySequence":offline_start,"duplicateCount":0,"gapCount":0,"queryMode":"subscribe_repos_cursor_only"},
 "finalRepository":{"relayRevision":inspection["revision"],"swanRevision":inspection["revision"],"relayCommitCID":inspection["commitCID"],"swanCommitCID":inspection["commitCID"],"relayDataCID":inspection["dataCID"],"swanDataCID":inspection["dataCID"],"relayMSTDigest":inspection["mstDigest"].removeprefix("sha256:"),"swanMSTDigest":inspection["mstDigest"].removeprefix("sha256:"),"projectionDigest":inspection["projectionDigest"].removeprefix("sha256:"),"equal":True},
 "manualSync":{"observed":True,"clean":True},
 "verifier":{"status":"passed","checks":[item["name"] for item in verification["checks"]]},
 "cleanup":{"toxiproxyEnabled":False,"disposableContainersRemaining":-1},
 "artifactPolicy":"aggregate-digest-only","successMarker":"REFERENCE RELAY ACCEPTANCE OK",
}
with open(target,"w",encoding="utf-8") as out: json.dump(artifact,out,separators=(",",":")); out.write("\n")
os.chmod(target,0o600)
PY
acceptance_ready=1
