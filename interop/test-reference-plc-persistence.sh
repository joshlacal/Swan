#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
suffix="${PPID}-$(date +%s)"
image="swan-reference-plc-persistence-test-${suffix}"
container="swan-reference-plc-persistence-${suffix}"
volume="swan-reference-plc-persistence-data-${suffix}"

cleanup() {
  docker rm --force "${container}" >/dev/null 2>&1 || true
  docker volume rm "${volume}" >/dev/null 2>&1 || true
  docker image rm "${image}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker build \
  --file "${root}/interop/Dockerfile.reference-plc" \
  --tag "${image}" \
  "${root}/.." >/dev/null
docker volume create "${volume}" >/dev/null
docker run --detach \
  --name "${container}" \
  --volume "${volume}:/plc" \
  "${image}" >/dev/null

wait_for_health() {
  for _ in $(seq 1 30); do
    if docker exec "${container}" node --input-type=module -e \
      "fetch('http://127.0.0.1:2582/_health').then(r => { if (!r.ok) process.exit(1) }).catch(() => process.exit(1))" \
      >/dev/null 2>&1
    then
      return 0
    fi
    sleep 1
  done
  docker logs "${container}" >&2 || true
  return 1
}

wait_for_health

did="$(docker exec "${container}" node --input-type=module -e '
import crypto from "./node_modules/.pnpm/@atproto+crypto@0.1.0/node_modules/@atproto/crypto/dist/index.js"
import plc from "./node_modules/.pnpm/@did-plc+lib@0.0.1/node_modules/@did-plc/lib/dist/index.js"
const main = async () => {
  const signing = await crypto.EcdsaKeypair.create()
  const rotation = await crypto.EcdsaKeypair.create()
  const created = await plc.createOp({
    signingKey: signing.did(),
    handle: "persistence.example",
    pds: "https://pds.test",
    rotationKeys: [rotation.did()],
    signer: rotation,
  })
  const response = await fetch(`http://127.0.0.1:2582/${created.did}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(created.op),
  })
  if (response.status !== 200) throw new Error(`unexpected PLC write status ${response.status}`)
  console.log(created.did)
}
main().catch((error) => { console.error(error); process.exit(1) })
' | tr -d '\r\n')"
case "${did}" in
  did:plc:????????????????????????) ;;
  *) echo "persistent PLC test did not produce a canonical DID" >&2; exit 1 ;;
esac

docker restart "${container}" >/dev/null
wait_for_health
docker exec "${container}" node --input-type=module -e \
  "fetch('http://127.0.0.1:2582/${did}').then(async r => { if (!r.ok) throw new Error('DID did not survive restart'); const body = await r.json(); if (body.id !== '${did}') throw new Error('persisted DID mismatch') }).catch(e => { console.error(e); process.exit(1) })" \
  >/dev/null

# A tampered state file must stop the pinned server rather than silently
# resetting the PLC registry and allowing Swan's durable accounts to drift.
docker exec "${container}" sh -c 'printf "%s\n" "not-json" > /plc/operations.json'
docker restart "${container}" >/dev/null 2>&1 || true
for _ in $(seq 1 10); do
  if [ "$(docker inspect --format '{{.State.Running}}' "${container}")" = "false" ]; then
    echo "REFERENCE PLC PERSISTENCE OK"
    exit 0
  fi
  sleep 1
done
echo "persistent PLC accepted a tampered state file" >&2
exit 1
