#!/bin/sh
set -eu

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

cat >"$tmp/recovery.json" <<'JSON'
{"status":"passed","corruptionRejected":true,"lastValidHeadPreserved":true,"replacementHeadGeneration":2,"replacementHeadRevision":"3lqjz7x4abc2m","replacementCommitment":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","finalHeadGeneration":2,"finalHeadRevision":"3lqjz7x4abc2m","finalCommitment":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
JSON

printf '%s\n' '{"head":{"generation":1,"revision":"3lqjz7x4abc2m","commitment":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}' \
  >"$tmp/before.json"

python3 Scripts/project-corruption-recovery-witness.py \
  "$tmp/recovery.json" "$tmp/before.json" "$tmp/intended.json" \
  "$tmp/after-fault.json" "$tmp/after-heal.json"

python3 - "$tmp/before.json" "$tmp/intended.json" "$tmp/after-fault.json" "$tmp/after-heal.json" <<'PY'
import json
import sys

heads = []
for path in sys.argv[1:]:
    with open(path, encoding="utf-8") as handle:
        heads.append(json.load(handle)["head"])
if len({json.dumps(head, sort_keys=True) for head in heads}) != 1:
    raise SystemExit("preserved recovery heads did not agree")
PY

python3 - "$tmp/recovery.json" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, encoding="utf-8") as handle:
    artifact = json.load(handle)
artifact["finalCommitment"] = "b" * 64
with open(path, "w", encoding="utf-8") as handle:
    json.dump(artifact, handle)
PY

if python3 Scripts/project-corruption-recovery-witness.py \
  "$tmp/recovery.json" "$tmp/reject-before.json" "$tmp/reject-intended.json" \
  "$tmp/reject-after-fault.json" "$tmp/reject-after-heal.json"; then
  echo "mismatched final recovery head was accepted" >&2
  exit 1
fi

echo "CORRUPTION RECOVERY WITNESS PROJECTION OK"
