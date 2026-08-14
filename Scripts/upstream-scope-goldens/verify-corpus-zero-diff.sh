#!/usr/bin/env bash
#
# §7.6 step 7 — the golden-corpus regeneration gate.
#
# Regenerates Tests/SwanOAuthTests/Fixtures/pinned-typescript-oauth-scopes.json
# from upstream's own @atproto/oauth-scopes at the pinned commit and asserts a
# ZERO DIFF against the checked-in fixture. A non-empty diff means either the pin
# moved or the fixture was hand-edited; both are blockers, and neither is visible
# from a green test run, because the Swift suite asserts Swift against the
# fixture, not the fixture against upstream.
#
# Usage:
#   SWAN_UPSTREAM_ATPROTO=/path/to/atproto-at-bddc99fb \
#     Scripts/upstream-scope-goldens/verify-corpus-zero-diff.sh
#
# The upstream tree must be a FULL checkout of the pinned commit — a subtree
# export is what produced five invented "no upstream source exists" open
# questions in the first draft of the spec. It must contain
# packages/oauth/oauth-scopes/src/scopes/space-permission.ts; a tree without it
# is not bddc99fb and this script refuses it.
#
# The upstream tree is COPIED to a scratch directory before any mutation, so the
# caller's checkout is never modified.

set -euo pipefail

REFERENCE_COMMIT="bddc99fb24c34b4078b9bf65837283f37b49ab66"

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$here/../.." && pwd)"
fixture="$repo_root/Tests/SwanOAuthTests/Fixtures/pinned-typescript-oauth-scopes.json"

fail() { printf 'verify-corpus-zero-diff: %s\n' "$1" >&2; exit 1; }

[ -f "$fixture" ] || fail "checked-in fixture missing at $fixture"

upstream="${SWAN_UPSTREAM_ATPROTO:-}"
[ -n "$upstream" ] || fail \
  "set SWAN_UPSTREAM_ATPROTO to a full checkout of bluesky-social/atproto at $REFERENCE_COMMIT"
[ -d "$upstream/packages/oauth/oauth-scopes/src" ] || fail \
  "$upstream is not an atproto checkout (packages/oauth/oauth-scopes/src missing)"

# Positive control for "this is the pinned tree, not an older export". The space
# plane lands with the scopes work; a tree lacking it predates the pin, and every
# `space:` vector generated from it would be silently wrong rather than absent.
[ -f "$upstream/packages/oauth/oauth-scopes/src/scopes/space-permission.ts" ] || fail \
  "$upstream lacks scopes/space-permission.ts — that tree is NOT $REFERENCE_COMMIT"

command -v node >/dev/null || fail "node not on PATH"
command -v npm  >/dev/null || fail "npm not on PATH"

node_major="$(node -p 'process.versions.node.split(".")[0]')"
[ "$node_major" -ge 22 ] || fail "node >= 22 required for --experimental-transform-types (found $(node -v))"

scratch="$(mktemp -d "${TMPDIR:-/tmp}/swan-scope-corpus.XXXXXX")"
trap 'rm -rf "$scratch"' EXIT

up="$scratch/atproto"
gen="$scratch/gen"
mkdir -p "$gen"

printf 'verify-corpus-zero-diff: copying upstream tree (read-only source) ...\n' >&2
# Copy only the packages the generator's import graph reaches. The full monorepo
# is large and none of the rest is on the path from @atproto/oauth-scopes.
mkdir -p "$up/packages/oauth" "$up/packages/lex"
cp -R "$upstream/packages/did"                  "$up/packages/did"
cp -R "$upstream/packages/syntax"               "$up/packages/syntax"
cp -R "$upstream/packages/lex/lex-document"     "$up/packages/lex/lex-document"
cp -R "$upstream/packages/oauth/oauth-scopes"   "$up/packages/oauth/oauth-scopes"

# 1. Leaf npm deps FIRST — npm prunes symlinks it does not recognise, so
#    installing after the workspace links are made silently deletes them.
printf 'verify-corpus-zero-diff: installing leaf deps ...\n' >&2
( cd "$gen" && npm init -y >/dev/null && \
  npm install --no-audit --no-fund zod@3 iso-datestring-validator multiformats >/dev/null )

# 2. Link the workspace packages in BOTH scratch dirs: module resolution starts
#    at the importing file, and upstream files import each other across packages.
for d in "$gen" "$up"; do
  mkdir -p "$d/node_modules/@atproto"
  for p in did syntax lex/lex-document oauth/oauth-scopes; do
    ln -sfn "$up/packages/$p" "$d/node_modules/@atproto/$(basename "$p")"
  done
done
for dep in zod iso-datestring-validator multiformats; do
  ln -sfn "$gen/node_modules/$dep" "$up/node_modules/$dep"
done

# 3. Point each package's "exports" at src/index.ts. The published entry points
#    reference ./dist, which does not exist in an unbuilt checkout.
for p in did syntax lex/lex-document oauth/oauth-scopes; do
  node -e '
    const fs = require("fs");
    const path = process.argv[1];
    const pkg = JSON.parse(fs.readFileSync(path, "utf8"));
    pkg.exports = { ".": "./src/index.ts" };
    pkg.main = "./src/index.ts";
    delete pkg.types;
    fs.writeFileSync(path, JSON.stringify(pkg, null, 2) + "\n");
  ' "$up/packages/$p/package.json"
done

# 4. Generate.
cp "$here/generate.mjs" "$here/ts-hook.mjs" "$here/ts-hook-register.mjs" "$gen/"
regenerated="$scratch/regenerated.json"
printf 'verify-corpus-zero-diff: running the pinned reference ...\n' >&2
( cd "$gen" && node --experimental-transform-types --import ./ts-hook-register.mjs generate.mjs ) \
  > "$regenerated"

# The generated header records the generating node version, which legitimately
# differs between machines and is NOT corpus drift. Everything else must match
# byte for byte.
strip_node_version() { grep -v '"nodeVersion"' "$1"; }

if diff -u <(strip_node_version "$fixture") <(strip_node_version "$regenerated"); then
  printf 'verify-corpus-zero-diff: OK — zero diff against %s\n' "$REFERENCE_COMMIT"
  exit 0
fi

cat >&2 <<'EOF'

verify-corpus-zero-diff: FAILED — the checked-in fixture does not match the
reference output. Either the pin moved or the fixture was hand-edited. Both are
blockers. Do NOT "fix" this by copying the regenerated file over a fence row:
§7.1a — a corpus regeneration must never overwrite a Swan-judgement row, because
a fence row changing is a design change, not a drift fix.
EOF
exit 1
