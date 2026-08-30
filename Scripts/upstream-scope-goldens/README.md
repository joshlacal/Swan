# Upstream OAuth scope golden vectors

Regenerates `Tests/SwanOAuthTests/Fixtures/pinned-typescript-oauth-scopes.json` by
running **upstream's own `@atproto/oauth-scopes`**, unbuilt, at the commit Swan
targets. No expected value in that fixture is hand-transcribed: each one is
whatever the normative TypeScript actually returned.

This exists because hand-transcribing a grammar from a reference implementation
is where the errors come from. A golden corpus catches a whole class of them at
once.

## Use the right tree, and prove it before you trust the output

The procedure below works **only** against a full checkout of `bddc99fb`. Against
that tree it runs with no source patching at all. Against Swan's *other* pinned
upstream commit — `3f6c96d5…`, the one in `.interop-cache/` that
`interop/fetch-reference.sh` and `THIRD_PARTY_NOTICES.md` name — it needs 80
type-only-import rewrites before Node will even load the package, and then it
silently produces six **different** `values` rows (`skey=a+b`, `a%20b`, `a,b`,
`a/b`, `a@b`, `a%25b` all parse there and none parse at `bddc99fb`). Two commits
are in play in this repo and only one is the scope corpus's.

Positive controls, both cheap:

- `packages/oauth/oauth-scopes/src/scopes/space-permission.ts` must exist. A tree
  without it predates the space plane entirely and every `space:` vector
  generated from it would be wrong rather than absent.
- The generator must run with **zero** source edits. If you find yourself
  patching imports to make it load, you are on the wrong tree — stop.

`referenceCommit` in the emitted JSON is a **string constant** in `generate.mjs`;
the generator never checks it against the tree it imported. It records intent,
not provenance. `verify-corpus-zero-diff.sh` is what actually establishes
provenance, by regenerating and diffing.

## Regenerating

```bash
UP=/path/to/atproto-checkout      # a clean `git checkout bddc99fb24c34b4078b9bf65837283f37b49ab66`
G=/path/to/scratch

# 1. Leaf npm deps first — npm prunes symlinks it does not recognise, so
#    installing after step 2 silently deletes the workspace links.
cp package.json package-lock.json "$G/"
cd "$G" && npm ci --ignore-scripts --no-audit --no-fund
# 2. Link the workspace packages, in BOTH scratch and the export: module
#    resolution starts at the importing file, and upstream files import each
#    other across packages.
for d in "$G" "$UP"; do
  mkdir -p "$d/node_modules/@atproto"
  for p in did syntax lex/lex-document oauth/oauth-scopes; do
    ln -sfn "$UP/packages/$p" "$d/node_modules/@atproto/$(basename $p)"
  done
done
for d in zod iso-datestring-validator multiformats; do
  ln -sfn "$G/node_modules/$d" "$UP/node_modules/$d"
done

# 3. Point each package's "exports" at src/index.ts — the published entry points
#    reference ./dist, which does not exist in an unbuilt checkout.
#    (One-line patch per package.json; see the transcript for the exact edit.)

# 4. Generate.
cp generate.mjs ts-hook.mjs ts-hook-register.mjs "$G/"
cd "$G" && node --experimental-transform-types --import ./ts-hook-register.mjs generate.mjs \
  > "$SWAN/Tests/SwanOAuthTests/Fixtures/pinned-typescript-oauth-scopes.json"
```

`ts-hook.mjs` is a resolve hook that remaps upstream's `./foo.js` self-imports to
`./foo.ts`, since those `.js` paths only exist after a build.

`--experimental-transform-types`, not `--experimental-strip-types`: the package
uses TypeScript parameter properties (`constructor(public readonly scope: string)`),
which erasure alone cannot handle.

## What the corpus contains

| Section | Covers |
|---|---|
| `values` | per-value parse + canonical form for 52 scope strings, incl. bulleted.app's five |
| `strings` | whole scope-string normalisation, `normalizeAtprotoOauthScope` |
| `matches` | `ScopePermissions.allows*` outcomes for 8 representative grants |
| `didRefs` | `isAtprotoDidRefAbsolute` truth table |
| `encoders` | `encodeURIComponent` vs `URLSearchParams` per character |

## Findings worth knowing before reading the fixture

- **`authority=self` and `skey=*` vanish in canonical form.** Both
  `space:com.example.group?authority=self` and `?skey=*` canonicalise to bare
  `space:com.example.group`. A design that needs to distinguish a *stated*
  `skey=*` from a defaulted one cannot recover it from the canonical string.
- **Canonical form reorders parameters by schema declaration order, not input
  order.** `?action=create&action=read` becomes `?action=read&action=create`,
  and bulleted.app's scope becomes
  `space:app.bulleted.space?action=read_self&manage=create&manage=update&manage=delete`.
- **`~` is percent-encoded in query position and the round-trip is stable.**
  `skey=a~b` canonicalises to `skey=a%7Eb`.
- **Most punctuation is rejected outright in a `skey`** — `+`, `%20`, `,`, `/`,
  `@`, `%25` all fail to parse, so the upstream `+` round-trip instability is not
  reachable through this parameter.
- **`rpc:*`, `rpc:*?aud=*` and `account:*` are rejected**, while `identity:*`,
  `repo:*` and `blob:*/*` are accepted. Wildcards are per-family, not universal.
- **`isAtprotoDidRefAbsolute` is stricter than "valid DID + non-empty fragment"
  in one direction and looser in another.** `did:example:456#service_id` is
  rejected (atproto allows only `plc` and `web`) and `did:web:example.com:path#x`
  is rejected (no path components in web DIDs) — but `#has/slash`, `#has?question`
  and `#has%20escape` are all *accepted*, because the fragment grammar is RFC3986
  `pchar` plus `/` and `?` plus percent escapes.
