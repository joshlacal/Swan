# Operating instructions — OAuth permission-scopes implementation

Read this before your first edit. It is short on purpose; the design lives in the
spec, and this file only says how to work against it.

## The spec is sealed authority

`docs/superpowers/specs/2026-08-14-oauth-permission-scopes-design.md`, sealed at
commit **`168b14a5`**, is the implementation authority. It has been through two
adversarial verification passes and two rounds of human review.

- **Implement what it says.** Where it gives Swift, that Swift is the target, not
  a suggestion. Where it gives test vectors, use those vectors.
- **Do not reopen a ruled question.** §9.1 carries decisions D1-D23 and §9.2
  carries the four questions that genuinely remain open plus O5. If a question is
  not in §9.2, it has been ruled — including questions whose ruling you disagree
  with.
- **Do report a contradiction.** The spec is sealed against *prose review*, not
  against reality. If implementation discovers an actual contradiction — two
  sections that cannot both be satisfied, a citation that does not say what it
  claims, Swift that cannot compile — surface it with the evidence rather than
  picking a side silently. That is the one thing worth interrupting for.

## Two things a "simplification" will try to undo

Both were found by review, and both look like redundancy from inside a single
file:

1. **Provenance is durable state, not parser metadata (§9-D23).** Do not
   reconstruct `stated` / `defaulted` by re-parsing a persisted scope string. The
   string is lossy in both directions: resolving `self` makes a defaulted
   `authority` look stated, and canonical serialisation deletes a stated `skey=*`.
   Persist provenance beside the effective grant, and keep the
   mint → persist → reload → `getDelegationToken` tests. A parse → matcher test
   passes with the bug present, which is why those tests exist in that shape.
2. **The delegation and listing fences are load-bearing because
   `isIssuableQualified` is gone (§9-D21).** They are not redundant with a gate
   that no longer exists.

## Golden vectors, not transcription

`Tests/SwanOAuthTests/Fixtures/pinned-typescript-oauth-scopes.json` was produced
by running upstream's own `@atproto/oauth-scopes` at the pinned commit. When the
spec and the fixture disagree about what a scope string parses or canonicalises
to, **the fixture wins** — and that disagreement is worth reporting.
Regeneration instructions: `Scripts/upstream-scope-goldens/README.md`.

Upstream source is a complete tree, not an excerpt. If you need to check a claim
against `bluesky-social/atproto`, use a full checkout of `bddc99fb`. The first
draft of this spec was written against a three-subtree export and invented five
"no upstream source exists" open questions, one of which produced the wrong
security model for the lexicon resolver. Never conclude "upstream has no X"
without naming the positive control you ran.

## VCS

This repo is jj-colocated. Git is read-only; see the workspace `CLAUDE.md` for
the full discipline. One rule matters most here, because it has bitten this work
three times:

> **After sealing a logical unit, run `jj new` immediately** — before anything
> else, including reporting what you just did.

jj's working copy is itself a commit. Every later edit amends the change you just
sealed, and a later `jj describe` replaces its message outright. Leave a clean
successor change so the next task — or the next agent — starts from an empty
working copy rather than silently rewriting a finished one.

If you are working alongside other agents in the same tree, seal only paths you
own: use a path-restricted `jj commit <paths>` or `jj split <paths>`, never a
bare `jj describe` over a working copy containing someone else's in-flight edits.
