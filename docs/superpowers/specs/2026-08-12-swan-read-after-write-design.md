# Swan Read-After-Write — Design (Phase 2)

**Date:** 2026-08-12
**Status:** Approved (design), not yet implemented
**Phase:** 2 of 2. Phase 1 (proxying + preferences) shipped — see
`2026-08-11-swan-appview-proxying-design.md`.

## Goal

Make an account's own writes visible immediately in its own views, instead of
only after the AppView has indexed them.

Phase 1 made `app.bsky.*` work by proxying to an AppView. The AppView is
eventually consistent, so a just-created post is briefly absent from the
author's timeline and profile, and a just-deleted post briefly lingers. This
phase closes that window by merging the account's local repo state into
proxied responses.

## Scope

Six routes, matching the reference PDS
(`atproto/packages/pds/src/read-after-write/`):
`getTimeline`, `getProfile`, `getProfiles`, `getAuthorFeed`, `getPostThread`,
`getActorLikes`.

Only the **authenticated account's own** records are ever merged. RAW never
invents or alters another actor's content.

**Out of scope:** unauthenticated views, other actors' writes, and any change
to Phase 1's routing, credential isolation, or peer-pinning. RAW is a
decorator on the proxy's response path and must not alter its request path.

## Decisions

### D1 — Typed munging via Petrel

Swan already depends on Petrel (`Package.swift:25`,
`.package(path: "../Petrel")`), and Petrel generates the complete `app.bsky`
lexicon surface in Swift — `AppBskyFeedDefs` (`FeedViewPost`, `PostView`),
`AppBskyActorDefs`, `AppBskyFeedGetPostThread`, and the rest.

So munging decodes the AppView response into the Petrel output type, merges,
and re-encodes. The alternative — splicing raw JSON — was rejected: it would
hand-maintain the shape of every view type with no compiler check, and the
types are already available at zero cost.

This was the phase's largest unknown. It is resolved before any code is
written: Swan does not need to model the `app.bsky` view surface.

### D2 — Read the local repo directly

Local records come from Swan's repo storage, not a side cache. The repo is
already the source of truth; a write cache would be a second one, with drift,
eviction, and invalidation to keep correct. Correct-by-construction beats
cheaper-per-request here.

### D3 — Insert **and** remove

The reference PDS both adds missing records and removes deleted ones. Both
halves ship together. A just-deleted post still visible to its author is more
jarring than a new post arriving a second late, so shipping insertions alone
would leave the more visible half of the problem unsolved.

### D4 — Time-bounded merge window

Only records written within a recent window (default 5 minutes, configurable)
are considered. Beyond that the AppView has certainly indexed them, and
merging older records risks duplicating what the AppView already returned.
This also bounds per-request repo reads to a small set regardless of how
active the account is.

The window is a freshness heuristic, not a correctness boundary: dedupe by URI
(below) is what actually prevents duplicates.

### D5 — Fail open

If munging throws for any reason, return the AppView's unmodified response.

This deliberately inverts Phase 1's posture. Phase 1 guards credentials and
routing, where the safe failure is to refuse. Phase 2 only improves freshness,
where the safe failure is to serve slightly stale data — Phase 1's behaviour.
A RAW bug must never turn a working feed into a broken one.

Every fail-open path logs at `warning` with the route and reason. Silent
degradation would make RAW appear to work while doing nothing — the failure
mode hardest to notice and hardest to debug.

## Architecture

```
proxied XRPC ──▶ Phase 1 pipethrough ──▶ AppView response
                                              │
                                    (authenticated + munged NSID?)
                                              │ yes
                                              ▼
                                   SwanLocalWriteReader     (repo → records)
                                              │
                                              ▼
                                   SwanRecordViewBuilder    (records → Petrel views)
                                              │
                                              ▼
                                   per-route munger         (merge into response)
                                              │
                                              ▼
                                        client response
```

### Unit 1 — `SwanLocalWriteReader`

Returns the authenticated account's records written inside the merge window,
and the URIs of records deleted inside it.

Deletions need a tombstone or equivalent. If Swan's repo storage does not
already expose deletions within a time window, that gap must be surfaced
during implementation rather than worked around — D3 depends on it, and
silently dropping the removal half would ship half the feature while
appearing complete.

### Unit 2 — `SwanRecordViewBuilder`

Turns a local record into the Petrel view type a route expects. The author is
always the authenticated account, since RAW only surfaces the user's own
writes, so the author's `ProfileViewBasic` is built once per request from the
account rather than fetched per record.

Fields the AppView owns and the local repo cannot know — like counts and
viewer state — are set to their zero/empty values on locally-built views. A
brand-new post genuinely has no likes yet, so this is accurate rather than a
placeholder.

### Unit 3 — Per-route mungers

Six small functions, each owning one route's semantics:

| Route | Merge |
|---|---|
| `getTimeline` | prepend own posts missing from the feed; drop deleted |
| `getAuthorFeed` | same, when the requested actor **is** the account |
| `getActorLikes` | prepend own likes missing from the list; drop deleted |
| `getProfile` / `getProfiles` | adjust counts for local creates/deletes |
| `getPostThread` | insert own replies missing from the thread; drop deleted |

**Dedupe by URI is mandatory in every insertion path.** The AppView may
already have indexed a record inside the merge window, and inserting it again
would show the user a duplicate of their own post — a bug more visible than
the staleness this phase exists to fix.

`getAuthorFeed` and `getProfile` must merge only when the requested actor is
the authenticated account. Merging the account's own posts into *another*
actor's feed would be a correctness and privacy failure, not merely a display
bug.

## Error handling

| Condition | Behaviour |
|---|---|
| Munging throws | return unmodified AppView response, log at `warning` |
| AppView response undecodable | return it unmodified, log at `warning` |
| Local repo read fails | return unmodified, log at `warning` |
| Non-2xx from AppView | pass straight through, never munge |

## Testing

**Unit.** View construction from a record; dedupe-by-URI; window boundary
(inside merged, outside not); deletion removal; zeroed counts on local views.

**Route-level.** For each of the six: a canned AppView response plus known
local records, asserting the merged output. Each route needs a negative case
proving no merge happens when the requested actor is not the authenticated
account.

**Fail-open.** A builder that throws must yield the AppView response
byte-identical. This is the property that keeps a RAW bug from becoming an
outage, so it is tested explicitly rather than assumed.

**Live.** Post from Catbird against the swan.place account and confirm the
post appears in the author's own timeline immediately; delete it and confirm
it disappears immediately. Per the project's verification rules a clean build
is not "done" — this must be observed in the running app.

## Risks

1. **Deletion visibility in repo storage** (Unit 1). The likeliest source of
   design churn; resolve it first, before building the mungers.
2. **Petrel view-type fidelity.** If a Petrel type has drifted from what the
   live AppView returns, decoding a real response will fail and RAW will
   fail open — correct, but invisible. The live test is what catches this;
   watch for the `warning` log rather than trusting a green suite.
3. **`getPostThread` shape.** Threads are recursive and the trickiest merge.
   Consider landing it last, after the flat-list routes prove the pattern.

## Non-goals

No change to Phase 1's request path. No caching layer. No munging of other
actors' content. No unauthenticated munging.
