# Swan Read-After-Write — Design (Phase 2)

**Date:** 2026-08-12
**Status:** Approved (design), amended 2026-08-12 after storage and type
feasibility research, not yet implemented
**Phase:** 2 of 2. Phase 1 (proxying + preferences) shipped — see
`2026-08-11-swan-appview-proxying-design.md`.

> **Amendment note (2026-08-12).** D1, D3's justification, and D4 changed after
> two research passes tested the original decisions against the code and against
> live AppView responses. Every change is recorded inline at the decision it
> affects, with the evidence that forced it. Risks #1 and #2 are both resolved
> and now read as settled findings rather than open questions.

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

One narrow, deliberate exception, added by this amendment: RAW reads the
`atproto-repo-rev` **response** header inside the pipethrough (D4). That is a
read of Phase 1's response, not a change to its request path, and the header is
explicitly **not** added to the client-facing forward allow-list.

## Decisions

### D1 — Splice at the JSON array level; use Petrel types only to build new rows

**Amended 2026-08-12.** The original D1 said RAW would decode the AppView
response into Petrel's generated output types, merge, and re-encode. Testing
that premise against live data proved it lossy.

A scratch harness decoded real `public.api.bsky.app` responses into Petrel's
output types and re-encoded them. `getAuthorFeed`, `getProfile` and
`getProfiles` round-tripped clean. `getPostThread` **silently dropped
`originalText` and `updatedAt`** from an edited post's record — Bluesky's
post-editing feature, which Petrel's lexicon corpus does not model. The local
`atproto/` reference checkout does not model it either, so regenerating from
local sources would not close the gap.

The mechanism is `ATProtocolValueContainer`'s dispatch guard
(`ATProtocolValueContainer.swift:3489-3499`), which deliberately ignores
raw-only fields so lexicon drift cannot tombstone records — the fix from two
prior Petrel incidents. Correct for decode; it means encode is lossy for
anything the guard let through. Decode **succeeds**, so nothing throws, so D5's
fail-open never fires, and the drop is unlogged. The blast radius is the whole
response — every post RAW re-encodes on its way to inserting one row, not just
the inserted row.

Drift is a permanent condition, not a one-time gap: Bluesky ships lexicon
changes before Petrel's corpus catches up. Any design that re-serializes
AppView-owned content signs up for silently dropping whatever is newest.

**So RAW never re-serializes content it is not modifying.** Concretely:

- Parse the AppView response as **generic JSON**, locate the collection the
  route merges into (`feed`, `profiles`, `thread.replies`), and insert or
  remove entries there. Entries RAW does not touch pass through byte-identical.
- Use Petrel's typed views for the one job typed views are good at: **building
  the newly-inserted local rows** from local records, compiler-checked. This is
  Unit 2, which never round-trips AppView JSON.

This keeps D1's original benefit — Swan does not hand-maintain the `app.bsky`
view surface — exactly where it is real, and drops it where it was dangerous.
It also removes the 23–28 % response-size inflation the round-trip caused by
re-injecting `$type` on nested non-union objects.

The splice surface that loses compile-time checking is small and testable:
find the array, match by URI, insert or remove.

### D2 — Read the local repo directly

Local records come from Swan's repo storage, not a side cache. The repo is
already the source of truth; a write cache would be a second one, with drift,
eviction, and invalidation to keep correct. Correct-by-construction beats
cheaper-per-request here.

Confirmed feasible and cheap — see Unit 1.

### D3 — Insert **and** remove

Both halves ship together. A just-deleted post still visible to its author is
more jarring than a new post arriving a second late, so shipping insertions
alone would leave the more visible half of the problem unsolved.

**Correction (2026-08-12).** The original justification claimed "the reference
PDS both adds missing records and removes deleted ones." **It does not.** The
reference is insert-only: `read-after-write/types.ts:6-11` defines
`LocalRecords = { count, profile, posts }` with no deleted-URI field;
`actor-store/record/reader.ts:268-283` reads only rows that still exist; and
none of the six munges filter. The removal half is a **Swan-original
capability**, not parity.

The decision stands on its own merit, and it turns out to be nearly free — see
Unit 1. But the plan must not cite the reference as precedent for removal,
because that precedent will be consulted to resolve future ambiguities and will
give wrong answers.

### D4 — Window keyed on `atproto-repo-rev`, wall clock as fallback

**Amended 2026-08-12.** The original D4 specified a 5-minute wall-clock window.

The AppView returns `atproto-repo-rev` on proxied responses: the exact
repository revision it has indexed up to. That is a real correctness boundary,
not a heuristic, and it is what the reference PDS builds RAW on
(`read-after-write/util.ts:45-46`). Merge every local commit with a revision
greater than it.

The wall-clock window fails at both ends. When the AppView is seconds behind it
over-merges (dedupe absorbs that). When the AppView is *more* than 5 minutes
behind — an incident, precisely when RAW matters most — records between 5
minutes and the AppView's actual lag appear in neither the response nor the
merge window, and vanish from the author's own timeline.

**Blocker this creates.** Swan's pipethrough currently **strips this header**.
`pipethroughResponse` (`Sources/SwanHTTP/SwanXRPCPipethrough.swift:692-720`)
forwards exactly `content-type` and `location` and drops everything else by
design. RAW must read `atproto-repo-rev` **inside** the pipethrough, before
that stripping, and must **not** add it to the client-facing forward list —
Phase 1's narrow allow-list is a security posture.

Fallback: when the header is absent or unparseable, use a 5-minute wall-clock
window (configurable) **and log at `warning`**. The reference returns the
response unmunged in that case; Swan degrades to the weaker window instead,
which is strictly more useful, but the log is mandatory so the fallback cannot
become the silent normal.

The window is a freshness bound, not a correctness boundary: dedupe by URI is
what actually prevents duplicates.

### D5 — Fail open

If munging throws for any reason, return the AppView's unmodified response.

This deliberately inverts Phase 1's posture. Phase 1 guards credentials and
routing, where the safe failure is to refuse. Phase 2 only improves freshness,
where the safe failure is to serve slightly stale data — Phase 1's behaviour.
A RAW bug must never turn a working feed into a broken one.

Every fail-open path logs at `warning` with the route and reason. Silent
degradation would make RAW appear to work while doing nothing — the failure
mode hardest to notice and hardest to debug.

**Note (2026-08-12).** D5 only ever fires on `throw`. The silent field drop
that forced D1's amendment did not throw, and D5 would not have caught it.
Under amended D1 that class of bug is structurally impossible — untouched
entries are never deserialized — which is a reason to prefer prevention here
over adding a runtime drift check.

## Architecture

```
proxied XRPC ──▶ Phase 1 pipethrough ──▶ AppView response + atproto-repo-rev
                                              │
                                    (authenticated + munged NSID?)
                                              │ yes
                                              ▼
                                   SwanLocalWriteReader     (repo → records + deletions,
                                              │              bounded by repo-rev)
                                              ▼
                                   SwanRecordViewBuilder    (records → Petrel views)
                                              │
                                              ▼
                                   per-route munger         (splice into the response's
                                              │              JSON array, by URI)
                                              ▼
                                        client response
```

### Unit 1 — `SwanLocalWriteReader`

Returns the authenticated account's records written after a given repository
revision, and the paths of records deleted after it.

**Risk #1 is resolved: no new storage and no new writes are required.**

Swan already retains the full per-commit operation log — creates, updates, and
deletes — in `public_repository_mutation_requests.committed_projection`,
written inside the same transaction as the record-index mutation
(`PublicRepositoryStore.swift:627-648` vs. `:595-604`). A `delete` entry
survives there after its index row is gone. Nothing prunes the table, and
`next_revision` carries a `UNIQUE` index, so the window read is an indexed
range scan on the tail — O(window), independent of table size.

Recency comes from the **repository revision**, never from rkeys. There is no
per-record timestamp column. `next_revision` is server-allocated as
`max(wallClockMicroseconds << 10, floor + 1)`, so it decodes to microseconds —
verified numerically against both live rows, within 9 ms of the corresponding
event timestamps. Client-supplied rkeys are unsuitable: they are stamped by the
client's clock, and are frequently not TIDs at all (`self`).

The path deliberately **not** taken: `public_event_outbox` would also expose
deletions, but it is written only when a firehose commit context is supplied,
it requires parsing the firehose wire format, and oversize commits degrade to a
`#sync` row carrying no operation list at all — so RAW would silently miss
deletions on large batches.

Two obligations the implementation must carry:

- Fold by path, newest revision wins. Create-then-delete inside the window must
  yield one deletion and no record; create-then-update must yield one record at
  the latest CID. This is the most bug-prone step and needs a dedicated test.
- RAW's dependence on `public_repository_mutation_requests` retention must be
  pinned by a regression test and a comment at the DDL. The table grows
  unbounded today; if anyone later adds the natural cleanup, it must retain at
  least the RAW window or the removal half stops working with no error
  anywhere.

Unit 1 does **not** go through public-read generation admission. It reads block
bytes by direct CID lookup — no MST walk, no PLC verification.

### Unit 2 — `SwanRecordViewBuilder`

Turns a local record into the Petrel view type a route expects. The author is
always the authenticated account, so the author's `ProfileViewBasic` is built
once per request rather than fetched per record.

Fields the AppView owns and the local repo cannot know — like counts and
viewer state — are set to their zero/empty values. A brand-new post genuinely
has no likes yet, so this is accurate rather than a placeholder.

**Author avatar.** The reference builds avatar URLs from its own image CDN.
Swan has no image CDN, so a locally built `ProfileViewBasic` cannot produce a
loadable avatar URL. Instead, **lift the author's `ProfileViewBasic` out of the
AppView response** when it already contains one for the requester — every route
in scope does, except an empty feed — and fall back to DID plus canonical
handle with `avatar: nil`. On the common path this is better than the
reference.

### Unit 3 — Per-route mungers

Six small functions, each owning one route's semantics:

| Route | Merge |
|---|---|
| `getTimeline` | prepend own posts missing from the feed; drop deleted |
| `getAuthorFeed` | same, when the requested actor **is** the account |
| `getActorLikes` | prepend own likes missing from the list; drop deleted |
| `getProfile` / `getProfiles` | adjust counts for local creates/deletes |
| `getPostThread` | insert own replies missing from the thread; drop deleted |

**Dedupe by URI is mandatory in every insertion path.** The AppView may already
have indexed a record inside the window, and inserting it again would show the
user a duplicate of their own post — a bug more visible than the staleness this
phase exists to fix.

**Removal matching is per-route, not one URI rule.** `getTimeline` and
`getAuthorFeed` match `post.uri`; a deleted **like** is visible only as
`post.viewer.like`; a deleted **repost** as `reason.uri`, which is optional.
Three distinct match rules, and reposts degrade gracefully when the AppView
omits `reason.uri`.

`getAuthorFeed` and `getProfile` must merge only when the requested actor is
the authenticated account. Merging the account's own posts into *another*
actor's feed would be a correctness and privacy failure, not merely a display
bug.

## Error handling

| Condition | Behaviour |
|---|---|
| Munging throws | return unmodified AppView response, log at `warning` |
| AppView response unparseable as JSON | return it unmodified, log at `warning` |
| Local repo read fails | return unmodified, log at `warning` |
| `atproto-repo-rev` absent/unparseable | fall back to wall-clock window, log at `warning` |
| Non-2xx from AppView | pass straight through, never munge |

## Testing

**Unit.** View construction from a record; dedupe-by-URI; revision-window
boundary (inside merged, outside not); the create-then-delete and
create-then-update folds; deletion removal via all three match rules; zeroed
counts on local views.

**Retention pin.** A committed delete must still be recoverable from
`committed_projection` at the window boundary. This guards an implicit
cross-layer dependency that is otherwise invisible.

**Route-level.** For each of the six: a canned AppView response plus known
local records, asserting the merged output. Each route needs a negative case
proving no merge happens when the requested actor is not the authenticated
account.

**Non-regression on untouched content.** Given a response containing a record
with fields Petrel does not model, the merged output must preserve them
byte-for-byte. This is the test that would have caught the D1 defect, and it is
the property amended D1 exists to guarantee.

**Fail-open.** A builder that throws must yield the AppView response
byte-identical.

**Live.** Post from Catbird against the swan.place account and confirm the post
appears in the author's own timeline immediately; delete it and confirm it
disappears immediately. Per the project's verification rules a clean build is
not "done" — this must be observed in the running app.

## Risks

1. **~~Deletion visibility in repo storage~~ — RESOLVED.** `committed_projection`
   retains deletes indefinitely. No new storage. The residual risk is future
   pruning of that table, mitigated by the retention pin above.
2. **~~Petrel view-type fidelity~~ — RESOLVED by amended D1.** Confirmed lossy
   and confirmed silent; the merge strategy changed so RAW never re-serializes
   AppView-owned content. Unit 2 still uses Petrel types, but only to build
   rows from local records, where there is nothing to lose.
3. **`getPostThread` shape.** Threads are recursive and the trickiest merge.
   Land it last, after the flat-list routes prove the pattern.
4. **Header plumbing touches Phase 1.** Reading `atproto-repo-rev` requires
   reaching into the pipethrough's response handling. The change must be
   read-only with respect to Phase 1's behaviour, and must not widen the
   client-facing header allow-list.

## Non-goals

No change to Phase 1's request path. No caching layer. No munging of other
actors' content. No unauthenticated munging. No new persistence.
