# Swan Production Readiness — Design

**Date:** 2026-08-12
**Status:** Draft for review
**Companion:** `2026-08-12-swan-read-after-write-design.md` (Phase 2 RAW). RAW is
independent of this work and can proceed in parallel — its local-write reader
deliberately bypasses public-read generation admission.

## Goal

Make swan.place a PDS the network can read **continuously**, then join it to the
network so posts made on it appear on Bluesky.

Today it can do neither. The public read surface fails permanently on a routine
trigger, and the firehose that would announce the repo to a relay has never been
switched on.

## What the research established

Four research passes produced the findings this design responds to. The evidence
lives in the session's scratchpad; the load-bearing conclusions:

- **Public reads fail permanently on a foreign-connection commit.** Reproduced
  symmetrically for both hosted accounts against real production data. Observed
  live on 2026-08-12: reads returned 200 at 13:04:33 and 503 from 13:10:22
  onward, for nearly three hours, with **nothing logged**.
- **The relay does not need most of what looked missing.** Indigo's relay makes
  exactly three outbound XRPC calls — `describeServer`, `getRepoStatus`, and
  `listHosts` (against another relay). It never calls `listRepos`, `getRepo`,
  `getBlocks`, `getRecord`, or `listBlobs` on a PDS, and has no backfill step.
- **Relay admission is open.** No allowlist, no approval, no auth on public
  `requestCrawl`; the 2024 Early Access Federation regime is gone.
- **The WebSocket path through Cloudflare works.** Header forwarding measured at
  the origin for this hostname; 30,665 completed upgrades through the same
  Cloudflare account and the same Caddy instance; `websockets: on` confirmed for
  the zone. Swan already sends a 30s `autoPing`.
- **`/xrpc/**` authenticates before it routes**, so every unimplemented NSID
  answers 401. A missing route is indistinguishable from a login failure, which
  is why this list stayed invisible.

## Scope

Three workstreams, strictly ordered. W1 gates W3.

### W1 — The read path must not fail permanently

**D1. A stale generation pin re-admits; it does not fail.**

`activePublicReadContext` treats the control-account row as the sole cache key
and never asks whether the cached generation is still valid.
`requirePublicRepositoryGenerationWithoutGate` re-checks three pins on every
cached read — `fileIdentity`, `PRAGMA data_version`, and the exact
`public_repository_state` — and returns `.unavailable` if any moved. Nothing
ever re-admits.

`PRAGMA data_version` is the sharp edge: it is monotonic, it moves on **any**
commit from a different connection to **any** table in that account database,
and it never returns to its prior value. Swan already holds two file descriptors
per account database in the live process, so the second connection required to
trigger this is not hypothetical — it exists today.

A read that finds a stale pin must re-admit once and retry, and only return 503
if that re-admission genuinely fails. This is the single change that turns a
permanent outage into a self-healing one.

It is also **confirmed to be the right fix, empirically**: on 2026-08-12 the live
outage was cleared with no restart by creating a record, whose post-commit
refresh re-admitted the generation. Reads recovered immediately at
`rev 3msv3rpplne22`. That also disproved the competing hypothesis that a SQLite
connection had errored — re-admission succeeded, so the connection was healthy
and a stale pin was the whole story.

**D2. A failed post-mutation refresh evicts; it does not fail the mutation.**

The commit is already durable when `refreshPublicReadGenerationAfterMutation`
runs. A refresh error must not fail the request, and must not leave a
known-stale generation cached. Evict the entry; with D1, the next read
re-admits.

**D3. `data_version` becomes change detection, not a validity assertion.**

With D1 in place it is harmless. Without D1 it is a liveness landmine armed by
any future component that opens a second connection.

**D4. The read path must say why it failed.**

This incident cost two rounds of forensics — a local repro built against copied
production databases — purely because `PublicRepositoryReadError.unavailable`
erases which of eight guards fired, and six `catch` sites collapse every cause
into an identical opaque 503. `journalctl` showed **nothing** across three hours
of live failures.

One structured log line naming the failed guard, server-side only, never
widening the client-visible body. This is not polish: it is the difference
between diagnosing a recurrence in minutes and rebuilding the forensic harness.

### W2 — Route surface

Ordered by who actually breaks, using the relay evidence rather than
reference-PDS parity.

**D5. Route before authenticating.**

`SwanXRPCPipethrough` runs auth (step 2) before routing (step 3), so
unimplemented NSIDs return 401 rather than 404. `SwanXRPCProxyRouter.route` is
documented as pure with no I/O, so evaluating it first costs nothing and
preserves the stated invariant that an anonymous caller can never make Swan open
a socket — routing opens no sockets; the resolver does, and that stays behind
auth.

This is a diagnosability fix as much as a correctness one.

**D6. Implement `com.atproto.identity.resolveHandle`, unauthenticated.**

Handle resolution is unauthenticated on every real PDS. Swan already has the
lookup — an unknown handle returns `RepoNotFound` through `describeRepo` today,
which means it resolves and returns nil. Needs no generation admission, so it
ships independently of W1. Add `/xrpc/com.atproto.identity.*` to the unknown-
endpoint guards so the rest of that namespace 404s instead of 401ing.

**D7. Public blob reads move to the read path.**

`com.atproto.sync.getBlob` is registered inside the **mutation** endpoint block,
so it is gated behind `--enable-public-repository-mutations`. An operator who
disables public writes silently disables avatar and image serving for the whole
network. It is on in production today, which is the only reason blobs work.

This is the same conditional-registration shape that produced two prior security
bugs here. Move it to the read path and delete its special case.

**D8. Serve `/.well-known/did.json`.**

`describeServer` advertises `did:web:swan.place`, which returns 404 and is
therefore unresolvable. Today's AppView proxying is unaffected because service
tokens are minted under the account DID, but this bites relay, labeler, and
mod-service interop.

**D9. `describeServer` stops advertising an invite requirement it cannot honour.**

`inviteCodeRequired: true` is hardcoded and there is no invite mechanism
anywhere in Swan. A conformant client asks the user for a code and has nowhere
to send it. Set it accurately and derive it from configuration rather than a
literal.

**D10. The public route surface must honour `--profile`.**

Route registration iterates a hardcoded `PublicDataTesting20260727` while the
permissioned surface correctly iterates the loaded profile. Switching
`--profile` changes nothing, and one profile that ships on disk has no Swift
registry at all. Select from the loaded profile, and fail loudly at startup when
a profile has no matching registry.

**Explicitly not in scope**, with reasons:

- `sync.listRepos`, `sync.getRecord`, `sync.getBlocks`, `sync.listBlobs` — the
  relay never calls them. They were ranked P0 on the assumption that relays
  enumerate a PDS during onboarding; reading indigo's source disproved that.
  Revisit when a consumer that actually needs them appears.
- The `createSession` / app-password family — this needs a **decision** before
  code: is Swan OAuth-only? The code strongly implies yes, and leaving
  `createSession` proxyable once leaked account passwords to a caller-named
  service. If yes, document it and return method-correct `501 NotImplemented`
  so clients get an actionable error instead of 401.
- Invite codes — no mechanism, and D9 removes the false advertisement.

### W3 — Relay activation

**D11. Two lines, gated on W1.**

Add `-e SWAN_PUBLIC_CRAWLERS=https://bsky.network` to the `docker run` line and
`--enable-public-firehose` to the `serve` arguments. Retention defaults stay.

**The gate: public reads must be working and must have survived a
foreign-connection commit without a restart.** The relay itself does not read
the repo — but it serves `getRepo` as a **302 redirect to the PDS**, so the
AppView and every downstream backfiller land on Swan directly. A PDS that 503s
on those redirects publishes nothing, and does so silently.

**D12. `force-sync` is the delivery mechanism, not the queued backlog.**

Indigo dials a new host with **no cursor** and streams from current. The two
commits already queued in the outbox will sequence into `firehose.sqlite` and go
nowhere — that is the protocol, not a bug. `swan firehose force-sync` after the
subscription is live is the intended and only tool; a `#sync` for a never-seen
DID lazily creates the relay-side account.

**D13. Strike the grey-cloud fallback from the relay plan.**

Caddy serves a **Cloudflare Origin CA** certificate — issuer `CloudFlare Origin
SSL Certificate Authority`, valid to 2041, which is itself proof of private
trust since public CAs are capped at 398 days. Grey-clouding would hand indigo a
certificate Go cannot verify, failing the handshake outright and taking every
browser with it. It is strictly worse than the problem it purports to solve.

If a direct-to-origin path is ever needed, the remedy is a Caddy built with the
Cloudflare DNS module using DNS-01 (HTTP-01 cannot work while the record is
proxied), verified against the origin IP *before* changing DNS.

## Sequencing

```
W1 (read path)  ──▶  W2 (routes)  ──▶  W3 (relay activation)
     │                                        ▲
     └──── hard gate: reads survive a ────────┘
           foreign-connection commit
```

W2 is not a gate on W3 — the relay needs only `describeServer` and
`getRepoStatus`, both of which work. It is sequenced second because D5's
route-before-auth change makes everything else diagnosable, and because
announcing to a public relay with a knowingly broken `resolveHandle` and an
unresolvable service DID is not a good first impression on the network.

## Testing

**W1.** A regression test that commits from a second connection to an account
database and asserts public reads still succeed — the exact scenario reproduced
in the repro harness. Plus: a failing post-mutation refresh evicts rather than
failing the mutation; a genuinely unadmittable account still 503s, and logs why.

**W2.** `GET /xrpc/com.atproto.identity.resolveHandle` with no Authorization
header returns 404 before D6 and 200 after — never 401. `getBlob` registers when
public writes are disabled. Startup fails when a loaded profile has no registry.

**W3.** The runbook's nine steps, each with expected output and failure
signature. Two independent witnesses that the relay actually subscribed —
`listHosts` on the relay side, and a `subscribe_repos.open` line with
`cursor_mode=live` on Swan's side. Do not treat "announcer logged success" as
proof: indigo returns 200-with-empty-body on several failure paths, and one path
returns 200 with no subscription at all.

**Live.** A post from Catbird appears in `public.api.bsky.app`'s
`getAuthorFeed`. That is the actual success criterion for this entire document.

## Risks

1. **The 2026-08-12 onset is still unexplained.** All three pins verifiably did
   not move between the last success and the first failure, and the cause was
   process-resident state a file copy cannot carry. D1 fixes the symptom
   regardless — confirmed, since re-admission succeeded — but the *trigger*
   remains unidentified. **D4's logging is what will identify it if it recurs**,
   and is the reason D4 is not deferrable.
2. **A write path exists that leaves no access-log trace.** The account database
   was committed at 12:58:11 with no corresponding request in Caddy's log,
   implying a request made directly to `127.0.0.1:3020`. Worth understanding
   before trusting the access log as a complete record.
3. **End-to-end WebSocket on swan.place is unproven** — every component is
   proven individually, but the composed path needs the route enabled. First
   action after flipping the flag is a manual `websocat`, before pointing the
   relay at it.
4. **`requestCrawl` is irreversible.** There is no retraction; the relay marks a
   host offline after 15 failed dials. This is the one genuinely one-way step,
   and it needs explicit authorization.
5. **Whether the AppView materialises records from a `#sync` alone** is
   unverified. If the two pre-existing posts do not appear while a new post
   does, that is the expected shape of "the relay does not backfill" — and the
   remedy runs through Swan's `getRepo`, which is why W1 gates W3.

## Non-goals

No account creation or invite system. No app-password authentication. No image
CDN. No change to Phase 1's proxying, credential isolation, or peer-pinning. No
new persistence.
