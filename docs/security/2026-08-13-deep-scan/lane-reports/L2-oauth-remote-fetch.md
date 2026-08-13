# L2 — oauth-remote-fetch

Closes **F19**, **F09**, **F40**, **F10**. All four verified against the tree at
`75e7b509` before any edit; every claim below is cited at the line it was read
at (pre-edit line numbers are marked where they have since moved).

---

## 1. Per-finding verdicts

### F19 — durable freshness capacity claimed before the fetch — **CONFIRMED, fixed**

Verified as filed. `OAuthClientMetadataLoader.loadAndCache` called
`beginClientMetadataFetch` (pre-edit `:286-294`) before the first byte of
remote I/O (`:296`); `issueClientMetadataFetchTicketLocked` stamped
`retain_until = now + 3_600` (pre-edit `OAuthControlStore.swift:1235-1237`,
constant at `:201`); the table cap is 8,192
(`OAuthControlStore.swift:116-117`); and `purgeExpiredLocked` (pre-edit
`:1529-1541`) deletes a freshness row only when `retain_until <= ?` **and** no
`oauth_control_client_metadata` row exists, so a never-published row survived
the full hour. There was no abandon path: `grep -rn beginClientMetadataFetch
Sources` returns exactly one caller.

**One correction to the program's prescribed predicate.** The program says to
delete where `published_generation = 0`. That predicate can essentially never
match. `issueClientMetadataFetchTicketLocked` seeds a new row with
`published_generation = nextGeneration - 1` (pre-edit
`OAuthControlStore.swift:1279-1284`, now `:1373`), and `nextGeneration` is a
process-wide monotonic counter, so `published_generation` is zero only for the
very first ticket a database ever issues. The schema's own
`CHECK(published_generation <= latest_generation)`
(`Sources/SwanSQLite/SwanSQLite.swift:76-78`) is why the sentinel is written
that way.

What "nothing has published since this ticket was issued" actually looks like in
this schema is `published_generation = latest_generation - 1`, and because the
generation counter is global that equality can only hold while this ticket is
the single outstanding one for its client — any interleaved ticket, for this
client or any other, breaks it. That is the predicate I shipped, and it is
strictly safer than the one specified: it also refuses to delete the row when an
*older* flight is still outstanding, which the literal predicate would have
deleted, turning that older flight's legitimate publication into a
`malformedRecord` error.

Shipped, both halves as directed:

1. `abandonClientMetadataFetch(ticket:now:)` on the `OAuthControlStore` protocol
   (`Sources/SwanStorage/SwanStorage.swift:542`), implemented beside
   `publishClientMetadata` (`Sources/SwanSQLite/OAuthControlStore.swift:517`),
   deleting only where
   `client_id = ? AND latest_generation = ? AND published_generation =
   latest_generation - 1 AND NOT EXISTS (cached document)`. It is called on
   every non-publishing exit from the fetch through an explicit `catch` rather
   than a `defer` (`OAuthClientMetadataLoader.swift:383-390`) so the release is
   *durably complete before the caller sees the error* — a detached best-effort
   task would have left the capacity claimed for an unbounded interval, which is
   the whole finding.
2. Ticket retention split: `clientMetadataFetchTicketRetention = 60`
   (`OAuthControlStore.swift:212`) at insert (`:1330`), extended to
   `clientMetadataFreshnessRetention = 3_600` only in
   `markClientMetadataFetchPublishedLocked` (`:1390-1409`, via
   `retain_until = MAX(retain_until, ?)`).

**Composition with the `MAX(existing, excluded)` upsert (`:1362-1369`) was
verified, not assumed.** `testStartingAFetchDoesNotShortenAPublishedClientRetention`
publishes a client, starts a *new* fetch for it, and then proves the row is
still retained at T+3,001 s and gone at T+3,601 s. That test also fails against
the pre-fix tree, for the opposite reason: today a new ticket *extends* a
published client's retention by a further hour every time one is issued.

60 s is sized against the worst-case fetch the policy permits: four bounded DNS
resolutions plus two bounded HTTP requests at `timeout <= 30`, but with the
production default of 5 s that is ~30 s, and the loader passes the *same* `now`
to `begin` and `publish`, so a row cannot be purged by its own transaction.

### F09 — process-global remote-document budget starved pre-authentication — **CONFIRMED, fixed; the program's fix is necessary but not sufficient**

Verified as filed: `OAuthRemoteFetchAdmission.shared` was a process-global,
non-queueing 8-permit gate (pre-edit `OAuthRemoteFetch.swift:474-496`) covering
metadata and its remote JWKS, reached pre-authentication from PAR, and
`/oauth/token` and `/oauth/revoke` revalidate with `bypassCache: true`
(`OAuthClientMetadataLoader.swift:349-351` pre-edit), so starvation denies the
one real account's token refresh.

**Finding the program missed, in the item the program itself lanes here.**
Splitting `OAuthRemoteFetchAdmission` alone does not close F09.
`OAuthClientMetadataLoader` has a *second* non-partitioned 8-slot gate,
`maximumConcurrentFlights` (pre-edit `:137`), and it is reached **first** — the
flight table is consulted inside the actor before the detached task ever asks
for a fetch permit. Eight anonymous flights therefore refuse an authorized
client at the loader, before any reserved fetch permit is consulted. I mirrored
the reservation there (`generalConcurrentFlights = 6`,
`OAuthClientMetadataLoader.swift:92`, enforced at `:156-182`) as well as in the
fetch pool (`OAuthRemoteFetchAdmission(limit: 8, generalLimit: 6)`,
`OAuthRemoteFetch.swift:475`). Both are reservations, not partitions: an
authorized client may use all eight, an anonymous one at most six. The limit was
**not** raised and no queueing was added, preserving the decision documented at
`OAuthRemoteFetch.swift:461-464`.

**Second correction to the program.** The reserved tier cannot key on
`published_generation > 0` as specified. Beyond that column not meaning what the
program says (see F19), the property it names is *attacker-creatable*: serving
one syntactically valid client-metadata document is enough to publish a
generation, so an attacker would classify into the reserved pool as easily as
into the general one, and the split would buy nothing.

The reserved tier keys instead on the one client-identity fact available before
any remote document is fetched that an anonymous caller cannot manufacture: a
live, unrevoked token family naming that `client_id`
(`clientHoldsLiveAuthorization`, `OAuthControlStore.swift:555`, over
`oauth_control_token_families.client_id`,
`Sources/SwanSQLite/SwanSQLite.swift:91-105`). Creating one requires completing
an authorization against the account's own credentials. It is also exactly the
population the finding is about — token refresh and revocation are what
`revalidate` serves. The check fails closed to the general tier if the control
database is unavailable (`OAuthClientMetadataLoader.swift:280-292`), and it is
consulted **only after the general tier is already full** and only while a
reserved slot is still winnable (`OAuthRemoteFetch.swift:605-618`,
`OAuthClientMetadataLoader.swift:156-168`), so a rejected anonymous caller
never costs a control-database round trip.

Accepted narrowing, stated plainly: a legitimate client's *first ever*
authorization has no token family and so competes in the general tier. Six of
eight permits remain available to it.

Per-host in-flight cap of 2 added alongside `maximumConcurrentFlights`
(`OAuthClientMetadataLoader.swift:97`, `:149-155`), sized so one legitimate
client can still hold a cache-miss load and a `bypassCache` revalidation at once.

`OAuthRemoteFetchAdmissionTests.swift:393` and its `:490-500` assertions were
tightened rather than relaxed — still fail-closed, now pinned to the six-permit
general tier so a future widening is caught.

### F40 — pipethrough lease held across an unbounded blocking resolve — **CONFIRMED, fixed**

`SwanPeerPinnedProxySender.send` called `resolver.resolve(host:)` with no
deadline (pre-edit `SwanProxyHTTPTransport.swift:67`) while the caller holds a
pipethrough lease, and production resolution is blocking `getaddrinfo` with no
cancellation handle (`OAuthRemoteFetch.swift:341-379`). `resolveOAuthHostname`
is now internal (`OAuthRemoteFetch.swift:279-283`) and used at
`SwanProxyHTTPTransport.swift:66-75`, bounding it by `policy.timeout`.

**Was the serial DNS queue deliberate? No — and I have positive evidence, not
just absence.** Three facts:

1. `jj file annotate` puts the serial queue at
   `Sources/SwanOAuth/OAuthRemoteFetch.swift:347` (pre-edit) in
   `1b1ab448f488` "feat(oauth): validate client proofs and metadata",
   2026-07-26 — the commit that *created* the file. `OAuthBlockingDNSAdmission`
   and its four permits arrived five days later in `69ae480672a3`
   "security: adversarially harden Swan interop alpha", 2026-07-31. The queue
   predates the bound it is now claimed to be part of.
2. No comment anywhere in the tree states a thread-count rationale for it. The
   only rationale present, at `OAuthRemoteFetch.swift:187-191`, names the
   admission — not the queue — as the control on "an unbounded dispatch
   backlog".
3. Decisively: a serial queue makes those four permits unreachable. Three
   permit holders would sit *behind* one unresponsive lookup, still holding
   their permits, which is the stall the finding describes. Serial and the
   documented design contradict each other; they cannot both have been
   intended.

The queue is now `.concurrent` (`OAuthRemoteFetch.swift:327-339`) with
`OAuthBlockingDNSAdmission.shared` (4 permits, fail-fast) as the sole bound.
Worst-case blocked dispatch threads: 1 → 4, which is what that limit is sized
for. No maintainer decision needed; the recommendation at §4 item 13 stands and
the residual documentation at `:187-191` was not needed.

Note for L7/L8: `Sources/SwanAccounts/ATHandleVerification.swift:153-157` has
the same serial-queue shape for handle DNS. It is outside this lane's files and
was left alone.

### F10 — special-purpose IPv6 ranges accepted by the OAuth classifier — **CONFIRMED, fixed**

Confirmed independently that `b5f161088e96` "fix(accounts): harden handle
verification boundaries" (2026-07-27) is an un-back-ported fix, not a design
choice: `jj diff -r b5f1610 --summary` lists eleven files and
`Sources/SwanOAuth/OAuthRemoteFetch.swift` is not among them, while
`jj file annotate` attributes the whole prefix table at
`ATHandleVerification.swift:105-113` to that commit.

The OAuth copy accepted all of 2000::/3 except 2001:db8::/32 and 2001::/27
(pre-edit `OAuthRemoteFetch.swift:99-100` — note the second guard is
`bytes[3] < 0x20` over a fixed `2001:00`, i.e. /27, not the "/32" the scan
says), so 2002::/16 and 3fff::/20 passed.

One classifier now lives in `Sources/SwanCore/SwanPublicAddressPolicy.swift`;
`OAuthIPAddress` (`OAuthRemoteFetch.swift:57-80`) and `ATHandleIPAddress`
(`ATHandleVerification.swift:65-85`) both delegate. The hoisted version rebases
the IPv6 octets before indexing, which the two originals did not — they index
`Data` absolutely and would have misread any slice with a non-zero
`startIndex`. No caller supplies one today.

`Tests/SwanAccountsTests/ATHandleVerificationTests.swift:81-101` is mirrored
into the OAuth suite, plus the embedded-IPv4 case the scan calls out: a 6to4
address carries an IPv4 destination in bytes 2...5, so `2002:7f00:1::`,
`2002:0a00:1::`, `2002:c0a8:1::` and `2002:a9fe:a9fe::` are each asserted
rejected alongside the direct literal they encode.

---

## 2. Migration

**None.** No column, table, or index was added, and no existing row is
rewritten. `abandonClientMetadataFetch` and `clientHoldsLiveAuthorization` are
new statements over the existing `oauth_control_client_metadata_freshness` and
`oauth_control_token_families` schemas.

Effect on the deployed database with live rows: nothing at startup. The one
behavioural difference an existing row sees is retention. Freshness rows already
carrying `retain_until = created + 3600` keep that value — the publish-time
extension uses `MAX(retain_until, ?)` and the ticket upsert already used
`MAX(existing, excluded)` — so no live row's retention is shortened by the
deploy. Only rows created after it get the 60 s unpublished window.

One cost to record: `clientHoldsLiveAuthorization` has no index on
`oauth_control_token_families(client_id)`; SQLite can use the existing
`oauth_control_family_expiry` index for the `expires_at > ?` half. The table is
capped at 65,536 rows and can only grow through a completed authorization, so it
is a handful of rows on the deployed single-account server, and an anonymous
caller cannot inflate it. Adding `CREATE INDEX IF NOT EXISTS ... (client_id,
expires_at)` would require editing `Sources/SwanSQLite/SwanSQLite.swift`, which
belongs to no lane in this wave; it is a cheap follow-up if a multi-account
deployment ever appears.

---

## 3. Exact pre-fix failures

Every fix was driven by a test that compiles and fails against `75e7b509`
before the corresponding change. Verbatim, from
`swift test --skip-build --filter 'SwanOAuthTests.(OAuthRemoteFetchAdmissionTests|SwanProxyHTTPTransportTests)'`
at the sealed tree (`Executed 29 tests, with 15 failures`):

```
OAuthClientMetadataLoader.swift:213: error: -[…testFailedAnonymousMetadataFetchesCannotDenyANewLegitimateClient] : failed: caught error: "unavailable: OAuth metadata cache unavailable"
OAuthControlStore.swift:1452: error: -[…testUnpublishedFreshnessTicketsExpireWithinTheShortFetchWindow] : failed: caught error: "unavailable: OAuth control state capacity is exhausted"
OAuthControlStore.swift:1452: error: -[…testStartingAFetchDoesNotShortenAPublishedClientRetention] : failed: caught error: "unavailable: OAuth control state capacity is exhausted"
OAuthClientMetadataLoader.swift:215: error: -[…testSlowAnonymousOriginsCannotDenyAnAuthorizedClientRevalidation] : failed: caught error: "CancellationError()"
OAuthRemoteFetchAdmissionTests.swift:1098: error: -[…testOneHostCannotHoldMoreThanTwoConcurrentMetadataFlights] : XCTAssertFalse failed - one host must not hold more than two concurrent metadata flights
OAuthRemoteFetchAdmissionTests.swift:1115: error: -[…testProductionOAuthIPv6PolicyRejectsSpecialPurposeRanges] : XCTAssertFalse failed - 2002::1
OAuthRemoteFetchAdmissionTests.swift:1115: error: … : XCTAssertFalse failed - 3fff::1
OAuthRemoteFetchAdmissionTests.swift:1115: error: … : XCTAssertFalse failed - 3fff:fff::1
OAuthRemoteFetchAdmissionTests.swift:1142: error: -[…testOAuthPolicyRejects6to4AddressesEmbeddingRejectedIPv4Destinations] : XCTAssertFalse failed - 2002:7f00:0001::
OAuthRemoteFetchAdmissionTests.swift:1142: error: … - 2002:0a00:0001::  /  2002:c0a8:0001::  /  2002:a9fe:a9fe::
OAuthRemoteFetchAdmissionTests.swift:1149: error: -[…testResolvedSpecialPurposeAnswersAreRejectedByFetchPolicy] : XCTAssertThrowsError failed: did not throw an error
SwanProxyHTTPTransportTests.swift:90: error: -[…testHostnameResolutionIsBoundedByThePolicyDeadline] : failed - a blackholed resolver must not produce a proxied request
SwanProxyHTTPTransportTests.swift:96: error: … : XCTAssertLessThan failed: ("5.103984208 seconds") is not less than ("2.0 seconds") - the proxy lease must be released on the policy deadline
```

The F09 pre-fix failure is worth reading closely: the authorized client's
`revalidate` did not merely observe a counter, it **failed** — the loader
aborted it at `OAuthClientMetadataLoader.swift:215` while six slow anonymous
origins held the transport. That is the denial of a legitimate authenticated
operation the lane brief asked to be demonstrated. F19's first test is the same
shape: a previously unseen legitimate client cannot onboard at all once four
anonymous callers have named four URLs that never validated.

Two tests could not be written to fail first because they exercise an API that
did not exist — `testAbandoningATicketNeverRemovesAConcurrentFlightsRow` and
`testAnAbandonedTicketCannotPublishLater`. They are stated as such rather than
claimed as regressions.

---

## 3a. Suite and Linux results

Baseline at `75e7b509`: exit 0, 1,489 passed, 0 failed, 9 skipped, 11 targets.

Final tree: **exit 0, 1,500 passed, 0 failed, 9 skipped, 11 targets**, and zero
`Some test targets reported failures` lines. 1,489 + the 11 tests this lane adds
= 1,500; nothing was removed or disabled.

Two notes on how that number was obtained, because both cost time:

- The pass-counting pattern in the lane brief, `Test Case '-\[.*\] passed`,
  matches nothing — XCTest prints `Test Case '-[Suite testName]' passed`, with a
  closing quote before ` passed`. The pattern that works is
  `Test Case '-\[.*\]' passed`. A run counted with the brief's pattern reports
  0 passes and looks like a crashed target.
- Two full-suite runs hung — not failed, hung — in
  `PLCSpaceCredentialPublicKeyResolverTests`, a suite this lane does not touch.
  Cause: my two concurrency tests originally released their barrier transport
  from a `defer` via a detached `Task`, so blocked flights outlived the test and
  reached the control database after teardown had closed it. Loader flights are
  detached from their callers by design, so cancelling the callers does not stop
  them. Both tests now release the transport and `await` every load before
  returning. The suite has run clean end-to-end since. Pre-existing tests in the
  same file share the older `defer`-release shape and were left alone.

**Linux (`swift:6.1-jammy`, Docker): every library target and the `swan`
product build clean — `[3844/3855] Linking swan`, no error from any file this
lane touches.** `swift build` exits 0.

`swift build --build-tests` exits 1, on a **pre-existing** incompatibility with
the Swift 6.1 toolchain that has nothing to do with this lane:

```
/work/Tests/SwanSQLiteTests/AccountPermanentDeletionSQLiteTests.swift:260:37:
error: 'async' call cannot occur in a defer body
```

That is `defer { try? await database.close() }` in a file this lane does not
modify, and it is the *only* error in the whole `--build-tests` run. Swift 6.1
rejects `await` in a `defer` body; the macOS toolchain in use here (Xcode-beta)
accepts it. So the test suite as a whole does not currently compile under
`swift:6.1-jammy` — worth knowing for CI, and worth fixing, but not this lane's
file.

Getting that far took four attempts; recording the environment traps so the
next lane does not repeat them:

1. The package has `.package(path: "../Petrel")`, which resolves to `/Petrel`
   inside the container and must be mounted, or the build fails immediately
   with "the package at '/Petrel' cannot be accessed".
2. Mounting the live sibling checkout fails with `input file
   '/Petrel/.../AppBskyFeedSendInteractions.swift' was modified during the
   build` while another lane is active. Use a snapshot copy.
3. Docker Desktop on this machine does not share `/private/tmp`, so a snapshot
   in the scratchpad mounts as an empty directory and fails silently in a
   confusing way. The snapshot has to live under a shared path; this build put
   it in the gitignored `.build-l2-linux/`.
4. Building directly against the bind-mounted source fails at `Copying
   Fixtures` with `NSCocoaErrorDomain Code=512` — `Tests/SwanOAuthTests/
   Fixtures/pinned-typescript-notify-write.json` carries a
   `com.apple.provenance` xattr that `xattr -rc` does not clear and that
   SwiftPM's resource copy cannot reproduce across the mount. Copying the tree
   into the container with `tar` first avoids it.
5. The build stage needs `libsodium-dev pkg-config libsecret-1-dev
   libglib2.0-dev`, exactly as `Dockerfile:4-9` installs them.
6. The container's SwiftPM rewrites `Package.resolved` (dropping
   `swift-configuration`, changing `originHash`) when `/src` is mounted
   writable. Mount it `:ro`. It was restored here and is not in this lane's
   diff.

One limitation stated plainly: Docker on this Apple Silicon host builds
`aarch64-unknown-linux-gnu`, not the deployment target's `x86_64`. The lane
brief's own command has the same property. Nothing in this change is
architecture-dependent — no SIMD, no pointer-width assumptions, no new
`#if arch` — but x86_64 was not compiled and is not claimed.

---

## 4. Not done, and why

- **Did not raise the fetch limit and did not add queueing.** Both reverse the
  decision documented at `OAuthRemoteFetch.swift:465-473`.
- **Did not relax any fail-closed assertion.** The two global-budget tests were
  tightened to the new general tier instead.
- **Did not touch `ATHandleVerification`'s serial DNS queue** (`:153-157`),
  though it has the same shape as the one F40 fixes. It is reached only from
  handle verification, which is not in this lane's scope, and changing it would
  edit a file for a finding not laned here.
- **Did not add the `oauth_control_token_families(client_id)` index** — it needs
  `Sources/SwanSQLite/SwanSQLite.swift`, owned by no lane.
- **Did not implement the scan's F10 remediation string**, which is F07's
  DID-binding text and has nothing to do with IP ranges, exactly as the program
  records at its §1.

## 5. Residual

- The reserved tier protects clients the account *already* authorizes. A first
  authorization for a genuinely new client still competes in the six-permit
  general tier, and an attacker sustaining six slow origins degrades new-client
  onboarding. Cloudflare rate-limiting `/oauth/*` (program §2) is still the
  cheaper mitigation for that half.
- A freshness row for an authorized client is purged an hour after its last
  publication if its cached document has also expired; that does not affect the
  reserved tier, which reads the token-family table, not the freshness table.
- `abandonClientMetadataFetch` is awaited on the failure path, so a failing
  fetch now holds its admission permit for one extra bounded control-DB write.
