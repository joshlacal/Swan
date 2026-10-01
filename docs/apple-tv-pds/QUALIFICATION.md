# AT Protocol qualification ladder

Swan's actual public surface (from `Sources/SwanPublicWire/SwanPublicWire.swift:34-47`
and route literals in `Sources/SwanHTTP/`): `com.atproto.repo.{applyWrites,
createRecord, deleteRecord, describeRepo, getRecord, listRecords, putRecord,
uploadBlob}`, `com.atproto.sync.{getBlob, getLatestCommit, getRepo,
getRepoStatus, subscribeRepos}`, `com.atproto.server.{createAccount,
createSession, describeServer}`, `com.atproto.identity.resolveHandle`
(out-of-profile opt-in), OAuth (`/.well-known/oauth-authorization-server`,
PAR, authorize, token; enabled by `--enable-oauth-authorization-server`),
`/health`, plus Swan's permissioned `com.atproto.space.*` /
`com.atproto.simplespace.*` family.

Note: Swan does **not** serve `/xrpc/_health` (returns 404, OBSERVED on
macOS); its health route is `GET /health` (200). Gate P0 uses `/health` and
`describeServer`; adding `/xrpc/_health` as an alias is a one-line route if a
client turns out to need it.

| Gate | Meaning | Swan routes | Proof command (against the Apple TV) | Public ingress needed |
|---|---|---|---|---|
| P0 | process serves | `GET /health`, `describeServer` | `curl -s http://<tv>:8080/health`; `curl -s http://<tv>:8080/xrpc/com.atproto.server.describeServer` | no |
| P1 | identity bootstrap | `did:web` document route (`SwanDidWebIdentityHTTP`) or PLC provisioning via management listener | `swan account create …` equivalent executed in-extension (management path) then `curl /.well-known/did.json` | did:web: yes (HTTPS origin) — PLC: PLC directory reachable |
| P2 | repo read | `describeRepo`, `getRecord`, `listRecords`, `sync.getRepo`, `getLatestCommit`, `getRepoStatus` | `curl '/xrpc/com.atproto.repo.listRecords?repo=<did>&collection=app.bsky.feed.post'`; `sync.getRepo` CAR verified with Petrel's CAR reader | no |
| P3 | repo write | `createRecord`, `putRecord`, `deleteRecord`, `applyWrites` | authenticated `createRecord` then `getRecord` round-trip; `getLatestCommit` rev advanced | no |
| P4 | blob upload | `uploadBlob`, `sync.getBlob` | upload 200 KB image, reference it from a record, fetch by CID; verify object exists in vault (`GET /v1/objects/<sha256>`) | no |
| P5 | sessions/OAuth | `createSession` (legacy) ; full OAuth AS | `createSession` with app password; OAuth metadata + PAR + token with DPoP via Swan's `SwanOAuthLabClient` (`Sources/SwanInterop`) | OAuth: yes (HTTPS issuer) |
| P6 | CRUD lifecycle | P3 routes + swap semantics | create/put/delete with `swapRecord`/`swapCommit`, expect `InvalidSwap` on stale | no |
| P7 | sequencing | `sync.subscribeRepos` (`--enable-public-firehose`) | websocket client receives `#commit` for each P3 write with monotonically increasing `seq`; restart extension mid-stream, resume with `cursor` | no |
| P8 | external client login | P5 + client metadata fetch by the PDS | Catbird (via nest gateway) or `goat`/`bsky` CLI logs in | yes |
| P9 | Bluesky-compatible client posts | P3/P4/P5 through public origin | post from Catbird appears in `listRecords` and on the firehose | yes |
| P10 | federation | relay crawl (`com.atproto.sync.requestCrawl` announce, `PublicCrawlAnnouncer`), appview indexing | post visible on bsky.app via relay ingestion | yes |

Existing harnesses to reuse: `Sources/SwanInterop` (`LiveInterop.swift`,
`ScenarioRunner.swift`, `SwanOAuthLabClient.swift`) and
`docs/interop-lab.md`. These already drive Swan through the public routes and
compare against the reference PDS; pointing them at `http://<tv>:8080` covers
P0–P7 without new test code.

## Milestone mapping

* M4 = P0. M5 = P2+P3 (+ P6) with extension restart / Apple TV restart /
  router restart between write and read. M6 = P8+P9 with Catbird.
  M7 = P10. M8/M9 = FAILURE_TESTS + lifecycle matrix, not new protocol gates.

## Status

All gates UNKNOWN on Apple TV. On macOS, Swan passes its own interop lab for
the same routes (see `docs/interop-lab.md`); the ladder measures tvOS + vault,
not Swan's protocol correctness.
