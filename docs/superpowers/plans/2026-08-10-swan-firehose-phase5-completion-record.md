# Swan Firehose Phase 5 Completion Record (Task 7 Execution)

Date: 2026-08-10
Head tree: `55aa5d51a0e85dab29f6e75b91db9a00f417c10d` (clean working copy; every
gate below ran against this exact tree)
Parent plan: `docs/superpowers/plans/2026-08-08-swan-firehose-phase4-corrective-phase5-relay.md`

Per the parent plan, this record distinguishes local static verification, the
pinned reference-relay runtime proof, the recovery proofs, the `getRepo?since`
observation, and what remains unproven. A green Task 7 alone does not make
Phase 5 complete: the independent whole-branch review is still open, and live
deployment remains a separate activation gate.

## 1. Local static verification (all green)

- `interop/fetch-reference-indigo.sh` repopulated the pinned Indigo source
  cache (commit `8b43a326dbbb394f63b6d68761553cdfe25532de`, archive SHA-256
  `bc6f57e6…78fdd0b` verified); `interop/verify-reference-indigo.sh` and
  `interop/verify-reference-indigo-vendor.sh` green after
  `interop/materialize-reference-indigo-vendor.sh` rebuilt the vendor closure
  through the digest-pinned Go image.
- `Scripts/verify-interop-lab.sh`: interop-lab and reference-relay effective
  Compose invariants plus static invariants OK.
- Mutation suites: `Scripts/test-verify-interop-lab.sh` (verifier mutation
  tests + bootstrap lookup fail-closed tests) and
  `Scripts/test-reference-relay-acceptance.sh` (artifact validation + runner
  mutation tests) both OK.
- Protected profile/wire gates on the head tree: `Scripts/verify-profile.sh`
  green; `Scripts/verify-wire-generation.sh` and
  `Scripts/verify-public-wire-generation.sh` green against the pinned Petrel
  generator workspace (`@-` = `c2a1cdbee8c621c7682416114700f032cc7e2b37`),
  "verified without worktree mutation". Note: the pinned generator commit is
  now also an ancestor of Petrel `main` (`fe67a38f882c`) via a merge that
  preserved its commit ID; the workspace pin is unchanged.

## 2. Pinned reference-relay runtime proof

`Scripts/run-reference-relay-acceptance.sh` executed the ordered scenario
against the byte-pinned Indigo relay image in the Compose lab (colima /
docker 29.5.2). Artifact: `artifacts/live/reference-relay-acceptance.json`
(schema 2, mode 0600, aggregate/digest-only), SHA-256
`be3175cb5eb803e68f54a3750014d37d6c59efe909ee414c4f7e9fc50286457b`, bound to
`swanHead` `55aa5d51…` and Indigo image ID `5030c2fd94fb…`. Status: `passed`;
success marker `REFERENCE RELAY ACCEPTANCE OK`; independent verifier passed
all six checks (canonical frames, ordered lifecycle, cursor recovery,
repository commits, getRepo mode, final MST equality).

All ten ordered steps completed in order: fresh_state (relay volume removed,
`listHosts` count 0) → crawl → subscription_open → admission_sync →
public_host_entry → account_activation → activation_lifecycle → first_commit →
offline_five_commit_recovery → manual_sync. Event census exact:
`identity ×1, account ×1, activation sync ×1, commit ×6, manual sync ×1` in
the required kind order; capture helper ran through the final required frame.

## 3. Cursor and forced-sync recovery proof

- Five commits were created while relay→Swan subscription was severed via
  toxiproxy. On reconnect the relay recovered exactly five (relay sequences
  6–10, first delivered 6, upstream cursor 5), with 0 duplicates and 0 gaps.
- Final repository equality: relay and Swan agree on revision
  (`3msqccctvbl22`), commit CID, data CID, and MST digest; `equal: true`.
- Forced `swan firehose force-sync` produced a clean relay resynchronization
  (`manualSync.observed && clean`).

## 4. getRepo?since observation

The pinned relay never issued `getRepo?since`; recovery ran in
`subscribe_repos_cursor_only` mode (connection observations: ordinal 1 live
with nil upstream cursor, ordinal 2 backfill from cursor 5). The plan's
fail-closed `since` branch was therefore never entered and revision-aware
block selection remains unexercised and unimplemented — acceptable per the
plan because the branch is fail-closed, but it is unproven behavior if a
future relay revision starts issuing `since`.

## 5. Full-suite receipt on the exact head tree

`xcrun swift test` (Xcode beta toolchain, Swift 6.4, macOS 27.0 SDK) on the
head tree after the runtime proof: **3,993 XCTest tests + 6 Swift Testing
tests, 0 failures, exit 0**. The only "failed" strings in the log are a
pkg-config search-path warning and an intentional announcer-backoff test log
line. (Four earlier suite invocations died from an unrelated concurrent
process issuing machine-wide `pkill -9 -f swift-frontend`; after it was
stopped and the corrupted `.build/out` was moved aside, the suite ran clean.)

## 6. Environment notes

- The lab's `swan-interop-alpha` volumes had to be recreated before the
  passing run: the 2026-08-08/09 session had initialized the Swan key store
  under an ephemeral secrets directory that no longer exists, so
  `ServeLocalSpaceRuntime` could not open it with any surviving KEK. Old
  volume state was archived outside the repository, volumes were removed, and
  the stack re-initialized freshly from a persistent owner-only secrets
  directory. The scenario's own fresh-state guarantee (relay volume removal)
  was additionally enforced by the runner as designed.

## 7. Still unproven / open gates

- **Independent whole-branch review** of the Phase 4 corrective + Phase 5
  work: OPEN. Phase 5 may not be called complete until it passes.
- Public Linux deployment: no Linux-native execution of the relay acceptance
  scenario; all runtime proof above is macOS/colima (linux/arm64 containers).
- `bsky.network` / real-crawler interoperability: unproven; only the pinned
  Indigo revision was exercised.
- Revision-aware `getRepo?since` handling: unexercised (see §4).
- Live deployment remains a separate activation gate requiring explicit
  authorization.
