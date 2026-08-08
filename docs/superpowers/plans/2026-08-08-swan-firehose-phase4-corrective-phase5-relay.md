# Swan Firehose Phase 4 Corrective Wave and Phase 5 Relay Acceptance Plan

Date: 2026-08-08
Workspace: `.worktrees/swan-public-federation`
Starting head: `f49fdb69`
Parent design: `docs/superpowers/specs/2026-08-04-swan-public-firehose-design.md`

## Goal

Repair the two load-bearing Phase 4 lifecycle defects found by independent
review, re-establish a deterministic full-suite exit gate, then implement the
Phase 5 pinned-indigo relay lab and its independent acceptance proof.

Phase 5 must not begin until Tasks 1-3 are complete and reviewed.

## Global constraints

- VCS is jj; Git is read-only. Work only in the existing
  `swan-public-federation` jj workspace.
- Use TDD for every production change: capture RED, implement the minimum
  behavior, then capture GREEN.
- Preserve `Profiles/`, `Scripts/public-wire-generation-common.sh`, and
  `Sources/SwanPublicWire/` byte-for-byte unless a separately approved wire
  change becomes unavoidable. The current plan requires no wire change.
- Keep `--enable-public-firehose` default-off.
- Never put permissioned commits, values, credentials, proofs, or raw secret
  material into the public firehose, fixtures, reports, or artifacts.
- Network I/O must remain outside SQLite transactions.
- Control/account lock order is control gate before account gate. No new path
  may acquire the control gate while holding an account gate.
- One mutation owner at a time in the shared workspace. Read-only audits and
  reviews may run in parallel.
- Every task receives a task-scoped review. Critical/Important findings enter
  the fix loop before dependent work proceeds.

## Task 0: Plan and ledger

Commit this plan and create the parent-level SDD ledger. Record the exact
starting head and the reproduced lifecycle idempotence failure.

## Task 1: Deterministic lifecycle replay and durable completion anchors

Fix activation, rotation-identity, reactivation-sync, and manual-sync replay
so the same durable operation/source key converges across later invocation
times, process restarts, and retries after sequencing.

Required behavior:

1. Persisted lifecycle payloads use canonical sorted-key JSON.
2. Lifecycle material time comes from durable operation state, not the retry
   invocation clock. Activation uses the installed account's durable creation
   time; rotation uses the persisted PLC history entry creation time. Status
   transitions continue to use their transaction's durable transition time.
3. Completion leaves a durable, non-pending idempotence anchor for lifecycle
   batches and account firehose source rows. Pending scans, FIFO leasing, and
   sequencer selection must ignore completed anchors. A completed retry must
   neither allocate a new lifecycle generation nor append a new global event.
4. Exact source-key reuse with any non-time semantic difference still fails
   closed as a conflict. Corrupt rows still fail as corruption.
5. Schema migration is restart-safe, recorded in both relevant migration
   ledgers, and tested on reopen. Retained completion anchors must have an
   explicit storage/retention ruling in the completion record.

RED tests must include:

- activation retry with a later invocation time;
- rotation retry with a later invocation time;
- retry after lifecycle/global sequencing, with unchanged generation and
  global event count;
- crash point after lifecycle completion but before activation sync drain;
- repeated execution proving canonical JSON does not flake;
- changed handle/CID/material under the same operation key still conflicts.

Run the focused lifecycle emitter, outbox, sequencer, activation, and rotation
suites. Commit only after all focused suites are green.

## Task 2: Atomic rotation publication and signer-generation fencing

Close both rotation TOCTOU windows:

1. After PLC submission is verified, enqueue the rotation `#identity` batch
   and promote control-plane signing/rotation generations in one control
   transaction using the existing in-transaction lifecycle enqueue primitive.
2. Bind the signer used to prepare a public commit to its signing generation.
   The publication fence must compare that generation with the active control
   row inside the same authorization/generation transaction. A stale signer
   must trigger a bounded retry that re-resolves the signer; it must never fall
   back to a non-emitting mutation.
3. Keep PLC network submission and key-store/network work outside the control
   transaction. Pure signing/key lookup may occur only where the documented
   lock-duration and Sendable constraints are satisfied.

RED tests must use deterministic continuations/barriers, never sleeps:

- park rotation before transaction commit and prove a concurrent publication
  fence cannot pass;
- release rotation and prove signer generation equals lifecycle generation;
- force a stale signer and prove retry re-resolves rather than committing or
  silently suppressing firehose emission;
- drain the log and verify no commit signed by generation g appears after the
  identity announcing generation g+1.

Run focused rotation, mutation coordinator, authorization-fence, lifecycle,
and sequencer suites. Document the final lock ordering.

## Task 3: Phase 4 corrective exit gate

Run, in the foreground and without overlapping SwiftPM invocations:

1. The lifecycle idempotence regression repeatedly (minimum 25 process
   invocations with `--skip-build`).
2. All Task 1-2 focused suites.
3. `xcrun swift build`.
4. The full unfiltered `xcrun swift test` suite.
5. Profile hash and every generated-wire manifest check.
6. Protected-path diff from `a9bbd311` to the corrective head.

Record literal exit codes, per-bundle counts, skips, failures, warnings, and
the exact corrective head. A single flake fails the gate.

## Task 4: Checksum-pinned indigo source foundation

Select a concrete `bluesky-social/indigo` commit from the authoritative
upstream repository and record the archive SHA-256. Add:

- `interop/fetch-reference-indigo.sh`;
- `interop/verify-reference-indigo.sh`;
- static mutation tests for wrong commit, checksum, missing required relay
  files, corrupt archive, and unexpected cache layout;
- dockerignore allowlisting for exactly the pinned archive.

Follow the existing atproto reference pattern: staged download, checksum
verification before extraction, required-file checks, no Dockerfile network
fetch, and `.interop-cache` excluded from commits. This task may use the
network only to fetch the authoritative pinned archive.

## Task 5: Reference relay container and static lab topology

Add `interop/Dockerfile.reference-relay` and a `reference-relay` Compose
service using indigo `cmd/relay` with:

- the checksum-pinned local archive;
- Caddy private-CA trust;
- PLC resolution pointed at `reference-plc`;
- persistent relay data in a named volume;
- an internal healthcheck and no unnecessary host port;
- a dedicated toxiproxy path for relay-to-Swan subscription interruption;
- file/volume-based secrets only if indigo requires credentials;
- `SWAN_PUBLIC_CRAWLERS` wired to the relay and public firehose explicitly
  enabled only inside this lab topology.

Extend `Scripts/verify-interop-lab.sh` and its mutation suite before changing
the topology, so missing pin, trust, health, dependency, network, or secret
constraints fail RED first.

## Task 6: Ordered Phase 5 scenario and independent verifier

Add a fail-fast acceptance runner and artifact validator implementing the
design's exact order:

1. request crawl and wait for relay `listHosts`;
2. wait for Swan-observed `subscribeRepos` connection;
3. create and activate a fresh account;
4. prove `#identity -> #account -> activation #sync`;
5. create a public record and observe the relay's outbound `#commit`;
6. interrupt relay-to-Swan through toxiproxy, create N commits, reconnect,
   and prove exactly-once cursor recovery plus equal `getRepo` state;
7. force manual `#sync` and prove clean relay resynchronization.

The independent verifier must validate binary framing, bounds, DID
resolution, signed commit CID/signature, repo/rev/commit agreement, every CAR
block CID, CAR root, op paths and old/new CIDs, reverse-op `prevData`,
`since`/`prevData`, and final MST equality. Observe whether the pinned relay
sends `getRepo?since`; never label a full snapshot as a diff.

Artifacts are aggregate/digest-only, mode 0600, under ignored evidence paths.
No record value, credential, token, proof, or raw private log is retained.

## Task 7: Phase 5 execution and completion record

Run the static verifier and mutation suite, build the pinned relay image, run
the ordered acceptance scenario, validate its artifact, then rerun the full
Swift suite and protected profile/wire checks on the exact head tree.

Write a completion record that distinguishes:

- local static verification;
- pinned reference-relay runtime proof;
- cursor and forced-sync recovery proof;
- any `getRepo?since` observation;
- anything still unproven for a public Linux deployment or `bsky.network`.

Only a green Task 7 plus a clean whole-branch review may be called Phase 5
complete. Live deployment remains a separate activation gate.
