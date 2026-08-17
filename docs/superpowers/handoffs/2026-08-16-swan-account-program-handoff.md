# Swan Account Program Handoff — 2026-08-16

## Start here

The authoritative local checkpoint is:

- Workspace: `/Users/joshlacalamito/Developer/Catbird+Petrel/Swan-account-program`
- Integrated commit: `2ca80d27b5dd3cf75d745c135f4b7bb9abab0069`
- Change ID: `wwttrlqmkruszxtxnqvryuonxywlplzr`
- Expected working copy: an empty child of `2ca80d27`
- Push/deploy status: neither authorized nor performed

Before doing work, run:

```bash
cd /Users/joshlacalamito/Developer/Catbird+Petrel/Swan-account-program
jj status
jj log -r '@ | @-' --no-graph -T 'commit_id ++ " " ++ description.first_line() ++ "\n"'
```

Stop if `@-` is not `2ca80d27`, the tree is dirty for unexplained reasons, or another agent already owns the files you need.

## Availability vocabulary

Every handoff document uses these labels:

- **LIVE** — constructed by `SwanCommand`, registered in the production Hummingbird router, and reachable in `swan serve` when configured.
- **INTEGRATED SEAM** — present in the integrated tree and locally tested, but missing production service construction, route registration, worker lifecycle, or enforcement.
- **DEFERRED** — intentionally fail-closed or recorded as unavailable; do not register it merely because an adapter or protocol exists.
- **EVIDENCE COMPLETE** — the named local command passed at this checkpoint.
- **EXTERNAL GATE OPEN** — no live environment evidence exists.

The central truth at this checkpoint is: the account-program foundation is integrated, but the new Milestone 1 account experience is not yet LIVE. Milestone 2 and most of Milestone 3 are INTEGRATED SEAM or DEFERRED. Milestone 4 remains an open operational program.

## Plan resolutions

Read only as deep as needed:

1. [Master resolution](../plans/2026-08-16-swan-account-program-master-resolution.md) — how this program fits Swan, release order, definition of done, and program-wide non-negotiables.
2. [Milestone resolution](../plans/2026-08-16-swan-account-program-milestone-resolution.md) — four release slices, present status, exit gates, and dependency order.
3. [Runtime integration resolution](../plans/2026-08-16-swan-account-program-runtime-integration-resolution.md) — the next executable wave, shared-file ownership, construction order, route order, and focused tests.
4. [Lane resolution](../plans/2026-08-16-swan-account-program-lane-resolution.md) — identity, onboarding, legacy auth, portal, MFA, parity, operations, and integration cards with exact files and residual work.
5. [Original implementation plan](../plans/2026-08-16-swan-account-identity-reference-parity.md) and [approved design](../specs/2026-08-16-swan-account-identity-reference-parity-design.md) — requirements authority when a lower-resolution document omits detail.
6. [Broader Swan production-readiness ledger](../records/2026-08-12-swan-production-readiness/README.md) — upstream Swan state outside this account program, including unstarted relay activation and outstanding deployed-instance acceptance.

If documents disagree, use this priority: approved design → current source at `2ca80d27` → this handoff suite → historical lane report. Lane reports are evidence journals, not runtime-availability claims.

## Current evidence

Passed on the integrated tree:

```text
swift build
swift test
npm run prepare
npm run check
npm test
npm run lint
npm run build
npm run test:browser
docker build --target account-web-build ...
```

The final `swift test` run exited 0. The frontend checks, two Vitest tests, two Playwright tests, lint, and static build passed. The Docker evidence covers the Node-only static frontend stage, not the complete Linux x86_64 Swift runtime image.

Known evidence limits:

- Opt-in 256 MiB CAR/restore/RSS stress tests were skipped.
- `npm audit` reports three low-severity issues.
- No production SMTP, Turnstile, official Bluesky client, federation/AppView, moderation-delivery, backup/restore, key-rotation, load, production configuration, push, or deployment gate ran.
- Direct portal router tests use an injected test service; they do not prove `SwanCommand` composition.

## Next execution wave

The next wave is not “finish every lane independently.” It is a serialized production-composition wave with one integration owner:

1. Add startup configuration and assemble one enforced `SignupPolicy`.
2. Compose authenticated SMTP and the durable signup/outbox/account-creation transaction.
3. Compose legacy sessions/app passwords and their exact XRPC routes.
4. Compose management sessions and a real `SwanAccountPortalServing`; make the static portal reachable.
5. Compose `did:web` reservation/claim/revalidation and connect suspension to token/write admission.
6. Compose MFA factors and step-up enforcement into portal and legacy login.
7. Register reference routes only after exact wire/storage verification; keep import and operations fail-closed until their dependencies exist.
8. Run local Hummingbird acceptance, then Linux, browser, official-client, network, and operational gates in that order.

Do not parallelize edits to `Package.swift`, shared control migrations, `Sources/SwanHTTP/SwanHTTP.swift`, `Sources/swan/SwanCommand.swift`, or `Dockerfile`. Parallel agents may prepare read-only audits, focused tests, or non-overlapping concrete service implementations, but the integration owner alone assembles shared runtime files.

## Handoff completion rule

An agent may mark a surface LIVE only with all four facts:

1. A concrete production service is constructed from durable dependencies.
2. The exact route is registered before guards and proxy fallback.
3. A real Hummingbird test reaches it through the same assembly path used by `SwanCommand`.
4. Restart/revocation/failure behavior is covered where state is durable.

Route existence, protocol conformance, static asset generation, or a pure-adapter unit test is not enough.

## Boundaries with the broader Swan program

This handoff does not supersede the Swan production-readiness ledger. In particular, it does not close W3 relay activation, deployed-instance read-path acceptance, the permissioned-profile hardcoding backlog, or the fatal-shutdown NIO lifecycle hazard recorded there. Account-program agents should not absorb those tasks into a lane unless the user explicitly expands scope. Conversely, a green account-program suite does not authorize relay activation or prove deployed federation behavior.
