# Swan production readiness — execution record (2026-08-12)

Working artifacts from executing
`docs/superpowers/plans/2026-08-12-swan-production-readiness.md`
against
`docs/superpowers/specs/2026-08-12-swan-production-readiness-design.md`.

Copied here from `.superpowers/sdd/`, which is gitignored — so without this copy the
endpoint tables, the recorded disagreements between implementers and reviewers, and the
falsification evidence would exist only on one machine.

`progress.md` is the ledger and the best entry point. Each task has a `-brief.md`
(requirements as handed to the implementer) and a `-report.md` (what was done, why, and
what was deliberately not done).

## Scope

W1 (read path) and W2 (route surface) are complete. **W3 — relay activation — was not
started.** `requestCrawl` is irreversible and is gated on live acceptance plus explicit
authorization.

Task 5, live acceptance against the deployed instance, is also outstanding: the defect
this work fixes was invisible to the test suite for its entire life, so a green suite is
not evidence that it is fixed in production.

## Things a reader should not have to reconstruct

**The original defect.** `PRAGMA data_version` is monotonic, moves on any commit from any
other connection to any table in an account database, and never returns to its prior
value. A cached public-read generation pinned it and nothing ever re-admitted, so one
foreign commit meant permanent 503 until process restart. Observed live on 2026-08-12:
reads returned 200 at 13:04:33 and 503 from 13:10:22 for nearly three hours, with nothing
logged. It cleared with no restart when a record was written.

**Two claims in the design spec are false**, discovered during execution and recorded
rather than silently worked around:

- D10's "the permissioned surface correctly iterates the loaded profile" — it does not;
  `SwanHTTP.swift` hardcodes `PermissionedData0016.methods`. Neither surface was
  profile-driven. Out of scope for Task 10; still open.
- D10's premise that `--profile` could name a public profile — `ProtocolProfile` requires
  a `permissioned-data-` id prefix and fields no public artifact carries. Resolved with a
  sibling `--public-profile` rather than by loosening the type.

**A reviewer finding that was wrong, and was not "fixed".** Two reviewers claimed
`com.atproto.server.confirmEmail` is forwarded to the AppView with its request body.
`SwanXRPCProxyRouter.proxyablePrefixes` is an allow-list that excludes `com.atproto.*` by
design, checked before header parsing and before any body read.
`Tests/SwanHTTPTests/SwanXRPCPipethroughTests.swift:927` already posts
`{"identifier":…,"password":"hunter2"}` to `createSession` and `resetPassword` under an
`atproto-proxy` header naming a resolvable attacker DID document, and asserts 404 with no
upstream contact. A `com.atproto.server.*` wildcard guard was added anyway as defense in
depth — deliberately **not** described as closing a credential leak, because a changelog
claiming a fix for a hole that never existed teaches the next reader that this class was
reachable here and discounts the next real one.

**A false green worth knowing about.** `swift test` exits 1 with *zero* failed test cases
when a target crashes: `SwanXRPCPipethroughTests` was trapping in
`NIOAsyncWriter.deinit`, truncating everything after it while counting-failed-lines
reported 1389 passed / 0 failed. Judge the suite by its exit code and by grepping for
`Some test targets reported failures`. Piping through `tail` reports `tail`'s exit code
and hides it completely.
