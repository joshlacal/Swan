# Task 1 report — pinned Compose laboratory

## Status

DONE_WITH_CONCERNS. The cache-gated Compose topology, local TLS route,
sanitized scenario artifact path, focused tests, and offline verifier are
implemented. No reference-PDS matrix is claimed as passing.

## Files changed

- `docker-compose.yml` now defines Swan, the pinned reference PDS and PLC,
  Caddy, Mailpit, Toxiproxy plus its one-shot setup client, and the Swift
  scenario runner. Sensitive runtime values use required host environment
  variables only; no secret or account fixture was added.
- `interop/Dockerfile.reference-pds` and
  `interop/Dockerfile.reference-plc` build from the single ignored atproto
  archive after checking SHA-256 `1924ced5c07fb0ae5d8f13f0911bcbd2efc66e9460e463e9d8da10b94e8215ea`.
  They do not clone or curl TypeScript source. `interop/Caddyfile` provides
  only Caddy-local-CA TLS routes for `swan.test` and `pds.test`; the PDS route
  passes through Toxiproxy.
- `interop/fetch-reference.sh` now extracts through a checked staging
  directory and rejects an archive missing PDS inputs.
  `interop/verify-reference.sh` validates the ignored cache without starting
  containers, and `interop/compose.sh` requires that check before invoking
  Docker Compose.
- `Sources/SwanInterop/SwanInterop.swift` adds path-free cache diagnostics and
  a deliberately summary-only scenario-artifact type. `Sources/swan/main.swift`
  changes `swan lab` from an informational command to `validate` and
  `scenario`; the latter accepts no request, response, account, credential, or
  key field.
- `Tests/SwanInteropTests/SwanInteropTests.swift` covers archive-pin failure,
  source-shape validation, and the artifact's credential-free key schema.
  `Scripts/verify-interop-lab.sh` checks the cache, required services/pins,
  local TLS/Toxiproxy route, and no-network-source-fetch Dockerfile invariant.
- `docs/superpowers/plans/swan-spaces-interoperability-alpha.md` records this
  evidence and the explicit non-passing/live-matrix gates.

## Architecture decisions

- The only TypeScript reference-source acquisition is
  `interop/fetch-reference.sh`, which places the archive and extracted tree in
  ignored `.interop-cache`. Compose image builds consume the archive, verify
  it again, and unpack it locally; normal builds do not fetch a source checkout.
- Caddy exposes no cleartext fallback. PLC, Mailpit, and Toxiproxy are not
  Caddy routes; Mailpit and Toxiproxy's admin API are loopback-bound on the
  host. The reference PDS is reached through a named Toxiproxy proxy so the
  runner can introduce fault modes later.
- The scenario runner emits `planned-not-executed` JSON containing only the
  frozen profile/revision pins, scenario name, fault intent, and fixture
  policy. It is intentionally not a protocol-result fixture and cannot be
  evidence of matrix success.

## Verification

All commands ran from `/Users/joshlacalamito/Developer/Catbird+Petrel/Swan`.

| Command | Result |
| --- | --- |
| `swift test --filter SwanInteropTests` | PASS — 13 tests, 0 failures. The build also compiled the `swan` executable. Environment emitted pre-existing `pkg-config`/`libsecret-1` warnings and an Xcode/libsodium deployment-target linker warning. |
| `Scripts/verify-interop-lab.sh` | PASS — verified archive SHA/source shape and all static laboratory invariants. |
| `swift run swan lab validate --root .` | PASS — `LAB PREREQUISITES OK: 3f6c96d5d2d25438bd40fa89d6ecc37865f8e354`. |
| `swift run swan lab scenario --name reference-matrix --fault delayed --fault corrupted --output <temporary-file>` plus a Node JSON key check | PASS — artifact was written and contains no forbidden credential/key field names. |
| `git diff --check` | PASS. |

## Commits

- `be852c5421b34e000dc69bc75851bf66a9753ddd` — implementation and focused
  verification changes for the pinned Compose laboratory.

## Live blockers and unsupported behavior

- Docker and Docker Compose v2 are not installed on this host (`docker:
  command not found`), so neither `docker compose config` nor the container
  build/start/reference-PDS matrix could run. This report does not claim that
  matrix passes.
- A real matrix still needs disposable operator/PDS secrets supplied outside
  the repository, Caddy local-CA trust installed in its client runner, and the
  still-unimplemented permissioned endpoint/credential behavior. The Compose
  topology preserves those gates rather than adding a public fallback.
