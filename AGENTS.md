# Swan agent guidelines

Swan is a Swift-native AT Protocol permissioned-data server and interoperability laboratory implementing space records, repository storage, OAuth authorization, public firehose relaying, and account management.

## Version control safety

The Jujutsu (`jj`) tool owns every colocated working copy in this repository. Git is for read-only inspection only:
- A detached Git `HEAD` is expected. Never attempt to attach it to a branch.
- Never run mutating Git commands (`git commit`, `git checkout`, `git stash`, `git reset`, `git merge`, `git pull`, `git push`).
- Leave all modified files directly in the working copy for `jj` tracking.

## Target architecture and module layout

Swan is organized into distinct Swift Package Manager targets defined in `Package.swift`, plus a Svelte frontend in `web/`:

| Target | Location | Purpose and ownership |
|---|---|---|
| `CATHandleDNS` | `Sources/CATHandleDNS` | C library providing DNS resolution via `resolv` for AT Protocol handle verification. |
| `CBLAKE3` | `Sources/CBLAKE3` | C implementation of the BLAKE3 cryptographic hash function. |
| `SwanCore` | `Sources/SwanCore` | Base models, identifiers (`DID`, `TID`, `NSID`, `ATProtocolDate`), core error types, and logging primitives. |
| `SwanSpacesWire` | `Sources/SwanSpacesWire` | Space wire models and permissioned data method registry. |
| `SwanPublicWire` | `Sources/SwanPublicWire` | Public AT Protocol lexicon wire models and request/response structures. |
| `SwanSpaces` | `Sources/SwanSpaces` | Space semantics, authorization, space commit codec, content-binding MAC verification, space membership, and policies. |
| `SwanStorage` | `Sources/SwanStorage` | Core storage abstractions, storage traits, and repository persistence interfaces. |
| `SwanSQLite` | `Sources/SwanSQLite` | SQLite backend implementation managing the three distinct storage planes with strict permission checking and WAL mode. |
| `SwanAccounts` | `Sources/SwanAccounts` | Account lifecycle, identity resolution (DID/PLC/handle DNS), credentials, MFA factors, passkeys (WebAuthn), and password hashing (libsodium Argon2id / secp256k1). |
| `SwanOAuth` | `Sources/SwanOAuth` | OAuth 2.0 authorization server and client flows, DPoP verification, token minting, and PLC space-credential public-key caching. |
| `SwanAccountExport` | `Sources/SwanAccountExport` | Export and backup serialization for account data, packing records and repositories into CAR archives. |
| `SwanHTTP` | `Sources/SwanHTTP` | Hummingbird 2 HTTP and WebSocket server, XRPC proxy routing, and REST endpoints for the account portal (`/account/api/**`). |
| `SwanInterop` | `Sources/SwanInterop` | Interoperability test harnesses, reference PDS client bindings, and protocol conformance verification. |
| `swan` | `Sources/swan` | Command-line executable (`ArgumentParser`) declaring 8 subcommands (`serve`, `account`, `export`, `backup`, `restore`, `verify`, `lab`, `firehose`). |
| Account portal | `web/` | Svelte 5 / SvelteKit 2 / Vite 7 single-page application for account management, running under strict CSP. |

## Build and test commands

Swan uses Swift Package Manager for backend components and npm for the account portal frontend.

Full compilation (`swift build`) compiles multiple cryptographic and networking targets and typically takes about 68 seconds. Do not assume build steps are instant.

### Backend commands

Build the entire package:
```bash
swift build
```

Run all unit and integration tests:
```bash
swift test
```

Run a specific test suite or test case:
```bash
swift test --filter SwanSQLiteTests
swift test --filter SwanOAuthTests/testDPoPVerification
```

Run the `swan` CLI executable:
```bash
swift run swan <subcommand> [flags]
```

### Account portal commands

The account portal lives in `web/`:
```bash
cd web

# Run TypeScript and Svelte type-checking
npm run check

# Run Vitest unit and integration tests
npm test

# Run Playwright browser tests against a local fixture
npm run test:browser

# Build production static SPA bundle
npm run build
```

## Storage planes and per-account isolation

Swan separates persistent state into three distinct storage planes in the data directory:

1. **Control plane (`control.sqlite`)**: Contains accounts, identity bindings, MFA factors, portal sessions, OAuth tokens, outboxes, actor preferences, crawler announcements, and the resolved-lexicon cache.
2. **Account repository plane (`<did>.sqlite`)**: One dedicated database per provisioned account, stored under `actors/<digest-prefix-2>/<digest>.sqlite` where digest is `SHA256(did)` in hex. Holds public repository records, MST blocks, signed commits, and private space records.
3. **Firehose plane (`firehose.sqlite`)**: Contains public event sequencing, frame logs, and diff CAR archives.

Blobs are stored by content digest under `blobs/`, and encrypted account keys reside in `keys/`.

### Isolation rules

- Per-account repository data must remain isolated in `<did>.sqlite`. Repository records deliberately never flow into `control.sqlite`.
- SQLite connections configure `PRAGMA busy_timeout = 5000`, `PRAGMA journal_mode = WAL`, and `PRAGMA foreign_keys = ON`.
- `SQLiteProtectedPaths` enforces exact POSIX permissions: directories must be `0700` and database files `0600`, owned by the current process EUID. Retained directory file descriptors validate directory confinement before opening absolute database paths.

## Protocol profiles

Swan uses protocol profile pins under `Profiles/*.json` to fix protocol versions, lexicon dependencies, and expected cryptographic hashes.

- The active profile in source is `permissioned-data-0016-2026-08-15` (defined in `Profiles/permissioned-data-0016-2026-08-15.json`).
- Profile pins specify SHA-256 hashes of lexicon definitions (`.lexicons.sha256`) and generated wire code (`.generated-wire.sha256`).
- Regenerating wire types is an explicit profile-pinned operation that uses an external generator workspace. Wire types are never regenerated during a normal `swift build`.

## Generated-code boundary

The directory `Sources/SwanPublicWire/Generated` contains Swift code generated from pinned lexicon schemas by an external Petrel generator workspace.

- Never manually edit files in `Sources/SwanPublicWire/Generated`.
- The CI gate `Scripts/verify-public-wire-generation.sh` ensures generated sources match the pinned profile byte-for-byte.
- To run public wire generation verification locally, provide the generator path via environment variables:
```bash
export PETREL_GENERATOR_ROOT="/path/to/petrel-generator"
export PETREL_GENERATOR_ENTRYPOINT="run.py"
./Scripts/verify-public-wire-generation.sh
```
## Security invariants

When modifying Swan code, you must preserve these security boundaries:

1. **Exposure prevention**: Permissioned records and private space data must never reach a public repository, public blob namespace, server log line, error message, or test fixture.
2. **Read-only space credentials**: Space credentials presented to a repository host are read-only tokens. They are never write capabilities. Repository writes require an OAuth scope covering the authenticated account's own `(space, repo)` pair.
3. **Explicit authorization contexts**: All authorization is structured through `AuthorizationContext` (public, account OAuth, validated delegation exchange, self-only read, space credential, and service contexts). No repository API may accept an unvalidated boolean authenticated flag.
4. **Secret handling**: Secrets (master encryption keys, operator secrets, session tokens, passwords, DPoP private keys, and intermediate key material) must never be accepted via environment variable interpolation. They must be loaded from owner-only (`0600`) files (such as `--operator-secret-file` or `--master-key-file`).
5. **Constant-time error paths and fixed diagnostics**: Authentication and cryptographic validation failure paths must execute in constant time and report errors using fixed diagnostic vocabularies rather than echoing credentials or raw inputs.
6. **Delegation resolution**: Delegation JWTs resolve exclusively through local or pinned `#atproto` keys. Unknown issuers must never trigger dynamic DID, PLC, DNS, or HTTP network lookups.
7. **HTTPS origin integrity authority**: The pinned HTTPS source origin is the exact-content integrity authority for permissioned repository content. Commitments must be checked against origin freshness witnesses with equivocation and stale-recovery detection.
8. **PLC key cache bounded staleness**: The PLC space-credential and delegation public-key cache enforces a bounded 60-second lifetime with active eviction upon failed refresh, mitigating key-revocation latency without creating amplification vectors against the PLC directory.

## Verify-first workflow

The default subcommand for `swan` is `verify`:
```bash
swift run swan
# equivalent to:
swift run swan verify
```

The verify subcommand runs `OfflineProtocolProfileVerifier.verify`, checking that:
- The pinned profile JSON (`Profiles/permissioned-data-0016-2026-08-15.json` by default) is syntactically and semantically valid.
- Checked-in generated wire files in `Sources/SwanSpacesWire/Generated` match their pinned SHA-256 digests without requiring network access.

To verify pinned lexicons against an upstream reference repository:
```bash
swift run swan verify --reference-directory /path/to/atproto-reference
```
