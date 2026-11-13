# Swan

Swan is a Swift-native AT Protocol server and permissioned-data interoperability engine. It provides an AT Protocol Personal Data Server (PDS) implementation, an OAuth 2.1 authorization server with DPoP, multi-factor authentication (TOTP and WebAuthn passkeys), a SvelteKit account portal, multi-plane SQLite storage, an XRPC proxy, and protocol testing harnesses.

The active protocol profile is `permissioned-data-0016-2026-11-12`. Its upstream pins and security definitions live in `Profiles/`.

The [November 12 migration notes](docs/migrations/2026-11-12-spaces.md) record the pinned revisions, wire cutover, and upgrade constraints. The [October 29 notes](docs/migrations/2026-10-29-spaces.md) cover the previous profile.

## Scope and trust boundaries

Swan is developed for protocol interoperability testing and self-hosted environments; it does not claim to be a general-purpose public production PDS on the open federation today.

The November 12 alpha is a breaking wire cutover: deploy Swan, syncers, managing apps and repository hosts together. Old method names, notification registration, STAR framing and response-MAC headers are intentionally unsupported. Account and repository data are retained, but syncers must register again through `authorizeSpaceSync`; see the migration notes above.

Permissioned data in Swan is access-controlled rather than end-to-end encrypted. A hosting PDS remains inside the trust boundary and is responsible for enforcing read and write capabilities across spaces and repositories.
## Architecture

Swan is organized around the following subsystems:

- **HTTP runtime:** Built on Hummingbird 2 with structured concurrency and non-blocking I/O.
- **Multi-plane SQLite storage:**
  - `control.sqlite`: Account records, identity bindings, MFA factors, web portal sessions, OAuth tokens, and write notification outboxes.
  - `<did>.sqlite`: Per-account databases containing public records, Merkle Search Tree (MST) blocks, signed commits, and private space records.
  - `firehose.sqlite`: Event sequencing, event frames, and diff CAR slices for WebSocket streaming.
  - All SQLite databases operate in WAL mode with `PRAGMA foreign_keys = ON`.
- **Blob and key storage:** Content-addressed public and private blobs are stored in `blobs/`. Encrypted key envelopes protected by a Key Encryption Key (KEK) reside in `keys/`.
- **Authentication and identity:** OAuth 2.1 with DPoP, scoped app passwords, Argon2id password hashing, and second-factor authentication using TOTP and WebAuthn passkeys.
- **Account portal:** SvelteKit frontend in `web/`, served at `/account` and styled with daisyUI.
- **XRPC proxy:** Namespace-based proxy routing for `app.bsky.*`, `chat.bsky.*`, `tools.ozone.*`, and moderation endpoints, with destination dispatch via the `atproto-proxy` header.

## Build and run

### Prerequisites

- Swift 6.1 or later, as declared by `Package.swift` (`swift-tools-version: 6.1`)
- macOS 15 or later, or Linux
- libsodium, discovered through `pkg-config`. Install it with `brew install libsodium` or `apt install libsodium-dev`.

### Local instance setup

1. Build the project:
   ```sh
   swift build
   ```

2. Verify the offline protocol profile:
   ```sh
   swift run swan verify
   ```

3. Install a local test account:
   ```sh
   echo "test-password-123" > /tmp/swan-test-password.txt
   chmod 0600 /tmp/swan-test-password.txt

   swift run swan account install-local \
     --data-directory .swan-data \
     --did did:plc:example1234567890123456 \
     --handle user.test \
     --revision 3jxyz00000000 \
     --password-file /tmp/swan-test-password.txt
   ```

4. Start the server:
   ```sh
   swift run swan serve --data-directory .swan-data --port 3000 --host 127.0.0.1
   ```

## Documentation

- [Documentation index](docs/README.md): Complete index of all technical documentation and specifications.
- [Modular architecture](docs/architecture.md): Runtime model, multi-plane storage architecture, MST repository engine, and event sequencing.
- [Deployment guide](docs/deployment-guide.md): Production deployment with Docker and systemd, secrets management, and reverse proxy configuration.
- [Operational runbook](docs/operational-runbook.md): Service health checks, encrypted backup and restore, key rotation, and SQLite maintenance.
- [API reference](docs/api-reference.md): XRPC method catalog, OAuth 2.1 discovery and token endpoints, and account portal REST APIs.
- [Server surfaces](docs/server-surfaces.md): Foreign handle resolution, OAuth browser styling, account portal configuration, and XRPC proxy routing.
- [Interoperability laboratory](docs/interop-lab.md): Offline semantic testing, live network harnesses, and Docker Compose testbed.
- [Forum test vehicle](docs/forum-lab.md): Minimal multi-writer forum vehicle, subcommands, and thread merge ordering rules.
- [Threat boundaries](docs/threat-boundaries.md): Security model, cryptographic accumulators, and PLC resolution caching.
- [OAuth scope limits](docs/oauth-scope-limits.md): Input budgets, grant limits, and protocol admission rules.
- [Spaces open interop](docs/notes/2026-10-01-spaces-open-interop.md): The opt-in `--enable-spaces-open-interop` posture and every behaviour it changes.

## License

MIT License. See [LICENSE](LICENSE).
