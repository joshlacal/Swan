# Swan

Swan is a Swift-native AT Protocol server and permissioned-data interoperability engine. It provides an AT Protocol Personal Data Server (PDS) implementation, an OAuth 2.1 authorization server with DPoP, multi-factor authentication (TOTP and WebAuthn passkeys), a SvelteKit account portal, multi-plane SQLite storage, an XRPC proxy, and protocol testing harnesses.

The active protocol profile is `permissioned-data-0016-2026-10-01`. Its upstream pins and security definitions live in `Profiles/`.

The [October 1 upstream alignment notes](docs/notes/permissioned-data-2026-10-01.md) record the pinned revisions, the lexicon delta, and what is still being implemented. The [September 19 notes](docs/notes/permissioned-data-2026-09-19.md) cover the previous profile.

## Scope and trust boundaries

Swan is developed for protocol interoperability testing and self-hosted environments; it does not claim to be a general-purpose public production PDS on the open federation today.

**October 1 credential cutover:** Space credentials are bound to a P-256 `did:key` (`cnf.kid`) and every exchange and use carries an `atproto-space` HTTP message signature instead of a Spaces DPoP proof. Credentials minted in the DPoP format (`cnf.jkt`) are rejected; clients reacquire through a new delegation exchange. Ordinary OAuth DPoP is unchanged.

**September 19 credential cutover:** Space credentials require a DPoP key at issuance and a fresh proof on each request. Existing bearer space credentials must be replaced through a new delegation exchange. Account OAuth sessions and repository data are retained.

**September 10 alpha migration:** The current profile uses independent read/write policies, `putMember` flags, and access-specific `checkUserAccess` requests. SQLite v23 copies each legacy policy and managing-app choice to both axes and preserves existing members' read/write access. It does not reset account or session data.

This is a breaking wire cutover: update clients that send `policy` or call `addMember` before switching their PDS to this profile. Historical profile tags marked `destructiveBeforeAlpha` describe earlier protocol iteration boundaries, not a requirement to reset current databases. Production qualification for federated multi-tenant deployments remains deferred until the upstream specification stabilizes.

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
