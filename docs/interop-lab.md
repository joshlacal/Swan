# Interoperability laboratory

This document describes Swan's interoperability laboratory, offline semantic test runner, live network-backed test harnesses, disposable Docker Compose environment, acceptance suites, and protocol wire generation.

## Development and local verification

To build, verify, and run local development commands:

```sh
swift test
swift run swan verify
swift run swan serve --data-directory .swan-data
```

To run an offline semantic test:

```sh
swift run swan lab semantic --output /tmp/swan-semantic.json
```

To run a live host-to-host test (tokens are read from environment variables):

```sh
swift run swan lab live --mode public --body-file ./fixtures/public-put.json \
  --repository did:plc:... --collection app.bsky.feed.post --rkey fixture-1 \
  --producer-auth bearer --consumer-auth bearer \
  --output /tmp/swan-live-public.json
```

## Offline semantic verification

The `lab semantic` subcommand provides an offline local gate. It spins up two independent, durable SQLite roots to exercise replay, write ordering, retention-gap recovery, CAR verification, permissioned credentials, and public and private blob reachability.

The resulting summary artifact is explicitly labeled `swan-durable-to-swan-durable` and serves as local engine validation. It does not constitute proof against the pinned TypeScript reference PDS matrix.

## Network-backed live testing

The `lab live` subcommand is a stateful network-backed test runner that supports two operational modes.

### Public mode

In `public` mode, the runner performs a `com.atproto.repo.putRecord` operation on the producer host and compares the returned CID with a subsequent `com.atproto.repo.getRecord` query executed on the consumer host.

Public live runs can include blob testing with `--blob-file <path>`. Place the literal placeholder `{{BLOB_CID}}` in the JSON record body where the uploaded blob CID belongs. The runner replaces this placeholder only after validating the upload response, and subsequently verifies the blob bytes through `com.atproto.sync.getBlob`. The live blob fixture is bounded to 2 MiB; production HTTP upload and download paths remain streamed.

Disposable test bodies may also use the literal placeholder `{{REPOSITORY_DID}}` in the `repo` field. The runner substitutes the freshly bootstrapped account DID so clean Compose test runs do not require hardcoding generated identities into static fixtures.

### Permissioned mode

In `permissioned` mode:
1. The member writes to its repository using member OAuth and DPoP authentication.
2. The member obtains a delegation token from its home host.
3. The member exchanges the delegation token at the authority for a space read credential.
4. The member reads the repository through the authority using that read-only space credential. Space credentials cannot be used as write capabilities.

By default, the read host is `authority`. Pass `--permissioned-read-host member` when the member repository is hosted on an external implementation, ensuring the credential is verified at the repository host rather than against a local authority copy.

Pass `--provision-space` to configure a disposable authority and member setup when testing against the Compose Swan host.

Use `--producer-auth oauth` for Swan account OAuth; handle and password credentials are read from environment variables, and fresh DPoP proofs are minted per request. The alternative `--producer-auth bearer` mode reads static token values from environment variables and is intended for pinned reference hosts.

The output artifact records only HTTP statuses, CIDs, response digests, and sanitized endpoint events. Request bodies, record values, credentials, and cryptographic proofs are never written to the artifact.

### Incremental sync verification

To verify the terminal incremental-sync page and its reader-bound commit, add `--permissioned-list-ops`. The verifier recomputes the LtHash commitment, content-binding MAC, and author context signature. Provide the repository author's public key through the `SWAN_LAB_PERMISSIONED_COMMIT_KEY` environment variable (as base64url-encoded secp256k1 bytes).

The pinned TypeScript reference implementation returns HTTP 500 when `listRepoOps` includes record values because its joined SQLite query leaves the `space` column ambiguous. To exercise its supported metadata-only form, pass `--permissioned-list-ops-exclude-values`. The artifact records `syncValuesIncluded: false` to make this limitation explicit. Swan's own endpoint is fully value-capable and is covered by its HTTP test suite.

### Stateful matrix verification

To run the stateful permissioned alpha gate, add `--permissioned-stateful-matrix` to `lab live --mode permissioned`. This exercises the full create-and-read flow and requires:
- Explicit write and read CID convergence.
- Matching `listRepoOps` operation CID and revision.
- A verified signed LtHash commitment matching the full-CAR recovery commitment.
- Correctly recovered CAR records.

The stateful matrix automatically enables terminal verifiers and requires value-bearing incremental sync pages. The `--permissioned-list-ops-exclude-values` flag is a separate metadata-only compatibility smoke test for the stock pinned TypeScript branch; it records `syncValuesIncluded: false` and must not be combined with `--permissioned-stateful-matrix`.

The default Compose service uses the unmodified, byte-for-byte pinned TypeScript image. Because that image lacks a `getRepo` implementation and has an unusable value-bearing `listRepoOps` query, it cannot independently satisfy the recovery requirements of the stateful matrix. To run this gate:
1. Populate the pinned cache.
2. Execute `interop/compose-recovery.sh`.

The wrapper applies a checksum-pinned recovery overlay to a disposable image without modifying `.interop-cache` or the reference source checkout. Results from this overlay represent qualified recovery evidence, not evidence of upstream image support.

### Full-CAR recovery verification

Pass `--permissioned-get-repo` to stream and verify the full two-root recovery CAR from the selected permissioned repository host. It uses the explicit repository-author key pin and records only the HTTP status, record count, and commitment in the artifact.

## Public repository import testing

The `lab import-public` subcommand streams a reference host's `com.atproto.sync.getRepo` response into durable per-account SQLite staging and publishes it only after signature, MST, CID, and revision CAS verification:

```sh
SWAN_LAB_PUBLIC_REPO_KEY="$PUBLIC_REPO_KEY" \
swift run swan lab import-public --remote-url https://pds.test \
  --data-directory .swan-data --did did:plc:... \
  --commit-key-algorithm secp256k1 --output /tmp/swan-public-import.json
```

The public import command requires an operator-supplied verification key; it does not resolve remote DID/PLC keys implicitly. Output artifacts are sanitized and contain no record values, tokens, passwords, or private key material.

For the disposable Compose laboratory, `--resolve-commit-key` enables an explicit pinned PLC resolver. This is permitted only with the laboratory PLC origin and host allowlist; production deployments must provide an operator-approved key resolver.

Pass `--promote-public-blobs` to fetch each raw-CID blob referenced by the imported public records using `com.atproto.sync.getBlob?did=<repo-did>&cid=<cid>`, verify its SHA-256 CID, and adopt it into the receiver's public blob namespace. Promotion runs after the CAR commit is durable and records only `promotedBlobCount` in the artifact.

## Dynamic delegation and key discovery

The cross-host TypeScript permissioned smoke test uses the pinned reference PDS as the member repository and Swan as the authority. It can operate using an operator-supplied static delegation public-key pin or via the allowlisted laboratory PLC resolver. A static-pin run proves credential issuance and repository-host verification, but does not prove dynamic DID/PLC discovery.

Operators can configure delegation-key discovery explicitly in a notification configuration file without forcing the request path to select an authority:

```json
{
  "delegationKeyPLC": {
    "origin": "http://reference-plc:2582",
    "laboratory": true,
    "allowlistedHost": "reference-plc",
    "allowedIssuers": ["did:plc:abcdefghijklmnopqrstuvwx"]
  }
}
```

The issuer list is required, duplicate-free, and DID-validated. Swan applies bounded PLC state and audit verification, durable key-continuity checkpoints, negative caching, and process-wide lookup admission. Local account keys and explicit pins always take precedence, and failed remote lookups fail closed. The checked-in Compose notification configuration does not enable this field; production origins must use HTTPS, and laboratory HTTP is restricted to configured allowlisted hosts.

### Dynamic delegation acceptance harness

To test the dynamic resolution path against a running disposable Compose project, run the dynamic delegation acceptance script:

```sh
export SWAN_INTEROP_SECRETS_DIR=/absolute/path/to/owner-only-lab-secrets
export SWAN_DYNAMIC_DELEGATION_PROJECT=disposable-compose-project
export SWAN_DYNAMIC_DELEGATION_OUTPUT=/absolute/path/to/sanitized-result.json
Scripts/run-reference-member-dynamic-delegation-acceptance.sh
```

The harness creates a fresh reference PDS account, rebuilds the project-scoped Swan image, temporarily replaces Swan with an ephemeral resolver configuration, runs the permissioned write/credential/read workflow, restores the original container, and writes a sanitized artifact.

Set `SWAN_DYNAMIC_DELEGATION_NO_BUILD=1` if the project image already reflects the current checkout. The harness never modifies the checked-in notification configuration and restores the Compose Swan container on success, failure, or interruption.

To include value-bearing incremental sync and two-root full-CAR recovery in the cross-host verification:
1. Start the disposable project with the checksum-pinned recovery overlay.
2. Run the acceptance script with stateful mode enabled:

```sh
SWAN_INTEROP_SECRETS_DIR=/absolute/path/to/owner-only-lab-secrets \
SWAN_DYNAMIC_DELEGATION_PROJECT=disposable-recovery-project \
SWAN_DYNAMIC_DELEGATION_STATEFUL=1 \
SWAN_DYNAMIC_DELEGATION_NO_BUILD=1 \
Scripts/run-reference-member-dynamic-delegation-acceptance.sh
```

This derives public `did:key` verification material from the lab PLC audit and produces a sanitized, owner-only artifact. It provides qualified evidence for the recovery overlay while preserving the unmodified stock TypeScript image.

To test the reverse-authority topology, set `SWAN_DYNAMIC_DELEGATION_DIRECTION=authority`:

```sh
SWAN_INTEROP_SECRETS_DIR=/absolute/path/to/owner-only-lab-secrets \
SWAN_DYNAMIC_DELEGATION_PROJECT=disposable-compose-project \
SWAN_DYNAMIC_DELEGATION_DIRECTION=authority \
SWAN_DYNAMIC_DELEGATION_NO_BUILD=1 \
Scripts/run-reference-member-dynamic-delegation-acceptance.sh
```

This assigns the space authority role to the disposable TypeScript account, keeps the provisioned Swan account as the member, and requires Swan to resolve the authority's credential key from the allowlisted PLC audit.

## Disposable Compose interoperability lab

The Compose lab environment does not accept secrets through Compose environment interpolation.

### Secrets preflight

Before starting the lab with `interop/compose.sh`, create a directory outside this repository with permissions set to `0700`. Inside this directory, create the following 15 regular files with permissions set to `0600`:

- `oauth-server-key`: URL-safe Base64 encoding of a 32-byte key.
- `account-kek`: URL-safe Base64 encoding of a 32-byte key.
- `operator-secret`: Secret string for management authorization.
- `authority.did`: Canonical DID or the string `generate` for dynamic creation.
- `authority.handle`: Canonical handle for the authority account.
- `authority.password`: Account password for the authority.
- `member.did`: Canonical DID or the string `generate` for dynamic creation.
- `member.handle`: Canonical handle for the member account.
- `member.password`: Account password for the member.
- `public-repo-revision`: Valid repository-v3 revision string.
- `pds-dpop-secret`: PDS DPoP key secret.
- `pds-jwt-secret`: PDS JWT signing secret.
- `pds-admin-password`: PDS administrative password.
- `pds-repo-signing-key`: PDS repository signing key material.
- `pds-plc-rotation-key`: PDS PLC rotation key material.

When `authority.did` or `member.did` contains `generate`, the bootstrap process creates a PLC-backed identity, writes the generated DID into the data volume, and requires that DID on subsequent boots. All files must be non-empty.

Set `SWAN_INTEROP_SECRETS_DIR` to the absolute path of this directory and start the lab:

```sh
export SWAN_INTEROP_SECRETS_DIR=/absolute/path/outside/this/repository
./interop/compose.sh up
```

The script rejects in-repository paths, symlinks, non-owner files, and files with group or world permissions before invoking Docker.

### Container secret isolation

Host file UIDs often differ from container UIDs (`swan` and `node`). The network-isolated `swan-secrets-init` service copies the validated host files into named Docker volumes with mode `0400` and container ownership:
- `swan-bootstrap` receives bootstrap credentials.
- `swan` receives runtime secrets (`oauth-server-key`, `account-kek`, `email-proof-key`) from the `swan-runtime-secrets` volume.
- `operator-secret` is copied into the separate `swan-operator-secrets` volume. The base topology never mounts this volume; only the reference-relay overlay mounts it at `/run/secrets/swan-operator` when `--management-port` is enabled.
- Reference PDS secrets are loaded internally through an unprivileged wrapper.

To clean up secrets and reset named volumes when upgrading or restarting an existing lab:

```sh
./interop/compose.sh down -v
```

### Startup sequence

The lab container lifecycle executes in five ordered stages:

1. `swan-secrets-init` and `swan-data-init` initialize secret and data volumes with correct ownership and permissions without network access.
2. Unprivileged `swan-bootstrap` creates disposable authority and member accounts using the reference PLC prepare/activate lifecycle, storing generated identities and genesis records in the Swan data volume.
3. Unprivileged `swan` starts behind Caddy with local-space interop enabled. Its healthcheck polls `/health`.
4. The pinned reference PLC and PDS start, gating readiness on `/_health` and `/xrpc/_health` probes.
5. Caddy initializes its local certificate authority (CA), copying the root certificate into a shared read-only trust volume (`caddy-ca-ready`).

### Ingress and network isolation

Caddy bound to loopback port 443 serves as the sole external host ingress, managing the internal network aliases `swan.test` and `pds.test`. Mailpit and Toxiproxy do not expose public host ports.

The Swan container runs with a read-only root filesystem; only a bounded `/tmp` tmpfs mount and the named data volume are writable.

Topology constraints are enforced statically by `Scripts/verify-interop-lab.sh` and tested for regressions with `Scripts/test-verify-interop-lab.sh`.

### Notification configuration and PLC persistence

The lab loads `interop/notification-config.json` from the `interop-notification-config` Dockerfile build stage via the `swan-notification-config-init` service, mounting it read-only at `/etc/swan/interop`.

The notification configuration routes the fixed restart-scenario DID to `http://localhost:3001` (pinned to `127.0.0.1`) and configures the laboratory PLC origin (`reference-plc`) with an explicit host allowlist.

The reference PLC service persists validated operations to an atomically replaced `reference-plc-data` volume and replays them on boot using `@did-plc/server`. To test PLC persistence independently:

```sh
interop/test-reference-plc-persistence.sh
```

## Notification restart acceptance harness

To verify outbox recovery and write notification delivery across process restarts:

```sh
export SWAN_INTEROP_SECRETS_DIR=/absolute/path/outside/this/repository
Scripts/run-notification-restart-acceptance.sh
```

The scenario executes the following sequence:
1. Installs two local accounts while Swan is stopped.
2. Executes a permissioned write via OAuth using a seed process with notifications disabled.
3. Verifies a pending outbox record in SQLite and terminates the seed process.
4. Starts an intercepting loopback proxy.
5. Launches Swan with outbox delivery enabled.
6. The proxy intercepts `notifyWrite`, drops the first successful delivery acknowledgement, and forwards the second attempt.
7. Verifies that the sender outbox drains completely in SQLite while the authority records exactly one receipt.
8. Restarts Swan without the proxy and verifies consistent state.

The harness prints no credentials, tokens, or private payload values, and removes temporary containers and volumes upon exit.

## Clean-cache acceptance harness

To execute a complete clean-cache build and test run in an isolated scratch directory on macOS:

```sh
Scripts/run-clean-cache-acceptance.sh --mode macos
```

To run clean-cache acceptance on Linux:

```sh
export SWAN_INTEROP_SECRETS_DIR=/absolute/path/outside/this/repository
Scripts/run-clean-cache-acceptance.sh --mode linux --wait-timeout 240
```

Options:
- `--reference-variant recovery`: Builds the Compose suite using the recovery reference overlay instead of the default pinned image.
- `--scratch-path <path>`: Specifies an explicit directory for the scratch build rather than an ephemeral temporary path.

### Stress testing

Large-scale CAR stress tests are disabled by default. To enable them during test runs, set the following environment variables:

```sh
export SWAN_CAR_256M_STRESS=1
export SWAN_RUN_256MIB_CAR_STAGING=1
export SWAN_RUN_256MIB_PUBLIC_GET_REPO=1
```

## Pinned wire generation

Swan compiles using pre-generated wire source files checked into `Sources/SwanSpacesWire/Generated`. Standard builds do not download lexicons or execute code generators.

To verify that the checked-in wire sources match the pinned protocol profile:

```sh
PETREL_GENERATOR_ROOT=/path/to/Petrel-swan-generator \
  ./Scripts/verify-wire-generation.sh
```

To regenerate the wire source files when updating protocol profiles:

```sh
PETREL_GENERATOR_ROOT=/path/to/Petrel-swan-generator \
  ./Scripts/regenerate-wire.sh
```

Set `PETREL_GENERATOR_ROOT` to the path of an isolated, reviewed checkout of the Petrel generator source workspace. Wire generation scripts do not fall back to ambient sibling directories and perform no network requests; all reference lexicons are loaded from `.interop-cache/`. Checksum verification is handled by `Scripts/sha256.sh`.

Swan ensures that permissioned records never enter public repositories, public blob storage, log output, or test fixtures. Permissioned data is access-controlled rather than end-to-end encrypted; a hosting PDS remains within the trust boundary.
