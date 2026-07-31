# Swan

Swan is a Swift-native AT Protocol permissioned-data interoperability laboratory.
It intentionally starts with protocol fidelity, durable local semantics, and
cross-implementation fixtures rather than attempting to be a public production
PDS on day one.

The active profile is `permissioned-data-0016-2026-07-30`. Its upstream pins
and security boundary live in `Profiles/`.

## Development

```sh
swift test
swift run swan verify
swift run swan serve --data-directory .swan-data
swift run swan lab semantic --output /tmp/swan-semantic.json
# A real host-to-host run (tokens stay in environment variables):
swift run swan lab live --mode public --body-file ./fixtures/public-put.json \
  --repository did:plc:... --collection app.bsky.feed.post --rkey fixture-1 \
  --producer-auth bearer --consumer-auth bearer \
  --output /tmp/swan-live-public.json
```

`lab semantic` is an offline local gate: it uses two independent durable
SQLite roots to exercise replay, ordering, retention-gap recovery, CAR
verification, permissioned credentials, and public/private blob reachability.
Its summary artifact is explicitly labeled `swan-durable-to-swan-durable` and
does not count as the pinned TypeScript PDS matrix.

`lab live` is the stateful network-backed runner. In `public` mode it performs
`repo.putRecord` on the producer and compares its returned CID with a
subsequent `repo.getRecord` on the consumer. In `permissioned` mode the member
writes its repository with member OAuth/DPoP, obtains a delegation, exchanges
it at the authority for a space credential, and reads the member repository
through the authority with that read-only credential. Space credentials are
never used as write capabilities. The default read host is `authority`; pass
`--permissioned-read-host member` when the member repository is hosted by a
different implementation, so the credential is verified at the repository
host rather than against a second authority-local copy. Add
`--provision-space` for a disposable
authority/member setup when running against the Compose Swan host. Use
`--producer-auth oauth` for Swan account OAuth; the handle/password values are
read from the environment and fresh DPoP proofs are minted per request.
`bearer` mode reads only the named token environment variable and is useful for
a pinned reference host. The output artifact keeps only statuses, CIDs,
response digests, and sanitized endpoint events; request bodies, values,
credentials, and proofs are never written.

To verify the terminal incremental-sync page and its reader-bound commit, add
`--permissioned-list-ops`. The verifier recomputes the LtHash commitment,
content-binding MAC, and author context signature; provide the repository
author's public key through `SWAN_LAB_PERMISSIONED_COMMIT_KEY` (base64url
secp256k1 bytes). The pinned TypeScript revision currently returns HTTP 500
when `listRepoOps` includes values because its joined SQLite query leaves
`space` ambiguous. Its supported metadata-only form can be exercised with
`--permissioned-list-ops-exclude-values`; the artifact records
`syncValuesIncluded: false` so this limitation is visible rather than hidden.
Swan's own endpoint remains value-capable and is covered by its HTTP tests.

For the stateful permissioned alpha result, add
`--permissioned-stateful-matrix` to `lab live --mode permissioned`. It runs
the existing create/read flow and requires explicit write/read CID convergence,
the matching `listRepoOps` operation CID and revision, a verified signed
LtHash commitment that matches the verified full-CAR recovery commitment,
and recovered CAR records before the artifact passes.
It automatically enables both terminal verifiers; use
`--permissioned-list-ops-exclude-values` for the pinned TypeScript branch's
metadata-only incremental page.

The default Compose service intentionally remains the byte-for-byte pinned
TypeScript image. That image currently has no `getRepo` implementation and
its value-bearing `listRepoOps` query is not usable, so it cannot by itself
prove the recovery half of this stateful matrix. For that explicit lab gate,
populate the pinned cache first and invoke `interop/compose-recovery.sh`; the
wrapper applies the checksum-pinned recovery overlay to a disposable image
without changing `.interop-cache` or the reference source checkout. Treat
results from that overlay as qualified recovery evidence, not as evidence
that the unmodified upstream image supports those endpoints.

Add `--permissioned-get-repo` to stream and verify the full two-root recovery
CAR from the selected permissioned repository host. It uses the same explicit
repository-author key pin and records only the HTTP status, record count, and
commitment in the artifact.

Public live runs can include `--blob-file <path>`. Put the literal
`{{BLOB_CID}}` wherever the uploaded blob CID belongs in the JSON record body;
the runner replaces that placeholder only after the upload response is
validated, then verifies the blob bytes through `sync.getBlob`. The live blob
fixture is intentionally bounded to 2 MiB; production HTTP upload/download
paths remain streamed. A disposable body may also use the literal
`{{REPOSITORY_DID}}` for its `repo` field; the runner replaces it with the
freshly bootstrapped account DID so clean Compose runs do not depend on a
generated identity being checked into a fixture.

For public repository handoff testing, `lab import-public` streams the pinned
reference host's `com.atproto.sync.getRepo` response into durable per-account
SQLite staging and publishes it only after signature, MST, CID, and revision
CAS verification:

```sh
SWAN_LAB_PUBLIC_REPO_KEY="$PUBLIC_REPO_KEY" \
swift run swan lab import-public --remote-url https://pds.test \
  --data-directory .swan-data --did did:plc:... \
  --commit-key-algorithm secp256k1 --output /tmp/swan-public-import.json
```

The public import command requires an operator-supplied verification key; it
does not resolve remote DID/PLC keys implicitly. Its output is sanitized and
contains no record values, tokens, passwords, or private key material.

For the disposable Compose laboratory, `--resolve-commit-key` enables the
explicit pinned PLC resolver. It is permitted only with the laboratory PLC
origin and host allowlist; production runs must provide an operator-approved
key resolver instead. Add `--promote-public-blobs` to fetch each raw-CID blob
referenced by the imported public records through
`com.atproto.sync.getBlob?did=<repo-did>&cid=<cid>`, verify its SHA-256 CID,
and adopt it in the receiver's public blob namespace. Promotion runs after
the CAR commit is durable and reports only `promotedBlobCount` in the
sanitized artifact.

The cross-host TypeScript permissioned smoke uses the pinned reference PDS as
the member repository and Swan as the authority. Swan's fail-closed remote key
policy requires an operator-supplied static delegation public-key pin for that
run (via the server's `--notification-config`); the pin contains verification
material only and must remain outside the repository. This proves credential
issuance and repository-host verification, but is not a substitute for the
full TypeScript semantic matrix or dynamic DID/PLC/JWKS discovery.

## Disposable Compose interoperability lab

The lab accepts no secret values through Compose environment interpolation.
Before invoking `interop/compose.sh`, create an owner-only directory **outside
this repository**, set it to mode `0700`, and create these owner-only regular
files at mode `0600`:

- `oauth-server-key`
- `account-kek`
- `operator-secret`
- `authority.did`
- `authority.handle`
- `authority.password`
- `member.did`
- `member.handle`
- `member.password`
- `public-repo-revision`
- `pds-dpop-secret`
- `pds-jwt-secret`
- `pds-admin-password`
- `pds-repo-signing-key`
- `pds-plc-rotation-key`

Both `oauth-server-key` and `account-kek` contain URL-safe Base64 encodings of
32-byte keys. The account identity files normally contain canonical DIDs/handles.
For a fresh disposable lab, either DID file may instead contain exactly
`generate`: bootstrap then creates the PLC-backed identity, records the generated
DID in the durable data volume, and requires that same DID on later starts. This
mode is explicit and is not accepted for production provisioning. `public-repo-revision`
must be a valid repository-v3 revision. PDS files
use the formats required by the pinned reference PDS; all files must be
nonempty even though this preflight intentionally never prints their values.

Set `SWAN_INTEROP_SECRETS_DIR` to that directory's absolute path. The wrapper
rejects in-repository paths, symlinks, non-owner files, and group/other
permissions before Docker is invoked:

```sh
export SWAN_INTEROP_SECRETS_DIR=/absolute/path/outside/this/repository
./interop/compose.sh up
```

Host file UIDs normally do not match the image's `swan` or `node` UIDs. The
network-isolated `swan-secrets-init` service therefore copies the validated
external files into named volumes with container ownership and mode `0400`.
This root service runs only the dedicated copy wrapper; it never invokes the
Swan executable. `swan-bootstrap` receives the bootstrap-only copy, while the
long-running `swan` service receives only `oauth-server-key` and `account-kek`.
The reference PDS loads its prepared files internally through an unprivileged
wrapper, so secret values never appear in the Compose model.

Startup is ordered as follows:

1. `swan-secrets-init` and `swan-data-init` prepare owner-correct secret/data
   volumes without network access.
2. Unprivileged `swan-bootstrap` creates disposable authority and member
   accounts through the reference PLC's prepare/activate lifecycle. It uses a
   static handle proof only for this local laboratory bootstrap; production
   account activation continues to use network handle verification. The
   generated PLC-backed identities and signed public genesis records are
   durable under the Swan data volume.
3. Unprivileged `swan` starts with local-space interop enabled behind Caddy;
   its healthcheck performs a bounded HTTP request to `/health`, so an
   executable that has not bound the listener cannot satisfy Compose readiness.
4. The pinned reference PLC and PDS must answer their own `/_health` and
   `/xrpc/_health` endpoints before the reference PDS or Toxiproxy setup is
   considered ready.
5. Caddy creates its local CA; its healthcheck gates `caddy-ca-ready`, which
   copies the public root certificate into an unprivileged read-only trust
   volume.

Caddy on loopback port 443 is the sole host ingress and owns the in-network
`swan.test` and `pds.test` aliases. Mailpit and Toxiproxy have no published
ports. The Compose `scenario-runner` remains an inert trust-handoff service;
stateful runs use an explicit one-shot `docker run` on the lab network so the
runner's credentials and request bodies are never part of the Compose model.
The same one-shot path runs the sanitized six-fault endpoint matrix.

`Scripts/verify-interop-lab.sh` statically enforces this topology, and
`Scripts/test-verify-interop-lab.sh` pressure-tests the verifier with unsafe
privilege, dependency, interpolation, mount, runner, and readiness mutations.
Normal Compose also loads the checked-in
`interop/notification-config.json` from the pinned Swan image. Keeping it in
the image avoids non-portable host file binds while preserving a read-only
runtime path. The Swan container root filesystem is read-only; only its bounded
`/tmp` tmpfs and named data volume are writable. Normal Compose explicitly
enables durable notification delivery, so startup installs the outbox recovery
service instead of merely loading receiver verification material.

The checked-in notification file is strictly disposable lab routing plus public
verification configuration. It has no secret, private-key, password, token,
recipient binding, or static key fields. Its sole authority route binds the
fixed restart-scenario DID and service-JWT audience to
`http://localhost:3001`, with the final peer pinned to `127.0.0.1`; there is no
wildcard or request-controlled destination. Its credential-key resolver uses
the pinned laboratory PLC origin (`reference-plc`) with an explicit host
allowlist. Production or cross-host notification pins remain an
operator-supplied configuration outside this repository.

### Notification crash/restart acceptance

Run the durable outbox closure against a disposable Compose project:

```sh
export SWAN_INTEROP_SECRETS_DIR=/absolute/path/outside/this/repository
Scripts/run-notification-restart-acceptance.sh
```

The scenario installs two disposable local accounts while Swan is stopped,
commits one real permissioned write through OAuth under a delivery-disabled
seed process, verifies one opaque pending outbox row, and kills that process.
It starts and waits for a loopback proxy before launching a recovery-enabled
Swan process with the normal Compose image, volumes, config, and delivery flag.
The proxy forwards `notifyWrite`, discards the first successful
acknowledgement, and returns the second. It must observe exactly two successful,
byte-identical forwards; this is not a claim that the deleted sender row
retains an exact attempt count. Read-only SQLite assertions require the sender
outbox to converge to empty while the authority retains exactly one receipt
and one writer-state effect. A final start of the normal Compose Swan service
must preserve that state without the proxy.

The private record value and OAuth artifact exist only in container tmpfs. The
proxy retains only counts and SHA-256 request digests, and the script prints no
credentials, service-auth headers, event IDs, request bodies, or permissioned
values. It tears down its uniquely named project and volumes on exit. Static
verification proves the configuration and scenario contract; this acceptance
is live Compose evidence only after the command itself completes successfully.

### Clean-cache acceptance

Run the reproducibility gate from a clean SwiftPM scratch path on macOS:

```sh
Scripts/run-clean-cache-acceptance.sh --mode macos
```

On Linux, provide the same external owner-only secret directory used for the
lab. The runner copies the source into a disposable scratch directory, fetches
the pinned reference archive into that copy, runs the static and Swift suites
there, then rebuilds the Compose images with `--no-cache` and waits for all
required services. Its generated Compose project is torn down with volumes at
the end; the scratch directory is retained for inspection.

```sh
export SWAN_INTEROP_SECRETS_DIR=/absolute/path/outside/this/repository
Scripts/run-clean-cache-acceptance.sh --mode linux --wait-timeout 240
```

To retain the exact scratch location in CI, supply a path that does not yet
exist:

```sh
Scripts/run-clean-cache-acceptance.sh --mode macos \
  --scratch-path /tmp/swan-clean-cache-macos
```

Prior Linux Compose artifacts cover health checks, PLC-backed account bootstrap,
Swan-to-Swan transport, public/private isolation, and endpoint-probe fault
scenarios. They are not a clean-cache run of the current working copy and are
not evidence of full Swan-to-TypeScript semantic convergence. The pinned
TypeScript host also has disposable public-record and cross-host permissioned
transport probes; those sanitized artifacts do not close the value-bearing sync,
compaction-gap, reverse-authority, or cross-implementation OAuth gates.

The current macOS clean-cache run completed the full Swift suite with zero
failures. Its opt-in 256 MiB stress tests remain explicitly skipped unless
`SWAN_CAR_256M_STRESS=1`, `SWAN_RUN_256MIB_CAR_STAGING=1`, and
`SWAN_RUN_256MIB_PUBLIC_GET_REPO=1` are supplied.

### Pinned wire generation

Normal Swift builds use only the checked-in `Sources/SwanSpacesWire/Generated`
sources; they do not download lexicons or invoke Petrel. Regeneration is an
explicit, profile-pinned operation. Materialize the pinned reference archive
first (so `.interop-cache/atproto-3f6c96d5d2d25438bd40fa89d6ecc37865f8e354`
exists), then select the reviewed Petrel generator workspace explicitly:

```sh
PETREL_GENERATOR_ROOT=/Users/joshlacalamito/Developer/Catbird+Petrel/Petrel-swan-generator \
  ./Scripts/verify-wire-generation.sh

# This is the intentional mutating form. It validates the profile, c2a1cdbe
# generator parent, server-contract capability, and entrypoint before writing.
PETREL_GENERATOR_ROOT=/Users/joshlacalamito/Developer/Catbird+Petrel/Petrel-swan-generator \
  ./Scripts/regenerate-wire.sh
```

`verify-wire-generation.sh` regenerates into a disposable temporary directory
and requires a byte-for-byte empty diff against the checked-in Swift output, so
it is the CI gate. Neither command falls back to the ordinary `../Petrel`
checkout. CI must materialize the pinned reference archive and the isolated
Petrel generator source locally; the scripts perform no network access.
Checksum validation goes through `Scripts/sha256.sh`, which uses `sha256sum`
when available and otherwise macOS `shasum -a 256`.

`Swan` never places permissioned records into a public repository, public blob
namespace, log line, or fixture. Permissioned data is access-controlled, not
end-to-end encrypted; a hosting PDS remains in the trust boundary.
