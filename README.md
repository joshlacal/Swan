# Swan

Swan is a Swift-native AT Protocol permissioned-data interoperability laboratory.
It intentionally starts with protocol fidelity, durable local semantics, and
cross-implementation fixtures rather than attempting to be a public production
PDS on day one.

The active profile is `permissioned-data-0016-2026-07-03`. Its upstream pins
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
32-byte keys. The account identity files must contain canonical DIDs/handles,
and `public-repo-revision` must be a valid repository-v3 revision. PDS files
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
The Linux Compose gate has been exercised with a clean cache: health checks,
PLC-backed account bootstrap, stateful public and permissioned Swan-to-Swan
round trips, public/private isolation, and the offline/disconnected/delayed/
duplicated/reordered/corrupted endpoint matrix all pass. The pinned TypeScript
host also passed a disposable public record smoke and a cross-host permissioned
round trip: it wrote on the reference member PDS, received a Swan-issued space
credential, and read the same CID back from that member host. The sanitized
transport artifact is not a claim of full Swan-to-TypeScript semantic
convergence.

### Pinned wire generation

Normal Swift builds use only the checked-in `Sources/SwanSpacesWire/Generated`
sources; they do not download lexicons or invoke Petrel. Regeneration is an
explicit, profile-pinned operation. Materialize the pinned reference archive
first (so `.interop-cache/atproto-3f6c96d5d2d25438bd40fa89d6ecc37865f8e354`
exists), then select the reviewed Petrel generator workspace explicitly:

```sh
PETREL_GENERATOR_ROOT=/Users/joshlacalamito/Developer/Catbird+Petrel/Petrel-swan-generator \
  ./Scripts/verify-wire-generation.sh

# This is the intentional mutating form. It validates the profile, d011ccf0
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
