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
```

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
2. Unprivileged `swan-bootstrap` installs the disposable authority and member
   accounts idempotently using supported `swan account` commands.
3. Unprivileged `swan` starts with local-space interop enabled behind Caddy.
4. Caddy creates its local CA; its healthcheck gates `caddy-ca-ready`, which
   copies the public root certificate into an unprivileged read-only trust
   volume.

Caddy on loopback port 443 is the sole host ingress and owns the in-network
`swan.test` and `pds.test` aliases. Mailpit and Toxiproxy have no published
ports. The `scenario-runner` belongs to the opt-in `planned-not-executed`
profile, has no network, and only validates the prepared CA trust file. Task 28
does not run probes, the cross-host matrix, or fault mutations.

`Scripts/verify-interop-lab.sh` statically enforces this topology, and
`Scripts/test-verify-interop-lab.sh` pressure-tests the verifier with unsafe
privilege, dependency, interpolation, mount, runner, and readiness mutations.
Docker/Compose startup, Linux UID behavior, TLS requests, reference account
setup, and the real cross-host/fault matrix remain explicit future gates on a
Docker-capable Linux host.

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
