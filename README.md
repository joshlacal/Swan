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
