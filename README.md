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

`Swan` never places permissioned records into a public repository, public blob
namespace, log line, or fixture. Permissioned data is access-controlled, not
end-to-end encrypted; a hosting PDS remains in the trust boundary.
