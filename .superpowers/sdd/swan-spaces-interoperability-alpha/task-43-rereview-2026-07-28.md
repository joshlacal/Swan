# Task 43 independent rereview

Date: 2026-07-28
Reviewed implementation line: Task 43 public-read change `66bf469bf53b` and
its verified descendants through `ef0c31e4`.

## Verdict

**PASS for the scoped Task 43 public-read contract.** This is a local
macOS/toolchain result; it is not a live cross-host or Linux acceptance result.

## Remediation review

- `getRepo` uses the bounded SQLite/TEMP-table traversal in
  `PublicRepositoryBoundedExport.swift`; it does not retain the complete MST
  topology in ordinary Swift arrays.
- Spool admission takes a process-global lease before creating the spool and
  releases it idempotently on success, cancellation, and response-body
  abandonment.
- `listRecords` matches the pinned TypeScript contract: default descending
  order, a strict `< cursor` comparator, reverse ascending order, and the
  returned page's final record key as cursor.
- `RepositoryMSTValidation` decodes DAG-CBOR directly and rejects floats and
  wide integers without a JSON conversion bridge.
- Public identity reads verify the complete PLC genesis/signature binding and
  fail closed when the durable identity history or key references do not match.

## Verification

The following commands passed with the Xcode toolchain and serialized SwiftPM
builds:

```sh
env -u SDKROOT -u TOOLCHAINS \
  DEVELOPER_DIR=/Applications/Xcode-beta.app/Contents/Developer \
  /usr/bin/xcrun --toolchain XcodeDefault swift test --jobs 1 \
  --filter PublicRepositoryReadHTTPTests

env -u SDKROOT -u TOOLCHAINS SWAN_RUN_256MIB_PUBLIC_GET_REPO=1 \
  DEVELOPER_DIR=/Applications/Xcode-beta.app/Contents/Developer \
  /usr/bin/xcrun --toolchain XcodeDefault swift test --jobs 1 \
  --filter PublicRepositoryReadDirectoryTests.testOptIn256MiBProductionDirectoryGetRepoHasBoundedRSS
```

The HTTP filter executed 8 tests with 0 failures. The opt-in 256 MiB
production-directory RSS test passed. The complete serialized macOS suite
also passed with exit code 0. Profile and interop static verification passed:

- `Scripts/verify-profile.sh`
- `Scripts/verify-interop-lab.sh`
- `Scripts/test-verify-interop-lab.sh`
- `git diff --check`

## Boundary

This rereview closes Task 43 only. The pinned TypeScript PDS matrix,
permissioned cross-host credential/record synchronization, Docker Compose,
Linux, Petrel regeneration with the isolated generator checkout, and full
public/private isolation gates remain separate acceptance work.
