# Lane L9 — deployment and startup configuration

**Workspace:** `/Users/joshlacalamito/Developer/Catbird+Petrel/Swan-L9-deploy-config`
**Base:** `c1a71eb38adf`
**Scope:** F12, F17, F36, F38, plus the configuration halves of F05 and F13.
**Logs:** `/private/tmp/swan-lane-L9-deploy-config/`

## Result

| Gate | Outcome |
|---|---|
| `xcrun --toolchain XcodeDefault swift build --build-tests` | exit 0, 0 `error:` — `build-final.log` |
| Full macOS suite (`swift test --skip-build`) | exit 0, **1582** `^Test Case .* passed`, **0** `Some test targets reported failures`, 0 failed cases — `test-full.log` |
| New interlock tests alone | exit 0, 11 passed — `test-interlocks.log` |
| `Scripts/verify-interop-lab.sh` (as checked in) | **could not run here** — see below |
| `Scripts/verify-interop-lab.sh` via symlink harness | exit 0, `INTEROP LAB STATIC INVARIANTS OK` — `verify-harness.log` |
| Two custody mutations | both refused — `verify-mutation-f12.log`, `verify-mutation-f12b.log` |
| `Package.resolved` `"identity"` count | 35 (unchanged after Docker probes) |

## F12 — the operator secret shared the runtime volume

`interop/prepare-interop-secrets.sh` copied `operator-secret` into
`$runtime_directory`, the volume every Swan service mounts. The credential that
authenticates the management control plane was readable by the long-running
public runtime, which has no management listener at all.

- The script now prepares a separate `$operator_directory`
  (`SWAN_OPERATOR_SECRETS_DIR`, default `/prepared/swan-operator`) and copies
  `operator-secret` there.
- `docker-compose.yml` publishes it as a new `swan-operator-secrets` volume from
  `swan-secrets-init`. **No base service mounts it.**
- `interop/docker-compose.reference-relay.yml` — the only topology that passes
  `--management-port` — mounts it read-only at `/run/secrets/swan-operator` and
  its `--management-operator-secret-file` now points there.

### The verifier check was the actual bug

`Scripts/verify-interop-lab.sh:541-543` were three `reject_contains` calls over
the `swan` service block. They passed the whole time the operator secret was in
the runtime volume, because Compose YAML never spells the *filename* — it spells
the *volume*. The check was reading the label on the box.

It is replaced by `verify_prepared_secret_custody`, which **executes**
`interop/prepare-interop-secrets.sh` against a temporary tree (with an `install`
stub reproducing its file/directory creation minus the root-only ownership
changes) and then asserts over the files that actually land:

1. every `--*-file` argument in a Swan `command:` resolves to a file the
   preparation script writes into a directory that service mounts;
2. the long-running public runtime reaches exactly
   `{oauth-server-key, account-kek, email-proof-key}` and no `*.password`;
3. `operator-secret` is reachable only by `swan-bootstrap` and by the overlay
   runtime that enables the management listener.

The external-secret *inventory* is derived from the script's own `copy_secret`
call sites; the *routing* is decided by running the script, which is the half
that was wrong.

**Mutation proofs (both leave every line of Compose YAML untouched):**

- Restoring `copy_secret "operator-secret" "$runtime_directory"` →
  `prepared-secret custody: the long-running Swan runtime reaches
  ['account-kek', 'email-proof-key', 'oauth-server-key', 'operator-secret'],
  not exactly the three runtime secrets`. The old text search would not have
  seen this.
- Pointing `--management-operator-secret-file` back at
  `/run/secrets/swan-runtime/operator-secret` →
  `prepared-secret custody: reference-relay swan passes
  --management-operator-secret-file /run/secrets/swan-runtime/operator-secret,
  which the preparation script never writes into a mounted volume`.

### README

`README.md` said the runtime "receives only `oauth-server-key` and
`account-kek`" — it received four files. It now names the three it actually
gets and states that `operator-secret` goes to a separate volume mounted only by
the management topology. A blockquote adds the upgrade step: Docker never
re-initialises a named volume that already has content, so an operator who
merely restarts keeps the stale operator-secret copy in `swan-runtime-secrets`.
`./interop/compose.sh down -v` is required; `down` alone is not.

## F17 — laboratory notification config baked into every runtime image

`Dockerfile:21-23` did `mkdir /etc/swan/interop`, `touch`, and `COPY` of
`interop/notification-config.json` into the runtime stage, so every production
image shipped a `laboratory: true` PLC policy one flag away from being loaded.

The runtime stage is now named `runtime` and carries none of it. A lab-only
stage `FROM runtime AS interop-notification-config` carries the file at
`/usr/local/share/swan/interop/notification-config.json`, and a trailing
`FROM runtime` keeps the **default** build target clean — verified empirically
with a scratch three-stage build: the default target contained only the runtime
marker, `--target lab-only` contained both (`stage-probe/probe.log`).

A new network-isolated `swan-notification-config-init` service publishes the
file into the `swan-notification-config` named volume, which `swan` mounts
read-only at `/etc/swan/interop`. Not a host bind — `verify-interop-lab.sh:560`
rejects a bind for that path, and a bind would also be operator-writable under a
read-only root filesystem.

### Startup interlock

`SwanCommand.Serve.requireLaboratoryPLCStaysOffPublicOrigins` refuses to start
when the notification configuration selects a laboratory PLC policy (credential
*or* delegation resolver) and the resolved `--public-url` names a publicly
reachable HTTPS origin. `ServeNotificationRuntime.selectsLaboratoryPLC(from:)`
is a separate, non-throwing decode so the refusal happens before any database,
key store, or listener exists.

## F36 — metadata IP allowlist on a public deployment

`SwanCommand.Serve.requireMetadataIPAllowlistStaysOffPublicOrigins` refuses a
non-empty `--oauth-allow-metadata-ip` on a publicly reachable HTTPS origin.
Same shape, same error style, same shared classifier as the F17 interlock, and
placed beside it. `Sources/SwanOAuth/OAuthRemoteFetch.swift` was **not** touched
(read-only reuse of the public `OAuthIPAddress` type only).

## The classifier — a deliberate departure from the brief

The brief specified "non-loopback HTTPS origin" for both interlocks. Implemented
literally, that **breaks the interop laboratory and an existing test**:

- `interop/docker-compose.reference-relay.yml:13` serves `https://swan.test`
  with `interop/notification-config.json`, which is `"laboratory": true`. F17 as
  written refuses the lab it exists to protect.
- `Tests/SwanCLITests/ServeLocalSpaceInteropCLITests.swift:289-305` starts
  `serve` with `--public-url https://swan.example` **and**
  `--oauth-allow-metadata-ip 127.0.0.1`, asserting `result.started`. F36 as
  written fails that test — in a file this lane does not own.

`isPubliclyReachableHTTPSOrigin` therefore asks whether the origin could
actually be delegated in public DNS: HTTPS, and the host is neither an IP
literal the outbound-address policy already refuses, nor a bare single label,
nor under a permanently reserved suffix (RFC 6761 `test`/`example`/`invalid`/
`localhost`, RFC 6762 `local`, RFC 8375 `home.arpa`, RFC 2606
`example.com|net|org`, ICANN's `internal`). `swan.catbird.blue` is refused;
`swan.test` and `swan.example` are not.

## F05 config half — `--max-connections`

New `Serve` option, default 256, validated to `1 ... 65536` (`SwanHTTPConfiguration`
only `precondition`s `> 0`, and a precondition failure is a crash, not a
readable refusal). It is passed as `maximumConnections` into the
`SwanHTTPConfiguration` the public server is built with, which is what
`PublicFirehoseSubscriberAdmission(listenerBudget:)` sizes the anonymous
`subscribeRepos` reservation from. **No L1-owned file was edited** —
`PublicFirehoseSubscriberAdmission.swift` and `SwanHTTP.swift` are read-only
here; the existing seam already took the value from configuration. At the 256
default that is 64 subscriber slots and 192 permanently reachable.

## F13 startup refusal — an advertised endpoint must have a route

`requireAdvertisedEndpointsAreServed` refuses a `--public-profile` artifact whose
`endpoints` array names an NSID outside the resolved surface's
`servedMethodNSIDs`. `resolvePublicRouteSurface` now reads the artifact once and
resolves from those bytes, so the surface and the advertisement come from the
same read.

It is a subset test, not an equality test:
`SwanPublicRouteSurface.outOfProfilePublicMethods` (`resolveHandle`) is served
without being declared and that asymmetry is intended. It is a no-op on all four
shipped profiles — asserted in the new tests — and guards the case that already
exists in the registry: `public-data-testing-2026-08-06` aliases
`PublicDataTesting20260805`'s method list, so a successor that genuinely changes
its contract is one `Profiles/` file away from advertising a route that 404s.

## F38 — build context

1. `Dockerfile.dockerignore` gains `Swan/artifacts`, `Swan/artifacts/**`,
   `Swan/.interop-live`, `Swan/.interop-live/**`, placed above the
   `.interop-cache` re-includes (a later `!` re-include wins).

2. **The BuildKit-fallback claim is confirmed empirically**, not asserted. A
   scratch context with `Mine.Dockerfile.dockerignore` excluding `*.pem` and
   `artifacts/`, and a `.dockerignore` excluding neither:

   - `DOCKER_BUILDKIT=1` → context is `Mine.Dockerfile`,
     `Mine.Dockerfile.dockerignore`, `keep.txt`. (`buildkit1.log`)
   - `DOCKER_BUILDKIT=0` → context also contains `artifacts` and `secret.pem`.
     (`buildkit0.log`)

   The legacy builder ignores `<dockerfile>.dockerignore` entirely. Docker
   29.6.2 prints "The legacy builder is deprecated and will be removed in a
   future release", so this is a shrinking but live exposure.

   `/Users/joshlacalamito/Developer/Catbird+Petrel/.dockerignore` therefore now
   carries the same `artifacts`/`.interop-live` exclusions **and** the
   `**/.env*`, `**/*.pem`, `**/*.key`, `**/*.p8`, `**/keys/`,
   `**/.swan-interop-secrets/`, `**/*.sqlite*`, `**/.swan-data/` exclusions that
   only existed in `Swan/Dockerfile.dockerignore`. Sealed as its own
   path-restricted commit in the workspace repo: `c9ea8198`.

   **That commit had to include `.gitignore`, one line, and here is why.** The
   first attempt, `jj commit .dockerignore -m ...`, printed `Warning: The given
   paths do not match any file: .dockerignore` and produced an *empty* commit —
   the workspace repo's `.gitignore` starts with a `/*` whitelist and never
   re-includes `.dockerignore`, so the file was untracked. Proven with a
   positive control: `jj file list` returns 496 paths, matches `CLAUDE.md` once,
   and matches `dockerignore` zero times. That empty commit was rolled back with
   `jj undo`. Delivering F38's second half is impossible without the
   `!.dockerignore` re-include, so the commit is `.dockerignore` + `.gitignore`
   and nothing else. `.gitignore` is **not** on this lane's owned-file list —
   flagging it rather than burying it.

   Everything else dirty in that repo belongs to other actors and was left
   untouched: `.superpowers/sdd/progress.md`,
   `docs/audits/2026-04-27-lexicon-codegen-audit.md`,
   `docs/bluesky-watch/.state.json`, two files under
   `docs/feedback/repost-ghost-overlay/`, and five files under
   `docs/superpowers/plans/`. The commit is path-restricted, so none of them
   were sealed.

3. **Severity is lower than the scan claims.** Greps for `password`,
   `accessJwt`, `refreshJwt`, `-----BEGIN`, and bare `eyJ` over
   `Swan/artifacts` + `Swan/.interop-live` in the canonical checkout (39 + 37
   files, ~600 KB) return **zero** files for every pattern. Positive control,
   same greps, same run: `Swan/Sources` + `Swan/Scripts` return 65 / 3 / 0 / 0 /
   6 files, and `Sources+Scripts+docs` in this workspace return 88 / 6 / 3 / 3 /
   8. The greps work; the trees are clean. This is build hygiene and context
   size, not credential leakage. (`f38-sensitivity-grep.log`,
   `f38-sensitivity-grep-canonical.log`)

## Verifier execution — what actually ran

`./Scripts/verify-interop-lab.sh` **as checked in exits 1 in this workspace**
at `./interop/verify-reference.sh` with `pinned reference cache is unavailable`:
this jj workspace carries no `.interop-cache/` (untracked; it exists only in the
canonical checkout). That is environmental and pre-existing — the abort happens
before any check this lane touched.

To exercise the changes, a harness in `/private/tmp/swan-lane-L9-deploy-config/`
symlinks every repository entry and runs a copy of the verifier with only the
three pinned-archive fetch checks neutralised. That run is **exit 0** and prints
all three success banners, including `INTEROP LAB EFFECTIVE COMPOSE INVARIANTS
OK` and `REFERENCE RELAY EFFECTIVE COMPOSE INVARIANTS OK` — so `docker compose
config` did resolve the new service, the new volumes, and the overlay merge.

**No Docker laboratory was started.** The only containers run were three
throwaway `docker build`/`docker run` probes for the `.dockerignore` and
multi-stage questions, all named `swan-lane-L9-*`, all `aarch64`, no
`--platform`, images removed afterwards.

`Scripts/test-verify-interop-lab.sh` was **not** run: it sets
`SWAN_INTEROP_REQUIRE_EFFECTIVE_COMPOSE=1` and requires the same pinned
reference cache for its baseline.

Verifier changes beyond the custody rewrite:

- `swan-notification-config-init` added to the required-service list and to the
  effective-Compose `required_services` set.
- Assertions for the operator volume, the notification-config volume mount and
  its initializer, and `SWAN_OPERATOR_SECRETS_DIR` added to
  `safe_secret_directory_variables`.
- Dockerfile stage assertions: the runtime `FROM` line now matches `AS runtime`;
  the lab stage and the trailing default stage are required; a Python pass
  rejects `notification-config.json` entering any stage but
  `interop-notification-config`, rejects any stage creating `/etc/swan/interop`,
  and requires the final stage to be the unnamed clean runtime.

## Blocked / needs another owner

**`Scripts/run-permissioned-recovery-acceptance.sh:353-387` will fail.** It does
a raw `docker run` of the default image and passes
`--notification-config /etc/swan/interop/notification-config.json` with no mount
for it. Now that the file is out of the runtime image, that path does not exist.
The file is not on this lane's owned list. The fix is one mount alongside the
existing ones at `:361`:

```
  --mount "type=volume,src=${notification_config_volume},dst=/etc/swan/interop,readonly" \
```

with `notification_config_volume` discovered the same way `runtime_secrets_volume`
already is. The other acceptance scripts
(`run-clean-cache-acceptance.sh`, `run-notification-restart-acceptance.sh`)
layer Compose overrides on `docker-compose.yml` and inherit the new mount, so
they need nothing.

## Client-visible behaviour

None. No status code, error name, wire field, or response body changed. All
three new refusals are startup-time `ValidationError`s on operator-supplied
configuration; none is reachable by a request, and none of them fires on any
configuration checked into this repository.
