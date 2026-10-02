# Permissioned-data alignment, 2026-10-01 (October 1 Spaces alpha)

Bluesky published the October 1, 2026 Spaces alpha (npm `0.0.0-spaces-alpha-20261001173819`, built from atproto `679724ad`). It renames several request and response fields, replaces the Spaces DPoP binding with HTTP Message Signatures, shortens credential lifetimes, adds credential revocation for repo hosts, and adds space revisions for write notifications. This note records the new immutable Swan profile, `permissioned-data-0016-2026-10-01`, which pins that release, and tracks which of those behaviors Swan already implements. Decisions are logged in `Catbird+Petrel/docs/DECISIONS.md`; the previous alignment is [permissioned-data-2026-09-19.md](permissioned-data-2026-09-19.md) and the open-interop flag is described in [2026-10-01-spaces-open-interop.md](2026-10-01-spaces-open-interop.md).

## Sources and immutable pins

| Pin | `permissioned-data-0016-2026-09-19` | `permissioned-data-0016-2026-10-01` |
| --- | --- | --- |
| Proposal 0016 | `119fa6b63476d30c2516846c714319046e0422f3` | `0c9c2e88ba385809fc9ecba92f362389d9338e16` |
| Reference implementation | `907f41a7b379a7e649a6c4842864946eef6eb757` | `679724ad62eb9a02f7f40429c3c4fdd65d3e4c79` |
| Reference archive SHA-256 | `418f7213…` | `4f326ac19b74773fec8fe2d1403978f20779a19670ace185129ae04f60cacaa8` |
| Petrel runtime package | `35155c926fb7e49e139883feb29308d61aff8db5` | `f15887c9975e12af534f3ac7e72bac404142a0e0` |
| Petrel generator | `710ecb0af23f07737c5c9b60eeed24092cb3aa3c` | unchanged |

Petrel `f15887c9` is the Swan line of Petrel (bookmark `spaces-oct1-swan-20261002`): it re-vendors the 30 Spaces lexicons from `679724ad` byte-for-byte, regenerates the Swift types with the generator code already on that line, and changes Petrel's own `SpaceCredentialManager` client to HTTP Message Signatures. Swan does not use that client.

`interop/fetch-reference.sh` fetches the `679724ad` archive. `Scripts/verify-profile.sh` checks the 30 lexicon digests and the exact lexicon file set, and keeps every historical profile, including `2026-09-19`, byte-for-byte.

## Lexicon delta from the 2026-09-19 pin

Six of the 30 Spaces lexicon files changed:

- `space/listSpaces`: query filter `type` is now `spaceType`.
- `simplespace/createSpace`: body field `type` is now `spaceType`.
- `space/notifyWrite`: `rev` is now `repoRev`; forwarded notifications add `spaceRev` and optional `prevSpaceRev`; declared errors `SpaceNotFound` and `FutureRev`.
- `space/listRepos`: entries are `{did, repoRev, hash, spaceRev}` in ascending `spaceRev` order; the cursor is an exclusive space-revision checkpoint and is omitted on an empty page.
- `space/getSpaceCredential`: descriptions only (HTTP Message Signature instead of DPoP; no `cnf.jkt`).
- `space/notifyCredentialRevoked` (new): `{space, credentials: [jti, …]}` sent by a space authority to repo hosts.

The profile lists 28 endpoints (27 plus `notifyCredentialRevoked`), and the `SwanSpacesWire` registry matches the lexicons' kinds, encodings, and declared errors.

## Intentional divergences recorded in the profile

The profile carries over the `getRepo` streaming divergence and both compatibility exceptions (the `@did-plc/server` submit status and the `listRepoOps` retention gap, both re-checked at `679724ad`). It rewrites the `notifyWrite` divergence for the new reference and adds the items listed in the open-interop note:

- `notifyWrite`: by default Swan requires a `req`-bound service JWT. Unbound tokens are accepted only with `--enable-spaces-open-interop`.
- `registerNotify`: by default Swan also requires `Atproto-Service-Auth`. Registrations made with the space credential alone are accepted only with the flag, and are rate-capped.
- `getSpaceCredential`: Swan's own authority issues 300 s credentials, not the reference's 600 s default. Both are under the 3600 s ceiling.
- `createSpace` / `updateSpace`: `managingAppPolicy` is rejected with `UnsupportedPolicy`.

## Implementation status

Done:

- Petrel re-pin. Wire members follow the renamed generated types: `notifyWrite` sends and accepts `repoRev`, and `listRepos` entries carry `repoRev` and `spaceRev`.
- The profile and registry above, set as the active default (`swan serve` / `swan verify --profile`).

Remaining in this alignment:

- **Request-field renames.** `listSpaces` and `createSpace` still read `type`; the October 1 alpha reads only `spaceType`.
- **HTTP Message Signatures.** `getSpaceCredential` still binds credentials with DPoP (`cnf.jkt`). The new reference expects an `atproto-space` HTTP signature and `cnf.kid`.
- **Revocations.** `notifyCredentialRevoked` is routed as a method-correct 503 gate. Swan does not yet receive or enforce revocations.
- **Space-host sequencing.** Swan does not yet assign space revisions or reject repo revisions more than five minutes in the future (`FutureRev`). Until it does, a `listRepos` entry's `spaceRev` carries the writer's repo revision, the cursor is still the last writer DID, and forwarded notifications carry no `spaceRev`.

## Compatibility boundaries

- Portable exports and operator account backups embed the profile ID and are accepted only under the same ID. Archives produced by a `2026-09-19` build do not restore on this build. Restore them with the build that produced them, or produce new ones after upgrading.
- A `notifyWrite` body that uses `rev` is rejected with 400 `InvalidRequest`. This applies both to a Swan peer still on the `2026-09-19` profile and to a reference repo host older than `679724ad`.
- No stored data is migrated by the profile change itself.
