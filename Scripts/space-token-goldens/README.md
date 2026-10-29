# Space token goldens

Re-signs Swan's frozen space-token test vectors with **upstream's own signing
path**, so a vector stays a cross-implementation check and never becomes a
Swift-signed, self-consistent one. Both scripts change one claim, `aud`, in the
raw payload bytes. Key order and spelling stay exactly as originally frozen.

The October 22, 2026 Spaces alpha (atproto ac0c9f15, upgrade guide section 3)
moved both audiences from `<authority>#atproto_space_host` to
`<authority>#atproto_pds`. That is the change these scripts were written for.
Each test that uses a re-signed vector also keeps the original one and asserts
that it is now rejected.

`package.json` and `package-lock.json` pin `@noble/curves` 1.8.0 and
`@noble/hashes` 1.7.0, with the integrity hashes in upstream's `pnpm-lock.yaml`.

## `sign-delegation.mjs`: ES256K space delegation

Used by:

- `Tests/SwanOAuthTests/SpaceCredentialAuthorityTests.swift`
  (`testES256KGoldenDelegationAndBoundCredentialFallbackRejectLegacyBearer`)
- `Tests/SwanOAuthTests/PermissionedResolverCompositionTests.swift`
  (`remoteDelegation`)

Signing path: `@atproto/crypto` `Secp256k1Keypair.sign`
(`packages/crypto/src/secp256k1/keypair.ts`), which is `sha256`, then a
deterministic low-S secp256k1 signature in 64-byte compact form. The key is
secp256k1 scalar 1. Its public key is the generator point the tests pin
(`Anm-Zn753LusVaBilc6HCwcCm_zbLc4o2VnygVsW-BeY`).

Positive control: the original atproto 3f6c96d golden was produced by this
same deterministic path. The script re-signs that golden's own signing input
and refuses to continue unless it reproduces the signature byte for byte.

## `sign-client-attestation.mjs`: ES256 client attestation

Used by `Tests/SwanOAuthTests/ClientAttestationPolicyTests.swift`
(`testFixedTypeScriptShapedES256VectorVerifies`).

Signing path: `@atproto/crypto` `P256Keypair.sign`
(`packages/crypto/src/p256/keypair.ts`), the same shape on P-256. The key is
the P-256 scalar `0x0102…20`, the tests' `fixedPrivateKey()`, and the script
checks that it matches the JWK the test pins.

Positive control: the original vector was signed with a randomized ECDSA
nonce, so its signature cannot be reproduced. The script instead requires that
the old signature verifies, as low-S, under the pinned key. The new signature
is deterministic (RFC 6979), so its output can be reproduced byte for byte.

## Regenerating

```bash
G=/path/to/scratch
cp package.json package-lock.json "$G/"
(cd "$G" && npm ci --ignore-scripts --no-audit --no-fund)

node sign-delegation.mjs "$G/node_modules" '<old delegation JWT>' \
  'did:plc:abcdefghijklmnopqrstuvwx#atproto_pds'
node sign-client-attestation.mjs "$G/node_modules" '<old attestation JWT>' \
  'did:plc:abcdefghijklmnopqrstuvwx#atproto_pds'
```

Copy `newJwt` from each output into the tests. Keep the old vector as a
rejected negative case.
