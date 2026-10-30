// Re-signs a compact ES256K space-delegation golden exactly as upstream
// @atproto/crypto `Secp256k1Keypair.sign` does at atproto ac0c9f15
// (packages/crypto/src/secp256k1/keypair.ts):
//
//   k256.sign(sha256(signingInput), priv, { lowS: true }).toCompactRawBytes()
//
// with @noble/curves 1.8.0 and @noble/hashes 1.7.0, the versions upstream's
// pnpm-lock.yaml pins. package-lock.json here carries the same integrity hashes.
//
// The golden key is secp256k1 scalar 1, so its public key is the generator
// point the tests pin as "Anm-Zn753LusVaBilc6HCwcCm_zbLc4o2VnygVsW-BeY".
//
// Positive control first: the script re-signs the old golden's own signing
// input and refuses to continue unless that reproduces the old signature byte
// for byte. Only then does it replace the `aud` value, and nothing else, in the
// raw payload bytes, so key order and spelling stay exactly as TypeScript
// emitted them, and sign the result.
//
// Usage: node sign-delegation.mjs <node_modules-dir> <old-golden-jwt> <new-aud>
import path from 'node:path'
import { pathToFileURL } from 'node:url'

const [depsDir, oldJwt, newAud] = process.argv.slice(2)
if (!depsDir || !oldJwt || !newAud) {
  console.error('usage: node sign-delegation.mjs <node_modules-dir> <old-golden-jwt> <new-aud>')
  process.exit(2)
}
const imp = (p) => import(pathToFileURL(path.join(depsDir, p)).href)
const { secp256k1: k256 } = await imp('@noble/curves/secp256k1.js')
const { sha256 } = await imp('@noble/hashes/sha256.js')

const PINNED_PUBLIC_KEY = 'Anm-Zn753LusVaBilc6HCwcCm_zbLc4o2VnygVsW-BeY'
const b64url = (bytes) => Buffer.from(bytes).toString('base64url')
const priv = new Uint8Array(32)
priv[31] = 1 // secp256k1 scalar 1
const sign = (input) =>
  b64url(k256.sign(sha256(new TextEncoder().encode(input)), priv, { lowS: true }).toCompactRawBytes())

const fail = (message) => {
  console.error(message)
  process.exit(1)
}

const publicKey = b64url(k256.getPublicKey(priv, true))
if (publicKey !== PINNED_PUBLIC_KEY) fail(`unexpected public key: ${publicKey}`)

const parts = oldJwt.split('.')
if (parts.length !== 3) fail('old golden is not a compact JWT')
const [header, payloadPart, oldSignature] = parts
const oldInput = `${header}.${payloadPart}`
const oldSignatureReproduced = sign(oldInput) === oldSignature
if (!oldSignatureReproduced) fail('positive control failed: the old signature was not reproduced')

const payload = Buffer.from(payloadPart, 'base64url').toString('utf8')
const oldAud = JSON.parse(payload).aud
const oldAudMember = `"aud":${JSON.stringify(oldAud)}`
if (payload.split(oldAudMember).length !== 2) fail(`unexpected payload: ${payload}`)
const newPayload = payload.replace(oldAudMember, `"aud":${JSON.stringify(newAud)}`)
const newInput = `${header}.${Buffer.from(newPayload, 'utf8').toString('base64url')}`
const newSignature = sign(newInput)
const newVerifies = k256.verify(
  Buffer.from(newSignature, 'base64url'),
  sha256(new TextEncoder().encode(newInput)),
  k256.getPublicKey(priv, true),
  { lowS: true },
)
if (!newVerifies) fail('the new signature does not verify')

console.log(JSON.stringify({
  publicKeyCompressedB64url: publicKey,
  header: Buffer.from(header, 'base64url').toString('utf8'),
  oldPayload: payload,
  oldSignatureReproduced,
  newPayload,
  newJwt: `${newInput}.${newSignature}`,
  newVerifies,
}, null, 1))
