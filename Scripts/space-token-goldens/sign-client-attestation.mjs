// Re-signs the ES256 client-attestation golden with upstream @atproto/crypto's
// `P256Keypair.sign` path at atproto ac0c9f15
// (packages/crypto/src/p256/keypair.ts):
//
//   p256.sign(sha256(signingInput), priv, { lowS: true }).toCompactRawBytes()
//
// with @noble/curves 1.8.0 and @noble/hashes 1.7.0, the versions upstream's
// pnpm-lock.yaml pins. That signature is deterministic (RFC 6979), so anyone
// can reproduce this script's output byte for byte.
//
// The golden key is the P-256 scalar 0x0102...20, which is the tests'
// `fixedPrivateKey()` and the public JWK they pin.
//
// Positive control first. The original golden was signed with a randomized
// ECDSA nonce, so its signature cannot be reproduced. Instead the script
// requires that the old signature verifies, as low-S, under the pinned key
// before it signs anything. It then replaces the `aud` value, and nothing
// else, in the raw payload bytes, so the TypeScript insertion order
// (iss, sub, aud, iat, exp, jti) stays exactly as frozen, and signs the result.
//
// Usage: node sign-client-attestation.mjs <node_modules-dir> <old-golden-jwt> <new-aud>
import path from 'node:path'
import { pathToFileURL } from 'node:url'

const [depsDir, oldJwt, newAud] = process.argv.slice(2)
if (!depsDir || !oldJwt || !newAud) {
  console.error('usage: node sign-client-attestation.mjs <node_modules-dir> <old-golden-jwt> <new-aud>')
  process.exit(2)
}
const imp = (p) => import(pathToFileURL(path.join(depsDir, p)).href)
const { p256 } = await imp('@noble/curves/p256.js')
const { sha256 } = await imp('@noble/hashes/sha256.js')

const PINNED_JWK = {
  x: 'UVw9brnjlrkE0_7Kf1T9zQzB6Ze_N13KUVrQpsO0A18',
  y: 'RTa-OlDzGPv5pUdZAqIhUCvvDVfgjFOyzApW8X2fk1Q',
}
const b64url = (bytes) => Buffer.from(bytes).toString('base64url')
const priv = Uint8Array.from({ length: 32 }, (_, index) => index + 1)
const publicKey = p256.getPublicKey(priv, false)
const digest = (input) => sha256(new TextEncoder().encode(input))
const sign = (input) =>
  b64url(p256.sign(digest(input), priv, { lowS: true }).toCompactRawBytes())
const verifies = (signature, input) =>
  p256.verify(Buffer.from(signature, 'base64url'), digest(input), publicKey, { lowS: true })

const fail = (message) => {
  console.error(message)
  process.exit(1)
}

const jwk = { x: b64url(publicKey.slice(1, 33)), y: b64url(publicKey.slice(33)) }
if (jwk.x !== PINNED_JWK.x || jwk.y !== PINNED_JWK.y) fail(`unexpected public key: ${JSON.stringify(jwk)}`)

const parts = oldJwt.split('.')
if (parts.length !== 3) fail('old golden is not a compact JWT')
const [header, payloadPart, oldSignature] = parts
const oldSignatureVerifies = verifies(oldSignature, `${header}.${payloadPart}`)
if (!oldSignatureVerifies) fail('positive control failed: the old signature does not verify under the pinned key')

const payload = Buffer.from(payloadPart, 'base64url').toString('utf8')
const oldAud = JSON.parse(payload).aud
const oldAudMember = `"aud":${JSON.stringify(oldAud)}`
if (payload.split(oldAudMember).length !== 2) fail(`unexpected payload: ${payload}`)
const newPayload = payload.replace(oldAudMember, `"aud":${JSON.stringify(newAud)}`)
const newInput = `${header}.${Buffer.from(newPayload, 'utf8').toString('base64url')}`
const newSignature = sign(newInput)
const newVerifies = verifies(newSignature, newInput)
if (!newVerifies) fail('the new signature does not verify')

console.log(JSON.stringify({
  publicJwk: jwk,
  header: Buffer.from(header, 'base64url').toString('utf8'),
  oldPayload: payload,
  oldSignatureVerifies,
  newPayload,
  newJwt: `${newInput}.${newSignature}`,
  newVerifies,
}, null, 1))
