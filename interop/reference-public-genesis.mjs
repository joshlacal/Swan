#!/usr/bin/env node

import { readFile } from 'node:fs/promises'
import path from 'node:path'
import process from 'node:process'
import { pathToFileURL } from 'node:url'

// This is a fixed, publicly-known test scalar used only to reproduce the
// checked-in vector. It is never an account, DPoP, or fixture private key.
const TEST_VECTOR_P256_SCALAR = '01'.repeat(32)

function fail(message) {
  throw new Error(message)
}

function parseArguments(argv) {
  const options = new Map()
  for (let index = 0; index < argv.length; index += 2) {
    const name = argv[index]
    const value = argv[index + 1]
    if (!name?.startsWith('--') || value === undefined || options.has(name)) {
      fail('usage: reference-public-genesis.mjs --reference <directory> --fixture <file>')
    }
    options.set(name, value)
  }
  if (options.size !== 2 || !options.has('--reference') || !options.has('--fixture')) {
    fail('usage: reference-public-genesis.mjs --reference <directory> --fixture <file>')
  }
  return {
    reference: path.resolve(options.get('--reference')),
    fixture: path.resolve(options.get('--fixture')),
  }
}

function requiredString(object, key) {
  const value = object?.[key]
  if (typeof value !== 'string' || value.length === 0) {
    fail(`fixture has no valid ${key}`)
  }
  return value
}

function requiredCAR(object, key) {
  const value = requiredString(object, key)
  const bytes = Buffer.from(value, 'base64')
  if (bytes.length === 0 || bytes.toString('base64') !== value) {
    fail(`fixture has no valid ${key}`)
  }
  return bytes
}

function assertEqual(actual, expected, label) {
  if (actual !== expected) {
    fail(`${label} differs from the pinned vector`)
  }
}

async function expectReject(operation, label) {
  try {
    await operation()
  } catch {
    return
  }
  fail(`${label} was accepted`)
}

const { reference, fixture: fixturePath } = parseArguments(process.argv.slice(2))
const fixture = JSON.parse(await readFile(fixturePath, 'utf8'))
const repo = await import(pathToFileURL(path.join(reference, 'packages/repo/dist/index.js')).href)
const crypto = await import(pathToFileURL(path.join(reference, 'packages/crypto/dist/index.js')).href)

const did = requiredString(fixture, 'did')
const revision = requiredString(fixture, 'revision')
const signingKeyDID = requiredString(fixture, 'signingKeyDID')
const typeScript = fixture?.typeScript
const swift = fixture?.swift

const keypair = await crypto.P256Keypair.import(TEST_VECTOR_P256_SCALAR)
assertEqual(keypair.did(), signingKeyDID, 'test-vector signing key')

const storage = new repo.MemoryBlockstore()
const generated = await repo.Repo.formatInitCommit(storage, did, keypair, [], revision)
await storage.applyCommit(generated)
const generatedCAR = Buffer.from(
  await repo.concatBytesAsync(repo.getFullRepo(storage, generated.cid)),
)
assertEqual(generated.cid.toString(), requiredString(typeScript, 'commitCID'), 'TypeScript commit CID')
assertEqual(
  generatedCAR.toString('base64'),
  requiredString(typeScript, 'carBase64'),
  'TypeScript CAR',
)

for (const [name, entry] of [['TypeScript', typeScript], ['Swift', swift]]) {
  const car = requiredCAR(entry, 'carBase64')
  const verified = await repo.verifyRepoCar(car, did, signingKeyDID)
  assertEqual(verified.commit.cid.toString(), requiredString(entry, 'commitCID'), `${name} commit CID`)
  assertEqual(verified.commit.rev, revision, `${name} revision`)
  if (verified.creates.length !== 0) {
    fail(`${name} genesis unexpectedly contains records`)
  }

  const mutated = Buffer.from(car)
  mutated[mutated.length - 1] ^= 1
  await expectReject(
    () => repo.verifyRepoCar(mutated, did, signingKeyDID),
    `${name} corrupt CAR`,
  )
}

console.log(`REFERENCE PUBLIC GENESIS OK: ${path.basename(fixturePath)}`)
