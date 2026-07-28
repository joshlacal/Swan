#!/usr/bin/env node

import { readFile } from 'node:fs/promises'
import path from 'node:path'
import process from 'node:process'
import { pathToFileURL } from 'node:url'

function fail(message) {
  throw new Error(message)
}

function argumentsFrom(argv) {
  if (argv.length !== 4 || argv[0] !== '--reference' || argv[2] !== '--fixture') {
    fail('usage: reference-public-repository-car.mjs --reference <directory> --fixture <file>')
  }
  return {
    reference: path.resolve(argv[1]),
    fixture: path.resolve(argv[3]),
  }
}

const options = argumentsFrom(process.argv.slice(2))
const fixture = JSON.parse(await readFile(options.fixture, 'utf8'))
if (fixture.pin !== '3f6c96d5d2d25438bd40fa89d6ecc37865f8e354') {
  fail('fixture pin differs')
}
const repo = await import(
  pathToFileURL(path.join(options.reference, 'packages/repo/dist/index.js')).href
)

async function verifyEntry(producer, entry, expectedRecords) {
  const car = Buffer.from(entry.carBase64, 'base64')
  if (car.length === 0 || car.toString('base64') !== entry.carBase64) {
    fail(`${producer} fixture CAR is not canonical base64`)
  }
  const verified = await repo.verifyRepoCar(
    car,
    fixture.did,
    fixture.signingKeyDID,
  )
  if (verified.commit.cid.toString() !== entry.commitCID) {
    fail(`${producer} verified commit CID differs`)
  }
  if (verified.commit.rev !== fixture.revision) {
    fail(`${producer} verified revision differs`)
  }
  if (verified.creates.length !== expectedRecords.length) {
    fail(`${producer} fixture create count differs`)
  }
  const actualPaths = verified.creates
    .map((create) => `${create.collection}/${create.rkey}`)
    .sort()
  const expectedPaths = expectedRecords
    .map((record) => `${record.collection}/${record.rkey}`)
    .sort()
  if (JSON.stringify(actualPaths) !== JSON.stringify(expectedPaths)) {
    fail(`${producer} verified record paths differ`)
  }
  if (entry.blockOrder) {
    const parsed = await repo.readCarWithRoot(car)
    const actualOrder = []
    for (const block of parsed.blocks.entries()) {
      actualOrder.push(block.cid.toString())
    }
    if (JSON.stringify(actualOrder) !== JSON.stringify(entry.blockOrder)) {
      fail(`${producer} CAR block order differs`)
    }
    if (entry.blockOrder[0] !== entry.commitCID || entry.blockOrder[1] !== entry.dataCID) {
      fail(`${producer} CAR root ordering facts differ`)
    }
  }

  const storage = new repo.MemoryBlockstore()
  await storage.applyCommit(verified.commit)
  const reexported = Buffer.from(
    await repo.concatBytesAsync(repo.getFullRepo(storage, verified.commit.cid)),
  )
  if (!reexported.equals(car)) {
    fail(`${producer} pinned TypeScript full-repository re-export differs`)
  }
}

for (const [producer, entry] of [
  ['TypeScript', fixture],
  ['Swift', fixture.swift],
]) {
  await verifyEntry(producer, entry, [fixture.record])
}
await verifyEntry('TypeScript multi-layer', fixture.multiLayer, fixture.multiLayer.records)

console.log(`REFERENCE PUBLIC REPOSITORY CAR OK: ${path.basename(options.fixture)}`)
