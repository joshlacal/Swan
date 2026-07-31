#!/usr/bin/env node

// The pinned @did-plc/server binary uses Database.mock() when DATABASE_URL is
// absent.  That is useful for unit tests, but it makes a Compose restart erase
// every DID while Swan's durable account databases remain active.  Keep the
// exact pinned HTTP implementation and validation rules, but persist the
// accepted operation bodies in an owner-only, atomically replaced file.

import { randomBytes } from 'node:crypto'
import { chmod, mkdir, open, readFile, rename, lstat, unlink } from 'node:fs/promises'
import path from 'node:path'
import process from 'node:process'
// The pinned PLC build uses pnpm's non-hoisted dependency layout. Resolve the
// package from the verified archive's exact installed path rather than relying
// on ambient NODE_PATH or a mutable global module.
import plc from './node_modules/.pnpm/@did-plc+server@0.0.1/node_modules/@did-plc/server/dist/index.js'

const { Database, PlcServer } = plc

const stateDirectory = path.resolve(process.env.PLC_DATA_DIRECTORY || '/plc')
const statePath = path.join(stateDirectory, 'operations.json')
const maximumStateBytes = 64 * 1024 * 1024
const maximumOperations = 100_000

function fail(message) {
  throw new Error(`persistent PLC state: ${message}`)
}

async function requireDirectory(directory) {
  let directoryStat
  try {
    directoryStat = await lstat(directory)
  } catch (error) {
    if (error?.code !== 'ENOENT') throw error
    await mkdir(directory, { recursive: true, mode: 0o700 })
    directoryStat = await lstat(directory)
  }
  if (!directoryStat.isDirectory() || (directoryStat.mode & 0o077) !== 0) {
    fail('data directory must be a non-symlink 0700 directory')
  }
}

async function readState() {
  let fileStat
  try {
    fileStat = await lstat(statePath)
  } catch (error) {
    if (error?.code === 'ENOENT') return []
    throw error
  }
  if (!fileStat.isFile() || (fileStat.mode & 0o077) !== 0) {
    fail('state file must be a non-symlink owner-only regular file')
  }
  if (fileStat.size > maximumStateBytes) fail('state file is too large')
  const raw = await readFile(statePath, 'utf8')
  let decoded
  try {
    decoded = JSON.parse(raw)
  } catch {
    fail('state file is not valid JSON')
  }
  if (decoded?.version !== 1 || !Array.isArray(decoded.operations)) {
    fail('state file has an unsupported shape')
  }
  if (decoded.operations.length > maximumOperations) {
    fail('state file contains too many operations')
  }
  for (const entry of decoded.operations) {
    if (
      !entry ||
      typeof entry.did !== 'string' ||
      !entry.did.startsWith('did:plc:') ||
      !entry.operation ||
      typeof entry.operation !== 'object' ||
      Array.isArray(entry.operation)
    ) {
      fail('state file contains an invalid operation')
    }
  }
  return decoded.operations
}

async function writeState(operations) {
  if (operations.length > maximumOperations) {
    fail('operation capacity exhausted')
  }
  const payload = `${JSON.stringify({ version: 1, operations })}\n`
  if (Buffer.byteLength(payload) > maximumStateBytes) {
    fail('operation state capacity exhausted')
  }
  const temporaryPath = path.join(
    stateDirectory,
    `.operations.${process.pid}.${randomBytes(12).toString('hex')}.tmp`,
  )
  try {
    const handle = await open(temporaryPath, 'wx', 0o600)
    try {
      await handle.writeFile(payload, 'utf8')
      await handle.sync()
    } finally {
      await handle.close()
    }
    await rename(temporaryPath, statePath)
    await chmod(statePath, 0o600)
  } catch (error) {
    await unlink(temporaryPath).catch(() => {})
    throw error
  }
}

await requireDirectory(stateDirectory)
const storedOperations = await readState()
const database = Database.mock()
const originalValidateAndAddOp = database.validateAndAddOp.bind(database)

// Rebuild through the pinned validator rather than trusting persisted CID or
// nullification metadata.  A corrupt or tampered state file therefore stops
// startup before the HTTP listener is exposed.
for (const entry of storedOperations) {
  await originalValidateAndAddOp(entry.did, entry.operation)
}

let operationLog = storedOperations.map((entry) => ({
  did: entry.did,
  operation: entry.operation,
}))
let mutationTail = Promise.resolve()

database.validateAndAddOp = (did, operation) => {
  const next = mutationTail.then(async () => {
    await originalValidateAndAddOp(did, operation)
    const durableOperation = JSON.parse(JSON.stringify({ did, operation }))
    operationLog.push(durableOperation)
    try {
      await writeState(operationLog)
    } catch (error) {
      // The pinned in-memory database cannot roll back a validated operation.
      // Do not keep serving a registry whose accepted state is not durable;
      // fail closed so the next start replays the last complete state file.
      console.error('persistent PLC state write failed; stopping', error)
      process.nextTick(() => process.exit(1))
      throw error
    }
  })
  mutationTail = next.catch(() => {})
  return next
}

const port = Number.parseInt(process.env.PORT || '', 10) || 2582
const server = PlcServer.create({
  db: database,
  port,
  version: '0.0.1-swan-persistent-mock',
})

let shutdownPromise
async function shutdown(signal) {
  if (shutdownPromise) return shutdownPromise
  shutdownPromise = (async () => {
    await mutationTail
    await server.destroy()
    process.exit(0)
  })().catch((error) => {
    console.error(`persistent PLC shutdown failed after ${signal}`, error)
    process.exit(1)
  })
  return shutdownPromise
}

process.once('SIGTERM', () => { void shutdown('SIGTERM') })
process.once('SIGINT', () => { void shutdown('SIGINT') })

await server.start()
console.log(`Persistent PLC server is running at http://localhost:${port}`)
