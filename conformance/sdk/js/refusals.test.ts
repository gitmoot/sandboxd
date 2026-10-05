// sandboxd-authored: every unsupported E2B feature is refused with 501 and
// its documented message, raised by the stock SDK as its generic API error
// (docs/compatibility.md#not-supported). Copied by conformance/run.py into
// the js-e2b suite as tests/sandboxd/.
import { afterAll, beforeAll, expect, test } from 'vitest'

import { Sandbox, SandboxError, Secret, SecretError, Template, Volume, VolumeError } from '../../src'

const DOC = '; see docs/compatibility.md#not-supported'
const PAUSE = 'pause and resume are not supported: sandboxd never pauses a sandbox (deferred, owner decision D7)'
const SNAPSHOTS = 'snapshots are not supported: sandboxd keeps no sandbox state after a sandbox ends (deferred with pause, D7)'
const FORK = 'fork is not supported: it needs snapshots (deferred with pause, D7)'
const NETWORK = "network updates are not supported: a sandbox's network policy is fixed by the operator"
const VOLUMES = "volumes are not supported: sandboxd keeps no storage beyond a sandbox's lifetime"
const SECRETS = 'secrets are not supported: pass values to a sandbox in envVars instead'

let sandbox: Sandbox

beforeAll(async () => {
  sandbox = await Sandbox.create({ timeoutMs: 120_000 })
}, 60_000)

afterAll(async () => {
  await sandbox?.kill()
})

async function refused(errorClass: new (...args: never[]) => Error, reason: string, call: () => Promise<unknown>) {
  const error = await call().then(
    () => undefined,
    (e: unknown) => e
  )
  expect(error).toBeInstanceOf(errorClass)
  expect((error as Error).message).toBe(`501: ${reason}${DOC}`)
  if (error instanceof SandboxError) {
    expect(error.statusCode).toBe(501)
  }
}

test('pause is refused', async () => {
  await refused(SandboxError, PAUSE, () => sandbox.pause())
  expect(await sandbox.isRunning()).toBe(true)
})

test('auto-pause is refused', async () => {
  await refused(SandboxError, 'autoPause (pause and resume) is not supported', () =>
    Sandbox.create({ lifecycle: { onTimeout: 'pause' } })
  )
})

test('snapshots are refused', async () => {
  await refused(SandboxError, SNAPSHOTS, () => sandbox.createSnapshot())
})

test('fork is refused', async () => {
  await refused(SandboxError, FORK, () => sandbox.fork())
})

test('network updates are refused', async () => {
  await refused(SandboxError, NETWORK, () => sandbox.updateNetwork({}))
})

test('volumes are refused', async () => {
  await refused(VolumeError, VOLUMES, () => Volume.create('volume'))
})

test('secrets are refused', async () => {
  await refused(SecretError, SECRETS, () => Secret.create({ name: 'name', value: 'value' }))
})

test('MCP is refused', async () => {
  await refused(SandboxError, 'MCP gateways are not supported', () => Sandbox.create({ mcp: { exa: { apiKey: 'x' } } }))
})

test('registered templates exist', async () => {
  expect(await Template.exists('base')).toBe(true)
  expect(await Template.exists('sandboxd-no-such-template')).toBe(false)
})
