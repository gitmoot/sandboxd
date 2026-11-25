// sandboxd-authored: every unsupported E2B feature is refused with 501 and
// its documented message, raised by the stock SDK as its generic API error
// (docs/compatibility.md#not-supported). Copied by conformance/run.py into
// the js-e2b suite as tests/sandboxd/.
import { afterAll, beforeAll, expect, test } from 'vitest'

import { Sandbox, SandboxError, Secret, SecretError, Template } from '../../src'

const DOC = '; see docs/compatibility.md#not-supported'
const PAUSE_FILESYSTEM = "filesystem-only pause (memory=false) is not supported: a sandboxd pause always keeps the sandbox's memory"
const SNAPSHOTS = 'snapshots are not supported: sandboxd keeps no sandbox state after a sandbox ends (D7)'
const FORK = 'fork is not supported: it needs snapshots (D7)'
const NETWORK = "network updates are not supported: a sandbox's network policy is fixed by the operator"
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

test('filesystem-only pause is refused', async () => {
  await refused(SandboxError, PAUSE_FILESYSTEM, () => sandbox.pause({ keepMemory: false }))
  expect(await sandbox.isRunning()).toBe(true)
  await refused(SandboxError, PAUSE_FILESYSTEM, () =>
    Sandbox.create({ lifecycle: { onTimeout: { action: 'pause', keepMemory: false } } })
  )
})

test('auto-resume is refused', async () => {
  await refused(SandboxError, 'autoResume is not supported', () =>
    Sandbox.create({ lifecycle: { onTimeout: 'pause', autoResume: true } })
  )
})

test('reboot resume is refused', async () => {
  const paused = await Sandbox.create({ timeoutMs: 120_000 })
  try {
    expect(await paused.pause()).toBe(true)
    await refused(SandboxError, PAUSE_FILESYSTEM, () => Sandbox.connect(paused.sandboxId, { onResume: 'reboot' }))
    expect((await Sandbox.getInfo(paused.sandboxId)).state).toBe('paused')
  } finally {
    await paused.kill()
  }
}, 60_000)

test('snapshots are refused', async () => {
  await refused(SandboxError, SNAPSHOTS, () => sandbox.createSnapshot())
})

test('fork is refused', async () => {
  await refused(SandboxError, FORK, () => sandbox.fork())
})

test('network updates are refused', async () => {
  await refused(SandboxError, NETWORK, () => sandbox.updateNetwork({}))
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
