// sandboxd-authored: sandbox logs through the stock SDK's API client (no
// Sandbox method calls the logs routes in SDK 2.52.0). Copied by
// conformance/run.py into the js-e2b suite as tests/sandboxd/.
import { expect, test } from 'vitest'

import { ApiClient, ConnectionConfig, FileNotFoundError, Sandbox } from '../../src'

test('logs serve envd logs', { timeout: 60_000 }, async () => {
  const client = new ApiClient(new ConnectionConfig())
  const sandbox = await Sandbox.create({ timeoutMs: 120_000 })
  const logs = (query: Record<string, string | number> = {}) =>
    client.api.GET('/v2/sandboxes/{sandboxID}/logs', {
      params: { path: { sandboxID: sandbox.sandboxId }, query },
    })
  try {
    await sandbox.commands.run('echo $SANDBOXD_PROBE', { envs: { SANDBOXD_PROBE: 'do-not-log-me' } })
    await expect(sandbox.files.read('/no/such/file')).rejects.toBeInstanceOf(FileNotFoundError)

    let errors: { level: string; message: string; fields: Record<string, string> }[] = []
    for (const deadline = Date.now() + 15_000; errors.length === 0 && Date.now() < deadline; ) {
      const res = await logs({ level: 'error' })
      expect(res.response.status).toBe(200)
      errors = res.data!.logs
    }
    expect(errors.length).toBeGreaterThan(0)
    expect(errors.every((e) => e.level === 'error')).toBe(true)
    expect(errors.some((e) => e.fields.source === 'envd')).toBe(true)

    const all = await logs()
    const entries = all.data!.logs
    expect(entries.length).toBeGreaterThan(errors.length)
    expect(entries.some((e) => e.message.includes('started'))).toBe(true)
    expect(JSON.stringify(entries)).not.toContain('do-not-log-me')

    const newest = await logs({ direction: 'backward', limit: 1 })
    expect(newest.data!.logs).toEqual([entries[entries.length - 1]])

    const old = await client.api.GET('/sandboxes/{sandboxID}/logs', {
      params: { path: { sandboxID: sandbox.sandboxId }, query: { limit: 2 } },
    })
    expect(old.data!.logs.map((l) => l.line)).toEqual(entries.slice(0, 2).map((e) => e.message))
  } finally {
    await sandbox.kill()
  }
  expect((await logs()).response.status).toBe(404)
})
