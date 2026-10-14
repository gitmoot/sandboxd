// sandboxd-authored: an e2b-profile process and its sandbox outlive the
// client's stream (gitmoot/sandboxd#47). The upstream suites never drop a
// stream and reconnect, nor stream more than the gitmoot-strict profile's
// 64 MiB output cap. Copied by conformance/run.py into the js-e2b suite as
// tests/sandboxd/.
import { expect, test } from 'vitest'

import { Sandbox } from '../../src'

// gitmoot-strict ends the sandbox past this much output on one process
// stream (internal/envd/handler.go); e2b-profile streams have no such cap.
const strictOutputCap = 64 << 20

test('process outlives a dropped stream', { timeout: 90_000 }, async () => {
  const sandbox = await Sandbox.create({ timeoutMs: 120_000 })
  try {
    const cmd = await sandbox.commands.run('while read -r line; do echo "got $line"; done', {
      background: true,
      stdin: true,
    })
    const pid = cmd.pid
    await cmd.disconnect()
    // Give the dropped stream time to reach sandboxd and envd: nothing the
    // client can observe signals that the server has seen the drop.
    await new Promise((resolve) => setTimeout(resolve, 2_000))

    expect(await sandbox.isRunning()).toBe(true)
    expect((await sandbox.commands.list()).map((p) => p.pid)).toContain(pid)

    let received = ''
    const { promise: line, resolve: gotLine } = Promise.withResolvers<void>()
    const handle = await sandbox.commands.connect(pid, {
      timeoutMs: 30_000,
      onStdout: (data) => {
        received += data
        if (received.includes('got hello\n')) gotLine()
      },
    })
    await sandbox.commands.sendStdin(pid, 'hello\n')
    await line
    expect(received).toBe('got hello\n')

    expect(await handle.kill()).toBe(true)
    expect((await sandbox.commands.run('echo alive')).stdout).toBe('alive\n')
  } finally {
    await sandbox.kill()
  }
})

test('output past the strict cap keeps stream and sandbox', { timeout: 180_000 }, async () => {
  const sandbox = await Sandbox.create({ timeoutMs: 180_000 })
  try {
    const size = strictOutputCap + (8 << 20)
    let seen = 0
    const result = await sandbox.commands.run(`head -c ${size} /dev/zero | tr '\\0' x`, {
      onStdout: (data) => {
        seen += data.length
      },
      timeoutMs: 150_000,
    })
    expect(result.exitCode).toBe(0)
    expect(seen).toBe(size)

    expect(await sandbox.isRunning()).toBe(true)
    expect((await sandbox.commands.run('echo alive')).stdout).toBe('alive\n')
  } finally {
    await sandbox.kill()
  }
})
