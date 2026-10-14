// sandboxd-authored: a volume mounted in a sandbox keeps its files after the
// sandbox ends, is attached to one sandbox at a time, and is deleted only when
// free. sandboxd serves volumes through mounts only: the volume content API
// stays refused (docs/compatibility.md). Copied by conformance/run.py into the
// js-e2b suite as tests/sandboxd/.
import { randomUUID } from 'node:crypto'

import { expect, test } from 'vitest'

import { Sandbox, SandboxError, Volume, VolumeError, VolumeNotFoundError } from '../../src'

const MOUNT = '/home/user/data'

test('volume outlives its sandbox', { timeout: 120_000 }, async () => {
  const volume = await Volume.create(`sandboxd-${randomUUID().slice(0, 12)}`)
  const sandboxes: Sandbox[] = []
  try {
    const first = await Sandbox.create({ timeoutMs: 120_000, volumeMounts: { [MOUNT]: volume } })
    sandboxes.push(first)
    await first.files.write(`${MOUNT}/kept.txt`, 'kept across sandboxes')
    const owner = await first.commands.run(`stat -c %U ${MOUNT}/kept.txt`)
    expect(owner.stdout.trim()).toBe('user')

    // One sandbox at a time.
    const refused = await Sandbox.create({ timeoutMs: 120_000, volumeMounts: { [MOUNT]: volume.name } }).then(
      (sandbox) => {
        sandboxes.push(sandbox)
        throw new Error('a second sandbox mounted an attached volume')
      },
      (err: unknown) => err
    )
    expect(refused).toBeInstanceOf(SandboxError)
    expect((refused as SandboxError).statusCode).toBe(409)

    expect((await Volume.list()).some((v) => v.volumeId === volume.volumeId && v.name === volume.name)).toBe(true)
    expect((await Volume.getInfo(volume.volumeId)).name).toBe(volume.name)
    const attached = Volume.destroy(volume.volumeId)
    await expect(attached).rejects.toBeInstanceOf(VolumeError)
    await expect(attached).rejects.toThrow(/^409: /)
    // The content API authenticates with the volume token, which sandboxd
    // does not serve; with the API key it reaches the refusal.
    const content = volume.list('/', {
      apiUrl: process.env.E2B_API_URL,
      headers: { 'X-API-Key': process.env.E2B_API_KEY! },
    })
    await expect(content).rejects.toBeInstanceOf(VolumeError)
    await expect(content).rejects.toThrow(/^501: /)

    await first.kill()
    const second = await Sandbox.create({ timeoutMs: 120_000, volumeMounts: { [MOUNT]: volume } })
    sandboxes.push(second)
    expect(await second.files.read(`${MOUNT}/kept.txt`)).toBe('kept across sandboxes')
    await second.kill()

    expect(await Volume.destroy(volume.volumeId)).toBe(true)
    await expect(Volume.getInfo(volume.volumeId)).rejects.toBeInstanceOf(VolumeNotFoundError)
    await expect(Volume.connect(volume.volumeId)).rejects.toBeInstanceOf(VolumeNotFoundError)
    expect((await Volume.list()).every((v) => v.volumeId !== volume.volumeId)).toBe(true)
    expect(await Volume.destroy(volume.volumeId)).toBe(false)
  } finally {
    for (const sandbox of sandboxes) {
      await sandbox.kill()
    }
    await Volume.destroy(volume.volumeId)
  }
})
