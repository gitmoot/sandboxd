"""sandboxd-authored: a volume mounted in a sandbox keeps its files after the
sandbox ends, is attached to one sandbox at a time, and is deleted only when
free. sandboxd serves volumes through mounts only: the volume content API
stays refused (docs/compatibility.md).

Copied by conformance/run.py into the python-e2b suite as tests/sandboxd/."""

import os
import uuid

import pytest

from e2b import Sandbox, SandboxException, Volume
from e2b.exceptions import VolumeException, VolumeNotFoundException

MOUNT = "/home/user/data"


def test_volume_outlives_its_sandbox():
    volume = Volume.create(f"sandboxd-{uuid.uuid4().hex[:12]}")
    sandboxes = []
    try:
        first = Sandbox.create(timeout=120, volume_mounts={MOUNT: volume})
        sandboxes.append(first)
        first.files.write(f"{MOUNT}/kept.txt", "kept across sandboxes")
        owner = first.commands.run(f"stat -c %U {MOUNT}/kept.txt")
        assert owner.stdout.strip() == "user"

        # One sandbox at a time.
        with pytest.raises(SandboxException) as raised:
            sandboxes.append(Sandbox.create(timeout=120, volume_mounts={MOUNT: volume.name}))
        assert raised.value.status_code == 409

        assert any(v.volume_id == volume.volume_id and v.name == volume.name for v in Volume.list())
        assert Volume.get_info(volume.volume_id).name == volume.name
        with pytest.raises(VolumeException) as raised:
            Volume.destroy(volume.volume_id)
        assert str(raised.value).startswith("409: ")
        # The content API authenticates with the volume token, which sandboxd
        # does not serve; with the API key it reaches the refusal.
        with pytest.raises(VolumeException) as raised:
            volume.list("/", api_url=os.environ["E2B_API_URL"], headers={"X-API-Key": os.environ["E2B_API_KEY"]})
        assert str(raised.value).startswith("501: ")

        first.kill()
        second = Sandbox.create(timeout=120, volume_mounts={MOUNT: volume})
        sandboxes.append(second)
        assert second.files.read(f"{MOUNT}/kept.txt") == "kept across sandboxes"
        second.kill()

        assert Volume.destroy(volume.volume_id) is True
        with pytest.raises(VolumeNotFoundException):
            Volume.get_info(volume.volume_id)
        with pytest.raises(VolumeNotFoundException):
            Volume.connect(volume.volume_id)
        assert all(v.volume_id != volume.volume_id for v in Volume.list())
        assert Volume.destroy(volume.volume_id) is False
    finally:
        for sandbox in sandboxes:
            sandbox.kill()
        Volume.destroy(volume.volume_id)
