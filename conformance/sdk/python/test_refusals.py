"""sandboxd-authored: every unsupported E2B feature is refused with 501 and
its documented message, raised by the stock SDK as its generic API error
(docs/compatibility.md#not-supported).

Copied by conformance/run.py into the python-e2b suite as tests/sandboxd/."""

import pytest

from e2b import BuildException, Sandbox, SandboxException, Secret, Template, Volume
from e2b.exceptions import SecretException, VolumeException

DOC = "; see docs/compatibility.md#not-supported"
PAUSE = "pause and resume are not supported: sandboxd never pauses a sandbox (deferred, owner decision D7)"
SNAPSHOTS = "snapshots are not supported: sandboxd keeps no sandbox state after a sandbox ends (deferred with pause, D7)"
FORK = "fork is not supported: it needs snapshots (deferred with pause, D7)"
NETWORK = "network updates are not supported: a sandbox's network policy is fixed by the operator"
VOLUMES = "volumes are not supported: sandboxd keeps no storage beyond a sandbox's lifetime"
SECRETS = "secrets are not supported: pass values to a sandbox in envVars instead"
TEMPLATES = ("template builds and template management through the API are not supported: "
             "the operator builds and registers templates with the sandboxd CLI (D8)")
DELETE = ("deleting templates or snapshots through the API is not supported: the operator registers "
          "templates with the sandboxd CLI (D8) and sandboxd has no snapshots (D7)")


def refused(exception_type, reason, call):
    with pytest.raises(exception_type) as raised:
        call()
    assert str(raised.value) == "501: " + reason + DOC
    if isinstance(raised.value, SandboxException):
        assert raised.value.status_code == 501
    return raised.value


@pytest.fixture(scope="module")
def sandbox():
    sandbox = Sandbox.create(timeout=120)
    yield sandbox
    sandbox.kill()


def test_pause_is_refused(sandbox):
    refused(SandboxException, PAUSE, sandbox.pause)
    assert sandbox.is_running()


def test_auto_pause_is_refused():
    refused(SandboxException, "autoPause (pause and resume) is not supported", lambda: Sandbox.create(lifecycle={"on_timeout": "pause"}))


def test_snapshots_are_refused(sandbox):
    refused(SandboxException, SNAPSHOTS, sandbox.create_snapshot)
    refused(SandboxException, SNAPSHOTS, lambda: Sandbox.list_snapshots().next_items())
    refused(SandboxException, DELETE, lambda: Sandbox.delete_snapshot("snapshot-id"))


def test_fork_is_refused(sandbox):
    refused(SandboxException, FORK, sandbox.fork)


def test_network_update_is_refused(sandbox):
    refused(SandboxException, NETWORK, lambda: sandbox.update_network({}))


def test_volumes_are_refused():
    refused(VolumeException, VOLUMES, lambda: Volume.create("volume"))


def test_secrets_are_refused():
    refused(SecretException, SECRETS, lambda: Secret.create("name", "value"))
    refused(SecretException, SECRETS, lambda: Secret.list().next_items())


def test_mcp_is_refused():
    refused(SandboxException, "MCP gateways are not supported", lambda: Sandbox.create(mcp={"exa": {"apiKey": "x"}}))


def test_template_build_is_refused():
    refused(BuildException, TEMPLATES, lambda: Template.build(Template().from_image("ubuntu:22.04"), "sandboxd-refused"))


def test_registered_templates_exist():
    assert Template.exists("base") is True
    assert Template.exists("sandboxd-no-such-template") is False
