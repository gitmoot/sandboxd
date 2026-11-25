"""sandboxd-authored: every unsupported E2B feature is refused with 501 and
its documented message, raised by the stock SDK as its generic API error
(docs/compatibility.md#not-supported).

Copied by conformance/run.py into the python-e2b suite as tests/sandboxd/."""

import pytest

from e2b import BuildException, Sandbox, SandboxException, Secret, Template
from e2b.exceptions import SecretException

DOC = "; see docs/compatibility.md#not-supported"
PAUSE_FILESYSTEM = "filesystem-only pause (memory=false) is not supported: a sandboxd pause always keeps the sandbox's memory"
SNAPSHOTS = "snapshots are not supported: sandboxd keeps no sandbox state after a sandbox ends (D7)"
FORK = "fork is not supported: it needs snapshots (D7)"
NETWORK = "network updates are not supported: a sandbox's network policy is fixed by the operator"
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


def test_filesystem_only_pause_is_refused(sandbox):
    refused(SandboxException, PAUSE_FILESYSTEM, lambda: sandbox.pause(keep_memory=False))
    assert sandbox.is_running()
    refused(SandboxException, PAUSE_FILESYSTEM,
            lambda: Sandbox.create(lifecycle={"on_timeout": {"action": "pause", "keep_memory": False}}))


def test_auto_resume_is_refused():
    refused(SandboxException, "autoResume is not supported",
            lambda: Sandbox.create(lifecycle={"on_timeout": "pause", "auto_resume": True}))


def test_reboot_resume_is_refused():
    paused = Sandbox.create(timeout=120)
    try:
        assert paused.pause() is True
        refused(SandboxException, PAUSE_FILESYSTEM, lambda: Sandbox.connect(paused.sandbox_id, on_resume="reboot"))
        assert Sandbox.get_info(paused.sandbox_id).state == "paused"
    finally:
        paused.kill()


def test_snapshots_are_refused(sandbox):
    refused(SandboxException, SNAPSHOTS, sandbox.create_snapshot)
    refused(SandboxException, SNAPSHOTS, lambda: Sandbox.list_snapshots().next_items())
    refused(SandboxException, DELETE, lambda: Sandbox.delete_snapshot("snapshot-id"))


def test_fork_is_refused(sandbox):
    refused(SandboxException, FORK, sandbox.fork)


def test_network_update_is_refused(sandbox):
    refused(SandboxException, NETWORK, lambda: sandbox.update_network({}))


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
