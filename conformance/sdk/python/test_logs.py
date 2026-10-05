"""sandboxd-authored: sandbox logs through the stock SDK's generated API
client (no Sandbox method calls the logs routes in SDK 2.52.0).

Copied by conformance/run.py into the python-e2b suite as tests/sandboxd/."""

import time

from e2b import Sandbox
from e2b.api.client.api.sandboxes import get_sandboxes_sandbox_id_logs as v1_logs
from e2b.api.client.api.sandboxes import get_v_2_sandboxes_sandbox_id_logs as v2_logs
from e2b.api.client.models import LogLevel, LogsDirection
from e2b.api.client_sync import get_api_client
from e2b.connection_config import ConnectionConfig
from e2b.exceptions import FileNotFoundException


def wait_for_logs(sandbox_id, client, predicate, **query):
    deadline = time.monotonic() + 15
    while True:
        res = v2_logs.sync_detailed(sandbox_id, client=client, **query)
        assert res.status_code == 200, res.content
        if predicate(res.parsed.logs) or time.monotonic() > deadline:
            return res


def test_logs_serve_envd_logs():
    client = get_api_client(ConnectionConfig())
    sandbox = Sandbox.create(timeout=120)
    try:
        sandbox.commands.run("echo $SANDBOXD_PROBE", envs={"SANDBOXD_PROBE": "do-not-log-me"})
        try:
            sandbox.files.read("/no/such/file")
        except FileNotFoundException:
            pass

        res = wait_for_logs(sandbox.sandbox_id, client,
                            lambda logs: any(e.level == LogLevel.ERROR for e in logs), level=LogLevel.ERROR)
        errors = res.parsed.logs
        assert errors and all(e.level == LogLevel.ERROR for e in errors)
        assert any(e.fields.additional_properties.get("source") == "envd" for e in errors)

        everything = v2_logs.sync_detailed(sandbox.sandbox_id, client=client)
        logs = everything.parsed.logs
        assert len(logs) > len(errors)
        assert [e.timestamp for e in logs] == sorted(e.timestamp for e in logs)
        assert any("started" in e.message for e in logs)
        # Command environments are never served.
        assert b"do-not-log-me" not in everything.content

        newest = v2_logs.sync_detailed(sandbox.sandbox_id, client=client, direction=LogsDirection.BACKWARD, limit=1)
        assert len(newest.parsed.logs) == 1 and newest.parsed.logs[0].timestamp == logs[-1].timestamp

        found = v2_logs.sync_detailed(sandbox.sandbox_id, client=client, search=errors[0].message)
        assert found.parsed.logs and all(errors[0].message in e.message for e in found.parsed.logs)

        old = v1_logs.sync_detailed(sandbox.sandbox_id, client=client, limit=2)
        assert old.status_code == 200, old.content
        assert [line.line for line in old.parsed.logs] == [e.message for e in logs[:2]]
    finally:
        sandbox.kill()

    gone = v2_logs.sync_detailed(sandbox.sandbox_id, client=client)
    assert gone.status_code == 404
