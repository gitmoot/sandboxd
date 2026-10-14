"""sandboxd-authored: an e2b-profile process and its sandbox outlive the
client's stream (gitmoot/sandboxd#47). The upstream suites never drop a
stream and reconnect, nor stream more than the gitmoot-strict profile's
64 MiB output cap.

Copied by conformance/run.py into the python-e2b suite as tests/sandboxd/."""

import time

from e2b import Sandbox

# gitmoot-strict ends the sandbox past this much output on one process
# stream (internal/envd/handler.go); e2b-profile streams have no such cap.
STRICT_OUTPUT_CAP = 64 << 20


def test_process_outlives_a_dropped_stream():
    sandbox = Sandbox.create(timeout=120)
    try:
        cmd = sandbox.commands.run('while read -r line; do echo "got $line"; done', background=True, stdin=True)
        pid = cmd.pid
        cmd.disconnect()
        # Give the dropped stream time to reach sandboxd and envd: nothing
        # the client can observe signals that the server has seen the drop.
        time.sleep(2)

        assert sandbox.is_running()
        assert pid in [p.pid for p in sandbox.commands.list()]

        handle = sandbox.commands.connect(pid, timeout=30)
        sandbox.commands.send_stdin(pid, "hello\n")
        received = ""
        for stdout, _, _ in handle:
            received += stdout or ""
            if "got hello\n" in received:
                break
        assert received == "got hello\n"

        assert sandbox.commands.kill(pid)
        assert sandbox.commands.run("echo alive").stdout == "alive\n"
    finally:
        sandbox.kill()


def test_output_past_the_strict_cap_keeps_stream_and_sandbox():
    sandbox = Sandbox.create(timeout=180)
    try:
        size = STRICT_OUTPUT_CAP + (8 << 20)
        seen = 0

        def count(chunk):
            nonlocal seen
            seen += len(chunk)

        result = sandbox.commands.run(f"head -c {size} /dev/zero | tr '\\0' x", on_stdout=count, timeout=150)
        assert result.exit_code == 0
        assert seen == size

        assert sandbox.is_running()
        assert sandbox.commands.run("echo alive").stdout == "alive\n"
    finally:
        sandbox.kill()
