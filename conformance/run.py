#!/usr/bin/env python3
"""Run the pinned upstream E2B SDK suites and the pinned Gitmoot client
conformance test against sandboxd-dev (the CI-only devvm driver) and gate on
the recorded per-test outcomes.

Modes:
  run.py            run every suite, compare with conformance/expected.json,
                    exit 1 when any recorded outcome changed (in either
                    direction) or the committed matrix is stale; exit 2 on a
                    harness failure, including a test file with no operation
                    mapping or a moved upstream tag.
  run.py --update   run every suite, rerun it once against a null server
                    (sandboxd offline) to classify which passing tests do not
                    need sandboxd, and
                    rewrite conformance/expected.json and
                    docs/conformance-matrix.md from the observed outcomes.
  run.py --render   only re-render docs/conformance-matrix.md from
                    conformance/expected.json.

The SDK suites are configured only through E2B_API_URL, E2B_SANDBOX_URL,
E2B_API_KEY and E2B_DOMAIN; every other E2B_* variable is removed from their
environment. Needs git, go, python3 (3.11+), node (22+) with npx, and root or
passwordless sudo: e2b guests run the pinned upstream envd as root.
Standard library only.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import http.server
import json
import os
import re
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CONFORMANCE = REPO / "conformance"
EXPECTED = CONFORMANCE / "expected.json"
MATRIX = REPO / "docs" / "conformance-matrix.md"

E2B_REPO = "https://github.com/e2b-dev/E2B"
GITMOOT_REPO = "https://github.com/gitmoot/gitmoot"
# Tag -> commit pins. The harness refuses to run if a tag moved.
E2B_SDK_COMMIT = "970b34dc24d628f8061e539925468c123e345d5f"
E2B_CI_JS_COMMIT = "10235faa2878a4ef38547f8ea7e676d7bd25c585"
GITMOOT_COMMIT = "a61e1435e7625bf062e05eed21337765833eade6"
NPM = "npm@11.21.0"
# Templates sandboxd-dev registers: Gitmoot's strict template, and the SDK
# suites' default "base" as an alias of an e2b-profile template, whose guests
# run the pinned upstream envd (the same release as images/e2b-amd64-fc);
# ENVD_VERSION is that release, reported to the SDKs.
STRICT_TEMPLATE = "review-arm64"
E2B_TEMPLATE = "sandboxd-base"
E2B_ALIAS = "base"
ENVD_VERSION = "0.9.0"
ENVD_URL = "https://storage.googleapis.com/e2b-artifact-binaries/envd/v0.9.0/envd"
ENVD_SHA256 = "c42a31d738718b5cf7654e258e5b111308646a905331b266294cdcbeb0a02355"
DOMAIN = "sandboxd.test"
SUITE_TIMEOUT = 45 * 60
SDK_ENV = ("E2B_API_URL", "E2B_SANDBOX_URL", "E2B_API_KEY", "E2B_DOMAIN")


@dataclass(frozen=True)
class Suite:
    name: str
    title: str
    version: str
    tag: str
    commit: str


SUITES = (
    Suite("python-e2b", "Python e2b", "2.52.0", "@e2b/python-sdk@2.52.0", E2B_SDK_COMMIT),
    Suite("js-e2b", "JS e2b", "2.52.0", "e2b@2.52.0", E2B_SDK_COMMIT),
    Suite("python-code-interpreter", "Python code-interpreter", "2.10.1", "@e2b/code-interpreter-python@2.10.1", E2B_SDK_COMMIT),
    Suite("js-code-interpreter", "JS code-interpreter", "2.8.0", "@e2b/code-interpreter@2.8.0", E2B_CI_JS_COMMIT),
    Suite("gitmoot", "Gitmoot client", GITMOOT_COMMIT[:8], "", GITMOOT_COMMIT),
)
SUITE_BY_NAME = {suite.name: suite for suite in SUITES}

# Rows of the matrix: (area, operation, normalized test-file keys). Keys come
# from normalize_key(); every test file of every suite must map to exactly one
# operation, so a suite bump that adds files fails until they are placed here.
OPERATIONS: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("Control plane", "`Sandbox.create`", ("create",)),
    ("Control plane", "`Sandbox.connect`", ("connect",)),
    ("Control plane", "`Sandbox.kill`", ("kill", "api/kill")),
    ("Control plane", "`Sandbox.get_info`", ("api/info",)),
    ("Control plane", "`Sandbox.list`", ("api/list",)),
    ("Control plane", "`set_timeout`", ("timeout",)),
    ("Control plane", "`get_metrics`", ("metrics",)),
    ("Control plane", "secure envd access token", ("secure",)),
    ("Control plane", "`get_host` / guest ports", ("host",)),
    ("Control plane", "pause, resume, snapshots", ("snapshot", "snapshot_api", "snapshot_filesystem_only", "api/snapshot", "on_resume_request")),
    ("Control plane", "lifecycle options (autoPause, onTimeout)", ("lifecycle_request", "lifecycle_payload")),
    ("Control plane", "`fork`", ("fork",)),
    ("Control plane", "network, internet access, egress proxy", ("network", "network_transform", "internet_access", "egress_proxy")),
    ("Control plane", "IAM", ("iam",)),
    ("Control plane", "client config and request plumbing", (
        "config_propagation", "api_defaults", "abort_signal", "sync_client_lifecycle", "http_version", "rpc_headers", "urls",
        "api/api_key", "api/handle_api_error", "api/http2", "api/inflight")),
    ("Commands", "`commands.run`", ("commands/run", "commands/command_handle")),
    ("Commands", "`commands.run` envs", ("commands/env_vars",)),
    ("Commands", "`commands.connect`", ("commands/connect",)),
    ("Commands", "`commands.kill`", ("commands/kill",)),
    ("Commands", "`commands.list`", ("commands/list",)),
    ("Commands", "`commands.send_stdin`", ("commands/send_stdin",)),
    ("Commands", "sandbox killed during a command", ("commands/sandbox_killed_during_run",)),
    ("Files", "`files.write`", ("files/write",)),
    ("Files", "`files.read`", ("files/read",)),
    ("Files", "`files.list`", ("files/list",)),
    ("Files", "`files.exists`", ("files/exists",)),
    ("Files", "`files.get_info`", ("files/info", "files/entry_info")),
    ("Files", "`files.make_dir`", ("files/make_dir",)),
    ("Files", "`files.remove`", ("files/remove",)),
    ("Files", "`files.rename`", ("files/rename",)),
    ("Files", "`files.watch_dir`", ("files/watch", "files/watch_handle")),
    ("Files", "file metadata", ("files/metadata",)),
    ("Files", "content encoding (gzip)", ("files/content_encoding",)),
    ("Files", "signed upload/download URLs", ("files/secured", "files/signing")),
    ("PTY", "`pty.create`", ("pty/pty", "pty/create")),
    ("PTY", "`pty.connect`", ("pty/connect",)),
    ("PTY", "`pty.kill`", ("pty/kill",)),
    ("PTY", "`pty.resize`", ("pty/resize",)),
    ("PTY", "`pty.send_input`", ("pty/send_input",)),
    ("Templates, volumes, secrets", "template build API", (
        "template/abort_signal", "template/api_defaults", "template/background_build", "template/bound_api_params",
        "template/bound_opts", "template/build", "template/exists", "template/methods/from_dockerfile",
        "template/methods/make_symlink", "template/methods/run_cmd", "template/methods/to_dockerfile",
        "template/stacktrace", "template/tags", "template/upload_file")),
    ("Templates, volumes, secrets", "volumes", ("volume/file", "volume/http_version", "volume/volume", "volume/volume_content")),
    ("Templates, volumes, secrets", "secrets", ("secret/secret",)),
    ("Code interpreter", "`run_code`", ("ci:basic", "ci:statefulness", "ci:execution_count", "ci:error_diagnostics", "ci:custom_repr_object")),
    ("Code interpreter", "`run_code` streaming and callbacks", ("ci:streaming", "ci:callbacks", "ci:messaging")),
    ("Code interpreter", "`run_code` results (data, display, images)", ("ci:data", "ci:display_data", "ci:images/bar", "ci:images/images")),
    ("Code interpreter", "`run_code` charts", (
        "ci:charts/bar", "ci:charts/box_and_whisker", "ci:charts/box_and_whiskers", "ci:charts/json", "ci:charts/line",
        "ci:charts/log", "ci:charts/log_chart", "ci:charts/pie", "ci:charts/scale", "ci:charts/scales",
        "ci:charts/scatter", "ci:charts/superchart", "ci:charts/unknown")),
    ("Code interpreter", "`run_code` envs", ("ci:env_vars/bash", "ci:env_vars/java", "ci:env_vars/js", "ci:env_vars/python", "ci:env_vars/r")),
    ("Code interpreter", "languages and kernels", ("ci:bash", "ci:default_kernels", "ci:kernels", "ci:java_kernel_readiness")),
    ("Code interpreter", "contexts and cwd", ("ci:contexts", "ci:cwd")),
    ("Code interpreter", "interrupt and execute timeout", ("ci:interrupt", "ci:execute_timeout")),
    ("Code interpreter", "killed sandbox handling", ("ci:killed", "ci:killed_sandbox")),
    ("Code interpreter", "reconnect", ("ci:reconnect",)),
    ("Code interpreter", "sandbox URL routing", ("ci:sandbox_url",)),
    ("Code interpreter", "systemd services", ("ci:systemd",)),
    ("Gitmoot", "pinned client conformance (v1 create, get, list, timeout, metrics, upload, start, cancel, delete)", ("gitmoot:conformance",)),
    ("Gitmoot", "client fixture tests (offline)", ("gitmoot:fixtures",)),
)
KEY_TO_OPERATION = {key: operation for _, operation, keys in OPERATIONS for key in keys}
OUTCOMES = ("pass", "fail", "skip")


class HarnessError(Exception):
    """The harness itself failed; no conformance verdict is possible."""


# ---------------------------------------------------------------- mapping


def camel_to_snake(value: str) -> str:
    return re.sub(r"(?<=[a-z0-9])([A-Z])", r"_\1", value).lower()


def normalize_key(suite: str, test_file: str) -> str:
    """Map a test file path (relative to the suite's tests directory) to the
    language-neutral key used by OPERATIONS."""
    if suite == "gitmoot":
        raise ValueError("gitmoot keys come from test names")
    parts = test_file.split("/")
    base = parts[-1]
    for suffix in (".test.ts", ".py"):
        base = base.removesuffix(suffix)
    for prefix in ("test_async_", "test_"):
        if base.startswith(prefix):
            base = base[len(prefix):]
            break
    base = camel_to_snake(base).replace("-", "_")
    dirs = [re.sub(r"_(a?sync)$", "", camel_to_snake(d)) for d in parts[:-1] if d not in ("sync", "async", "sandbox_sync", "sandbox_async")]
    if dirs[:1] == ["sandbox"]:
        dirs = dirs[1:]
    group = dirs[0] if dirs else ""
    for redundant in {"api": "sbx_", "commands": "cmd_", "files": "files_", "pty": "pty_"}.get(group, "").split():
        if base.startswith(redundant):
            base = base[len(redundant):]
    key = "/".join(dirs + [base])
    return "ci:" + key if "code-interpreter" in suite else key


def test_key(suite: str, test_id: str) -> str:
    if suite == "gitmoot":
        return "gitmoot:conformance" if test_id == "TestSandboxdPinnedClientConformance" else "gitmoot:fixtures"
    return normalize_key(suite, re.split(r"::| > ", test_id, maxsplit=1)[0])


def operation_for(suite: str, test_id: str) -> str:
    key = test_key(suite, test_id)
    if key not in KEY_TO_OPERATION:
        raise HarnessError(f"{suite}: test {test_id!r} (key {key!r}) has no operation in conformance/run.py OPERATIONS")
    return KEY_TO_OPERATION[key]


# ---------------------------------------------------------------- parsers


def unique(results: dict[str, str], test_id: str, outcome: str) -> None:
    candidate, n = test_id, 2
    while candidate in results:
        candidate, n = f"{test_id} #{n}", n + 1
    results[candidate] = outcome


def parse_junit(path: Path) -> dict[str, str]:
    """Parse pytest's xunit1 JUnit XML into {file::[Class::]name: outcome}."""
    results: dict[str, str] = {}
    root = ET.parse(path).getroot()
    for case in root.iter("testcase"):
        test_file = case.get("file") or ""
        name = case.get("name") or ""
        classname = case.get("classname") or ""
        module = test_file.removesuffix(".py").replace("/", ".")
        # classname is "<module>" or "<module>.<Class>"; keep only the class.
        index = classname.find(module + ".") if module else -1
        cls = classname[index + len(module) + 1:] if index >= 0 else ""
        if not test_file:
            # Collection errors have no file; classname is the dotted module.
            test_file = classname.replace(".", "/") + ".py"
        test_file = test_file.removeprefix("tests/")
        outcome = "pass"
        if case.find("failure") is not None or case.find("error") is not None:
            outcome = "fail"
        elif case.find("skipped") is not None:
            outcome = "skip"
        unique(results, "::".join(p for p in (test_file, cls, name) if p), outcome)
    return results


def parse_vitest(path: Path, package_dir: Path) -> dict[str, str]:
    """Parse vitest's JSON reporter into {file > describe > test: outcome}.
    A file that failed to load without reporting tests counts as one failure."""
    data = json.loads(path.read_text())
    results: dict[str, str] = {}
    tests_dir = package_dir / "tests"
    for file_result in data.get("testResults", []):
        test_file = Path(file_result["name"]).resolve().relative_to(tests_dir.resolve()).as_posix()
        assertions = file_result.get("assertionResults", [])
        if not assertions:
            unique(results, f"{test_file} > (file)", "fail" if file_result.get("status") == "failed" else "skip")
            continue
        for item in assertions:
            status = item.get("status")
            outcome = {"passed": "pass", "failed": "fail"}.get(status, "skip")
            unique(results, " > ".join([test_file, *item.get("ancestorTitles", []), item.get("title", "")]), outcome)
    return results


def parse_go_json(lines: str) -> dict[str, str]:
    results: dict[str, str] = {}
    for line in lines.splitlines():
        if not line.startswith("{"):
            continue
        event = json.loads(line)
        test, action = event.get("Test"), event.get("Action")
        if not test or action not in ("pass", "fail", "skip"):
            continue
        results[test] = action
    return results


# ---------------------------------------------------------------- comparison


@dataclass
class Drift:
    regressions: list[tuple[str, str, str, str]] = field(default_factory=list)
    improvements: list[tuple[str, str, str, str]] = field(default_factory=list)
    changes: list[tuple[str, str, str, str]] = field(default_factory=list)

    def empty(self) -> bool:
        return not (self.regressions or self.improvements or self.changes)


def compare(expected: dict[str, dict[str, str]], observed: dict[str, dict[str, str]]) -> Drift:
    """Compare per-test outcomes of the suites present in observed. A test
    missing from either side is a change ("absent")."""
    drift = Drift()
    for suite, results in observed.items():
        recorded = expected.get(suite, {})
        for test_id in sorted(set(recorded) | set(results)):
            before, after = recorded.get(test_id, "absent"), results.get(test_id, "absent")
            if before == after:
                continue
            entry = (suite, test_id, before, after)
            if before == "pass":
                drift.regressions.append(entry)
            elif after == "pass":
                drift.improvements.append(entry)
            else:
                drift.changes.append(entry)
    return drift


def format_drift(drift: Drift) -> str:
    out = []
    for title, entries in (("REGRESSIONS (recorded pass, now not passing)", drift.regressions),
                           ("UNRECORDED IMPROVEMENTS (record them with --update)", drift.improvements),
                           ("OTHER CHANGES", drift.changes)):
        if not entries:
            continue
        out.append(f"{title}: {len(entries)}")
        cells: dict[tuple[str, str], list[str]] = {}
        for suite, test_id, before, after in entries:
            try:
                operation = operation_for(suite, test_id)
            except HarnessError:
                operation = "(unmapped)"
            cells.setdefault((operation, SUITE_BY_NAME[suite].title), []).append(f"{test_id}: {before} -> {after}")
        for (operation, title_), lines in sorted(cells.items()):
            out.append(f"  cell {operation} / {title_}:")
            out.extend(f"    {line}" for line in lines)
    return "\n".join(out)


# ---------------------------------------------------------------- matrix


def cell_counts(results: dict[str, dict[str, str]], offline: dict[str, list[str]]) -> dict[tuple[str, str], dict[str, int]]:
    counts: dict[tuple[str, str], dict[str, int]] = {}
    for suite, tests in results.items():
        serverless = set(offline.get(suite, ()))
        for test_id, outcome in tests.items():
            cell = counts.setdefault((operation_for(suite, test_id), suite), {o: 0 for o in (*OUTCOMES, "offline")})
            cell[outcome] += 1
            if outcome == "pass" and test_id in serverless:
                cell["offline"] += 1
    return counts


def cell_text(cell: dict[str, int] | None) -> str:
    """Passed/run of the tests that need sandboxd; tests that also pass with
    sandboxd offline (upstream mocks and client-side checks) are counted
    separately so they cannot make a cell look green."""
    if not cell:
        return "—"
    live = cell["pass"] - cell["offline"]
    run = live + cell["fail"]
    notes = []
    if cell["offline"]:
        notes.append(f"+{cell['offline']} offline")
    if cell["skip"]:
        notes.append(f"{cell['skip']} skip")
    suffix = f" ({', '.join(notes)})" if notes else ""
    if run == 0:
        return f"⚪{suffix}" if notes else "—"
    mark = "✅" if cell["fail"] == 0 else ("❌" if live == 0 else "🟡")
    return f"{mark} {live}/{run}{suffix}"


def render_matrix(results: dict[str, dict[str, str]], offline: dict[str, list[str]]) -> str:
    counts = cell_counts(results, offline)
    suites = [suite for suite in SUITES if suite.name in results]
    lines = [
        "# E2B SDK conformance matrix",
        "",
        "Generated by `conformance/run.py --update` from `conformance/expected.json`; do not edit by hand.",
        "CI (`.github/workflows/conformance.yml`) reruns every suite on each pull request against",
        "`sandboxd-dev`, the CI-only `devvm` driver (local processes, no isolation), and fails when any",
        "recorded outcome changes. A regression fails the gate; so does an unrecorded improvement, which",
        "must be committed with `--update` so this file always shows the current state.",
        "",
        "Pinned inputs (stock SDKs configured only by `E2B_API_URL`, `E2B_SANDBOX_URL`, `E2B_API_KEY`, `E2B_DOMAIN`):",
        "",
        "| Suite | Version | Upstream tests | Commit |",
        "| --- | --- | --- | --- |",
    ]
    for suite in suites:
        if suite.name == "gitmoot":
            lines.append(f"| {suite.title} | `internal/execbackend/e2b` | `{GITMOOT_REPO.removeprefix('https://github.com/')}` | `{suite.commit}` |")
        else:
            lines.append(f"| {suite.title} | {suite.version} | `e2b-dev/E2B` tag `{suite.tag}` | `{suite.commit}` |")
    lines += [
        "",
        "Each cell counts the tests that need sandboxd: passed/run, with ✅ all pass, 🟡 some pass,",
        "❌ none pass, — no tests. `+N offline` counts tests that also pass with sandboxd offline, i.e.",
        "against a null server answering every request with 404 (upstream tests that mock the API or",
        "check only client-side behaviour). They are gated like every other test but say nothing about",
        "sandboxd. ⚪ means a cell has only such tests.",
        "",
        "| Area | Operation | " + " | ".join(s.title for s in suites) + " |",
        "| --- | --- | " + " | ".join("---" for _ in suites) + " |",
    ]
    for area, operation, _ in OPERATIONS:
        cells = [cell_text(counts.get((operation, s.name))) for s in suites]
        if all(c == "—" for c in cells):
            continue
        lines.append(f"| {area} | {operation} | " + " | ".join(cells) + " |")
    totals = {o: sum(c[o] for c in counts.values()) for o in (*OUTCOMES, "offline")}
    lines += [
        "",
        f"Totals: {totals['pass'] - totals['offline']} pass against sandboxd, {totals['offline']} pass offline,",
        f"{totals['fail']} expected failures, {totals['skip']} skipped.",
        "",
        "## Expected failures",
        "",
        "Every test below fails today and is recorded as `fail` in `conformance/expected.json`.",
        "A later milestone turns a cell green by making these pass and recording them.",
        "",
    ]
    for area, operation, _ in OPERATIONS:
        failing = []
        for suite in suites:
            for test_id, outcome in sorted(results[suite.name].items()):
                if outcome == "fail" and operation_for(suite.name, test_id) == operation:
                    failing.append(f"- {suite.title}: {code_span(test_id)}")
        if not failing:
            continue
        lines += [f"<details><summary>{area}: {operation} ({len(failing)})</summary>", "", *failing, "", "</details>", ""]
    return "\n".join(lines).rstrip() + "\n"


def code_span(text: str) -> str:
    return f"`` {text} ``" if "`" in text else f"`{text}`"


@dataclass
class Recorded:
    """conformance/expected.json: outcomes against sandboxd-dev, plus the
    passing tests that also pass with sandboxd offline."""

    suites: dict[str, dict[str, str]]
    offline: dict[str, list[str]]

    def matrix(self) -> str:
        return render_matrix(self.suites, self.offline)


def load_expected() -> Recorded:
    if not EXPECTED.exists():
        return Recorded({}, {})
    data = json.loads(EXPECTED.read_text())
    return Recorded(data["suites"], data.get("offline", {}))


def write_expected(recorded: Recorded) -> None:
    order = [s.name for s in SUITES]
    payload = {
        "comment": "Per-test outcomes against sandboxd-dev; 'offline' lists the passing tests that also pass against a null server. Regenerate with conformance/run.py --update.",
        "suites": {name: dict(sorted(recorded.suites[name].items())) for name in order if name in recorded.suites},
        "offline": {name: sorted(recorded.offline[name]) for name in order if recorded.offline.get(name)},
    }
    EXPECTED.write_text(json.dumps(payload, indent=1, ensure_ascii=False) + "\n")


# ---------------------------------------------------------------- execution


def log(message: str) -> None:
    print(f"[conformance] {message}", flush=True)


def sh(args: list[str], cwd: Path | None = None, env: dict[str, str] | None = None, timeout: int = 900) -> str:
    result = subprocess.run(args, cwd=cwd, env=env, capture_output=True, text=True, timeout=timeout)
    if result.returncode != 0:
        raise HarnessError(f"{' '.join(args)} failed ({result.returncode}):\n{result.stdout[-4000:]}\n{result.stderr[-4000:]}")
    return result.stdout


def verify_tag(repo: str, tag: str, commit: str) -> None:
    out = sh(["git", "ls-remote", "--tags", repo, f"refs/tags/{tag}", f"refs/tags/{tag}^{{}}"], timeout=120)
    refs = dict(line.split("\t")[::-1] for line in out.splitlines() if "\t" in line)
    peeled = refs.get(f"refs/tags/{tag}^{{}}") or refs.get(f"refs/tags/{tag}")
    if peeled != commit:
        raise HarnessError(f"tag {tag} resolves to {peeled}, pinned {commit}; bump the pin explicitly")


def checkout(repo: str, commit: str, dest: Path, sparse: list[str] | None) -> None:
    if (dest / ".conformance-ok").exists():
        return
    shutil.rmtree(dest, ignore_errors=True)
    dest.mkdir(parents=True)
    sh(["git", "init", "-q"], cwd=dest)
    sh(["git", "fetch", "-q", "--depth", "1", "--filter=blob:none", repo, commit], cwd=dest, timeout=600)
    if sparse:
        sh(["git", "sparse-checkout", "set", "--no-cone", *sparse], cwd=dest)
    sh(["git", "-c", "advice.detachedHead=false", "checkout", "-q", "FETCH_HEAD"], cwd=dest, timeout=600)
    head = sh(["git", "rev-parse", "HEAD"], cwd=dest).strip()
    if head != commit:
        raise HarnessError(f"{repo} checkout is {head}, wanted {commit}")
    (dest / ".conformance-ok").touch()


@dataclass
class Workspace:
    root: Path

    @property
    def sdk(self) -> Path:
        return self.root / "src" / "e2b-sdk"

    @property
    def ci_js(self) -> Path:
        return self.root / "src" / "e2b-code-interpreter-js"

    @property
    def gitmoot(self) -> Path:
        return self.root / "src" / "gitmoot"

    @property
    def venv_python(self) -> Path:
        return self.root / "venv" / "bin" / "python"

    @property
    def node_modules(self) -> Path:
        return self.root / "js" / "node_modules"

    @property
    def envd(self) -> Path:
        return self.root / "bin" / f"envd-{ENVD_VERSION}"

    @property
    def server(self) -> Path:
        return self.root / "bin" / "sandboxd-dev"

    @property
    def logs(self) -> Path:
        return self.root / "logs"


def prepare(ws: Workspace, suites: list[Suite]) -> None:
    names = {s.name for s in suites}
    ws.logs.mkdir(parents=True, exist_ok=True)
    for suite in suites:
        if suite.tag:
            verify_tag(E2B_REPO, suite.tag, suite.commit)
    if names & {"python-e2b", "js-e2b", "python-code-interpreter"}:
        log(f"fetching e2b-dev/E2B@{E2B_SDK_COMMIT[:12]} test sources")
        # The Python packages contribute only tests: the SDK under test is the
        # published wheel installed from conformance/python/requirements.txt.
        checkout(E2B_REPO, E2B_SDK_COMMIT, ws.sdk, [
            "/packages/python-sdk/tests/", "/packages/python-sdk/pytest.ini",
            "/packages/code-interpreter-python/tests/", "/packages/code-interpreter-python/pytest.ini",
            "/packages/js-sdk/", "!/packages/js-sdk/tests/runtimes/", "/tsconfig.sdk.json", "/vitest.sdk.config.mts",
        ])
    if "js-code-interpreter" in names:
        log(f"fetching e2b-dev/E2B@{E2B_CI_JS_COMMIT[:12]} code-interpreter JS sources")
        checkout(E2B_REPO, E2B_CI_JS_COMMIT, ws.ci_js, [
            "/packages/code-interpreter-js/", "!/packages/code-interpreter-js/tests/runtimes/",
            "/tsconfig.sdk.json", "/vitest.sdk.config.mts",
        ])
    if "gitmoot" in names:
        log(f"fetching gitmoot@{GITMOOT_COMMIT[:12]}")
        checkout(GITMOOT_REPO, GITMOOT_COMMIT, ws.gitmoot, None)
    if names & {"python-e2b", "python-code-interpreter"} and not (ws.root / "venv" / ".conformance-ok").exists():
        log("installing pinned Python SDKs into a throwaway venv")
        shutil.rmtree(ws.root / "venv", ignore_errors=True)
        sh([sys.executable, "-m", "venv", str(ws.root / "venv")])
        sh([str(ws.venv_python), "-m", "pip", "install", "-q", "--disable-pip-version-check", "--require-hashes",
            "-r", str(CONFORMANCE / "python" / "requirements.txt")], timeout=900)
        (ws.root / "venv" / ".conformance-ok").touch()
    if names & {"js-e2b", "js-code-interpreter"} and not (ws.root / "js" / ".conformance-ok").exists():
        log("installing pinned JS dependencies into a throwaway npm dir")
        shutil.rmtree(ws.root / "js", ignore_errors=True)
        (ws.root / "js").mkdir(parents=True)
        for name in ("package.json", "package-lock.json"):
            shutil.copy(CONFORMANCE / "js" / name, ws.root / "js" / name)
        sh(["npx", "-y", NPM, "ci", "--ignore-scripts", "--no-audit", "--no-fund"], cwd=ws.root / "js", timeout=900)
        (ws.root / "js" / ".conformance-ok").touch()
    for package in (ws.sdk / "packages" / "js-sdk", ws.ci_js / "packages" / "code-interpreter-js"):
        if package.is_dir() and not (package / "node_modules").exists():
            (package / "node_modules").symlink_to(ws.node_modules)
    if not ws.envd.exists():
        log(f"fetching upstream envd {ENVD_VERSION} (linux/amd64)")
        with urllib.request.urlopen(ENVD_URL, timeout=300) as response:
            data = response.read()
        if hashlib.sha256(data).hexdigest() != ENVD_SHA256:
            raise HarnessError(f"envd {ENVD_VERSION} checksum mismatch")
        ws.envd.parent.mkdir(parents=True, exist_ok=True)
        partial = ws.envd.with_suffix(".partial")
        partial.write_bytes(data)
        partial.chmod(0o755)
        partial.rename(ws.envd)
    log("building sandboxd-dev (-tags sandboxd_devdriver)")
    env = dict(os.environ, CGO_ENABLED="0")
    sh(["go", "build", "-tags", "sandboxd_devdriver", "-o", str(ws.server), "./cmd/sandboxd-dev"], cwd=REPO, env=env, timeout=900)


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


@dataclass
class Server:
    url: str
    key: str
    key_file: Path


@contextlib.contextmanager
def dev_server(ws: Workspace, suite: str):
    """A fresh sandboxd-dev, ledger and API key per suite. On exit the server
    must stop cleanly and leave no guest state behind."""
    run_dir = Path(tempfile.mkdtemp(prefix=f"{suite}-", dir=ws.root))
    key = "e2b_" + secrets.token_hex(20)
    key_file = run_dir / "api-key"
    key_file.touch(mode=0o600)
    key_file.write_text(key + "\n")
    port = free_port()
    state = run_dir / "guests"
    server_log = (ws.logs / f"{suite}-server.log").open("w")
    process = subprocess.Popen([
        str(ws.server), "-listen", f"127.0.0.1:{port}", "-db", str(run_dir / "ledger.db"),
        "-api-key-file", str(key_file), "-state-dir", str(state), "-template", STRICT_TEMPLATE,
        "-register-template", f"id={E2B_TEMPLATE},alias={E2B_ALIAS},profile=e2b,envd-version={ENVD_VERSION}",
        "-domain", DOMAIN, "-gateway-host", "127.0.0.1", "-max-vms", "16", "-envd", str(ws.envd),
    ], stdout=server_log, stderr=subprocess.STDOUT)
    try:
        deadline = time.monotonic() + 30
        while True:
            if process.poll() is not None:
                raise HarnessError(f"sandboxd-dev exited early; see {server_log.name}")
            with contextlib.suppress(OSError), socket.create_connection(("127.0.0.1", port), timeout=1):
                break
            if time.monotonic() > deadline:
                raise HarnessError("sandboxd-dev did not start listening")
            time.sleep(0.1)
        yield Server(f"http://127.0.0.1:{port}", key, key_file)
        if process.poll() is not None:
            raise HarnessError(f"sandboxd-dev died during {suite}; see {server_log.name}")
    finally:
        if process.poll() is None:
            process.send_signal(signal.SIGTERM)
            try:
                process.wait(timeout=60)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
                raise HarnessError("sandboxd-dev did not stop within 60s")
        server_log.close()
    if process.returncode != 0:
        raise HarnessError(f"sandboxd-dev exited {process.returncode}; see {server_log.name}")
    if state.exists():
        raise HarnessError(f"sandboxd-dev left guest state in {state}")
    shutil.rmtree(run_dir)


@contextlib.contextmanager
def offline_server(ws: Workspace, suite: str):
    """sandboxd offline: a null HTTP server answering every request with
    sandboxd's own unrouted response (404, "404 page not found"). Tests that
    pass against it do not depend on anything sandboxd implements. A refused
    port would be stricter but makes SDK connect retries take many minutes."""
    run_dir = Path(tempfile.mkdtemp(prefix=f"{suite}-offline-", dir=ws.root))
    key = "e2b_" + secrets.token_hex(20)
    key_file = run_dir / "api-key"
    key_file.touch(mode=0o600)
    key_file.write_text(key + "\n")
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), NullHandler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield Server(f"http://127.0.0.1:{server.server_address[1]}", key, key_file)
    finally:
        server.shutdown()
        server.server_close()
    shutil.rmtree(run_dir)


class NullHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def handle_one_request(self) -> None:
        self.raw_requestline = self.rfile.readline(65537)
        if not self.raw_requestline or not self.parse_request():
            self.close_connection = True
            return
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)
        elif "chunked" in (self.headers.get("Transfer-Encoding") or ""):
            self.close_connection = True
        body = b"404 page not found\n"
        self.send_response(404)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        self.wfile.flush()

    def log_message(self, *args) -> None:
        pass


def sdk_env(server: Server) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith("E2B_")}
    env.update(E2B_API_URL=server.url, E2B_SANDBOX_URL=server.url, E2B_API_KEY=server.key, E2B_DOMAIN=DOMAIN)
    return env


def run_logged(args: list[str], cwd: Path, env: dict[str, str], log_path: Path) -> int:
    with log_path.open("w") as out:
        try:
            return subprocess.run(args, cwd=cwd, env=env, stdout=out, stderr=subprocess.STDOUT, timeout=SUITE_TIMEOUT).returncode
        except subprocess.TimeoutExpired:
            raise HarnessError(f"{args[0]} exceeded {SUITE_TIMEOUT}s; see {log_path}")


def run_pytest(ws: Workspace, suite: str, package: Path, targets: list[str], server: Server) -> dict[str, str]:
    env = sdk_env(server)
    # The SDK under test must be the installed wheel, never a source tree.
    origin = sh([str(ws.venv_python), "-c", "import e2b, e2b_code_interpreter; print(e2b.__file__); print(e2b_code_interpreter.__file__)"], cwd=package, env=env)
    if any("site-packages" not in line for line in origin.split()):
        raise HarnessError(f"{suite}: SDK not imported from the venv: {origin}")
    report = ws.logs / f"{suite}.xml"
    code = run_logged([
        str(ws.venv_python), "-m", "pytest", "-p", "no:cacheprovider", "-o", "addopts=--import-mode=importlib",
        "-o", "junit_family=xunit1", f"--junitxml={report}", "--timeout=90", "-q", "-rN", *targets,
    ], package, env, ws.logs / f"{suite}.log")
    if code not in (0, 1) or not report.exists():
        raise HarnessError(f"{suite}: pytest exited {code}; see {ws.logs / (suite + '.log')}")
    return parse_junit(report)


def run_vitest(ws: Workspace, suite: str, package: Path, args: list[str], server: Server) -> dict[str, str]:
    report = ws.logs / f"{suite}.json"
    code = run_logged([
        "node", str(package / "node_modules" / "vitest" / "vitest.mjs"), "run", "--maxWorkers=4",
        "--reporter=json", f"--outputFile={report}", *args,
    ], package, sdk_env(server), ws.logs / f"{suite}.log")
    if code not in (0, 1) or not report.exists():
        raise HarnessError(f"{suite}: vitest exited {code}; see {ws.logs / (suite + '.log')}")
    return parse_vitest(report, package)


def js_targets(package: Path, dirs: list[str], exclude: list[str]) -> list[str]:
    files = []
    for directory in dirs:
        for path in sorted((package / "tests" / directory).rglob("*.test.ts")):
            relative = path.relative_to(package).as_posix()
            if not any(relative.startswith(prefix) for prefix in exclude):
                files.append(relative)
    return files


def run_suite(ws: Workspace, suite: Suite, offline: bool = False) -> dict[str, str]:
    """Run one suite against a fresh sandboxd-dev, or with offline=True
    against an endpoint that refuses connections. label names the logs."""
    label = suite.name + ("-offline" if offline else "")
    with (offline_server if offline else dev_server)(ws, label) as server:
        if suite.name == "python-e2b":
            return run_pytest(ws, label, ws.sdk / "packages" / "python-sdk", ["tests/sync", "tests/async"], server)
        if suite.name == "python-code-interpreter":
            return run_pytest(ws, label, ws.sdk / "packages" / "code-interpreter-python", ["tests"], server)
        if suite.name == "js-e2b":
            package = ws.sdk / "packages" / "js-sdk"
            files = js_targets(package, ["sandbox", "api", "volume", "secret", "template"], ["tests/template/utils/", "tests/sandbox/git/"])
            return run_vitest(ws, label, package, ["--project", "unit", "--project", "template", *files], server)
        if suite.name == "js-code-interpreter":
            package = ws.ci_js / "packages" / "code-interpreter-js"
            return run_vitest(ws, label, package, js_targets(package, [""], ["tests/runtimes/"]), server)
        if suite.name == "gitmoot":
            env = dict(os.environ, CGO_ENABLED="0", SANDBOXD_CONFORMANCE_URL=server.url,
                       SANDBOXD_CONFORMANCE_KEY_FILE=str(server.key_file), SANDBOXD_CONFORMANCE_TEMPLATE=STRICT_TEMPLATE,
                       SANDBOXD_CONFORMANCE_CANCEL="1")
            log_path = ws.logs / f"{label}.log"
            run_logged(["go", "test", "./internal/execbackend/e2b", "-count=1", "-json"], ws.gitmoot, env, log_path)
            results = parse_go_json(log_path.read_text())
            if "TestSandboxdPinnedClientConformance" not in results:
                raise HarnessError(f"{label}: conformance test did not run; see {log_path}")
            return results
    raise HarnessError(f"unknown suite {suite.name}")


def summarize(name: str, results: dict[str, str]) -> str:
    counts = {o: sum(1 for v in results.values() if v == o) for o in OUTCOMES}
    return f"{name}: {counts['pass']} pass, {counts['fail']} fail, {counts['skip']} skip"


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--update", action="store_true", help="record observed outcomes and regenerate the matrix")
    mode.add_argument("--render", action="store_true", help="only re-render the matrix from expected.json")
    parser.add_argument("--suite", action="append", choices=[s.name for s in SUITES], help="run only this suite (repeatable)")
    parser.add_argument("--workdir", type=Path, help="reuse and keep this work directory (default: a deleted temp dir)")
    parser.add_argument("--report", type=Path, help="copy observed results, matrix and logs here")
    args = parser.parse_args(argv)

    if args.render:
        MATRIX.write_text(load_expected().matrix())
        log(f"rendered {MATRIX.relative_to(REPO)}")
        return 0

    suites = [s for s in SUITES if not args.suite or s.name in args.suite]
    root = args.workdir.resolve() if args.workdir else Path(tempfile.mkdtemp(prefix="sandboxd-conformance-"))
    root.mkdir(parents=True, exist_ok=True)
    ws = Workspace(root)
    observed: dict[str, dict[str, str]] = {}
    try:
        prepare(ws, suites)
        expected = load_expected()
        offline = dict(expected.offline)
        for suite in suites:
            log(f"running {suite.title} against a fresh sandboxd-dev")
            observed[suite.name] = run_suite(ws, suite)
            for test_id in observed[suite.name]:
                operation_for(suite.name, test_id)
            log(summarize(suite.name, observed[suite.name]))
            if args.update:
                # Classification only: which passing tests do not need sandboxd.
                log(f"running {suite.title} with sandboxd offline (null server)")
                without = run_suite(ws, suite, offline=True)
                offline[suite.name] = [t for t, o in observed[suite.name].items() if o == "pass" and without.get(t) == "pass"]
                log(f"{suite.name}: {len(offline[suite.name])} of the passing tests also pass offline")
        merged = Recorded({name: r for name, r in expected.suites.items() if name not in observed} | observed,
                          offline if args.update else expected.offline)
        matrix = merged.matrix()
        (ws.logs / "results.json").write_text(json.dumps(observed, indent=1, sort_keys=True) + "\n")
        (ws.logs / "conformance-matrix.md").write_text(matrix)
        if summary := os.environ.get("GITHUB_STEP_SUMMARY"):
            with open(summary, "a") as out:
                out.write(matrix.split("\n## Expected failures")[0] + "\n")
        if args.update:
            write_expected(merged)
            MATRIX.write_text(matrix)
            log(f"recorded {EXPECTED.relative_to(REPO)} and {MATRIX.relative_to(REPO)}")
            return 0
        drift = compare(expected.suites, observed)
        stale = not MATRIX.exists() or MATRIX.read_text() != expected.matrix()
        if drift.empty() and not stale:
            log("every recorded outcome reproduced")
            return 0
        if not drift.empty():
            print(format_drift(drift), flush=True)
        if stale:
            log(f"{MATRIX.relative_to(REPO)} does not match {EXPECTED.relative_to(REPO)}; run conformance/run.py --render")
        return 1
    except HarnessError as error:
        log(f"HARNESS ERROR: {error}")
        return 2
    finally:
        if args.report and ws.logs.exists():
            shutil.copytree(ws.logs, args.report, dirs_exist_ok=True)
        if not args.workdir:
            shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
