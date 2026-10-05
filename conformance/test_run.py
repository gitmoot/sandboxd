"""Unit tests for the conformance gate logic: python3 -m unittest discover -s conformance"""

import json
import tempfile
import unittest
from pathlib import Path

import run


class NormalizeKeyTest(unittest.TestCase):
    def test_python_and_js_files_share_operation_keys(self):
        cases = {
            ("python-e2b", "sync/sandbox_sync/test_create.py"): "create",
            ("python-e2b", "async/sandbox_async/test_create.py"): "create",
            ("js-e2b", "sandbox/create.test.ts"): "create",
            ("python-e2b", "sync/api_sync/test_sbx_list.py"): "api/list",
            ("js-e2b", "api/list.test.ts"): "api/list",
            ("python-e2b", "async/sandbox_async/commands/test_cmd_connect.py"): "commands/connect",
            ("js-e2b", "sandbox/commands/connect.test.ts"): "commands/connect",
            ("python-e2b", "sync/sandbox_sync/files/test_files_list.py"): "files/list",
            ("python-e2b", "sync/sandbox_sync/pty/test_pty_create.py"): "pty/create",
            ("js-e2b", "sandbox/pty/ptyCreate.test.ts"): "pty/create",
            ("js-e2b", "sandbox/files/watchHandle.test.ts"): "files/watch_handle",
            ("python-code-interpreter", "async/test_async_basic.py"): "ci:basic",
            ("js-code-interpreter", "basic.test.ts"): "ci:basic",
            ("js-code-interpreter", "charts/boxAndWhisker.test.ts"): "ci:charts/box_and_whisker",
        }
        for (suite, path), key in cases.items():
            self.assertEqual(run.normalize_key(suite, path), key, (suite, path))

    def test_operation_lookup_rejects_unmapped_files(self):
        self.assertEqual(run.operation_for("js-e2b", "sandbox/create.test.ts > create"), "`Sandbox.create`")
        self.assertEqual(run.operation_for("gitmoot", "TestSandboxdPinnedClientConformance"), run.OPERATIONS[-2][1])
        self.assertEqual(run.operation_for("gitmoot", "TestCreate/v1"), run.OPERATIONS[-1][1])
        with self.assertRaises(run.HarnessError):
            run.operation_for("js-e2b", "sandbox/brandNew.test.ts > x")

    def test_every_key_maps_to_one_operation(self):
        keys = [key for _, _, group in run.OPERATIONS for key in group]
        self.assertEqual(len(keys), len(set(keys)))
        operations = [operation for _, operation, _ in run.OPERATIONS]
        self.assertEqual(len(operations), len(set(operations)))


class CompareTest(unittest.TestCase):
    def test_classifies_drift_in_both_directions(self):
        expected = {"js-e2b": {"a": "pass", "b": "fail", "c": "pass", "d": "skip", "e": "fail"}}
        observed = {"js-e2b": {"a": "fail", "b": "pass", "d": "fail", "e": "fail", "new": "fail"}}
        drift = run.compare(expected, observed)
        self.assertEqual(drift.regressions, [("js-e2b", "a", "pass", "fail"), ("js-e2b", "c", "pass", "absent")])
        self.assertEqual(drift.improvements, [("js-e2b", "b", "fail", "pass")])
        self.assertEqual(drift.changes, [("js-e2b", "d", "skip", "fail"), ("js-e2b", "new", "absent", "fail")])
        self.assertFalse(drift.empty())

    def test_identical_outcomes_and_unrun_suites_are_clean(self):
        expected = {"js-e2b": {"a": "pass"}, "gitmoot": {"TestX": "pass"}}
        self.assertTrue(run.compare(expected, {"js-e2b": {"a": "pass"}}).empty())

    def test_drift_report_names_the_red_cell(self):
        drift = run.compare({"js-e2b": {"sandbox/create.test.ts > create": "pass"}},
                            {"js-e2b": {"sandbox/create.test.ts > create": "fail"}})
        report = run.format_drift(drift)
        self.assertIn("REGRESSIONS", report)
        self.assertIn("cell `Sandbox.create` / JS e2b", report)


class MatrixTest(unittest.TestCase):
    def test_offline_passes_never_make_a_cell_green(self):
        self.assertEqual(run.cell_text({"pass": 3, "fail": 2, "skip": 0, "offline": 3}), "❌ 0/2 (+3 offline)")
        self.assertEqual(run.cell_text({"pass": 3, "fail": 0, "skip": 1, "offline": 3}), "⚪ (+3 offline, 1 skip)")
        self.assertEqual(run.cell_text({"pass": 4, "fail": 2, "skip": 0, "offline": 1}), "🟡 3/5 (+1 offline)")
        self.assertEqual(run.cell_text({"pass": 2, "fail": 0, "skip": 0, "offline": 0}), "✅ 2/2")
        self.assertEqual(run.cell_text(None), "—")

    def test_render_lists_each_expected_failure(self):
        results = {"js-e2b": {"sandbox/create.test.ts > create": "fail", "sandbox/create.test.ts > metadata": "pass"}}
        matrix = run.render_matrix(results, {})
        self.assertIn("| Control plane | `Sandbox.create` | 🟡 1/2 |", matrix)
        self.assertIn("- JS e2b: `sandbox/create.test.ts > create`", matrix)
        self.assertNotIn("metadata`", matrix)


class ParserTest(unittest.TestCase):
    def test_junit_outcomes_and_classes(self):
        xml = """<testsuites><testsuite>
<testcase classname="tests.sync.sandbox_sync.test_create" file="tests/sync/sandbox_sync/test_create.py" name="test_start"><failure/></testcase>
<testcase classname="tests.sync.sandbox_sync.test_create.TestGroup" file="tests/sync/sandbox_sync/test_create.py" name="test_ok"/>
<testcase classname="tests.sync.sandbox_sync.test_kill" file="tests/sync/sandbox_sync/test_kill.py" name="test_x"><skipped/></testcase>
<testcase classname="tests.sync.sandbox_sync.test_kill" file="tests/sync/sandbox_sync/test_kill.py" name="test_x"><error/></testcase>
</testsuite></testsuites>"""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "r.xml"
            path.write_text(xml)
            self.assertEqual(run.parse_junit(path), {
                "sync/sandbox_sync/test_create.py::test_start": "fail",
                "sync/sandbox_sync/test_create.py::TestGroup::test_ok": "pass",
                "sync/sandbox_sync/test_kill.py::test_x": "skip",
                "sync/sandbox_sync/test_kill.py::test_x #2": "fail",
            })

    def test_vitest_outcomes_and_load_failures(self):
        with tempfile.TemporaryDirectory() as tmp:
            package = Path(tmp)
            (package / "tests").mkdir()
            report = package / "r.json"
            report.write_text(json.dumps({"testResults": [
                {"name": str(package / "tests/sandbox/create.test.ts"), "status": "failed", "assertionResults": [
                    {"ancestorTitles": ["group"], "title": "create", "status": "failed"},
                    {"ancestorTitles": [], "title": "meta", "status": "passed"},
                    {"ancestorTitles": [], "title": "todo", "status": "skipped"},
                ]},
                {"name": str(package / "tests/api/list.test.ts"), "status": "failed", "assertionResults": []},
            ]}))
            self.assertEqual(run.parse_vitest(report, package), {
                "sandbox/create.test.ts > group > create": "fail",
                "sandbox/create.test.ts > meta": "pass",
                "sandbox/create.test.ts > todo": "skip",
                "api/list.test.ts > (file)": "fail",
            })

    def test_go_json_takes_final_actions(self):
        lines = "\n".join(json.dumps(e) for e in [
            {"Action": "run", "Test": "TestA"}, {"Action": "pass", "Test": "TestA"},
            {"Action": "fail", "Test": "TestB/sub"}, {"Action": "output", "Test": "TestB", "Output": "x"},
            {"Action": "pass", "Package": "p"},
        ])
        self.assertEqual(run.parse_go_json("go: downloading\n" + lines), {"TestA": "pass", "TestB/sub": "fail"})


if __name__ == "__main__":
    unittest.main()
