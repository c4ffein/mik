#!/usr/bin/env python3
"""Boundary tests for mik.

Deliberately tested at the CLI/effect boundary (args in -> subprocess / file effects out) rather than
against the internal dict-vs-class data model, so these survive the planned move to a class-based model.
Stdlib only; run with `make test` or `python test.py`.
"""

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import mik


class ValidatePathTests(unittest.TestCase):
    def test_accepts_normal_paths(self):
        for p in ("a.txt", "src/main.py", "a/b/c/d.json", ".gitignore", "dir/.gitignore"):
            self.assertTrue(mik.validate_path(p), p)

    def test_rejects_traversal_and_absolute(self):
        for p in ("/etc/passwd", "../secret", "a/../b", "", "a//b"):
            self.assertFalse(mik.validate_path(p), p)

    def test_rejects_git_and_known_junk(self):
        for p in (".git/config", ".gitmodules", "node_modules/x", "a/__pycache__/b.pyc"):
            self.assertFalse(mik.validate_path(p), p)

    def test_rejects_weird_chars(self):
        for p in ("a b.txt", "a;rm.txt", "a$b", "a\tb"):
            self.assertFalse(mik.validate_path(p), p)


class ValidateNameTests(unittest.TestCase):
    def test_accepts(self):
        for n in ("host", "user-1", "a.b.c", "Host01"):
            mik.validate_name(n)  # must not raise

    def test_rejects(self):
        for n in ("...", "a b", "a/b", "a;b", "a@b"):
            with self.assertRaises(Exception):
                mik.validate_name(n)


class ListAndAutocompleteTests(unittest.TestCase):
    def setUp(self):
        mik.instances_dict.clear()
        mik.instances_dict.update({"alpha": {}, "alpaca": {}, "beta": {}})

    def test_list_prints_all(self):
        with mock.patch("builtins.print") as p:
            mik.list_instances(SimpleNamespace())
        printed = {c.args[0] for c in p.call_args_list}
        self.assertEqual(printed, {"alpha", "alpaca", "beta"})

    def test_autocomplete_filters_by_prefix(self):
        with mock.patch("builtins.print") as p:
            mik.autocomplete(SimpleNamespace(autocomplete="alp"))
        printed = {c.args[0] for c in p.call_args_list}
        self.assertEqual(printed, {"alpha", "alpaca"})


class DeployTests(unittest.TestCase):
    def setUp(self):
        mik.instances_dict.clear()
        # bare object() has no .deploy attr -> deploy() takes the shell-script path
        mik.instances_dict.update(
            {"web": {"deploy": ["cd /srv", "make"], "object": object(), "deploy_shell": "/bin/sh"}}
        )

    def test_unknown_instance_raises(self):
        with self.assertRaises(mik.MikException):
            mik.deploy(SimpleNamespace(instance="nope"))

    def test_missing_script_raises(self):
        mik.instances_dict["bare"] = {"object": object()}
        with self.assertRaises(mik.MikException):
            mik.deploy(SimpleNamespace(instance="bare"))

    def test_runs_joined_script_and_records(self):
        with mock.patch.object(mik, "run_recorded", return_value=(0, "ok")) as rr:
            mik.deploy(SimpleNamespace(instance="web"))
        rr.assert_called_once_with("deploy", "web", "cd /srv\nmake", "/bin/sh")

    def test_nonzero_returncode_raises(self):
        with mock.patch.object(mik, "run_recorded", return_value=(2, "boom")):
            with self.assertRaises(mik.MikException):
                mik.deploy(SimpleNamespace(instance="web"))


class RunAndCaptureTests(unittest.TestCase):
    def test_captures_output_and_returncode(self):
        rc, out = mik.run_and_capture("echo hello", "/bin/sh")
        self.assertEqual(rc, 0)
        self.assertIn("hello", out)

    def test_nonzero_returncode(self):
        rc, out = mik.run_and_capture("exit 3", "/bin/sh")
        self.assertEqual(rc, 3)


class RecordRunTests(unittest.TestCase):
    def test_writes_one_json_per_run(self):
        with tempfile.TemporaryDirectory() as d:
            with mock.patch.object(mik, "RUNS_DIR", Path(d)):
                started = mik.datetime.now().astimezone()
                run_id = mik.record_run("deploy", "web", started, started, 0, "some output")
                files = list(Path(d).glob("*.json"))
                self.assertEqual(len(files), 1)
                rec = json.loads(files[0].read_text())
                self.assertEqual(rec["command"], "deploy")
                self.assertEqual(rec["target"], "web")
                self.assertEqual(rec["returncode"], 0)
                self.assertEqual(rec["output"], "some output")
                self.assertEqual(rec["id"], run_id)


class DevFetchPodTests(unittest.TestCase):
    def _project(self, local_repo):
        mik.projects_dict.clear()
        proj = SimpleNamespace(
            name="proj",
            local_repo=local_repo,
            dev={"container": "c1", "code_dir": "/code", "ssh-host": "user@host"},
        )
        mik.projects_dict["proj"] = proj

    def test_rejects_unexpected_path_in_fetch(self):
        # Pass 1 confirms a.txt (M); pass 2 tampers by returning evil.txt -> must abort, write nothing.
        list_resp = json.dumps({"files": [{"path": "a.txt", "status": "M"}], "errors": []}).encode()
        fetch_payload = {"files": {"evil.txt": "ZXZpbA=="}, "deleted": []}
        fetch_resp = mik.base64.b64encode(json.dumps(fetch_payload).encode())
        with tempfile.TemporaryDirectory() as d:
            self._project(d)
            # _run_remote_script returns (returncode, stderr, stdout)
            with mock.patch.object(
                mik, "_run_remote_script", side_effect=[(0, b"", list_resp), (0, b"", fetch_resp)]
            ), mock.patch("builtins.input", return_value="y"):
                with self.assertRaises(mik.MikException):
                    mik.dev_fetch_pod(SimpleNamespace(project="proj"))
            self.assertFalse((Path(d) / "evil.txt").exists())
            self.assertFalse((Path(d) / "a.txt").exists())

    def test_happy_path_writes_confirmed_file(self):
        list_resp = json.dumps({"files": [{"path": "a.txt", "status": "M"}], "errors": []}).encode()
        fetch_payload = {"files": {"a.txt": mik.base64.b64encode(b"hello").decode()}, "deleted": []}
        fetch_resp = mik.base64.b64encode(json.dumps(fetch_payload).encode())
        with tempfile.TemporaryDirectory() as d:
            self._project(d)
            with mock.patch.object(
                mik, "_run_remote_script", side_effect=[(0, b"", list_resp), (0, b"", fetch_resp)]
            ), mock.patch("builtins.input", return_value="y"):
                mik.dev_fetch_pod(SimpleNamespace(project="proj"))
            self.assertEqual((Path(d) / "a.txt").read_bytes(), b"hello")


def fake_github(responses):
    """Build a _github_get_json stand-in: longest matching key in `responses` wins (so the more specific
    '/repos/o/r/commits/...' beats '/repos/o/r'). A value that is an Exception is raised; unknown -> 404.
    """

    def _inner(path):
        best = None
        for key in responses:
            if key in path and (best is None or len(key) > len(best)):
                best = key
        if best is None:
            raise mik.MikException("404 Not Found")
        val = responses[best]
        if isinstance(val, Exception):
            raise val
        return val

    return _inner


class RollupTests(unittest.TestCase):
    def test_states(self):
        self.assertEqual(mik._rollup_check_runs([]), mik.CI_NO_CHECKS)
        self.assertEqual(mik._rollup_check_runs([{"status": "completed", "conclusion": "success"}]), mik.CI_GOOD)
        self.assertEqual(
            mik._rollup_check_runs(
                [{"status": "completed", "conclusion": "success"}, {"status": "completed", "conclusion": "skipped"}]
            ),
            mik.CI_GOOD,
        )
        self.assertEqual(mik._rollup_check_runs([{"status": "completed", "conclusion": "failure"}]), mik.CI_FAILURE)
        self.assertEqual(mik._rollup_check_runs([{"status": "in_progress", "conclusion": None}]), mik.CI_PENDING)


class SplitGithubRepoTests(unittest.TestCase):
    def test_accepts(self):
        self.assertEqual(mik._split_github_repo("c4ffein/mik"), ("c4ffein", "mik"))

    def test_rejects(self):
        for bad in ("noslash", "a/b/c", "/r", "o/", "o w/r", "o/r;rm", "../x"):
            with self.assertRaises(mik.MikException):
                mik._split_github_repo(bad)


class CiStatusTests(unittest.TestCase):
    def setUp(self):
        mik.projects_dict.clear()

    def _proj(self, name, github_repo):
        mik.projects_dict[name] = SimpleNamespace(name=name, github_repo=github_repo, local_repo=None, dev=None)

    def test_single_good_returns_zero(self):
        self._proj("p", "o/r")
        fake = fake_github(
            {
                "/repos/o/r": {"default_branch": "main"},
                "/repos/o/r/commits": {"check_runs": [{"status": "completed", "conclusion": "success"}]},
            }
        )
        with mock.patch.object(mik, "_github_get_json", side_effect=fake):
            self.assertEqual(mik.ci_status(SimpleNamespace(project="p")), 0)

    def test_single_failure_returns_nonzero(self):
        self._proj("p", "o/r")
        fake = fake_github(
            {
                "/repos/o/r": {"default_branch": "main"},
                "/repos/o/r/commits": {"check_runs": [{"status": "completed", "conclusion": "failure"}]},
            }
        )
        with mock.patch.object(mik, "_github_get_json", side_effect=fake):
            self.assertEqual(mik.ci_status(SimpleNamespace(project="p")), -1)

    def test_fetch_error_is_nonzero(self):
        self._proj("p", "o/r")
        fake = fake_github({"/repos/o/r": mik.MikException("404 Not Found")})
        with mock.patch.object(mik, "_github_get_json", side_effect=fake):
            self.assertEqual(mik.ci_status(SimpleNamespace(project="p")), -1)

    def test_missing_github_repo_raises(self):
        self._proj("p", None)
        with self.assertRaises(mik.MikException):
            mik.ci_status(SimpleNamespace(project="p"))

    def test_unknown_project_raises(self):
        with self.assertRaises(mik.MikException):
            mik.ci_status(SimpleNamespace(project="nope"))

    def test_all_excludes_repoless_and_flags_failures(self):
        self._proj("good1", "o/good")
        self._proj("bad1", "o/bad")
        self._proj("noci", None)  # no github_repo -> excluded from ALL entirely
        fake = fake_github(
            {
                "/repos/o/good": {"default_branch": "main"},
                "/repos/o/good/commits": {"check_runs": [{"status": "completed", "conclusion": "success"}]},
                "/repos/o/bad": {"default_branch": "main"},
                "/repos/o/bad/commits": {"check_runs": [{"status": "completed", "conclusion": "failure"}]},
            }
        )
        with mock.patch.object(mik, "_github_get_json", side_effect=fake):
            with mock.patch("builtins.print"):  # silence the grouped output during the test
                rc = mik.ci_status(SimpleNamespace(project="ALL"))
        self.assertEqual(rc, -1)  # bad1 is a failure

    def test_all_with_no_github_projects(self):
        self._proj("noci", None)
        with mock.patch("builtins.print") as p:
            rc = mik.ci_status(SimpleNamespace(project="ALL"))
        self.assertIsNone(rc)
        self.assertTrue(any("No projects with a github_repo" in str(c.args[0]) for c in p.call_args_list))


if __name__ == "__main__":
    unittest.main(verbosity=2)
