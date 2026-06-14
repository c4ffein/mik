#!/usr/bin/env python3
"""Boundary tests for mik.

Tested at the CLI/effect boundary (args in -> subprocess / HTTP / file effects out) rather than against
internals, mocking the subprocess / SSH / HTTP layers. Stdlib only; run with `make test` or `python test.py`.
"""

import json
import re
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import mik


def _printed(mock_print):
    """All printed lines with ANSI color codes stripped, for substring/equality assertions."""
    return [re.sub(r"\033\[[0-9]+m", "", str(c.args[0] if c.args else "")) for c in mock_print.call_args_list]


def _inst(name, **kw):
    """An Instance stand-in carrying whatever foreign keys / fields a test needs."""
    return SimpleNamespace(name=name, **kw)


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


class AutocompleteTests(unittest.TestCase):
    def setUp(self):
        mik.instances_dict.clear()
        mik.instances_dict.update({"alpha": _inst("alpha"), "alpaca": _inst("alpaca"), "beta": _inst("beta")})

    def test_autocomplete_filters_by_prefix(self):
        with mock.patch("builtins.print") as p:
            mik.autocomplete(SimpleNamespace(autocomplete="alp"))
        self.assertEqual(set(_printed(p)), {"alpha", "alpaca"})


class DeployTests(unittest.TestCase):
    def setUp(self):
        mik.instances_dict.clear()
        mik.instances_dict["web"] = _inst("web", deploy=["cd /srv", "make"], deploy_shell="/bin/sh")

    def test_unknown_instance_raises(self):
        with self.assertRaises(mik.MikException):
            mik.deploy(SimpleNamespace(instance="nope"))

    def test_missing_script_raises(self):
        mik.instances_dict["bare"] = _inst("bare", deploy=None)
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

    def test_callable_deploy_is_invoked(self):
        # An Instance whose `deploy` is a classmethod/callable runs itself instead of a shell script.
        marker = []
        mik.instances_dict["custom"] = _inst("custom", deploy=lambda: marker.append("ran"))
        mik.deploy(SimpleNamespace(instance="custom"))
        self.assertEqual(marker, ["ran"])


class RunStepTests(unittest.TestCase):
    def test_returns_stdout_on_success(self):
        self.assertEqual(mik.run_step(["sh", "-c", "echo hi"]), b"hi\n")

    def test_raises_on_nonzero_with_command_in_message(self):
        with self.assertRaises(mik.MikException) as cm:
            mik.run_step(["sh", "-c", "echo boom >&2; exit 2"])
        self.assertIn("sh -c", str(cm.exception))

    def test_stderr_tolerated_by_default(self):
        # ssh/scp/git write to stderr on success — default must not raise on that.
        self.assertEqual(mik.run_step(["sh", "-c", "echo oops >&2"]), b"")

    def test_stderr_strict_when_requested(self):
        with self.assertRaises(mik.MikException):
            mik.run_step(["sh", "-c", "echo oops >&2"], fail_on_stderr=True)


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


class InstanceRelationTests(unittest.TestCase):
    def setUp(self):
        mik.instances_dict.clear()
        mik.instances_dict.update(
            {
                "back-prod": _inst("back-prod", project="app", machine="prod"),
                "front-prod": _inst("front-prod", project="app", machine="prod"),
                "back-dev": _inst("back-dev", project="app", machine="dev"),
            }
        )

    def test_instances_for_project(self):
        self.assertEqual(mik.instances_for_project("app"), ["back-prod", "front-prod", "back-dev"])

    def test_instances_for_machine(self):
        self.assertEqual(mik.instances_for_machine("prod"), ["back-prod", "front-prod"])

    def test_projects_for_machine_deduped(self):
        self.assertEqual(mik.projects_for_machine("prod"), ["app"])

    def test_unrelated_returns_empty(self):
        self.assertEqual(mik.instances_for_machine("nobody"), [])


class ListingTests(unittest.TestCase):
    def setUp(self):
        mik.machines_dict.clear()
        mik.projects_dict.clear()
        mik.instances_dict.clear()
        mik.machines_dict.update(
            {
                "prod": SimpleNamespace(name="prod", ssh_host="u@prod"),
                "dev": SimpleNamespace(name="dev", ssh_host="u@dev"),
            }
        )
        mik.projects_dict.update({"app": SimpleNamespace(name="app"), "site": SimpleNamespace(name="site")})
        mik.instances_dict.update(
            {
                "back-prod": _inst("back-prod", project="app", machine="prod"),
                "front-prod": _inst("front-prod", project="app", machine="prod"),
                "back-dev": _inst("back-dev", project="app", machine="dev"),
            }
        )

    def test_list_instances_plain(self):
        with mock.patch("builtins.print") as p:
            mik.list_instances(SimpleNamespace())
        self.assertEqual(_printed(p), ["back-prod", "front-prod", "back-dev"])

    def test_list_instances_show_links(self):
        with mock.patch("builtins.print") as p:
            mik.list_instances(SimpleNamespace(show_links=True))
        text = "\n".join(_printed(p))
        self.assertIn("INSTANCES", text)
        self.assertIn("project=app", text)
        self.assertIn("machine=prod", text)

    def test_list_instances_filter_by_machine(self):
        with mock.patch("builtins.print") as p:
            mik.list_instances(SimpleNamespace(machine="prod"))
        self.assertEqual(_printed(p), ["back-prod", "front-prod"])

    def test_list_instances_filter_by_project(self):
        with mock.patch("builtins.print") as p:
            mik.list_instances(SimpleNamespace(project="app"))
        self.assertEqual(_printed(p), ["back-prod", "front-prod", "back-dev"])

    def test_list_instances_unknown_machine_raises(self):
        with self.assertRaises(mik.MikException):
            mik.list_instances(SimpleNamespace(machine="ghost"))

    def test_list_projects_show_instances(self):
        with mock.patch("builtins.print") as p:
            mik.list_projects(SimpleNamespace(show_instances=True))
        text = "\n".join(_printed(p))
        self.assertIn("PROJECTS", text)
        self.assertIn("back-prod", text)

    def test_list_projects_filter_by_machine(self):
        with mock.patch("builtins.print") as p:
            mik.list_projects(SimpleNamespace(machine="dev"))
        self.assertEqual(_printed(p), ["app"])  # only app has an instance on dev

    def test_list_machines_show_instances(self):
        with mock.patch("builtins.print") as p:
            mik.list_machines(SimpleNamespace(show_instances=True))
        text = "\n".join(_printed(p))
        self.assertIn("MACHINES", text)
        self.assertIn("back-prod", text)

    def test_list_machines_filter_by_project(self):
        with mock.patch("builtins.print") as p:
            mik.list_machines(SimpleNamespace(project="app"))
        self.assertEqual(sorted(_printed(p)), ["dev", "prod"])

    def test_list_all_sections_and_dangling(self):
        mik.instances_dict["orphan"] = _inst("orphan", project="ghostproj", machine="prod")
        with mock.patch("builtins.print") as p:
            mik.list_all(SimpleNamespace())
        text = "\n".join(_printed(p))
        for section in ("MACHINES", "PROJECTS", "INSTANCES"):
            self.assertIn(section, text)
        self.assertIn("unknown project 'ghostproj'", text)


class DevFetchPodTests(unittest.TestCase):
    def _setup(self, local_repo):
        mik.instances_dict.clear()
        mik.machines_dict.clear()
        mik.projects_dict.clear()
        mik.machines_dict["box"] = SimpleNamespace(name="box", ssh_host="user@host")
        mik.projects_dict["proj"] = SimpleNamespace(name="proj", local_repo=local_repo, github_repo=None)
        mik.instances_dict["inst"] = _inst("inst", project="proj", machine="box", container="c1", code_dir="/code")

    def test_rejects_unexpected_path_in_fetch(self):
        # Pass 1 confirms a.txt (M); pass 2 tampers by returning evil.txt -> must abort, write nothing.
        list_resp = json.dumps({"files": [{"path": "a.txt", "status": "M"}], "errors": []}).encode()
        fetch_payload = {"files": {"evil.txt": "ZXZpbA=="}, "deleted": []}
        fetch_resp = mik.base64.b64encode(json.dumps(fetch_payload).encode())
        with tempfile.TemporaryDirectory() as d:
            self._setup(d)
            with mock.patch.object(
                mik, "_run_remote_script", side_effect=[(0, b"", list_resp), (0, b"", fetch_resp)]
            ), mock.patch("builtins.input", return_value="y"):
                with self.assertRaises(mik.MikException):
                    mik.dev_fetch_pod(SimpleNamespace(instance="inst"))
            self.assertFalse((Path(d) / "evil.txt").exists())
            self.assertFalse((Path(d) / "a.txt").exists())

    def test_happy_path_writes_confirmed_file(self):
        list_resp = json.dumps({"files": [{"path": "a.txt", "status": "M"}], "errors": []}).encode()
        fetch_payload = {"files": {"a.txt": mik.base64.b64encode(b"hello").decode()}, "deleted": []}
        fetch_resp = mik.base64.b64encode(json.dumps(fetch_payload).encode())
        with tempfile.TemporaryDirectory() as d:
            self._setup(d)
            with mock.patch.object(
                mik, "_run_remote_script", side_effect=[(0, b"", list_resp), (0, b"", fetch_resp)]
            ), mock.patch("builtins.input", return_value="y"):
                mik.dev_fetch_pod(SimpleNamespace(instance="inst"))
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


class _FakeResp:
    def __init__(self, body):
        self._body = body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self):
        return self._body


class PinnedSslTests(unittest.TestCase):
    PIN = "ab" * 32  # 64 hex chars; value is only checked during a real handshake

    def test_context_is_pinned_and_verifying(self):
        import ssl

        ctx = mik.make_pinned_ssl_context(self.PIN)
        self.assertIsInstance(ctx, ssl.SSLContext)
        self.assertTrue(ctx.check_hostname)
        self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)
        self.assertEqual(type(ctx).__name__, "PinnedSSLContext")
        self.assertEqual(ctx.sslsocket_class.__name__, "PinnedSSLSocket")

    def test_get_uses_pinned_context_when_configured(self):
        captured = {}

        def fake_urlopen(req, timeout=None, context=None):
            captured["context"] = context
            return _FakeResp(b'{"ok": true}')

        with mock.patch.object(mik, "GITHUB_CERT_SHA256", self.PIN), mock.patch.object(mik, "urlopen", fake_urlopen):
            out = mik._github_get_json("/repos/o/r")
        self.assertEqual(out, {"ok": True})
        self.assertEqual(type(captured["context"]).__name__, "PinnedSSLContext")

    def test_get_no_context_without_pin(self):
        captured = {}

        def fake_urlopen(req, timeout=None, context=None):
            captured["context"] = context
            return _FakeResp(b"{}")

        with mock.patch.object(mik, "GITHUB_CERT_SHA256", None), mock.patch.object(mik, "urlopen", fake_urlopen):
            mik._github_get_json("/repos/o/r")
        self.assertIsNone(captured["context"])


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
        mik.projects_dict[name] = SimpleNamespace(name=name, github_repo=github_repo)

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
