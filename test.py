#!/usr/bin/env python3
"""Boundary tests for mik.

Tested at the CLI/effect boundary (args in -> subprocess / HTTP / file effects out) rather than against
internals, mocking the subprocess / SSH / HTTP layers. Stdlib only; run with `make test` or `python test.py`.
"""

import contextlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import tomllib
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

    def test_accepts_allowlisted_dotgit_exceptions(self):
        # Regression: the ".git" prefix ban must not swallow these explicitly-allowed, known-safe
        # names. .github/** (CI/workflows/templates) is the whole point of the exception.
        for p in (
            ".github/workflows/ci.yml",
            ".github/CODEOWNERS",
            ".github/ISSUE_TEMPLATE/bug.md",
            "dir/.github/x",
            ".gitkeep",
            "sub/.gitkeep",
        ):
            self.assertTrue(mik.validate_path(p), p)

    def test_rejects_traversal_and_absolute(self):
        for p in ("/etc/passwd", "../secret", "a/../b", "", "a//b"):
            self.assertFalse(mik.validate_path(p), p)

    def test_a_dot_is_not_a_name(self):
        # "." is the repo itself and "a/./b" is "a/b" again: one file, one way to write its path.
        for p in (".", "a/.", "./Makefile", "a/./b"):
            self.assertFalse(mik.validate_path(p), p)
        for p in ("...", "a/.b", ".a/b."):
            self.assertTrue(mik.validate_path(p), p)

    def test_rejects_git_and_known_junk(self):
        # The real repo-hijack vectors stay blocked (they alter checkout/filter/hook behavior).
        for p in (".git/config", ".gitmodules", ".gitattributes", "node_modules/x", "a/__pycache__/b.pyc"):
            self.assertFalse(mik.validate_path(p), p)

    def test_unknown_dotgit_is_denied_by_default(self):
        # Fail-closed: anything starting with ".git" that isn't explicitly allowlisted is rejected,
        # even if plausibly benign. Add it to ALLOWED_PATH_PARTS consciously if you actually need it.
        for p in (".gitlab-ci.yml", ".gitpod.yml", ".githooks/pre-commit", ".gitconfig", ".git-blame-ignore-revs"):
            self.assertFalse(mik.validate_path(p), p)

    def test_rejects_weird_chars(self):
        for p in ("a b.txt", "a;rm.txt", "a$b", "a\tb"):
            self.assertFalse(mik.validate_path(p), p)

    _ANY_CASE = (".GIT/hooks/pre-commit", ".Git/config", "sub/.gIt/config", ".GITMODULES", ".GitAttributes")

    def test_what_is_forbidden_is_forbidden_in_any_case(self):
        # A filesystem that ignores case opens .git under these names. What is allowed is so as written only.
        for p in (*self._ANY_CASE, "Node_Modules/x", "a/__PYCACHE__/b.pyc", ".GITHUB/workflows/ci.yml", ".GitIgnore"):
            self.assertFalse(mik.validate_path(p), p)

    def test_no_head_so_no_repository_inside_the_repository(self):
        # HEAD + objects/ + refs/ is a repository to git, whatever the directory is called, and its `config`
        # is obeyed (core.fsmonitor runs on `git status`). Without HEAD there is none.
        for p in ("tools/x/HEAD", "HEAD", "head", "a/Head", "HEAD/x", "a/HEAD/b.txt"):
            self.assertFalse(mik.validate_path(p), p)
        for p in ("tools/x/config", "tools/x/objects/a", "tools/x/refs/a", "HEAD.md", "header.py", "ahead", "a/HEADS"):
            self.assertTrue(mik.validate_path(p), p)

    def test_the_copy_that_runs_in_the_pod_says_the_same(self):
        # _REMOTE_VALIDATE_PATH is validate_path again, as source text: the two must not drift apart.
        pod = {}
        exec(mik._REMOTE_VALIDATE_PATH, pod)
        for p in (
            *("a.txt", "src/main.py", ".gitignore", ".github/workflows/ci.yml", "sub/.gitkeep", "-a/b_c.d"),
            *("/etc/passwd", "../x", "a/../b", "", "a//b", ".git/config", ".gitmodules", "node_modules/x"),
            *(".", "a/.", "./Makefile", "a/./b", "...", "a/.b"),
            *("a b", "a$b", "é.txt", ".GITHUB/x", "Node_Modules/x", *self._ANY_CASE),
            *("tools/x/HEAD", "head", "a/Head/b", "HEAD.md", "tools/x/config", "tools/x/objects/a"),
        ):
            self.assertEqual(pod["validate_path"](p), mik.validate_path(p), p)


def _tar_with(*members):
    """A .tar.gz BytesIO from (TarInfo, payload-or-None) pairs — payload only for regular files."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as t:
        for ti, data in members:
            t.addfile(ti, io.BytesIO(data) if data is not None else None)
    buf.seek(0)
    return buf


def _reg(name, data=b"x"):
    ti = tarfile.TarInfo(name)
    ti.type, ti.size = tarfile.REGTYPE, len(data)
    return (ti, data)


def _link(name, target, kind):
    ti = tarfile.TarInfo(name)
    ti.type, ti.linkname = kind, target  # kind: tarfile.SYMTYPE (symlink) or tarfile.LNKTYPE (hardlink)
    return (ti, None)


def _dev(name):
    ti = tarfile.TarInfo(name)
    ti.type, ti.devmajor, ti.devminor = tarfile.CHRTYPE, 1, 3
    return (ti, None)


class SafeTarMemberTests(unittest.TestCase):
    """Covers every row of the threat table for the safe_tar_member extraction filter.

    extract() runs a built archive through safe_tar_member into a throwaway dir; it returns the set of
    paths (relative to dest) that landed, and asserts nothing escaped the dest along the way.
    """

    def extract(self, *members):
        with tempfile.TemporaryDirectory() as d:
            with tarfile.open(fileobj=_tar_with(*members), mode="r:gz") as t:
                t.extractall(d, filter=mik.safe_tar_member)
            landed = sorted(os.path.relpath(os.path.join(root, f), d) for root, _, files in os.walk(d) for f in files)
            # nothing must have been written outside the destination tree
            for rel in landed:
                self.assertFalse(rel.startswith(".."), f"escaped dest: {rel}")
            return landed

    def test_plain_regular_file_extracts(self):
        self.assertEqual(self.extract(_reg("index.html")), ["index.html"])

    def test_absolute_name_is_de_rooted_into_dest(self):
        # data_filter strips the leading '/', so it lands *inside* dest rather than at /etc/passwd
        self.assertEqual(self.extract(_reg("/etc/passwd")), ["etc/passwd"])

    def test_escaping_dotdot_names_are_refused(self):
        # leading and *embedded* .. that resolve outside dest — data_filter judges by resolved target
        for name in ("../../escape", "a/../../b", "a/b/../../../c"):
            with self.assertRaises(mik.MikException, msg=name):
                self.extract(_reg(name))

    def test_normalized_but_safe_dotdot_lands_inside(self):
        # a/../b resolves to b *inside* dest, so it's allowed — only paths that actually escape are rejected
        self.assertEqual(self.extract(_reg("a/../b")), ["b"])

    def test_absolute_symlink_is_refused(self):
        with self.assertRaises(mik.MikException):
            self.extract(_link("evil", "/etc/passwd", tarfile.SYMTYPE))

    def test_escaping_symlink_is_refused(self):
        with self.assertRaises(mik.MikException):
            self.extract(_link("evil", "../../etc/passwd", tarfile.SYMTYPE))

    def test_device_special_file_is_refused(self):
        with self.assertRaises(mik.MikException):
            self.extract(_dev("nul"))

    def test_internal_symlink_is_refused(self):
        # data_filter would allow this (it's inside dest); safe_tar_member's added strictness rejects it
        with self.assertRaises(mik.MikException):
            self.extract(_reg("index.html"), _link("a", "index.html", tarfile.SYMTYPE))

    def test_internal_hardlink_is_refused(self):
        with self.assertRaises(mik.MikException):
            self.extract(_reg("index.html"), _link("a", "index.html", tarfile.LNKTYPE))


class ValidateNameTests(unittest.TestCase):
    def test_accepts(self):
        for n in ("host", "user-1", "a.b.c", "Host01"):
            mik.validate_name(n)  # must not raise

    def test_rejects(self):
        for n in ("...", "a b", "a/b", "a;b", "a@b"):
            with self.assertRaises(Exception):
                mik.validate_name(n)

    def test_rejects_a_leading_dash(self):
        # A name goes into an argv (ssh, docker exec), where this would be read as an option.
        for n in ("-oFoo", "-F.evil", "--privileged", "-"):
            with self.assertRaises(mik.MikException):
                mik.validate_name(n)
        mik.validate_name("a-b-")  # a dash elsewhere is fine


class ValidateCodeDirTests(unittest.TestCase):
    def test_accepts(self):
        for p in ("/code", "/home/dev/workspace/mik", "/a-b/c_d.e", "/x/y/z"):
            mik.validate_code_dir(p)  # must not raise

    def test_rejects(self):
        for p in ("", "code", "rel/path", "/a/../b", "/a b/c", "/a;b", "/a$b", "/a|b"):
            with self.assertRaises(mik.MikException):
                mik.validate_code_dir(p)


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
        rr.assert_called_once_with("deploy", "web", "set -e\ncd /srv\nmake", "/bin/sh")

    def test_another_interpreter_gets_the_lines_as_they_are(self):
        # `set -e` is only said to a shell that knows it: deploy_shell may be any interpreter.
        mik.instances_dict["py"] = _inst("py", deploy=["print(1)"], deploy_shell="/usr/bin/python3")
        with mock.patch.object(mik, "run_recorded", return_value=(0, "ok")) as rr:
            mik.deploy(SimpleNamespace(instance="py"))
        rr.assert_called_once_with("deploy", "py", "print(1)", "/usr/bin/python3")

    def test_a_line_that_fails_stops_the_deploy_there(self):
        # The real shell: `cd` fails, and what comes after must not run from wherever the shell was.
        for shell in (None, "/bin/sh"):
            lines = ["cd /nonexistent-mik-test", "echo REACHED"]
            mik.instances_dict["web"] = _inst("web", deploy=lines, deploy_shell=shell)
            out = io.BytesIO()
            with (
                self.subTest(shell=shell),
                mock.patch.object(mik, "record_run") as recorded,
                mock.patch.object(mik.sys, "stdout", SimpleNamespace(buffer=out, flush=lambda: None)),
            ):
                with self.assertRaises(mik.MikException):
                    mik.deploy(SimpleNamespace(instance="web"))
                self.assertNotEqual(recorded.call_args.args[4], 0)  # the return code that was recorded
                self.assertNotIn(b"REACHED", out.getvalue())

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

    def test_stderr_in_the_error_cannot_carry_escape_sequences(self):
        # for an ssh step, the one writing on stderr is the remote
        noise = "printf 'boom \\033[2J\\033[H\\nline 2\\n' >&2"
        for script, strict in ((f"{noise}; exit 3", False), (noise, True)):
            with self.subTest(strict=strict), self.assertRaises(mik.MikException) as cm:
                mik.run_step(["sh", "-c", script], fail_on_stderr=strict)
            self.assertTrue(str(cm.exception).endswith("\nboom [2J[H\nline 2"), str(cm.exception))
            self.assertNotIn("\033", str(cm.exception).split("\n", 1)[1])

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


class ArtifactNameTests(unittest.TestCase):
    """What names an artifact: chars from the allowlist ([A-Za-z0-9-._]) and nothing else."""

    _BAD = ("", ".", "..", "a/b", "../x", "a b", "é", "dist²", "a;b", "a$b", "a\n", None, 5)

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.store = Path(self._tmp.name) / "artifacts"
        self.store.mkdir()
        patcher = mock.patch.object(mik, "ARTIFACTS_DIR", self.store)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_a_category_is_one_plain_name(self):
        for category in self._BAD:
            for helper in (mik.artifact_category_dir, mik.latest_release, mik.prune_artifacts):
                with self.subTest(category=category, helper=helper.__name__), self.assertRaises(mik.MikException):
                    helper(category)
            with self.subTest(category=category, helper="resolve_release"), self.assertRaises(mik.MikException):
                mik.resolve_release(category, "1")
            with self.subTest(category=category, helper="build_artifact"), self.assertRaises(mik.MikException):
                mik.build_artifact(category, "dist", lambda staging: staging.mkdir())
        self.assertEqual(os.listdir(self._tmp.name), ["artifacts"])  # nothing made beside the store
        self.assertEqual(os.listdir(self.store), [])
        self.assertEqual(mik.artifact_category_dir("my-site_1.dist"), self.store / "my-site_1.dist")

    def test_a_suffix_is_one_plain_name_and_a_release_id_is_ascii_digits(self):
        built = []
        for suffix in self._BAD:
            with self.subTest(suffix=suffix), self.assertRaises(mik.MikException):
                mik.build_artifact("site", suffix, built.append)
        for release_id in ("²", "١٢٣", "12a", "-1", ""):
            with self.subTest(release_id=release_id), self.assertRaises(mik.MikException):
                mik.build_artifact("site", "dist", built.append, release_id=release_id)
        self.assertEqual(built, [])  # build() never ran
        final = mik.build_artifact("site", "dist", lambda staging: staging.mkdir(), release_id=1750000000)
        self.assertEqual(final, self.store / "site" / "1750000000-dist")

    def test_an_entry_with_another_name_is_not_a_release(self):
        # isdigit() says yes to "²" and int() then refuses it: such a name is skipped, like any odd one.
        base = self.store / "site"
        for entry in ("100-dist", "200-dist", "²-dist", "١٢٣-dist", "300-é", "400 dist", ".mik-build-500-dist"):
            (base / entry).mkdir(parents=True)
        self.assertEqual(mik.latest_release("site"), base / "200-dist")
        self.assertEqual(mik.resolve_release("site", "100"), base / "100-dist")
        self.assertEqual(mik.prune_artifacts("site", keep=1), [base / "100-dist"])
        self.assertEqual(len(os.listdir(base)), 6)  # only the release that was pruned is gone


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
    def setUp(self):
        # These local repos are plain directories: what git ignores is DevFetchPodIgnoredTests' to test.
        for asked_of_git in ("_locally_ignored", "_locally_unwatched"):
            patcher = mock.patch.object(mik, asked_of_git, return_value=[])
            patcher.start()
            self.addCleanup(patcher.stop)

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
            with (
                mock.patch.object(mik, "_run_remote_script", side_effect=[(0, b"", list_resp), (0, b"", fetch_resp)]),
                mock.patch("builtins.input", return_value="y"),
            ):
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
            with (
                mock.patch.object(mik, "_run_remote_script", side_effect=[(0, b"", list_resp), (0, b"", fetch_resp)]),
                mock.patch("builtins.input", return_value="y"),
            ):
                mik.dev_fetch_pod(SimpleNamespace(instance="inst"))
            self.assertEqual((Path(d) / "a.txt").read_bytes(), b"hello")

    def test_refuses_a_file_list_that_leaves_the_repo(self):
        # The pod is the one not trusted: whatever it lists is checked here, before the question is asked.
        for entry in (
            {"path": "../outside.txt", "status": "M"},
            {"path": "/etc/outside.txt", "status": "M"},
            {"path": ".git/hooks/pre-commit", "status": "A"},
            {"path": ".GIT/hooks/pre-commit", "status": "A"},
            {"path": "tools/x/HEAD", "status": "A"},  # with objects/ and refs/ beside it: a repository to git
            {"path": "a\033[2K.txt", "status": "M"},  # an escape sequence, to rewrite what is shown
            {"path": 'hello" : " \\" \\ "', "status": "A"},  # quotes and backslashes, to get out of a string
            {"path": 'a"]; import os; os.system("id") #', "status": "A"},
            {"path": "a$(id).txt", "status": "A"},
            {"path": "a b.txt", "status": "A"},
            {"path": "a.txt", "status": "\033[2K"},
            {"path": "a.txt"},
            {"path": ["a.txt"], "status": "M"},
            "a.txt",
        ):
            with self.subTest(entry=entry), tempfile.TemporaryDirectory() as d:
                repo = Path(d) / "repo"
                repo.mkdir()
                self._setup(str(repo))
                list_resp = json.dumps({"files": [{"path": "ok.txt", "status": "M"}, entry], "errors": []}).encode()
                asked = mock.Mock(side_effect=AssertionError("asked a question"))
                with (
                    mock.patch.object(mik, "_run_remote_script", side_effect=[(0, b"", list_resp)]) as remote,
                    mock.patch("builtins.input", asked),
                    mock.patch("builtins.print"),
                ):
                    with self.assertRaises(mik.MikException):
                        mik.dev_fetch_pod(SimpleNamespace(instance="inst"))
                self.assertEqual(remote.call_count, 1)  # never got to the fetch
                self.assertEqual(list(Path(d).rglob("*")), [repo])  # nothing written, inside or outside

    def test_nothing_is_written_or_deleted_through_a_local_symlink(self):
        # validate_path keeps a path inside the repo as a name; a symlink already there would take it out.
        for name, path, status in (
            ("a new file under a linked directory", "vendor/.bashrc", "A"),
            ("deeper under a linked directory", "vendor/sub/x.txt", "M"),
            ("a deletion under a linked directory", "vendor/precious.txt", "D"),
            ("the file itself is a link", "link.txt", "M"),
            ("the deleted file itself is a link", "link.txt", "D"),
        ):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as d:
                repo, outside = Path(d) / "repo", Path(d) / "outside"
                repo.mkdir()
                (outside / "sub").mkdir(parents=True)
                (outside / "precious.txt").write_text("keep me")
                (repo / "vendor").symlink_to(outside)
                (repo / "link.txt").symlink_to(outside / "precious.txt")
                before = sorted(str(x) for x in Path(d).rglob("*"))
                self._setup(str(repo))
                files = [{"path": "ok.txt", "status": "M"}, {"path": path, "status": status}]
                list_resp = json.dumps({"files": files, "errors": []}).encode()
                asked = mock.Mock(side_effect=AssertionError("asked a question"))
                with (
                    mock.patch.object(mik, "_run_remote_script", side_effect=[(0, b"", list_resp)]) as remote,
                    mock.patch("builtins.input", asked),
                    mock.patch("builtins.print"),
                ):
                    with self.assertRaises(mik.MikException) as ctx:
                        mik.dev_fetch_pod(SimpleNamespace(instance="inst"))
                self.assertIn("symlink", str(ctx.exception))
                self.assertEqual(remote.call_count, 1)  # never got to the fetch
                self.assertEqual(sorted(str(x) for x in Path(d).rglob("*")), before)  # nothing written or deleted
                self.assertEqual((outside / "precious.txt").read_text(), "keep me")
                self.assertTrue((repo / "link.txt").is_symlink())

    def test_a_local_repo_that_is_itself_a_symlink_is_the_configs_to_say(self):
        list_resp = json.dumps({"files": [{"path": "sub/a.txt", "status": "A"}], "errors": []}).encode()
        fetch_payload = {"files": {"sub/a.txt": mik.base64.b64encode(b"hello").decode()}, "deleted": []}
        fetch_resp = mik.base64.b64encode(json.dumps(fetch_payload).encode())
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "real").mkdir()
            (Path(d) / "repo").symlink_to(Path(d) / "real")
            self._setup(str(Path(d) / "repo"))
            with (
                mock.patch.object(mik, "_run_remote_script", side_effect=[(0, b"", list_resp), (0, b"", fetch_resp)]),
                mock.patch("builtins.input", return_value="y"),
                mock.patch("builtins.print"),
            ):
                mik.dev_fetch_pod(SimpleNamespace(instance="inst"))
            self.assertEqual((Path(d) / "real" / "sub" / "a.txt").read_bytes(), b"hello")

    def test_only_the_path_and_the_status_go_back_to_the_pod(self):
        # What a pod puts beside them is dropped: the confirmed list is written into the fetch script.
        entry = {"path": "a.txt", "status": "M", "x": 'q" + __import__("os").getcwd() + "', "n": None}
        self.assertEqual(mik._checked_remote_files([entry]), [{"path": "a.txt", "status": "M"}])
        fetch_resp = mik.base64.b64encode(json.dumps({"files": {"a.txt": "aGk="}, "deleted": []}).encode())
        list_resp = json.dumps({"files": [entry], "errors": []}).encode()
        with tempfile.TemporaryDirectory() as d:
            self._setup(d)
            with (
                mock.patch.object(
                    mik, "_run_remote_script", side_effect=[(0, b"", list_resp), (0, b"", fetch_resp)]
                ) as remote,
                mock.patch("builtins.input", return_value="y"),
                mock.patch("builtins.print"),
            ):
                mik.dev_fetch_pod(SimpleNamespace(instance="inst"))
        fetch_script = remote.call_args_list[1].args[2]
        self.assertIn('file_list = [{"path": "a.txt", "status": "M"}]\n', fetch_script)
        self.assertNotIn("getcwd", fetch_script)

    def test_a_fetch_answer_that_is_wrong_somewhere_writes_nothing(self):
        # Two files confirmed; the first one's content is fine every time, so anything written shows.
        ok = mik.base64.b64encode(b"x").decode()
        for name, payload in (
            ("content is a number", {"files": {"a.txt": ok, "b.txt": 5}, "deleted": []}),
            ("content is not base64", {"files": {"a.txt": ok, "b.txt": "not base64!"}, "deleted": []}),
            (
                "a path with an escape sequence",
                {"files": {"a.txt": ok, "b.txt": ok, "e\033[2J.txt": ok}, "deleted": []},
            ),
            ("a list instead of an object", [ok, ok]),
            ("files is a list", {"files": ["a.txt", "b.txt"], "deleted": []}),
            ("deleted holds a list", {"files": {"a.txt": ok, "b.txt": ok}, "deleted": [["a.txt"]]}),
            ("errors is a number", {"files": {"a.txt": ok, "b.txt": ok}, "deleted": [], "errors": 5}),
        ):
            list_resp = json.dumps({"files": [{"path": p, "status": "M"} for p in ("a.txt", "b.txt")]}).encode()
            fetch_resp = mik.base64.b64encode(json.dumps(payload).encode())
            with self.subTest(name=name), tempfile.TemporaryDirectory() as d:
                self._setup(d)
                with (
                    mock.patch.object(
                        mik, "_run_remote_script", side_effect=[(0, b"", list_resp), (0, b"", fetch_resp)]
                    ),
                    mock.patch("builtins.input", return_value="y"),
                    mock.patch("builtins.print") as printed,
                ):
                    with self.assertRaises(mik.MikException):  # said in a line, not a traceback
                        mik.dev_fetch_pod(SimpleNamespace(instance="inst"))
                self.assertEqual(os.listdir(d), [])
                shown = "".join(str(c.args[0]) for c in printed.call_args_list if c.args)
                self.assertNotIn("\033[2J", shown)

    def test_refuses_a_file_list_that_cannot_be_applied_as_shown(self):
        for name, files, said in (
            ("twice", [("a.txt", "M"), ("b.txt", "M"), ("a.txt", "D")], "more than once: a.txt"),
            ("a file and a directory", [("a", "D"), ("a/b.txt", "A")], "both a file and a directory in it: a"),
            ("deeper", [("x/a/b/c.txt", "A"), ("x/a", "M")], "both a file and a directory in it: x/a"),
        ):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as d:
                self._setup(d)
                listed = [{"path": path, "status": status} for path, status in files]
                list_resp = json.dumps({"files": listed, "errors": []}).encode()
                with (
                    mock.patch.object(mik, "_run_remote_script", side_effect=[(0, b"", list_resp)]),
                    mock.patch("builtins.input", mock.Mock(side_effect=AssertionError("asked a question"))),
                    mock.patch("builtins.print"),
                ):
                    with self.assertRaises(mik.MikException) as ctx:
                        mik.dev_fetch_pod(SimpleNamespace(instance="inst"))
                self.assertIn(said, str(ctx.exception))
                self.assertEqual(os.listdir(d), [])

    def test_a_list_answer_with_errors_that_are_no_list_is_refused_in_a_line(self):
        for errors in (5, "boom", {"a": 1}):
            list_resp = json.dumps({"files": [{"path": "a.txt", "status": "M"}], "errors": errors}).encode()
            with self.subTest(errors=errors), tempfile.TemporaryDirectory() as d:
                self._setup(d)
                with (
                    mock.patch.object(mik, "_run_remote_script", side_effect=[(0, b"", list_resp)]),
                    mock.patch("builtins.print"),
                ):
                    with self.assertRaises(mik.MikException):
                        mik.dev_fetch_pod(SimpleNamespace(instance="inst"))

    def test_nothing_goes_into_a_repository_that_is_already_there(self):
        # No HEAD from a pod, so it makes no repository; one the local repo holds already has its HEAD.
        for path in ("fixtures/repo.git/config", "fixtures/repo.git/hooks/pre-commit", "fixtures/repo.git/a/b.txt"):
            with self.subTest(path=path), tempfile.TemporaryDirectory() as d:
                bare = Path(d) / "fixtures" / "repo.git"
                (bare / "hooks").mkdir(parents=True)
                (bare / "HEAD").write_text("ref: refs/heads/main\n")
                (bare / "config").write_text("[core]\n")
                before = sorted(str(x) for x in Path(d).rglob("*"))
                self._setup(d)
                list_resp = json.dumps({"files": [{"path": path, "status": "A"}], "errors": []}).encode()
                with (
                    mock.patch.object(mik, "_run_remote_script", side_effect=[(0, b"", list_resp)]) as remote,
                    mock.patch("builtins.input", mock.Mock(side_effect=AssertionError("asked a question"))),
                    mock.patch("builtins.print"),
                ):
                    with self.assertRaises(mik.MikException) as ctx:
                        mik.dev_fetch_pod(SimpleNamespace(instance="inst"))
                self.assertIn("holds a HEAD", str(ctx.exception))
                self.assertEqual(remote.call_count, 1)
                self.assertEqual(sorted(str(x) for x in Path(d).rglob("*")), before)
                self.assertEqual((bare / "config").read_text(), "[core]\n")

    def test_nothing_goes_into_a_directory_that_has_its_own_dot_git(self):
        # A clone, a worktree or a submodule inside the local repo: `git status` there does not look into it.
        for name, make_dot_git in (
            ("a clone (.git is a directory)", lambda p: p.mkdir()),
            ("a worktree or a submodule (.git is a file)", lambda p: p.write_text("gitdir: /elsewhere\n")),
            ("a .git that is a broken link", lambda p: p.symlink_to("/nowhere/at/all")),
        ):
            for path, status in (("vendor/lib/evil.py", "A"), ("vendor/lib/sub/evil.py", "A"), ("vendor/lib/x", "D")):
                with self.subTest(name=name, path=path), tempfile.TemporaryDirectory() as d:
                    nested = Path(d) / "vendor" / "lib"
                    nested.mkdir(parents=True)
                    (nested / "x").write_text("keep me")
                    make_dot_git(nested / ".git")
                    before = sorted(str(x) for x in Path(d).rglob("*"))
                    self._setup(d)
                    files = [{"path": "ok.txt", "status": "M"}, {"path": path, "status": status}]
                    list_resp = json.dumps({"files": files, "errors": []}).encode()
                    with (
                        mock.patch.object(mik, "_run_remote_script", side_effect=[(0, b"", list_resp)]) as remote,
                        mock.patch("builtins.input", mock.Mock(side_effect=AssertionError("asked a question"))),
                        mock.patch("builtins.print"),
                    ):
                        with self.assertRaises(mik.MikException) as ctx:
                            mik.dev_fetch_pod(SimpleNamespace(instance="inst"))
                    self.assertIn("holds a .git", str(ctx.exception))
                    self.assertEqual(remote.call_count, 1)  # never got to the fetch
                    self.assertEqual(sorted(str(x) for x in Path(d).rglob("*")), before)
                    self.assertEqual((nested / "x").read_text(), "keep me")

    def test_the_local_repo_itself_has_its_dot_git_and_is_written_into(self):
        list_resp = json.dumps({"files": [{"path": "sub/a.txt", "status": "A"}], "errors": []}).encode()
        fetch_payload = {"files": {"sub/a.txt": mik.base64.b64encode(b"hello").decode()}, "deleted": []}
        fetch_resp = mik.base64.b64encode(json.dumps(fetch_payload).encode())
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / ".git").mkdir()
            self._setup(d)
            with (
                mock.patch.object(mik, "_run_remote_script", side_effect=[(0, b"", list_resp), (0, b"", fetch_resp)]),
                mock.patch("builtins.input", return_value="y"),
                mock.patch("builtins.print"),
            ):
                mik.dev_fetch_pod(SimpleNamespace(instance="inst"))
            self.assertEqual((Path(d) / "sub" / "a.txt").read_bytes(), b"hello")

    def test_a_name_that_starts_with_a_dot_is_shown_in_red_before_the_question(self):
        for path, dot in (
            (".envrc", True),
            (".vscode/tasks.json", True),
            ("a/.hg/hgrc", True),
            (".github/workflows/ci.yml", True),
            ("src/.hidden", True),
            ("src/a.py", False),
            ("a.b/c.d", False),
            ("Makefile", False),
        ):
            with self.subTest(path=path):
                self.assertEqual(mik._is_dot_path(path), dot)
        files = [{"path": "src/a.py", "status": "M"}, {"path": ".vscode/tasks.json", "status": "A"}]
        list_resp = json.dumps({"files": files, "errors": []}).encode()
        shown = []

        def answer(prompt):  # what was printed by the time the question is asked
            shown.extend(c.args[0] for c in printed.call_args_list if c.args)
            return "n"

        with tempfile.TemporaryDirectory() as d:
            self._setup(d)
            with (
                mock.patch.object(mik, "_run_remote_script", side_effect=[(0, b"", list_resp)]),
                mock.patch("builtins.input", side_effect=answer),
                mock.patch("builtins.print") as printed,
            ):
                mik.dev_fetch_pod(SimpleNamespace(instance="inst"))
        self.assertIn("  \033[32m  modified\033[39m  src/a.py", shown)
        self.assertIn("  \033[32m       new\033[39m  \033[31m.vscode/tasks.json\033[39m", shown)
        self.assertTrue(any("1 under a name that starts with a dot (in red)" in line for line in shown))

    def test_no_word_about_dot_names_when_there_is_none(self):
        list_resp = json.dumps({"files": [{"path": "src/a.py", "status": "M"}], "errors": []}).encode()
        with tempfile.TemporaryDirectory() as d:
            self._setup(d)
            with (
                mock.patch.object(mik, "_run_remote_script", side_effect=[(0, b"", list_resp)]),
                mock.patch("builtins.input", return_value="n"),
                mock.patch("builtins.print") as printed,
            ):
                mik.dev_fetch_pod(SimpleNamespace(instance="inst"))
        self.assertFalse(any("dot" in str(c.args[0]) for c in printed.call_args_list if c.args))

    def test_what_is_there_has_to_be_what_the_path_says(self):
        for name, path, said in (
            ("a file where a directory is", "src", "is not a regular file here"),
            ("a directory where a file is", "Makefile/x.txt", "is not a directory here"),
        ):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as d:
                (Path(d) / "src").mkdir()
                (Path(d) / "Makefile").write_text("all:\n")
                self._setup(d)
                files = [{"path": "ok.txt", "status": "M"}, {"path": path, "status": "M"}]
                list_resp = json.dumps({"files": files, "errors": []}).encode()
                with (
                    mock.patch.object(mik, "_run_remote_script", side_effect=[(0, b"", list_resp)]),
                    mock.patch("builtins.input", mock.Mock(side_effect=AssertionError("asked a question"))),
                    mock.patch("builtins.print"),
                ):
                    with self.assertRaises(mik.MikException) as ctx:
                        mik.dev_fetch_pod(SimpleNamespace(instance="inst"))
                self.assertIn(said, str(ctx.exception))
                self.assertEqual(sorted(os.listdir(d)), ["Makefile", "src"])

    def test_stderr_from_the_pod_cannot_carry_escape_sequences(self):
        # `docker exec ... python3`: the python3 that answers is the pod's own, and so is what it writes.
        with tempfile.TemporaryDirectory() as d:
            self._setup(d)
            with mock.patch.object(
                mik, "_run_remote_script", side_effect=[(1, b"boom \033[2J\033[H\nline 2\r\xff", b"")]
            ):
                with self.assertRaises(mik.MikException) as ctx:
                    mik.dev_fetch_pod(SimpleNamespace(instance="inst"))
        self.assertEqual(str(ctx.exception), "SSH failed: boom [2J[H\nline 2\n�")

    def test_remote_warnings_cannot_carry_escape_sequences(self):
        list_resp = json.dumps({"files": [], "errors": ["invalid path: a\033[2Kb"]}).encode()
        with tempfile.TemporaryDirectory() as d:
            self._setup(d)
            with (
                mock.patch.object(mik, "_run_remote_script", side_effect=[(0, b"", list_resp)]),
                mock.patch("builtins.print") as printed,
            ):
                mik.dev_fetch_pod(SimpleNamespace(instance="inst"))
        self.assertIn("\033[90m  warning: invalid path: a[2Kb\033[39m", [c.args[0] for c in printed.call_args_list])


@unittest.skipUnless(shutil.which("git"), "needs git")
class DevFetchPodIgnoredTests(unittest.TestCase):
    """What the local repo ignores, `git status` there does not show: a pod does not get to write or delete it."""

    def _git(self, repo, *argv):
        base = ["git", "-C", str(repo), "-c", "user.email=t@example.invalid", "-c", "user.name=t"]
        subprocess.run([*base, "-c", "commit.gpgsign=false", *argv], check=True, capture_output=True)

    def _repo(self, d):
        repo = Path(d) / "repo"
        (repo / ".venv" / "lib").mkdir(parents=True)
        self._git(repo, "init", "-q")
        (repo / ".gitignore").write_text(".venv/\n.env\n*.log\n!kept.log\n")
        (repo / "app.py").write_text("a\n")
        (repo / ".env").write_text("SECRET=1\n")
        self._git(repo, "add", ".gitignore", "app.py")
        (repo / "tracked.log").write_text("t\n")
        self._git(repo, "add", "-f", "tracked.log")
        self._git(repo, "commit", "-q", "-m", "init")
        for registry in (mik.instances_dict, mik.machines_dict, mik.projects_dict):
            registry.clear()
            self.addCleanup(registry.clear)
        mik.machines_dict["box"] = SimpleNamespace(name="box", ssh_host="user@host")
        mik.projects_dict["proj"] = SimpleNamespace(name="proj", local_repo=str(repo), github_repo=None)
        mik.instances_dict["inst"] = _inst("inst", project="proj", machine="box", container="c1", code_dir="/code")
        return repo

    def _fetch(self, files, answer=True):
        """Run dev-fetch-pod against a pod that lists [(path, status, content)] and sends just that."""
        listed = [{"path": path, "status": status} for path, status, _ in files]
        payload = {
            "files": {p: mik.base64.b64encode(c).decode() for p, status, c in files if status != "D"},
            "deleted": [p for p, status, _ in files if status == "D"],
        }
        responses = [(0, b"", json.dumps({"files": listed, "errors": []}).encode())]
        if answer:
            responses.append((0, b"", mik.base64.b64encode(json.dumps(payload).encode())))
        with (
            mock.patch.object(mik, "_run_remote_script", side_effect=responses) as remote,
            mock.patch("builtins.input", return_value="y" if answer else mock.DEFAULT) as asked,
            mock.patch("builtins.print"),
        ):
            try:
                mik.dev_fetch_pod(SimpleNamespace(instance="inst"))
            finally:
                self.calls, self.asked = remote.call_count, asked.call_count

    def test_what_git_knows_is_asked_of_git(self):
        with tempfile.TemporaryDirectory() as d:
            repo = self._repo(d)
            paths = ["app.py", ".venv/lib/x.pth", "new.py", "sub/debug.log", "kept.log", "tracked.log", ".env"]
            self.assertEqual(mik._locally_ignored(str(repo), paths), [".venv/lib/x.pth", "sub/debug.log", ".env"])
            self.assertEqual(mik._locally_ignored(str(repo), ["app.py", "new.py"]), [])
            self.assertEqual(mik._locally_ignored(str(repo), []), [])

    def test_an_ignored_path_is_refused_before_the_question_written_or_deleted(self):
        for path, status in ((".venv/lib/x.pth", "A"), ("sub/debug.log", "M"), (".env", "D")):
            with self.subTest(path=path), tempfile.TemporaryDirectory() as d:
                repo = self._repo(d)
                with self.assertRaises(mik.MikException) as ctx:
                    self._fetch([("app.py", "M", b"b\n"), (path, status, b"import os\n")], answer=False)
                self.assertIn(f"the local repo ignores {path}.", str(ctx.exception))
                self.assertEqual((self.calls, self.asked), (1, 0))  # no question, no fetch
                self.assertEqual((repo / "app.py").read_text(), "a\n")
                self.assertEqual((repo / ".env").read_text(), "SECRET=1\n")
                self.assertEqual(os.listdir(repo / ".venv" / "lib"), [])

    def test_what_git_shows_is_fetched(self):
        with tempfile.TemporaryDirectory() as d:
            repo = self._repo(d)
            self._fetch([("app.py", "M", b"b\n"), ("new.py", "A", b"n\n"), ("tracked.log", "M", b"t2\n")])
            self.assertEqual((repo / "app.py").read_text(), "b\n")
            self.assertEqual((repo / "new.py").read_text(), "n\n")
            self.assertEqual((repo / "tracked.log").read_text(), "t2\n")  # tracked: shown by git, ignored or not

    def test_a_gitignore_that_comes_with_a_file_and_hides_it_stops_everything_before_a_write(self):
        old_rules = ".venv/\n.env\n*.log\n!kept.log\n"
        for name, files, hidden in (
            (
                "the one at the top",
                [(".gitignore", "M", b".venv/\nconftest.py\n"), ("conftest.py", "A", b"import os\n")],
                "conftest.py",
            ),
            (
                "a new one in a new directory",
                [("pkg/.gitignore", "A", b"*.pth\n"), ("pkg/deep/x.pth", "A", b"import os\n")],
                "pkg/deep/x.pth",
            ),
            ("one that hides itself", [("pkg/.gitignore", "A", b".gitignore\n")], "pkg/.gitignore"),
        ):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as d:
                repo = self._repo(d)
                before = sorted(str(x) for x in repo.rglob("*") if ".git/" not in str(x))
                with self.assertRaises(mik.MikException) as ctx:
                    self._fetch([("app.py", "M", b"b\n"), *files])
                self.assertIn(f"would ignore {hidden}, and", str(ctx.exception))
                self.assertEqual(self.calls, 2)  # the contents were needed to know
                self.assertEqual(sorted(str(x) for x in repo.rglob("*") if ".git/" not in str(x)), before)
                self.assertEqual((repo / "app.py").read_text(), "a\n")
                self.assertEqual((repo / ".gitignore").read_text(), old_rules)

    def test_the_rules_are_those_the_repo_would_have(self):
        with tempfile.TemporaryDirectory() as d:
            repo = self._repo(d)
            ask = lambda paths, coming: mik._locally_ignored(str(repo), paths, coming)  # noqa: E731
            self.assertEqual(ask(["a.py", "x.log"], {".gitignore": b"a.py\n"}), ["a.py"])  # *.log is gone
            self.assertEqual(ask(["a.py", "x.log", ".env"], {".gitignore": None}), [])  # deleted: no rule left
            self.assertEqual(ask(["s/a.py", "t/a.py"], {"s/.gitignore": b"a.py\n"}), ["s/a.py"])
            self.assertEqual(ask(["s/x.log"], {"s/.gitignore": b"!x.log\n"}), [])  # a negation, read by git
            self.assertEqual(ask(["tracked.log"], {".gitignore": b"*\n"}), [])  # tracked: git shows it
            (repo / ".git" / "info" / "exclude").write_text("local-only.txt\n")
            self.assertEqual(ask(["local-only.txt"], {".gitignore": b""}), ["local-only.txt"])  # not .gitignore's
            self.assertEqual((repo / ".gitignore").read_text(), ".venv/\n.env\n*.log\n!kept.log\n")
            self.assertFalse((repo / "s").exists())  # asked elsewhere: nothing was written to know

    def test_a_gitignore_that_hides_nothing_that_came_is_fetched(self):
        with tempfile.TemporaryDirectory() as d:
            repo = self._repo(d)
            self._fetch([(".gitignore", "M", b".venv/\n.env\n*.log\ndist/\n"), ("new.py", "A", b"n\n")])
            self.assertEqual((repo / ".gitignore").read_text(), ".venv/\n.env\n*.log\ndist/\n")
            self.assertEqual((repo / "new.py").read_text(), "n\n")

    def test_a_local_repo_that_is_a_directory_of_a_repository(self):
        # The rules above local_repo count too, and the paths are from local_repo.
        with tempfile.TemporaryDirectory() as d:
            repo = self._repo(d)
            (repo / "sub").mkdir()
            (repo / "sub" / ".gitignore").write_text("secret.txt\n")
            ask = lambda paths, coming=None: mik._locally_ignored(str(repo / "sub"), paths, coming)  # noqa: E731
            self.assertEqual(ask(["a.py", "x.log", "secret.txt", "deep/x.log"]), ["x.log", "secret.txt", "deep/x.log"])
            self.assertEqual(ask(["a.py", "secret.txt"], {".gitignore": b"a.py\n"}), ["a.py"])

    def test_a_file_git_was_told_not_to_look_at_is_asked_of_git(self):
        with tempfile.TemporaryDirectory() as d:
            repo = self._repo(d)
            (repo / "sub").mkdir()
            for name in ("skipped.py", "assumed.py", "both.py", "sub/skipped.py", "sub/plain.py"):
                (repo / name).write_text("mine\n")
                self._git(repo, "add", name)
            self._git(repo, "commit", "-q", "-m", "more")
            self._git(repo, "update-index", "--skip-worktree", "skipped.py", "both.py", "sub/skipped.py")
            self._git(repo, "update-index", "--assume-unchanged", "assumed.py", "both.py")
            ask = mik._locally_unwatched
            paths = ["app.py", "skipped.py", "new.py", "assumed.py", "both.py", "sub/skipped.py", "sub/plain.py"]
            self.assertEqual(ask(str(repo), paths), ["skipped.py", "assumed.py", "both.py", "sub/skipped.py"])
            self.assertEqual(ask(str(repo), ["app.py", "new.py", "tracked.log", ".venv/lib/x.pth"]), [])
            self.assertEqual(ask(str(repo), []), [])
            # a local_repo that is a directory of a repository: the paths are from local_repo
            self.assertEqual(ask(str(repo / "sub"), ["skipped.py", "plain.py", "both.py"]), ["skipped.py"])

    def test_a_file_git_was_told_not_to_look_at_is_refused_before_the_question(self):
        for flag in ("--skip-worktree", "--assume-unchanged"):
            for status in ("M", "D"):
                with self.subTest(flag=flag, status=status), tempfile.TemporaryDirectory() as d:
                    repo = self._repo(d)
                    (repo / "local.cfg").write_text("upstream\n")
                    self._git(repo, "add", "local.cfg")
                    self._git(repo, "commit", "-q", "-m", "cfg")
                    self._git(repo, "update-index", flag, "local.cfg")
                    (repo / "local.cfg").write_text("my own change, kept out of sight\n")
                    with self.assertRaises(mik.MikException) as ctx:
                        self._fetch([("app.py", "M", b"b\n"), ("local.cfg", status, b"from the pod\n")], answer=False)
                    self.assertIn("git was told not to look at local.cfg in the local repo", str(ctx.exception))
                    self.assertEqual((self.calls, self.asked), (1, 0))  # no question, no fetch
                    self.assertEqual((repo / "local.cfg").read_text(), "my own change, kept out of sight\n")
                    self.assertEqual((repo / "app.py").read_text(), "a\n")

    def test_a_local_repo_git_cannot_be_asked_what_it_tracks_gets_nothing(self):
        with tempfile.TemporaryDirectory() as d:
            with mock.patch.dict(os.environ, {"GIT_CEILING_DIRECTORIES": d}):
                with self.assertRaises(mik.MikException) as ctx:
                    mik._locally_unwatched(d, ["a.txt"])
            self.assertIn("is it a git repository?", str(ctx.exception))
        with mock.patch.object(mik.subprocess, "run", side_effect=FileNotFoundError("git")):
            with self.assertRaises(mik.MikException):
                mik._locally_unwatched("/nowhere", ["a.txt"])

    def test_a_local_repo_git_cannot_be_asked_about_gets_nothing(self):
        with tempfile.TemporaryDirectory() as d:
            self._repo(d)
            plain = Path(d) / "plain"
            plain.mkdir()
            mik.projects_dict["proj"].local_repo = str(plain)
            with mock.patch.dict(os.environ, {"GIT_CEILING_DIRECTORIES": d}):
                with self.assertRaises(mik.MikException) as ctx:
                    self._fetch([("a.txt", "A", b"x")], answer=False)
            self.assertIn("is it a git repository?", str(ctx.exception))
            self.assertEqual((self.calls, self.asked), (1, 0))
            self.assertEqual(os.listdir(plain), [])
        with mock.patch.object(mik.subprocess, "run", side_effect=FileNotFoundError("git")):
            with self.assertRaises(mik.MikException):
                mik._locally_ignored("/nowhere", ["a.txt"])


class PopCappedTests(unittest.TestCase):
    def _py(self, code):
        return [sys.executable, "-c", code]

    def test_what_fits_comes_back_as_pop_gives_it(self):
        code = "import sys; sys.stdout.write('o' * 1000); sys.stderr.write('e' * 1000); sys.exit(3)"
        self.assertEqual(mik._pop_capped(self._py(code), 1000), (3, b"e" * 1000, b"o" * 1000))

    def test_more_than_the_limit_on_either_is_refused(self):
        for stream in ("stdout", "stderr"):
            with self.subTest(stream=stream):
                code = f"import sys\nwhile True: sys.{stream}.write('x' * 65536)"  # never ends by itself
                with self.assertRaises(mik.MikException) as ctx:
                    mik._pop_capped(self._py(code), 200_000)
                self.assertIn("more than 200000 bytes", str(ctx.exception))

    def test_a_remote_script_is_run_under_the_limit(self):
        with (
            mock.patch.object(mik, "_pop_capped", return_value=(0, b"", b"{}")) as capped,
            mock.patch.object(mik, "POD_OUTPUT_MAX_BYTES", 123),
        ):
            self.assertEqual(mik._run_remote_script("user@host", "c1", "print(1)"), (0, b"", b"{}"))
        (argv, limit), _ = capped.call_args
        self.assertEqual((argv[:2], limit), (["ssh", "user@host"], 123))


@unittest.skipUnless(shutil.which("git"), "needs git")
class RemoteListScriptTests(unittest.TestCase):
    """The listing script that runs in the pod, run here as it is, on a real repository."""

    def _git(self, repo, *argv):
        base = ["git", "-C", str(repo), "-c", "user.email=t@example.invalid", "-c", "user.name=t"]
        subprocess.run([*base, "-c", "commit.gpgsign=false", *argv], check=True, capture_output=True)

    def _list(self, repo):
        script = mik.REMOTE_SCRIPT_LIST.format(validate_path=mik._REMOTE_VALIDATE_PATH, code_dir=str(repo))
        out = subprocess.run([sys.executable, "-c", script], check=True, capture_output=True, text=True).stdout
        data = json.loads(out)
        return {f["path"]: f["status"] for f in data["files"]}, data["errors"]

    def _repo(self, d):
        repo = Path(d) / "repo"
        repo.mkdir()
        self._git(repo, "init", "-q")
        (repo / ".gitignore").write_text("secret.env\nbuild/\n")
        (repo / "old.py").write_text("a\n")
        (repo / "kept.py").write_text("a\n")
        self._git(repo, "add", ".")
        self._git(repo, "commit", "-q", "-m", "init")
        return repo

    def test_what_is_ignored_stays_out_of_a_new_directory(self):
        with tempfile.TemporaryDirectory() as d:
            repo = self._repo(d)
            (repo / "newdir" / "build").mkdir(parents=True)
            (repo / "newdir" / "keep.py").write_text("x\n")
            (repo / "newdir" / "secret.env").write_text("s\n")
            (repo / "newdir" / "build" / "out.bin").write_text("o\n")
            (repo / "kept.py").write_text("b\n")
            files, errors = self._list(repo)
        self.assertEqual(files, {"newdir/keep.py": "A", "kept.py": "M"})
        self.assertEqual(errors, [])

    def test_a_rename_is_a_deletion_and_a_new_file_staged_or_not(self):
        for staged in (True, False):
            with self.subTest(staged=staged), tempfile.TemporaryDirectory() as d:
                repo = self._repo(d)
                if staged:
                    self._git(repo, "mv", "old.py", "new.py")
                else:
                    (repo / "old.py").rename(repo / "new.py")
                files, errors = self._list(repo)
                self.assertEqual(files, {"old.py": "D", "new.py": "A"})
                self.assertEqual(errors, [])

    def test_a_symlink_and_a_repository_inside_are_left_out_with_a_warning(self):
        with tempfile.TemporaryDirectory() as d:
            repo = self._repo(d)
            (repo / "newdir" / "sub").mkdir(parents=True)
            (repo / "newdir" / "keep.py").write_text("x\n")
            (repo / "newdir" / "link").symlink_to("/etc/passwd")
            self._git(repo / "newdir" / "sub", "init", "-q")
            (repo / "newdir" / "sub" / "f.py").write_text("y\n")
            files, errors = self._list(repo)
        self.assertEqual(files, {"newdir/keep.py": "A"})
        self.assertEqual(sorted(errors), ["invalid path: newdir/sub/", "symlink rejected: newdir/link"])


class ConfigNameCollisionTests(unittest.TestCase):
    """The config is exec'd into mik's namespace: it must not get to replace what mik runs."""

    def _load(self, config):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "config.py").write_text(config)
            os.chmod(Path(d) / "config.py", 0o600)  # whatever the umask: load_config wants it yours alone
            with mock.patch.object(mik, "CONFIG_FILE", Path(d) / "config.py"):
                mik.load_config()

    def test_a_name_of_mik_defined_again_is_refused_naming_it(self):
        for config, taken in (
            ("def build(target):\n    pass\n", "build"),
            ("debug = True\n", "debug"),
            ("class Color:\n    pass\n", "Color"),
            ("def deploy():\n    pass\n\n\ndef pop(cmd):\n    pass\n", "deploy, pop"),
        ):
            with self.subTest(taken=taken), contextlib.ExitStack() as stack:
                for name in taken.split(", "):  # put mik's own back, whatever the config did to it
                    stack.enter_context(mock.patch.object(mik, name, getattr(mik, name)))
                with self.assertRaises(mik.MikException) as ctx:
                    self._load(config)
                self.assertTrue(str(ctx.exception).startswith(f"The config file defines {taken}: "))

    def test_settings_helpers_of_its_own_and_the_same_imports_are_fine(self):
        config = (
            "import os\nimport subprocess\nfrom pathlib import Path\nfrom datetime import datetime\n"
            'ROOT_CA_FILE = "/tmp/ca.pem"\nGITHUB_COM_CERT_SHA256 = ["ab" * 32]\n'
            'ARTIFACTS_DIR = Path("/tmp/artifacts")\n'
            "def my_collision_test_helper():\n    return run_step\n"
        )
        self.addCleanup(lambda: vars(mik).pop("my_collision_test_helper", None))
        with (
            mock.patch.object(mik, "ROOT_CA_FILE", None),
            mock.patch.object(mik, "GITHUB_COM_CERT_SHA256", None),
            mock.patch.object(mik, "ARTIFACTS_DIR", mik.ARTIFACTS_DIR),
        ):
            self._load(config)
            self.assertEqual(mik.ROOT_CA_FILE, "/tmp/ca.pem")
            self.assertEqual(mik.ARTIFACTS_DIR, Path("/tmp/artifacts"))
            self.assertIs(mik.my_collision_test_helper(), mik.run_step)


class ConfigPermissionTests(unittest.TestCase):
    """The config is run as Python: one that somebody else could have written is not."""

    def _load(self, file_mode, dir_mode):
        with tempfile.TemporaryDirectory() as d:
            inside = Path(d) / "mik"
            inside.mkdir()
            (inside / "config.py").write_text("config_permission_test_ran = True\n")
            os.chmod(inside / "config.py", file_mode)
            os.chmod(inside, dir_mode)
            self.addCleanup(lambda: vars(mik).pop("config_permission_test_ran", None))
            with mock.patch.object(mik, "CONFIG_FILE", inside / "config.py"):
                mik.load_config()

    def test_yours_alone_is_run(self):
        for file_mode, dir_mode in ((0o600, 0o700), (0o644, 0o755), (0o644, 0o1777)):  # the last: as in /tmp
            with self.subTest(file_mode=oct(file_mode), dir_mode=oct(dir_mode)):
                vars(mik).pop("config_permission_test_ran", None)
                self._load(file_mode, dir_mode)
                self.assertTrue(mik.config_permission_test_ran)

    def test_one_that_others_can_write_is_not_run(self):
        for file_mode, dir_mode, said in (
            (0o664, 0o700, "it has to be yours"),
            (0o646, 0o700, "it has to be yours"),
            (0o600, 0o775, "its directory has to be yours"),
            (0o600, 0o777, "its directory has to be yours"),
        ):
            with self.subTest(file_mode=oct(file_mode), dir_mode=oct(dir_mode)):
                with self.assertRaises(mik.MikException) as ctx:
                    self._load(file_mode, dir_mode)
                self.assertIn(said, str(ctx.exception))
                self.assertFalse(hasattr(mik, "config_permission_test_ran"))

    def test_somebody_elses_file_is_not_run(self):
        with mock.patch.object(mik.os, "geteuid", return_value=os.geteuid() + 1):
            if os.geteuid() == 0:
                self.skipTest("root's own files are trusted")
            with self.assertRaises(mik.MikException):
                self._load(0o600, 0o700)


class DuplicateNameTests(unittest.TestCase):
    """Defining a subclass registers it under its name: a second one with that name must not replace it."""

    def setUp(self):
        for registry in (mik.machines_dict, mik.projects_dict, mik.instances_dict):
            registry.clear()
            self.addCleanup(registry.clear)

    def test_duplicate_is_refused_naming_both_classes(self):
        for base, kind, fields in (
            (mik.Machine, "machine", {"name": "x", "ssh_host": "user@host"}),
            (mik.Project, "project", {"name": "x"}),
            (mik.Instance, "instance", {"name": "x"}),
        ):
            with self.subTest(kind=kind):
                first = type("First", (base,), dict(fields))
                with self.assertRaises(mik.MikException) as ctx:
                    type("Second", (base,), dict(fields))
                self.assertEqual(str(ctx.exception), f"Duplicate {kind} name 'x': classes First and Second")
                registry = {"machine": mik.machines_dict, "project": mik.projects_dict, "instance": mik.instances_dict}
                self.assertIs(registry[kind]["x"], first)  # the first one is still the one registered

    def test_same_name_across_kinds_is_fine(self):
        type("M", (mik.Machine,), {"name": "x", "ssh_host": "user@host"})
        type("P", (mik.Project,), {"name": "x"})
        type("I", (mik.Instance,), {"name": "x"})

    def test_load_config_reports_it_as_is(self):
        # No traceback, no generic "Something wrong in the config file": the message itself gets out.
        config = 'class DupTestOne(Instance):\n    name = "x"\n\n\nclass DupTestTwo(Instance):\n    name = "x"\n'
        self.addCleanup(lambda: [vars(mik).pop(n, None) for n in ("DupTestOne", "DupTestTwo")])
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "config.py").write_text(config)
            os.chmod(Path(d) / "config.py", 0o600)  # whatever the umask: load_config wants it yours alone
            with mock.patch.object(mik, "CONFIG_FILE", Path(d) / "config.py"):
                with contextlib.redirect_stderr(io.StringIO()) as err:
                    with self.assertRaises(mik.MikException) as ctx:
                        mik.load_config()
        self.assertEqual(str(ctx.exception), "Duplicate instance name 'x': classes DupTestOne and DupTestTwo")
        self.assertEqual(err.getvalue(), "")


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

        with (
            mock.patch.object(mik, "GITHUB_COM_CERT_SHA256", self.PIN),
            mock.patch.object(mik, "urlopen", fake_urlopen),
        ):
            out = mik._github_get_json("/repos/o/r")
        self.assertEqual(out, {"ok": True})
        self.assertEqual(type(captured["context"]).__name__, "PinnedSSLContext")

    def test_get_no_context_without_pin(self):
        captured = {}

        def fake_urlopen(req, timeout=None, context=None):
            captured["context"] = context
            return _FakeResp(b"{}")

        with mock.patch.object(mik, "GITHUB_COM_CERT_SHA256", None), mock.patch.object(mik, "urlopen", fake_urlopen):
            mik._github_get_json("/repos/o/r")
        self.assertIsNone(captured["context"])


class ConfiguredPinsTests(unittest.TestCase):
    PIN, OTHER = "ab" * 32, "cd" * 32

    def test_one_or_several(self):
        self.assertEqual(mik.configured_pins(self.PIN.upper()), (self.PIN,))
        self.assertEqual(mik.configured_pins([self.PIN, self.OTHER.upper()]), (self.PIN, self.OTHER))
        self.assertEqual(mik.configured_pins((self.PIN,)), (self.PIN,))

    def test_what_a_pin_command_prints(self):
        out = mik.run_step([sys.executable, "-c", f"print('{self.PIN}'); print('{self.OTHER}')"])
        self.assertEqual(mik.configured_pins(out.decode().split()), (self.PIN, self.OTHER))

    def test_bad_values_are_refused(self):
        too_many = [self.PIN] * (mik.PIN_MAX_COUNT + 1)
        bads = ("", "ab" * 31, "zz" * 32, self.PIN + " ", [], [""], [self.PIN, "nope"], [self.PIN, 1], too_many)
        for bad in (*bads, [self.PIN.encode()], self.PIN.encode(), 42, {self.PIN: 1}):
            with self.subTest(bad=bad), self.assertRaises(mik.MikException):
                mik.configured_pins(bad)

    def test_get_accepts_any_of_several(self):
        captured = {}

        def fake_urlopen(req, timeout=None, context=None):
            captured["context"] = context
            return _FakeResp(b"{}")

        def fake_context(pins, cafile=None):
            captured["pins"] = pins
            return "context"

        with (
            mock.patch.object(mik, "GITHUB_COM_CERT_SHA256", [self.PIN, self.OTHER]),
            mock.patch.object(mik, "make_pinned_ssl_context", fake_context),
            mock.patch.object(mik, "urlopen", fake_urlopen),
        ):
            mik._github_get_json("/repos/o/r")
        self.assertEqual(captured, {"pins": (self.PIN, self.OTHER), "context": "context"})

    def test_bad_pin_never_connects(self):
        for bad in ("", [], ["nope"]):
            with (
                self.subTest(bad=bad),
                mock.patch.object(mik, "GITHUB_COM_CERT_SHA256", bad),
                mock.patch.object(mik, "urlopen", side_effect=AssertionError("connected")),
            ):
                with self.assertRaises(mik.MikException):
                    mik._github_get_json("/repos/o/r")
                with self.assertRaises(mik.MikException):
                    mik.pinned_urlopen("https://x/y", bad)
                self.assertEqual(mik._fetch_ci_status("p", "o/r")["state"], mik.CI_FETCH_ERROR)


class PinnedUrlopenTests(unittest.TestCase):
    PIN = "ab" * 32  # 64 hex chars; only verified during a real handshake

    def test_pins_when_sha_given(self):
        captured = {}

        def fake_urlopen(url, timeout=None, context=None):
            captured["context"] = context
            return _FakeResp(b"x")

        with mock.patch.object(mik, "urlopen", fake_urlopen):
            with mik.pinned_urlopen("https://x/y", self.PIN) as r:
                self.assertEqual(r.read(), b"x")
        self.assertEqual(type(captured["context"]).__name__, "PinnedSSLContext")

    def test_no_pin_means_no_context(self):
        captured = {}

        def fake_urlopen(url, timeout=None, context=None):
            captured["context"] = context
            return _FakeResp(b"x")

        with mock.patch.object(mik, "urlopen", fake_urlopen):
            with mik.pinned_urlopen("https://x/y"):
                pass
        self.assertIsNone(captured["context"])

    def test_https_only_pin_or_not(self):
        # Over anything else there is no certificate: a pin would be given for nothing, without a word.
        with mock.patch.object(mik, "urlopen", side_effect=AssertionError("connected")):
            for url in ("http://x/y", "file:///etc/passwd", "ftp://x/y", "x/y", mik.Request("http://x/y"), None):
                for pin in (self.PIN, None):
                    with self.subTest(url=url, pin=pin), self.assertRaises(mik.MikException):
                        mik.pinned_urlopen(url, pin)

    def test_a_request_object_and_any_case_of_the_scheme_are_fine(self):
        with mock.patch.object(mik, "urlopen", return_value=_FakeResp(b"x")) as opened:
            mik.pinned_urlopen(mik.Request("https://x/y"))
            mik.pinned_urlopen("HTTPS://x/y")
        self.assertEqual(opened.call_count, 2)


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
            self.assertEqual(mik.ci_status(SimpleNamespace(project="p")), 1)

    def test_fetch_error_is_nonzero(self):
        self._proj("p", "o/r")
        fake = fake_github({"/repos/o/r": mik.MikException("404 Not Found")})
        with mock.patch.object(mik, "_github_get_json", side_effect=fake):
            self.assertEqual(mik.ci_status(SimpleNamespace(project="p")), 1)

    def test_a_branch_name_that_is_not_plain_does_not_go_into_the_url(self):
        # The default branch is what the API answered: only chars from the allowlist are put in a URL.
        for branch in ("dév", "a#b", "a?b=c", "a b", "../../users/x", "a//b", "/a", "a/", ".", "a%2fb", 5, ["main"]):
            self._proj("p", "o/r")
            fake = mock.Mock(side_effect=fake_github({"/repos/o/r": {"default_branch": branch}}))
            with self.subTest(branch=branch), mock.patch.object(mik, "_github_get_json", fake):
                result = mik._fetch_ci_status("p", "o/r")
                self.assertEqual(result["state"], mik.CI_FETCH_ERROR)
                self.assertIn("unsupported default branch name", result["detail"])
                fake.assert_called_once_with("/repos/o/r")  # nothing was asked about that branch

    def test_a_plain_branch_name_goes_into_the_url(self):
        for branch in ("main", "release/1.0", "feat/a-b_c.d"):
            self._proj("p", "o/r")
            runs = {"check_runs": [{"status": "completed", "conclusion": "success"}]}
            fake = mock.Mock(
                side_effect=fake_github({"/repos/o/r": {"default_branch": branch}, "/repos/o/r/commits/": runs})
            )
            with self.subTest(branch=branch), mock.patch.object(mik, "_github_get_json", fake):
                self.assertEqual(mik._fetch_ci_status("p", "o/r")["state"], mik.CI_GOOD)
                fake.assert_called_with(f"/repos/o/r/commits/{branch}/check-runs")

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
        self.assertEqual(rc, 1)  # bad1 is a failure

    def test_all_with_no_github_projects(self):
        self._proj("noci", None)
        with mock.patch("builtins.print") as p:
            rc = mik.ci_status(SimpleNamespace(project="ALL"))
        self.assertIsNone(rc)
        self.assertTrue(any("No projects with a github_repo" in str(c.args[0]) for c in p.call_args_list))


def _remote_cmds(rs_mock):
    """Each run_step() call flattened to a single string, for substring/order assertions."""
    out = []
    for c in rs_mock.call_args_list:
        cmda = c.args[0]
        out.append(" ".join(cmda) if isinstance(cmda, list) else str(cmda))
    return out


class DeployReleaseTests(unittest.TestCase):
    """deploy_release ships an already-built artifact via scp/ssh as the (unprivileged) ssh user — no sudo.
    We mock pop (the writability preflight) + run_step and assert the exact remote command sequence. The one
    step whose output matters is the look at the remote site root: `_survey` writes what it would print."""

    S = "/var/www/site"
    R = "/var/www/site/releases"
    M = "/var/www/site/merged"
    DAY = 86400
    NOW = 2_000_000

    def _src(self, d):
        """A finished artifact dir (what build_artifact would have produced) under tmp dir `d`."""
        src = Path(d) / "1750000000-dist"
        src.mkdir(parents=True)
        (src / "index.html").write_text("<html>")
        (src / "bundle.YYY.js").write_text("//y")
        return src

    @classmethod
    def _survey(cls, current, releases, merged=(), unfinished=()):
        """What the remote prints: its clock, where `current` leads, what is in the four directories."""
        lines = [f"now {cls.NOW}", f"current {current}".rstrip()]
        lines += [f"releases d {cls.NOW - age}.5 {name}" for name, age in releases]
        lines += [f"merged d {cls.NOW - 60}.0 {name}" for name in merged]
        lines += [f"{path.split('/')[0]} d {cls.NOW - 3600}.0 {path.split('/')[1]}" for path in unfinished]
        return ("\n".join(lines) + "\n").encode()

    def _deploy(self, survey, run_step=None, answer=None, **kwargs):
        """deploy_release of release 123 with ssh mocked; returns (pop mock, remote commands, printed, src).

        `answer` is what the user types when asked something; None means nothing may be asked."""

        def step(cmda, *a, **k):
            return survey if "echo now" in " ".join(cmda) else b""

        asked = mock.Mock(side_effect=AssertionError("asked a question") if answer is None else answer)
        self.cmds = []
        with tempfile.TemporaryDirectory() as d:
            src = self._src(d)
            with (
                mock.patch.object(mik, "pop", return_value=(0, b"", b"")) as pop,
                mock.patch.object(mik, "run_step", side_effect=run_step or step) as rs,
                mock.patch("builtins.print") as p,
                mock.patch("builtins.input", asked),
            ):
                try:
                    mik.deploy_release(src, "user@host", self.S, release_id="123", name="site", **kwargs)
                finally:
                    self.cmds = _remote_cmds(rs)  # also there for a test that expects the deploy to raise
            return pop, self.cmds, _printed(p), src

    @staticmethod
    def _idx(cmds, sub):
        return next(i for i, c in enumerate(cmds) if sub in c)

    def _ready(self, cmds):
        """The command that gets the upload ready beside what is served (and makes the merge)."""
        return cmds[self._idx(cmds, f"chmod -R u+rwX {self.S}/releasing/123")]

    # Three releases on the remote: two from before the last day (only the newer of them was still live
    # when the day began) and one from within it.
    HISTORY = [("100", 9 * DAY), ("105", 2 * DAY), ("110", DAY // 2)]

    def test_merge_sequence(self):
        survey = self._survey("merged/110", self.HISTORY, merged=["105", "110"])
        pop, cmds, printed, src = self._deploy(survey)

        pop.assert_called_once()  # writability preflight ran, on the four directories
        preflight = pop.call_args.args[0][-1]
        for where in ("releases", "merged", "releasing", "merging"):
            self.assertIn(f"test -w {self.S}/{where}", preflight)
        look = self._idx(cmds, "echo now $(date +%s)")
        self.assertIn("readlink current", cmds[look])
        self.assertIn("find releases merged releasing merging -mindepth 1 -maxdepth 1", cmds[look])
        self.assertIn("-printf '%h %y %T@ %f\\n'", cmds[look])
        # what is about to be merged is listed before anything is uploaded: 105 and 110, not 100
        held = self._idx(cmds, "-printf '%y %p\\0'")
        self.assertEqual(cmds[held], f"ssh user@host cd {self.R} && find 105 110 -mindepth 1 -printf '%y %p\\0'")
        scp = self._idx(cmds, "scp -r")
        # ships the artifact dir itself, no local copy, into releasing/ — not yet a release
        self.assertEqual(cmds[scp], f"scp -r {src} user@host:{self.S}/releasing/123")
        ready = self._idx(cmds, f"mkdir {self.S}/merging/123")
        live = self._idx(cmds, "ln -sfn merged/123")
        cleanup = self._idx(cmds, f"rm -rf {self.M}/105")
        # strict ordering: look -> what is to be merged -> ship -> get ready -> go live -> delete leftovers,
        # and nothing else
        self.assertEqual([look, held, scp, ready, live, cleanup], [0, 1, 2, 3, 4, 5])
        self.assertEqual(len(cmds), 6)

        # getting ready: the upload given the modes it is served with, then the merge — the release that was
        # live when the day began, the one from within the day, and the new one LAST so it wins on shared
        # names. 100 was already replaced before the day began: left out.
        built = cmds[ready]
        up, merge = f"{self.S}/releasing/123", f"{self.S}/merging/123"
        modes = "chmod -R u+rwX {0} && find {0} -type d -exec chmod 755 '{{}}' + && find {0} -type f -exec chmod 444 '{{}}' +"
        self.assertTrue(built.startswith(f"ssh user@host {modes.format(up)} && mkdir {merge} && "))
        sources = [f"{self.R}/105", f"{self.R}/110", up]
        copies = [built.index(f"cp -rL {source}/. {merge}/") for source in sources]
        self.assertEqual(copies, sorted(copies))
        self.assertNotIn(f"{self.R}/100/", built)
        # a copy of a read-only file is read-only: made writable before the next release is copied over it
        for source in sources:
            self.assertIn(f"cp -rL {source}/. {merge}/ && chmod -R u+rwX {merge}", built)
        self.assertTrue(built.endswith(f"cp -rL {up}/. {merge}/ && {modes.format(merge)}"))
        self.assertNotIn("a+rX", built)
        self.assertNotIn("ln -sfn", built)  # nothing that is served is touched while getting ready

        # going live is ONE command: both directories take their names, then `current` flips (an atomic
        # rename). So a release only ever gets into releases/ together with the flip.
        went = cmds[live]
        order = [
            went.index(f"mv -T {self.S}/releasing/123 {self.R}/123"),
            went.index(f"mv -T {self.S}/merging/123 {self.M}/123"),
            went.index(f"ln -sfn merged/123 {self.S}/.mik-cur-tmp"),
            went.index(f"mv -T {self.S}/.mik-cur-tmp {self.S}/current"),
        ]
        self.assertEqual(order, sorted(order))
        self.assertEqual(sum(f"mv -T {self.S}/releasing/123" in c for c in cmds), 1)

        # deleted: the merge nobody serves any more. Not the one served until a moment ago (110), and no
        # release: with keep=5 all of them stay.
        self.assertEqual(cmds[cleanup], f"ssh user@host rm -rf {self.M}/105")
        # the whole thing runs without sudo (user owns the web root), and without waiting for anything
        self.assertFalse(any("sudo" in c for c in cmds))
        self.assertFalse(hasattr(mik, "sleep"))
        self.assertTrue(any("merged/123" in line and "105, 110" in line for line in printed))

    def test_prune_keeps_what_the_next_merge_needs_and_what_was_being_served(self):
        # keep=1 asks for the new release alone; 105 and 110 are still needed to merge from, 100 is not
        survey = self._survey("merged/110", self.HISTORY, merged=["110"])
        _, cmds, _, _ = self._deploy(survey, keep=1)
        self.assertEqual(cmds[-1], f"ssh user@host rm -rf {self.R}/100")
        # keep=2: the new one and 110. 105 stays as well (merged), 100 still goes
        _, cmds, _, _ = self._deploy(survey, keep=2)
        self.assertEqual(cmds[-1], f"ssh user@host rm -rf {self.R}/100")
        # keep=4: all of them
        _, cmds, _, _ = self._deploy(survey, keep=4)
        self.assertIn("ln -sfn merged/123", cmds[-1])  # going live is the last thing done: nothing to delete

    def test_no_merge_when_zero_seconds(self):
        survey = self._survey("merged/110", self.HISTORY, merged=["105", "110"])
        _, cmds, printed, _ = self._deploy(survey, merge_seconds=0, keep=2)
        # nothing merged — `current` leads straight to the clean release
        self.assertFalse(any("cp -rL" in c for c in cmds))
        self.assertFalse(any("/merging/" in c for c in cmds))
        self.assertTrue(any("ln -sfn releases/123" in c for c in cmds))
        # 110 stays as one of the two newest; its merge stays because it was being served until now
        self.assertEqual(cmds[-1], f"ssh user@host rm -rf {self.R}/100 {self.R}/105 {self.M}/105")
        self.assertTrue(any(line.endswith("current -> releases/123") for line in printed))

    def test_first_deploy_serves_the_release_alone_under_its_merged_name(self):
        _, cmds, _, _ = self._deploy(self._survey("", []))
        self.assertEqual(cmds[2].count("cp -rL"), 1)
        self.assertIn("ln -sfn merged/123", cmds[-1])  # going live is the last thing done: nothing to delete yet

    def test_history_begins_at_a_release_that_was_served_alone(self):
        # `current` leads to releases/105, not merged/105: it was deployed with merge_seconds=0 so that
        # something in 100 would disappear. 100 is not merged again, and goes — keep=5 or not.
        history = [("100", 3 * self.DAY), ("105", 3600)]
        _, cmds, _, _ = self._deploy(self._survey("releases/105", history))
        self.assertNotIn(f"{self.R}/100/", self._ready(cmds))
        self.assertIn(f"cp -rL {self.R}/105/. {self.S}/merging/123/", self._ready(cmds))
        self.assertEqual(cmds[-1], f"ssh user@host rm -rf {self.R}/100")
        # the same when 100 is recent enough to be within the day
        _, cmds, _, _ = self._deploy(self._survey("releases/105", [("100", 7200), ("105", 3600)]))
        self.assertNotIn(f"{self.R}/100/", self._ready(cmds))
        self.assertEqual(cmds[-1], f"ssh user@host rm -rf {self.R}/100")
        # a deploy that does not merge either forgets nothing: `keep` decides, as ever
        _, cmds, _, _ = self._deploy(self._survey("releases/105", history), merge_seconds=0)
        self.assertIn("ln -sfn releases/123", cmds[-1])

    def test_forgotten_releases(self):
        releases = [(self.NOW - age, name) for name, age in [("100", 900), ("105", 500), ("110", 100)]]
        self.assertEqual(mik._forgotten_releases(releases, "123", "releases/110"), ["100", "105"])
        self.assertEqual(mik._forgotten_releases(releases, "123", "releases/105"), ["100"])
        self.assertEqual(mik._forgotten_releases(releases, "123", "merged/110"), [])  # merged: history goes on
        self.assertEqual(mik._forgotten_releases(releases, "123", ""), [])  # first deploy
        self.assertEqual(mik._forgotten_releases(releases, "123", "releases/999"), [])  # leads nowhere: unknown
        # the release being shipped is about to be replaced under that name: never listed for deletion
        self.assertEqual(mik._forgotten_releases(releases, "100", "releases/110"), ["105"])

    def test_a_release_shipped_again_is_replaced_when_going_live(self):
        survey = self._survey("merged/123", [("110", self.DAY), ("123", 500)], merged=["123"])
        _, cmds, _, _ = self._deploy(survey)
        went = cmds[self._idx(cmds, "ln -sfn merged/123")]
        for done, doing in ((self.R, "releasing"), (self.M, "merging")):
            self.assertLess(went.index(f"rm -rf {done}/123"), went.index(f"mv -T {self.S}/{doing}/123 {done}/123"))
        self.assertNotIn(f"{self.R}/123/.", self._ready(cmds))  # merged from the new upload, not its older copy
        after = cmds[self._idx(cmds, "ln -sfn merged/123") + 1 :]
        self.assertFalse(any(f"rm -rf {self.R}/123" in c or f"rm -rf {self.M}/123" in c for c in after))

    def test_an_unfinished_deploy_is_shown_and_deleted_only_once_agreed(self):
        left = ["releasing/120", "merging/120"]
        survey = self._survey("merged/110", self.HISTORY, merged=["110"], unfinished=left)
        # agreed: deleted before anything is uploaded, then the deploy goes on
        _, cmds, printed, _ = self._deploy(survey, answer=["y"])
        left_there = f"{self.S}/releasing/120 {self.S}/merging/120"
        self.assertEqual(cmds[1], f"ssh user@host chmod -R u+rwX {left_there} && rm -rf {left_there}")
        self.assertIn("find 105 110", cmds[2])
        self.assertIn("scp -r", cmds[3])
        self.assertTrue(any("did not finish" in line for line in printed))
        self.assertTrue(all(any(path in line for line in printed) for path in left))
        self.assertTrue(any("deployed site" in line for line in printed))
        # refused, or nobody to ask: nothing is deleted, nothing is uploaded, the deploy stops
        for answer in (["n"], [""], EOFError):
            with self.assertRaises(mik.MikException) as cm:
                self._deploy(survey, answer=answer)
            self.assertIn("releasing/120", str(cm.exception))
            self.assertEqual(len(self.cmds), 1, self.cmds)  # the look, and nothing after it
            self.assertIn("echo now", self.cmds[0])

    def test_releases_to_merge(self):
        pick = lambda releases, seconds=self.DAY: mik._releases_to_merge(  # noqa: E731
            [(self.NOW - age, name) for name, age in releases], "123", self.NOW, seconds
        )
        self.assertEqual(pick([]), [])  # first deploy
        self.assertEqual(pick(self.HISTORY), ["105", "110"])
        # nothing went live in the last day: what was live all along is still what open tabs hold
        self.assertEqual(pick([("100", 9 * self.DAY), ("105", 2 * self.DAY)]), ["105"])
        # everything went live within the day: all of it, oldest first, whatever order it is listed in
        self.assertEqual(pick([("110", 100), ("105", 200)]), ["105", "110"])
        # the release being shipped is never merged under itself, even if an older copy of it is listed
        self.assertEqual(pick([("123", 3 * self.DAY), ("110", 100)]), ["110"])
        self.assertEqual(pick(self.HISTORY, seconds=0), [])

    def test_merge_clashes(self):
        one = {"index.html": "f", "docs": "f", "assets": "d", "assets/a.js": "f"}
        two = {"index.html": "f", "docs": "d", "docs/index.html": "f", "assets": "d", "assets/b.js": "f"}
        self.assertEqual(mik._merge_clashes([("1", one), ("2", dict(one))]), [])
        # only the name where the two part, not what is under it; and once, however many releases follow
        self.assertEqual(mik._merge_clashes([("1", one), ("2", two)]), [("docs", "1", "f", "2", "d")])
        self.assertEqual(mik._merge_clashes([("1", one), ("2", two), ("3", one)]), [("docs", "1", "f", "2", "d")])
        self.assertEqual(mik._merge_clashes([("1", two), ("2", one)]), [("docs", "1", "d", "2", "f")])

    def test_what_the_releases_hold_is_read_strictly(self):
        out = b"d 105/assets\0f 105/assets/a b.js\0f 105/new\nline.js\0f 110/index.html\0"
        self.assertEqual(
            mik._parse_release_kinds(out, ["105", "110"]),
            {"105": {"assets": "d", "assets/a b.js": "f", "new\nline.js": "f"}, "110": {"index.html": "f"}},
        )
        self.assertEqual(mik._parse_release_kinds(b"", ["105"]), {"105": {}})  # an empty release
        for stray, said in (
            (b"l 105/leak.txt\0", "unexpected in the remote release 105: 'leak.txt'"),  # a symlink
            (b"p 105/\033[2Jpipe\0", "unexpected in the remote release 105: '[2Jpipe'"),  # and nothing printed raw
            (b"f 999/index.html\0", "could not read"),  # a release that was not asked about
            (b"find: something went wrong\0", "could not read"),
        ):
            with self.assertRaises(mik.MikException, msg=stray) as cm:
                mik._parse_release_kinds(out + stray, ["105", "110"])
            self.assertIn(said, str(cm.exception))

    def test_a_clash_stops_before_the_upload_and_names_the_way_out(self):
        survey = self._survey("merged/110", self.HISTORY, merged=["110"])

        def step(cmda, *a, **k):
            said = " ".join(cmda)
            if "find 105 110" in said:  # 110 has `bundle.YYY.js` as a directory; the artifact, as a file
                return b"f 105/index.html\0d 110/bundle.YYY.js\0f 110/bundle.YYY.js/part.js\0"
            return survey if "echo now" in said else b""

        with self.assertRaises(mik.MikException) as cm:
            self._deploy(survey, run_step=step)
        self.assertIn("  bundle.YYY.js: a directory in 110, a file in 123\n", str(cm.exception))
        self.assertIn("Deploy site once with merge_seconds=0", str(cm.exception))
        self.assertEqual(len(self.cmds), 2)  # the two looks, and nothing after them
        self.assertFalse(any("scp" in c for c in self.cmds))

    def test_names_in_the_listing_are_not_printed_as_they_came(self):
        # The remote is the one writing the listing: a name in it may be made to rewrite the terminal, or to
        # look like more lines of output. It is only compared, and shown without what is not printable.
        survey = self._survey("merged/110", self.HISTORY, merged=["110"])
        evil = b"\033[2J\033[Hfake\ndeployed site -> ok\xff"

        def step(cmda, *a, **k):
            said = " ".join(cmda)
            if "find 105 110" in said:
                return b"f 105/" + evil + b"\0d 110/" + evil + b"\0"
            return survey if "echo now" in said else b""

        with self.assertRaises(mik.MikException) as cm:
            self._deploy(survey, run_step=step)
        self.assertIn("\n  [2J[Hfakedeployed site -> ok: a file in 105, a directory in 110\n", str(cm.exception))
        self.assertNotIn("\033", str(cm.exception))
        self.assertEqual(len(str(cm.exception).split("\n")), 3)  # the three lines mik wrote, no line of its own
        str(cm.exception).encode()  # and nothing that could not be printed at all

    def test_survey_is_read_strictly(self):
        out = (
            b"now 2000000\ncurrent merged/110\n"
            b"releases d 1999000.25 110\nreleases d 1990000.0 105\nmerged d 1999000.5 110\n"
            b"releasing d 1999500.0 120\nmerging d 1999600.0 120\n"
        )
        self.assertEqual(
            mik._parse_site_survey(out),
            (
                2000000,
                "merged/110",
                [(1990000.0, "105"), (1999000.25, "110")],
                ["110"],
                ["releasing/120", "merging/120"],
            ),
        )
        self.assertEqual(mik._parse_site_survey(b"now 5\ncurrent\n"), (5, "", [], [], []))  # first deploy
        # anything mik did not put there stops the deploy: these names would go into remote commands
        for stray in (
            b"releases d 1990000.0 backup-old",  # a directory made by hand
            b"releases f 1990000.0 notes",  # not a directory
            b"releases d 1990000.0 a b",
            b"releases d soon 111",
            b"merged d 1.0 x;rm",
            b"merged d 1.0 .mik-OLD-110",
            b"releases d 1.0 \xc3\xa9t\xc3\xa9",  # letters, but not plain ones
            b"current ../../etc",  # `current` leading out of releases/ and merged/
            b"current releases/a/b",
            b"something else",
        ):
            with self.assertRaises(mik.MikException, msg=stray) as cm:
                mik._parse_site_survey(out + stray + b"\n")
            self.assertIn("unexpected", str(cm.exception))
        with self.assertRaises(mik.MikException):
            mik._parse_site_survey(b"current merged/110\n")  # no clock: the remote command did not run

    def test_something_unexpected_on_the_remote_stops_before_any_change(self):
        survey = self._survey("merged/110", self.HISTORY) + b"releases d 1.0 backup-old\n"
        with self.assertRaises(mik.MikException):
            self._deploy(survey)
        self.assertEqual(len(self.cmds), 1)  # the look, and nothing after it

    def test_unwritable_site_root_raises_before_side_effects(self):
        with (
            mock.patch.object(mik, "pop", return_value=(1, b"Permission denied", b"")),
            mock.patch.object(mik, "run_step") as rs,
        ):
            with self.assertRaises(mik.MikException) as cm:
                mik.deploy_release("/tmp/x", "user@host", "/var/www/site", release_id="123", name="site")
            self.assertIn("not writable", str(cm.exception))
            rs.assert_not_called()  # no scp/ssh side effect once the preflight fails

    def test_rejects_unsafe_inputs_before_any_remote_call(self):
        bad = [
            dict(release_id="1 2"),  # space -> not alnum
            dict(release_id="a/b"),  # slash -> not alnum
            dict(release_id="été"),  # letters, but the remote listing is only read as plain ones
            dict(keep=0),  # the new release counts: keeping none would delete what is live
            dict(merge_seconds=-1),
            dict(site_root="relative/path"),  # not absolute
            dict(site_root="/a/../b"),  # traversal
            dict(ssh_host="a b@host"),  # space in ssh user
        ]
        base = dict(
            src="/tmp/whatever",
            ssh_host="user@host",
            site_root="/var/www/site",
            release_id="123",
            name="site",
        )
        for override in bad:
            with (
                mock.patch.object(mik, "pop") as pop,
                mock.patch.object(mik, "run_step") as rs,
            ):
                with self.assertRaises(mik.MikException, msg=override):
                    mik.deploy_release(**{**base, **override})
                pop.assert_not_called()  # validation precedes even the preflight
                rs.assert_not_called()

    def test_symlink_in_artifact_refused_before_any_remote_call(self):
        # defense-in-depth: scp -r / cp -rL would dereference a stray link into the web root, so refuse first
        with tempfile.TemporaryDirectory() as d:
            src = self._src(d)
            (src / "sneaky").symlink_to("/etc/passwd")
            with (
                mock.patch.object(mik, "pop") as pop,
                mock.patch.object(mik, "run_step") as rs,
            ):
                with self.assertRaises(mik.MikException) as cm:
                    mik.deploy_release(src, "user@host", "/var/www/site", release_id="123", name="site")
            self.assertIn("symlink in artifact", str(cm.exception))
            pop.assert_not_called()  # payload check precedes even the writability preflight
            rs.assert_not_called()

    def test_prune_failure_does_not_fail_deploy(self):
        survey = self._survey("merged/110", self.HISTORY, merged=["105", "110"])

        def boom_on_prune(cmda, *a, **k):
            if f"rm -rf {self.M}/105" in " ".join(cmda):
                raise mik.MikException("prune blew up")
            return survey if "echo now" in " ".join(cmda) else b""

        _, _, printed, _ = self._deploy(survey, run_step=boom_on_prune)
        self.assertTrue(any("deployed site" in line for line in printed))


def _local_pop(cmda):
    """Stands in for mik.pop with the remote on this machine: `ssh host CMD` runs CMD in a local shell and
    `scp -r SRC host:DEST` is a local copy. The remote commands themselves run for real."""
    if cmda[0] == "ssh":
        argv = ["sh", "-c", cmda[2]]
    elif cmda[:2] == ["scp", "-r"]:
        argv = ["cp", "-r", cmda[2], cmda[3].partition(":")[2]]
    else:
        raise AssertionError(f"unexpected command: {cmda}")
    proc = subprocess.run(argv, capture_output=True, stdin=subprocess.DEVNULL)
    return proc.returncode, proc.stderr, proc.stdout


def _remote_tools_here():
    """Whether this machine has what deploy_release asks of the remote: find -printf and mv -T."""
    with tempfile.TemporaryDirectory() as d:
        probe = f"cd {d} && mkdir a && find a -maxdepth 0 -printf '%h %y %T@ %f\\n' && mv -T a b && test -d b"
        try:
            return subprocess.run(["sh", "-c", probe], capture_output=True).returncode == 0
        except OSError:
            return False


@unittest.skipUnless(_remote_tools_here(), "needs GNU find -printf and mv -T")
class DeployReleaseOnDiskTests(unittest.TestCase):
    """deploy_release against a real directory: only ssh/scp are replaced (see _local_pop), so the remote
    commands run and what is checked is what a web server following `current` would find."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        self.site = self.tmp / "site"
        self.site.mkdir()
        for target, new in (("pop", _local_pop), ("print", mock.Mock())):
            patcher = mock.patch.object(mik, target, new, create=target == "print")
            patcher.start()
            self.addCleanup(patcher.stop)

    def _ship(self, rid, files, answer=None, modes=None, **kwargs):
        """Build an artifact holding `files` ({name: text}) and deploy it as release `rid`.

        `modes` is (mode of its directories, mode of its files), for a build that comes with modes of its own.
        """
        src = self.tmp / f"build-{rid}"
        shutil.rmtree(src, ignore_errors=True)
        for name, text in files.items():
            (src / name).parent.mkdir(parents=True, exist_ok=True)
            (src / name).write_text(text)
        if modes:
            for p in [*sorted(src.rglob("*"), reverse=True), src]:  # what is inside a directory before it
                os.chmod(p, modes[0] if p.is_dir() else modes[1])
        asked = mock.Mock(side_effect=AssertionError("asked a question") if answer is None else [answer])
        with mock.patch("builtins.input", asked):
            mik.deploy_release(src, "user@host", str(self.site), release_id=rid, name="site", **kwargs)

    def _age(self, rid, seconds):
        """Make release `rid` look as if it had gone live `seconds` ago."""
        when = (self.site / "releases" / rid).stat().st_mtime - seconds
        os.utime(self.site / "releases" / rid, (when, when))

    def _served(self):
        """{name: text} of what `current` leads to."""
        root = (self.site / "current").resolve()
        return {str(p.relative_to(root)): p.read_text() for p in sorted(root.rglob("*")) if p.is_file()}

    def _there(self, where):
        return sorted(p.name for p in (self.site / where).iterdir())

    def test_a_page_loaded_before_the_deploy_still_finds_its_bundles(self):
        self._ship("1", {"index.html": "one", "a.1.js": "a1", "assets/logo.1.svg": "l1"})
        self.assertEqual(os.readlink(self.site / "current"), "merged/1")
        self.assertEqual(self._served(), {"index.html": "one", "a.1.js": "a1", "assets/logo.1.svg": "l1"})
        self._ship("2", {"index.html": "two", "a.2.js": "a2"})
        self.assertEqual(os.readlink(self.site / "current"), "merged/2")
        # the new index wins, and what the old page names is still there
        self.assertEqual(
            self._served(), {"index.html": "two", "a.1.js": "a1", "a.2.js": "a2", "assets/logo.1.svg": "l1"}
        )
        # the releases themselves stay pristine, and nothing is left half-done
        self.assertEqual(sorted(p.name for p in (self.site / "releases" / "2").iterdir()), ["a.2.js", "index.html"])
        self.assertEqual((self._there("releasing"), self._there("merging")), ([], []))
        # readable by a server that is not the owner
        self.assertTrue(all(p.stat().st_mode & 0o004 for p in (self.site / "merged" / "2").rglob("*")))

    def _modes(self, where):
        """{"d": modes of the directories under site/`where`, "f": modes of the files}, the directory included."""
        found = {"d": set(), "f": set()}
        for p in [self.site / where, *(self.site / where).rglob("*")]:
            found["d" if p.is_dir() else "f"].add(oct(p.stat().st_mode & 0o7777))
        return found

    def test_what_is_served_is_755_and_444_whatever_the_build_and_the_umask(self):
        files = {"index.html": "one", "assets/a.1.js": "a1"}
        for umask, modes in ((0o022, (0o777, 0o777)), (0o077, (0o700, 0o600)), (0o002, (0o775, 0o664))):
            old = os.umask(umask)
            try:
                self._ship("1", files, modes=modes)
            finally:
                os.umask(old)
            for where in ("releases/1", "merged/1"):
                with self.subTest(umask=oct(umask), where=where):
                    self.assertEqual(self._modes(where), {"d": {"0o755"}, "f": {"0o444"}})
            shutil.rmtree(self.site)
            self.site.mkdir()

    def test_a_build_with_read_only_files_and_directories_deploys_again_and_again(self):
        # cp cannot write over a read-only file, and a read-only directory can be neither filled, nor renamed
        # into releases/, nor deleted: none of that is left to the modes the build happened to have.
        for modes in ((0o755, 0o444), (0o555, 0o444)):
            with self.subTest(modes=[oct(m) for m in modes]):
                self._ship("1", {"index.html": "one", "assets/a.1.js": "a1"}, modes=modes)
                self._ship("2", {"index.html": "two", "assets/a.2.js": "a2"}, modes=modes)
                self._ship("3", {"index.html": "three", "assets/a.3.js": "a3"}, modes=modes)
                self.assertEqual(os.readlink(self.site / "current"), "merged/3")
                served = {"index.html": "three", "assets/a.1.js": "a1", "assets/a.2.js": "a2", "assets/a.3.js": "a3"}
                self.assertEqual(self._served(), served)
                self.assertEqual((self._there("releasing"), self._there("merging")), ([], []))
                self.assertEqual(self._modes("merged/3"), {"d": {"0o755"}, "f": {"0o444"}})
                # and what is no longer needed gets deleted: 1 is far enough back to go
                self._age("1", 3 * 86400)
                self._age("2", 2 * 86400)
                self._age("3", 86400 + 60)
                self._ship("4", {"index.html": "four"}, modes=modes, keep=1)
                self._ship("5", {"index.html": "five"}, modes=modes, keep=1)
                self.assertNotIn("1", self._there("releases"))
                self.assertEqual(self._there("merged"), ["4", "5"])
            subprocess.run(["chmod", "-R", "u+rwX", str(self.tmp)], check=True)
            for left in self.tmp.iterdir():
                shutil.rmtree(left)
            self.site.mkdir()

    def test_what_a_read_only_upload_left_halfway_can_be_deleted(self):
        self._ship("1", {"index.html": "one"})
        left = self.site / "releasing" / "9"
        (left / "assets").mkdir(parents=True)
        (left / "assets" / "a.js").write_text("a")
        for p in (left / "assets" / "a.js", left / "assets", left):
            os.chmod(p, 0o444 if p.is_file() else 0o555)
        self._ship("2", {"index.html": "two"}, answer="y")
        self.assertEqual((self._there("releasing"), self._there("merging")), ([], []))
        self.assertEqual(self._served(), {"index.html": "two"})

    def test_a_file_leaves_when_its_release_leaves_the_window(self):
        self._ship("1", {"index.html": "one", "a.1.js": "a1"})
        self._ship("2", {"index.html": "two", "a.2.js": "a2"})
        self._age("1", 3 * 86400)
        self._age("2", 2 * 86400)
        # 2 was live when the last day began, 1 was replaced long before
        self._ship("3", {"index.html": "three", "a.3.js": "a3"})
        self.assertEqual(self._served(), {"index.html": "three", "a.2.js": "a2", "a.3.js": "a3"})
        # what was served until a moment ago is still there; the merge before it is gone
        self.assertEqual(self._there("merged"), ["2", "3"])
        self.assertEqual(self._there("releases"), ["1", "2", "3"])  # keep=5
        self._ship("4", {"index.html": "four"}, keep=1)
        self.assertEqual(self._there("merged"), ["3", "4"])
        self.assertEqual(self._there("releases"), ["2", "3", "4"])  # 2 and 3 are what the next merge may need

    def test_a_page_removed_with_merge_seconds_0_stays_removed(self):
        self._ship("1", {"index.html": "one", "secret.html": "oops"})
        self._ship("2", {"index.html": "two"}, merge_seconds=0)
        self.assertEqual(os.readlink(self.site / "current"), "releases/2")
        self.assertEqual(self._served(), {"index.html": "two"})
        self._ship("3", {"index.html": "three", "a.3.js": "a3"})
        self.assertEqual(self._served(), {"index.html": "three", "a.3.js": "a3"})
        self.assertEqual(self._there("releases"), ["2", "3"])  # 1 is gone for good
        self._ship("4", {"index.html": "four"})
        self.assertEqual(self._served(), {"index.html": "four", "a.3.js": "a3"})

    def test_an_upload_that_never_went_live_is_never_merged(self):
        self._ship("1", {"index.html": "one", "a.1.js": "a1"})
        # release 2 was uploaded, then its deploy died: it sits in releasing/, and half a merge in merging/
        shutil.copytree(self.tmp / "build-1", self.site / "releasing" / "2")
        (self.site / "releasing" / "2" / "never.js").write_text("never live")
        (self.site / "merging" / "2").mkdir()
        before = self._served()
        with self.assertRaises(mik.MikException):
            self._ship("3", {"index.html": "three"}, answer="n")
        # refused: everything is as it was, the leftovers too
        self.assertEqual((self._served(), self._there("releasing"), self._there("merging")), (before, ["2"], ["2"]))
        self.assertEqual(self._there("releases"), ["1"])
        self._ship("3", {"index.html": "three"}, answer="y")
        self.assertEqual(self._served(), {"index.html": "three", "a.1.js": "a1"})
        self.assertEqual((self._there("releasing"), self._there("merging")), ([], []))
        self.assertEqual(self._there("releases"), ["1", "3"])

    def test_the_same_release_can_be_shipped_again(self):
        self._ship("1", {"index.html": "one", "a.1.js": "a1"})
        self._ship("2", {"index.html": "two", "a.2.js": "a2"})
        self._ship("2", {"index.html": "two again", "b.2.js": "b2"})  # while it is live
        self.assertEqual(self._served(), {"index.html": "two again", "a.1.js": "a1", "b.2.js": "b2"})
        self.assertEqual(self._there("releases"), ["1", "2"])
        self.assertEqual(self._there("merged"), ["2"])
        self._ship("2", {"index.html": "two alone"}, merge_seconds=0)
        self._ship("2", {"index.html": "two alone again"}, merge_seconds=0)
        self.assertEqual(self._served(), {"index.html": "two alone again"})

    def test_something_mik_did_not_put_there_stops_the_deploy(self):
        self._ship("1", {"index.html": "one"})
        (self.site / "releases" / "backup-old").mkdir()
        with self.assertRaises(mik.MikException) as cm:
            self._ship("2", {"index.html": "two"})
        self.assertIn("backup-old", str(cm.exception))
        self.assertEqual(self._served(), {"index.html": "one"})
        self.assertEqual(self._there("releasing"), [])  # stopped before the upload

    def test_a_file_here_and_a_directory_there_is_refused_before_the_upload(self):
        # cp replaces neither with the other: the merge would fail, at every try, for as long as both
        # releases are in the window. Said before anything is uploaded, with the way out.
        for one, two, said in (
            ({"docs": "a page"}, {"docs/index.html": "a directory now"}, "  docs: a file in 1, a directory in 2\n"),
            ({"docs/index.html": "a directory"}, {"docs": "a page now"}, "  docs: a directory in 1, a file in 2\n"),
        ):
            with self.subTest(said=said):
                shutil.rmtree(self.site)
                self.site.mkdir()
                self._ship("1", {"index.html": "one", **one})
                for _ in range(2):  # and again: nothing was left behind to be asked about
                    with self.assertRaises(mik.MikException) as cm:
                        self._ship("2", {"index.html": "two", **two})
                    self.assertIn(said, str(cm.exception))
                    self.assertIn("Nothing was uploaded", str(cm.exception))
                    self.assertIn("merge_seconds=0", str(cm.exception))
                    self.assertEqual(self._served(), {"index.html": "one", **one})
                    self.assertEqual((self._there("releasing"), self._there("merging")), ([], []))
                    self.assertEqual(self._there("releases"), ["1"])
                # the way out it names: served alone once, and history begins again there
                self._ship("2", {"index.html": "two", **two}, merge_seconds=0)
                self.assertEqual(self._served(), {"index.html": "two", **two})
                self._ship("3", {"index.html": "three", "a.3.js": "a3"})
                self.assertEqual(self._served(), {"index.html": "three", "a.3.js": "a3", **two})

    def test_file_names_that_would_mean_something_to_a_shell_are_only_names(self):
        odd = ['a"; touch PWNED #.js', "$(touch PWNED).js", "`touch PWNED`.js", "-rf", "new\nline.js", "a b/c d.js"]
        self._ship("1", {"index.html": "one", **{name: "x" for name in odd}})
        self._ship("2", {"index.html": "two"})  # listed, compared and merged, the names never in a command
        self.assertEqual(self._served(), {"index.html": "two", **{name: "x" for name in odd}})
        self.assertEqual([p for p in self.tmp.rglob("PWNED")], [])
        self.assertFalse(Path("PWNED").exists())

    def test_a_symlink_put_in_a_release_on_the_remote_is_not_merged(self):
        # mik uploads regular files and directories. `cp -rL` would follow the link and copy what it leads
        # to into what is served.
        (self.tmp / "secret").write_text("not for the web")
        self._ship("1", {"index.html": "one"})
        (self.site / "releases" / "1" / "leak.txt").symlink_to(self.tmp / "secret")
        with self.assertRaises(mik.MikException) as cm:
            self._ship("2", {"index.html": "two"})
        self.assertIn("unexpected in the remote release 1: 'leak.txt'", str(cm.exception))
        self.assertEqual(self._served(), {"index.html": "one"})
        self.assertEqual(self._there("releasing"), [])  # stopped before the upload


class FilterParamTests(unittest.TestCase):
    """The `key=NAME` filters of the list-* commands, through main(): a bad one is a usage error."""

    def setUp(self):
        for registry in (mik.machines_dict, mik.projects_dict, mik.instances_dict):
            registry.clear()
            self.addCleanup(registry.clear)
        mik.machines_dict["prod"] = SimpleNamespace(name="prod", ssh_host="user@host")
        mik.projects_dict.update({"app": SimpleNamespace(name="app"), "site": SimpleNamespace(name="site")})
        mik.instances_dict["app-prod"] = _inst("app-prod", project="app", machine="prod")
        mik.instances_dict["site-prod"] = _inst("site-prod", project="site", machine="prod")

    def test_bad_filter_is_a_usage_error(self):
        for argv, expected in (
            (["list-instances", "foo"], "expected project=NAME or machine=NAME, got 'foo'"),  # no "="
            (["list-instances", "color=red"], "expected project=NAME or machine=NAME, got 'color=red'"),
            (["list-instances", "project="], "expected project=NAME or machine=NAME, got 'project='"),
            (["list-machines", "machine=prod"], "expected project=NAME, got 'machine=prod'"),
            (["list-projects", "app"], "expected machine=NAME, got 'app'"),
        ):
            with self.subTest(argv=argv), mock.patch.object(mik, "load_config") as load_config:
                with contextlib.redirect_stderr(io.StringIO()) as err:
                    with self.assertRaises(SystemExit) as ctx:
                        mik.main(argv)
                self.assertEqual(ctx.exception.code, 2)
                self.assertIn(f"error: {expected}", err.getvalue())
                self.assertNotIn("Traceback", err.getvalue())
                load_config.assert_not_called()  # refused while parsing: the config is not even read

    def test_good_filter_still_filters(self):
        with mock.patch.object(mik, "load_config"), mock.patch("builtins.print") as printed:
            mik.main(["list-instances", "project=app", "machine=prod"])
        self.assertEqual(_printed(printed), ["app-prod"])


class CliTests(unittest.TestCase):
    """cli() is what the installed `mik` command runs: main(), with expected errors turned into exit codes."""

    def test_returns_what_main_returns(self):
        with mock.patch.object(mik, "main", return_value=7):
            self.assertEqual(mik.cli(), 7)

    def test_mik_exception_is_one_line_and_exit_1(self):
        with mock.patch.object(mik, "main", side_effect=mik.MikException("nope")):
            with mock.patch("builtins.print") as printed:
                self.assertEqual(mik.cli(), 1)
        self.assertEqual(_printed(printed), ["\n  !!  nope  !!  \n"])
        # red is put on here, once, and the line goes to stderr: stdout stays what the command printed
        self.assertEqual(printed.call_args.args[0], "\033[31m\n  !!  nope  !!  \n\033[39m")
        self.assertIs(printed.call_args.kwargs["file"], sys.stderr)

    def test_no_error_message_carries_its_own_colour(self):
        mik.instances_dict.clear()
        for command in (mik.deploy, mik.build, mik.dev_fetch_pod):
            with self.subTest(command=command.__name__), self.assertRaises(mik.MikException) as ctx:
                command(SimpleNamespace(instance="nope"))
            self.assertEqual(str(ctx.exception), "Instance not found")

    def test_keyboard_interrupt_is_exit_130(self):
        with mock.patch.object(mik, "main", side_effect=KeyboardInterrupt), mock.patch("builtins.print"):
            self.assertEqual(mik.cli(), 130)

    def test_pyproject_points_the_command_at_it(self):
        # The entry point is a string in pyproject.toml: nothing else would notice if cli() were renamed.
        project = tomllib.loads((Path(__file__).parent / "pyproject.toml").read_text())
        self.assertEqual(project["project"]["scripts"], {"mik": "mik:cli"})
        self.assertEqual(project["tool"]["setuptools"]["py-modules"], ["mik"])
        self.assertTrue(callable(mik.cli))


class ReadmeSyncTests(unittest.TestCase):
    def test_help_matches_readme(self):
        """The README's ## Help code block must match `mik --help` byte-for-byte.

        If this fails, regenerate the block: COLUMNS=80 python3 mik.py (argparse wraps to the
        terminal width, so the width is pinned here to keep the rendering deterministic).
        """
        buf = io.StringIO()
        # Pin prog name (argv[0]) and terminal width so the argparse rendering is deterministic.
        with mock.patch.object(mik.sys, "argv", ["mik"]), mock.patch.dict(os.environ, {"COLUMNS": "80"}):
            with contextlib.redirect_stdout(buf):
                mik.main()  # no sub-command -> parser.print_help(), returns before load_config()
        help_text = buf.getvalue()
        readme = (Path(__file__).parent / "README.md").read_text()
        help_section = readme.find("## Help")
        self.assertNotEqual(help_section, -1, "README should have a '## Help' section")
        fence_open = readme.find("```", help_section)
        self.assertNotEqual(fence_open, -1, "README should have a code block after ## Help")
        block_start = readme.index("\n", fence_open) + 1
        block_end = readme.find("```", block_start)
        self.assertNotEqual(block_end, -1, "README code block should be closed")
        self.assertEqual(help_text, readme[block_start:block_end], "README ## Help block is out of sync with --help")


if __name__ == "__main__":
    unittest.main(verbosity=2)
