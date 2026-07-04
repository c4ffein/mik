#!/usr/bin/env python3
"""Boundary tests for mik.

Tested at the CLI/effect boundary (args in -> subprocess / HTTP / file effects out) rather than against
internals, mocking the subprocess / SSH / HTTP layers. Stdlib only; run with `make test` or `python test.py`.
"""

import io
import json
import os
import re
import tarfile
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

        with mock.patch.object(mik, "GITHUB_COM_CERT_SHA256", self.PIN), mock.patch.object(
            mik, "urlopen", fake_urlopen
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
    We mock pop (the writability preflight) + run_step + sleep and assert the exact remote command sequence."""

    R = "/var/www/site/releases"

    def _src(self, d):
        """A finished artifact dir (what build_artifact would have produced) under tmp dir `d`."""
        src = Path(d) / "1750000000-dist"
        src.mkdir(parents=True)
        (src / "index.html").write_text("<html>")
        (src / "bundle.YYY.js").write_text("//y")
        return src

    @staticmethod
    def _idx(cmds, sub):
        return next(i for i, c in enumerate(cmds) if sub in c)

    @staticmethod
    def _idx_exact(cmds, whole):
        return next(i for i, c in enumerate(cmds) if c == whole)

    def test_overlap_sequence(self):
        with tempfile.TemporaryDirectory() as d:
            src = self._src(d)
            sleep_pos = []
            with mock.patch.object(mik, "pop", return_value=(0, b"", b"")) as pop, mock.patch.object(
                mik, "run_step"
            ) as rs, mock.patch.object(
                mik, "sleep", side_effect=lambda s: sleep_pos.append(rs.call_count)
            ) as slp, mock.patch("builtins.print"):
                mik.deploy_release(
                    src, "user@host", "/var/www/site", release_id="123", name="site", keep=5, overlap_seconds=30
                )

            pop.assert_called_once()  # writability preflight ran
            slp.assert_called_once_with(30)  # one wait, the configured window

            cmds = _remote_cmds(rs)
            ship_clear = self._idx_exact(cmds, f"ssh user@host rm -rf {self.R}/.mik-STAGING-123")
            scp = self._idx(cmds, "scp -r")
            self.assertIn(str(src), cmds[scp])  # ships the artifact dir itself, no local copy
            self.assertIn(f"user@host:{self.R}/.mik-STAGING-123", cmds[scp])
            promote = self._idx(cmds, f"mv {self.R}/.mik-STAGING-123 {self.R}/123")
            # world-readable before the mv, so the release is born readable
            self.assertIn("chmod -R a+rX", cmds[promote])
            self.assertLess(cmds[promote].index("chmod"), cmds[promote].index(f"mv {self.R}/.mik-STAGING-123"))
            overlap_build = self._idx(cmds, "cp -rL /var/www/site/current/.")
            ov_flip = self._idx(cmds, "ln -sfn releases/.mik-OVERLAP-123")
            clean_flip = self._idx(cmds, "ln -sfn releases/123")
            rm_overlap = self._idx_exact(cmds, f"ssh user@host rm -rf {self.R}/.mik-OVERLAP-123")
            prune = self._idx(cmds, "head -n -5")

            # strict ordering: clear -> ship -> promote -> build union -> flip-to-union -> SLEEP -> flip-to-clean
            for earlier, later in zip(
                [ship_clear, scp, promote, overlap_build, ov_flip, clean_flip, rm_overlap],
                [scp, promote, overlap_build, ov_flip, clean_flip, rm_overlap, prune],
            ):
                self.assertLess(earlier, later)
            # the union is served before the wait, the clean release only after it
            self.assertLess(ov_flip, sleep_pos[0])
            self.assertLessEqual(sleep_pos[0], clean_flip)
            # both flips are an atomic rename over `current`
            self.assertIn("mv -T", cmds[ov_flip])
            self.assertIn("mv -T", cmds[clean_flip])
            # the whole thing runs without sudo (user owns the web root)
            self.assertFalse(any("sudo" in c for c in cmds))

    def test_no_overlap_when_zero_seconds(self):
        with tempfile.TemporaryDirectory() as d:
            src = self._src(d)
            with mock.patch.object(mik, "pop", return_value=(0, b"", b"")), mock.patch.object(
                mik, "run_step"
            ) as rs, mock.patch.object(mik, "sleep") as slp, mock.patch("builtins.print"):
                mik.deploy_release(src, "user@host", "/var/www/site", release_id="123", name="site", overlap_seconds=0)
            slp.assert_not_called()
            cmds = _remote_cmds(rs)
            # no union built/flipped/torn-down — straight to the clean release
            self.assertFalse(any("cp -rL /var/www/site/current/." in c for c in cmds))
            self.assertFalse(any("ln -sfn releases/.mik-OVERLAP-123" in c for c in cmds))
            self.assertFalse(any(c == f"ssh user@host rm -rf {self.R}/.mik-OVERLAP-123" for c in cmds))
            self.assertTrue(any("ln -sfn releases/123" in c for c in cmds))

    def test_unwritable_site_root_raises_before_side_effects(self):
        with mock.patch.object(mik, "pop", return_value=(1, b"Permission denied", b"")), mock.patch.object(
            mik, "run_step"
        ) as rs, mock.patch.object(mik, "sleep"):
            with self.assertRaises(mik.MikException) as cm:
                mik.deploy_release("/tmp/x", "user@host", "/var/www/site", release_id="123", name="site")
            self.assertIn("not writable", str(cm.exception))
            rs.assert_not_called()  # no scp/ssh side effect once the preflight fails

    def test_rejects_unsafe_inputs_before_any_remote_call(self):
        bad = [
            dict(release_id="1 2"),  # space -> not alnum
            dict(release_id="a/b"),  # slash -> not alnum
            dict(keep=0),  # head -n -0 would wipe the live release
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
            with mock.patch.object(mik, "pop") as pop, mock.patch.object(mik, "run_step") as rs, mock.patch.object(
                mik, "sleep"
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
            with mock.patch.object(mik, "pop") as pop, mock.patch.object(mik, "run_step") as rs, mock.patch.object(
                mik, "sleep"
            ):
                with self.assertRaises(mik.MikException) as cm:
                    mik.deploy_release(src, "user@host", "/var/www/site", release_id="123", name="site")
            self.assertIn("symlink in artifact", str(cm.exception))
            pop.assert_not_called()  # payload check precedes even the writability preflight
            rs.assert_not_called()

    def test_prune_failure_does_not_fail_deploy(self):
        with tempfile.TemporaryDirectory() as d:
            src = self._src(d)

            def boom_on_prune(cmda, *a, **k):
                if any("head -n" in str(x) for x in cmda):
                    raise mik.MikException("prune blew up")
                return b""

            with mock.patch.object(mik, "pop", return_value=(0, b"", b"")), mock.patch.object(
                mik, "run_step", side_effect=boom_on_prune
            ), mock.patch.object(mik, "sleep"), mock.patch("builtins.print") as p:
                mik.deploy_release(src, "user@host", "/var/www/site", release_id="123", name="site", overlap_seconds=0)
            self.assertTrue(any("deployed site" in line for line in _printed(p)))


if __name__ == "__main__":
    unittest.main(verbosity=2)
