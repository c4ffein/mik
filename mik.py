#!/usr/bin/env python3

import sys
import argparse
import json
from pathlib import Path
import subprocess
import shutil
import stat
import tarfile
import tempfile
import string
import base64
import os
import re
import traceback
import unicodedata
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from enum import Enum
from hashlib import sha256
from ssl import (
    CERT_NONE,
    CERT_REQUIRED,
    PROTOCOL_TLS_CLIENT,
    PROTOCOL_TLS_SERVER,
    Purpose,
    SSLCertVerificationError,
    SSLContext,
    SSLSocket,
    _ASN1Object,
    _ssl,
)
from sys import exit, flags as sys_flags
from threading import Thread
from typing import Optional
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from uuid import uuid4


# I wanted my own system. It started quick and dirty, and is now of good-enough quality, with Claude's help.
# It is a single file that you can read: no need to trust the sources of a complex toolset.


# Your ~/.config/mik/config.py is exec'd into this module's namespace (see load_config), so every name
# defined here is callable from your config. __all__ documents that config-facing surface and keeps these
# helpers from reading as "unused" — they are public API for config authors, not dead code.
__all__ = [
    "Machine",
    "Instance",
    "Project",
    "MikException",
    "Color",
    "debug",
    "pop",
    "run_step",
    "deploy_release",
    "run_and_capture",
    "record_run",
    "make_pinned_ssl_context",
    "configured_pins",
    "pinned_urlopen",
    "ARTIFACTS_DIR",
    "artifact_category_dir",
    "build_artifact",
    "latest_release",
    "resolve_release",
    "prune_artifacts",
    "safe_tar_member",
]


# TODOs
# - backup system
# - system to easily pull trees
# - custom tasks graph + state for each + all race conditions handled
# - update system, track remote versions
# - reboot command
# - better data model, deploy a project to an instance, let an instance backup multiple projects...
# - `help <command>` surfacing the relevant helper docstring (e.g. `help deploy` -> deploy_release)


CONFIG_FILE = Path.home() / ".config/mik/config.py"
# Per-run records (combined stdout+stderr, rc, timing) live one-JSON-per-file here so concurrent runs
# never race on a shared index and old runs can be pruned by deleting files. Glob it to build an index.
RUNS_DIR = Path.home() / ".local/state/mik/runs"


colors = {"RED": "31", "GREEN": "32", "PURP": "34", "DIM": "90", "WHITE": "39"}
Color = Enum("Color", [(k, f"\033[{v}m") for k, v in colors.items()])


DEBUG = False


def debug(msg):
    if DEBUG:
        print(f"{Color.DIM.value}[debug] {msg}{Color.WHITE.value}", file=sys.stderr)


class MikException(Exception):
    pass


def _register(registry, kind, name, cls):
    """Record a config class under its name. Two classes with one name is a mistake in the config: the
    second would replace the first without a word, so it is refused, naming both.
    """
    if name in registry:
        raise MikException(f"Duplicate {kind} name {name!r}: classes {registry[name].__name__} and {cls.__name__}")
    registry[name] = cls


machines_dict = {}


class MachineMeta(type):
    def __new__(mcs, name, bases, namespace):
        if name == "Machine":
            return super().__new__(mcs, name, bases, namespace)
        if not namespace.get("name") or not namespace.get("ssh_host"):
            raise MikException(f"Machine {name} needs a name and an ssh_host")
        r = super().__new__(mcs, name, bases, namespace)
        _register(machines_dict, "machine", namespace["name"], r)
        return r


class Machine(metaclass=MachineMeta):
    """A real box you SSH into; hosts N instances (containers)."""

    name: Optional[str] = None
    ssh_host: Optional[str] = None  # "user@host"


instances_dict = {}


class InstanceMeta(type):
    def __new__(mcs, name, bases, namespace):
        if name == "Instance":  # the base class — skip registration
            return super().__new__(mcs, name, bases, namespace)
        if not namespace.get("name"):
            raise MikException(f"Instance {name} needs a name")
        r = super().__new__(mcs, name, bases, namespace)
        _register(instances_dict, "instance", namespace["name"], r)
        return r


class Instance(metaclass=InstanceMeta):
    """One project deployed on one machine, in one container."""

    name: Optional[str] = None
    project: Optional[str] = None  # -> Project name (N:1)
    machine: Optional[str] = None  # -> Machine name (N:1)
    container: Optional[str] = None  # docker container name
    code_dir: Optional[str] = None  # path inside the container
    deploy: Optional[list] = None  # shell commands (joined, run locally) — or override with a classmethod
    deploy_shell: Optional[str] = None  # optional; defaults to /bin/bash


projects_dict = {}


class ProjectMeta(type):
    def __new__(mcs, name, bases, namespace):
        if name == "Project":
            return super().__new__(mcs, name, bases, namespace)
        if not namespace.get("name"):
            raise MikException(f"No name for {name}")
        r = super().__new__(mcs, name, bases, namespace)
        _register(projects_dict, "project", namespace["name"], r)
        return r


class Project(metaclass=ProjectMeta):
    """The thing you develop (one repo); hosts N instances (its deployments)."""

    name: Optional[str] = None
    local_repo: Optional[str] = None
    github_repo: Optional[str] = None  # "owner/repo" — checked over the public GitHub API, no auth


def _unique(seq):
    seen = set()
    out = []
    for x in seq:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


# Relations are derived from the instance foreign keys — no join table, the instance IS the join.
def instances_for_project(project_name):
    return [name for name, i in instances_dict.items() if getattr(i, "project", None) == project_name]


def instances_for_machine(machine_name):
    return [name for name, i in instances_dict.items() if getattr(i, "machine", None) == machine_name]


def projects_for_machine(machine_name):
    return _unique(
        getattr(i, "project", None)
        for i in instances_dict.values()
        if getattr(i, "machine", None) == machine_name and getattr(i, "project", None)
    )


def get_projects():
    if not projects_dict:
        raise MikException("No projects data")
    return projects_dict


def get_instances():
    instances = instances_dict
    if not instances:
        raise MikException("No instances data")
    return instances


def _print_relation_section(title, names, related_of):
    """Print a bank-style section: each name with its related entities (or '(none)')."""
    print(f"{title}\n{'─' * len(title)}")
    for name in names:
        related = related_of(name)
        tail = ", ".join(related) if related else "(none)"
        print(f"  {Color.PURP.value}{name.ljust(16)}{Color.WHITE.value}{Color.DIM.value} → {tail}{Color.WHITE.value}")


def _warn_dangling_instances():
    """An instance can name a project/machine that was never defined (a typo); surface those, muted."""
    for name, i in instances_dict.items():
        project = getattr(i, "project", None)
        machine = getattr(i, "machine", None)
        if project and project not in projects_dict:
            print(
                f"{Color.DIM.value}  warning: instance {name!r} references unknown project "
                f"{project!r}{Color.WHITE.value}"
            )
        if machine and machine not in machines_dict:
            print(
                f"{Color.DIM.value}  warning: instance {name!r} references unknown machine "
                f"{machine!r}{Color.WHITE.value}"
            )


def _print_instance_section(title, names):
    """Each instance with its project and machine (its two foreign keys), bank-themed."""
    print(f"{title}\n{'─' * len(title)}")
    for name in names:
        i = instances_dict.get(name)
        project = getattr(i, "project", None) or "?"
        machine = getattr(i, "machine", None) or "?"
        print(
            f"  {Color.PURP.value}{name.ljust(20)}{Color.WHITE.value}"
            f"{Color.DIM.value} project={project}  machine={machine}{Color.WHITE.value}"
        )


def list_instances(args):
    """`list-instances`: bare instance names, or (with --show-links) each instance's project + machine.

    `project=NAME` / `machine=NAME` filter to instances on that project / machine.
    """
    names = list(instances_dict)
    project_filter = getattr(args, "project", None)
    if project_filter:
        if project_filter not in projects_dict:
            raise MikException(f"Project not found: {project_filter}")
        names = [n for n in names if n in set(instances_for_project(project_filter))]
    machine_filter = getattr(args, "machine", None)
    if machine_filter:
        if machine_filter not in machines_dict:
            raise MikException(f"Machine not found: {machine_filter}")
        names = [n for n in names if n in set(instances_for_machine(machine_filter))]
    if getattr(args, "show_links", False):
        _print_instance_section("INSTANCES", names)
    else:
        for n in names:
            print(n)


def list_projects(args):
    """`list-projects`: bare project names, or (with --show-instances) each project's instances.

    `machine=NAME` filters to projects with an instance on that machine.
    """
    names = list(projects_dict)
    machine_filter = getattr(args, "machine", None)
    if machine_filter:
        if machine_filter not in machines_dict:
            raise MikException(f"Machine not found: {machine_filter}")
        names = [n for n in names if n in set(projects_for_machine(machine_filter))]
    if getattr(args, "show_instances", False):
        _print_relation_section("PROJECTS", names, instances_for_project)
    else:
        for n in names:
            print(n)


def list_machines(args):
    """`list-machines`: bare machine names, or (with --show-instances) each machine's instances.

    `project=NAME` filters to machines running an instance of that project.
    """
    names = list(machines_dict)
    project_filter = getattr(args, "project", None)
    if project_filter:
        if project_filter not in projects_dict:
            raise MikException(f"Project not found: {project_filter}")
        running = {
            getattr(i, "machine", None)
            for i in instances_dict.values()
            if getattr(i, "project", None) == project_filter
        }
        names = [n for n in names if n in running]
    if getattr(args, "show_instances", False):
        _print_relation_section("MACHINES", names, instances_for_machine)
    else:
        for n in names:
            print(n)


def list_all(args):
    """`list`: everything — machines, projects, and instances, each with their links."""
    _print_relation_section("MACHINES", list(machines_dict), instances_for_machine)
    print()
    _print_relation_section("PROJECTS", list(projects_dict), instances_for_project)
    print()
    _print_instance_section("INSTANCES", list(instances_dict))
    _warn_dangling_instances()


def autocomplete(args):
    instances = get_instances()
    for i in instances:
        if i.startswith(args.autocomplete):
            print(i)


_POSIX_SHELLS = ("sh", "bash", "dash", "ksh", "zsh")


def deploy(args):
    instance_name = args.instance
    inst = instances_dict.get(instance_name)
    if not inst:
        raise MikException("Instance not found")
    d = getattr(inst, "deploy", None)
    if callable(d):
        # Custom Python deploy (a classmethod on the Instance) — it runs and reports itself.
        # An optional RELEASE_ID forwards through for instances whose deploy ships a chosen artifact.
        release_id = getattr(args, "release_id", None)
        return d(release_id) if release_id is not None else d()
    release_id = getattr(args, "release_id", None)
    if release_id is not None:
        raise MikException(f"{instance_name} has a script deploy; RELEASE_ID not supported")
    if not d:
        raise MikException("Instance has no deploy script")
    shell = getattr(inst, "deploy_shell", None) or "/bin/bash"
    s = "\n".join(d)
    # A line that fails stops the deploy there: without it, a `cd` that failed would be followed by `make
    # deploy` run from wherever the shell was, and only the last line's return code would tell. Only said to
    # a shell that knows `set -e` — deploy_shell may be any interpreter.
    if os.path.basename(shell) in _POSIX_SHELLS:
        s = "set -e\n" + s
    rc, _ = run_recorded("deploy", instance_name, s, shell)
    if rc != 0:
        raise MikException(f"deploy failed (rc={rc})")


def build(args):
    """`build INSTANCE`: run an instance's build step, producing a local artifact (no remote side effects)."""
    instance_name = args.instance
    inst = instances_dict.get(instance_name)
    if not inst:
        raise MikException("Instance not found")
    b = getattr(inst, "build", None)
    if not callable(b):
        raise MikException("Instance has no build step")
    return b()


def run_and_capture(script, executable="/bin/bash"):
    """Run a shell script, teeing combined stdout+stderr to the terminal live while capturing it.

    Config helper. Returns (returncode, combined_output_str). stderr is merged into stdout so the
    captured log matches what you saw on screen, and a single pipe keeps this thread-free.
    """
    chunks = []
    with subprocess.Popen(
        script,
        shell=True,
        executable=executable,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    ) as proc:
        for line in proc.stdout:
            sys.stdout.buffer.write(line)
            sys.stdout.flush()
            chunks.append(line)
    return proc.returncode, b"".join(chunks).decode(errors="replace")


def record_run(command, target, started_at, finished_at, returncode, output):
    """Persist a run record under RUNS_DIR for later scripted investigation.

    Config helper. Best-effort: a failure to record must never break a deploy, so errors are only
    surfaced via debug(). Cleaning/retention is intentionally left to a future command.
    """
    try:
        RUNS_DIR.mkdir(parents=True, exist_ok=True)
        run_id = f"{started_at.strftime('%Y%m%dT%H%M%S')}-{uuid4().hex[:8]}"
        record = {
            "id": run_id,
            "command": command,
            "target": target,
            "argv": sys.argv[1:],
            "started_at": started_at.isoformat(),
            "finished_at": finished_at.isoformat(),
            "returncode": returncode,
            "output": output,
        }
        # Atomic write: same-dir temp + replace, so a crash mid-write can't leave a torn record.
        # mkstemp's 0600 is kept on purpose: the captured output embeds whatever the deploy printed.
        fd, tmp_path = tempfile.mkstemp(dir=RUNS_DIR, prefix=f"{run_id}.", suffix=".tmp")
        try:
            try:
                os.write(fd, json.dumps(record, indent=2).encode())
            finally:
                os.close(fd)
            os.replace(tmp_path, RUNS_DIR / f"{run_id}.json")
        except BaseException:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise
        debug(f"recorded run {run_id} (rc={returncode})")
        return run_id
    except Exception as exc:
        debug(f"failed to record run: {exc}")
        return None


def run_recorded(command, target, script, executable):
    """Run a shell script via run_and_capture and persist the result via record_run.

    Returns (returncode, output). What a script deploy goes through: it streams live and leaves an
    investigable trail under RUNS_DIR.
    """
    started = datetime.now().astimezone()
    rc, output = run_and_capture(script, executable)
    record_run(command, target, started, datetime.now().astimezone(), rc, output)
    return rc, output


# ## Local artifact store #############################################################################
# Layout: ~/artifacts/<category>/<epoch>-<suffix>. One immutable entry per build; "newest" is the largest
# integer epoch prefix. An entry may be a directory (a static tree) OR a single file (e.g. a .tar image).
# A build stages into a hidden sibling *inside the category dir* (same filesystem) and atomically
# renames into place: a partial build is never visible to latest_release()/prune_artifacts() (they skip
# dotfiles) and is never half-shipped. A crash leaves only a `.mik-build-*` dotfile, which selectors ignore.
ARTIFACTS_DIR = Path.home() / "artifacts"


def artifact_category_dir(category):
    """Config helper: the directory holding every release of one artifact category.

    The category is one plain name ([A-Za-z0-9-._], not "." or ".."): it is a directory right under
    ARTIFACTS_DIR, and what prune_artifacts() deletes is looked for in it.
    """
    if not _is_plain_name(category):
        raise MikException(f"invalid artifact category (want letters, digits, - . _): {category!r}")
    return ARTIFACTS_DIR / category


def _remove_path(p):
    """rmtree a real directory, unlink anything else (file or symlink). No-op if absent."""
    if p.is_dir() and not p.is_symlink():
        shutil.rmtree(p)
    elif p.is_symlink() or p.exists():
        p.unlink()


def build_artifact(category, suffix, build, release_id=None):
    """Config helper: build one immutable artifact and return its path.

    `release_id` (epoch seconds) is minted here unless you pass one, so the id is fixed at *build* time
    and travels with the entry. `build(staging)` receives a not-yet-existing path under the category dir
    and must create it as a file or a directory; on success it is atomically renamed to
    <release_id>-<suffix>, on any error it is removed so no partial entry litters the store.
    """
    rid = str(release_id if release_id is not None else int(datetime.now().timestamp()))
    if not (rid.isascii() and rid.isdigit()):  # isdigit() alone says yes to "²", that int() then refuses
        raise MikException(f"bad release_id (want epoch digits): {rid!r}")
    base = artifact_category_dir(category)  # refuses a category that is not a plain name
    if not _is_plain_name(suffix):
        raise MikException(f"invalid artifact suffix (want letters, digits, - . _): {suffix!r}")
    base.mkdir(parents=True, exist_ok=True)
    final = base / f"{rid}-{suffix}"
    if final.exists():
        raise MikException(f"artifact already exists: {final}")
    staging = base / f".mik-build-{rid}-{suffix}"  # hidden + same dir => atomic rename, ignored by selectors
    _remove_path(staging)  # clear a previous half-done attempt
    try:
        build(staging)
        if not staging.exists():
            raise MikException(f"build() produced nothing at {staging}")
        staging.rename(final)  # atomic: same directory, same filesystem
    except BaseException:
        _remove_path(staging)
        raise
    debug(f"built artifact {final}")
    return final


def _artifact_entries(category):
    """(epoch:int, path) for every well-formed entry in a category, oldest-first. Dotfiles skipped.

    Restricting names to [A-Za-z0-9-._] keeps each entry's name safe to interpolate into a remote shell.
    """
    base = artifact_category_dir(category)
    entries = []
    for p in base.iterdir():
        if p.name.startswith("."):  # .mik-build-* staging and other hidden cruft
            continue
        head = p.name.split("-", 1)[0]
        if head.isascii() and head.isdigit() and _is_plain_name(p.name):
            entries.append((int(head), p))
    return sorted(entries, key=lambda t: t[0])


def latest_release(category):
    """Config helper: newest artifact (file or dir) in a category, ordered by integer epoch prefix."""
    entries = _artifact_entries(category)
    if not entries:
        raise MikException(f"no artifacts in {artifact_category_dir(category)}")
    return entries[-1][1]


def resolve_release(category, release_id):
    """Config helper: the artifact in `category` matching `release_id` (full entry name OR bare epoch prefix).

    So `resolve_release("presentations-dist", "1750000000")` and `"1750000000-dist"` both find the same
    entry — handy for rollback from the CLI, where you'd rather type the epoch than the full dir name.
    """
    for epoch, p in _artifact_entries(category):
        if p.name == release_id or str(epoch) == release_id:
            return p
    raise MikException(f"no artifact in {artifact_category_dir(category)} matching {release_id!r}")


def prune_artifacts(category, keep=10):
    """Config helper: delete all but the newest `keep` artifacts (file or dir). Returns removed paths."""
    if keep < 0:
        raise MikException("keep must be >= 0")
    entries = _artifact_entries(category)
    removed = []
    for _, p in entries[:-keep] if keep else entries:
        _remove_path(p)
        debug(f"pruned local artifact {p}")
        removed.append(p)
    return removed


def safe_tar_member(member, path):
    """Config helper: a tarfile extraction filter = the stdlib 'data' filter, then a flat refusal of links.

    Pass as `tar.extractall(dest, filter=safe_tar_member)`. data_filter already neutralises every escape:
    absolute member names are de-rooted into dest, names or link targets that would resolve outside dest
    raise (OutsideDestinationError / AbsoluteLinkError / LinkOutsideDestinationError), and device/FIFO
    specials raise (SpecialFileError). This only *adds* strictness on top — a built static artifact has no
    business carrying links, so every symlink/hardlink is rejected, including dest-internal ones data_filter
    would otherwise allow. Strictly stronger than filter="data": anything data_filter rejects, this rejects
    identically. Raising aborts extractall (the exception propagates), so a hostile or malformed archive
    fails the build loudly instead of extracting partially.
    """
    try:
        member = tarfile.data_filter(member, path)  # de-roots leading '/', raises on escape / special file
    except tarfile.FilterError as exc:  # surface as MikException so it prints clean + exits 1, not a traceback
        raise MikException(f"refusing archive member {member.name!r}: {exc}") from exc
    if member.issym() or member.islnk():
        raise MikException(f"refusing link in archive: {member.name!r} -> {member.linkname!r}")
    return member


def _assert_artifact_has_no_links(src):
    """Refuse, before any remote contact, if the artifact tree holds a symlink or a non-regular file.

    Defense-in-depth at the deploy chokepoint, independent of how the artifact was built: deploy can ship
    one produced by older code or a different build path (tar extract, copytree, ...), and `scp -r` / the
    merge `cp -rL` both dereference symlinks — a stray link would copy its target straight into the public
    web root. Only regular files and directories may ship. os.walk(followlinks=False) lists a symlinked dir
    but never descends into it, so links are reported, never followed; islink is checked before is_file/
    is_dir (which would follow the link) so the link itself is what we catch.
    """
    for root, dirs, files in os.walk(str(src), followlinks=False):
        for name in dirs + files:
            p = os.path.join(root, name)
            if os.path.islink(p):
                raise MikException(f"refusing to deploy: symlink in artifact: {p}")
            if not (os.path.isfile(p) or os.path.isdir(p)):
                raise MikException(f"refusing to deploy: non-regular file in artifact: {p}")


def pop(cmda):
    """Config helper: run an argv list, capturing stdout/stderr separately.

    returns value of last fail, so covers ssh fail, sudo fail, one of the remaining commands fail...
    """
    proc = subprocess.Popen(cmda, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    r, e = proc.communicate()
    return proc.returncode, e, r


def run_step(cmda, fail_on_stderr=False):
    """Config helper: run an argv list via pop(), raising MikException on rc!=0 (and optionally on stderr).

    Returns captured stdout. fail_on_stderr defaults to False because ssh/scp/git routinely write to
    stderr on success; pass True for commands you expect to stay silent. The failing command is included
    in the error, so config deploys stay locatable without a custom message per step. What the command
    wrote on stderr is in the error too, through _printable_lines: for an ssh step it is the remote that
    wrote it, and it must not get to send escape sequences to the terminal.
    """
    c, e, r = pop(cmda)
    debug(f"step rc={c} cmd={cmda} err={e!r} out={r!r}")
    if c != 0:
        raise MikException(f"step failed (rc={c}): {' '.join(cmda)}\n{_printable_lines(e)}")
    if fail_on_stderr and e:
        raise MikException(f"step wrote to stderr: {' '.join(cmda)}\n{_printable_lines(e)}")
    return r


_valid_name_ords = (
    *range(ord("A"), ord("Z") + 1),
    *range(ord("a"), ord("z") + 1),
    *range(ord("0"), ord("9") + 1),
    ord("-"),
    ord("."),
)


def validate_name(s):
    if s.startswith("-"):  # a name goes into an argv (ssh, docker exec): there, a leading dash is an option
        raise MikException(f"A name can't start with a dash: {s!r}")
    metone = False
    for c in s:
        if ord(c) not in _valid_name_ords:
            raise MikException(f"Found bad char {ord(c)} (printed {c}) when trying to validate a name")
        if c != ".":
            metone = True
    if not metone:
        raise MikException("Validating a name needs at least one char that is not a dot")


_valid_path_ords = (
    *range(ord("A"), ord("Z") + 1),
    *range(ord("a"), ord("z") + 1),
    *range(ord("0"), ord("9") + 1),
    ord("-"),
    ord("."),
    ord("_"),
)

# Fail closed on git-control files: a hostile pod must not slip us a .git dir, .gitattributes, .gitmodules,
# .githooks/, etc. — they hijack checkout/filter/hook behavior. So we deny the whole ".git" prefix and poke
# explicit holes only for known-safe exceptions: .gitignore, .github/** (CI/workflows/templates), .gitkeep.
# Anything else starting with ".git" is rejected by default — add it here consciously if you need it.
# What is forbidden is forbidden in any case (".GIT/hooks/x", ".Git/config"): a filesystem that ignores case
# (macOS, Windows, a casefold directory) opens .git under those names. What is allowed is so as written only.
# HEAD: a repository needs no ".git" in its name. Any directory that holds HEAD, objects/ and refs/ is one to
# git (a bare one), found from anywhere under it, and its `config` is then obeyed: core.fsmonitor there is a
# command that `git status` runs. A pod could send those four as new files, each with a harmless name. HEAD is
# the one every such directory has to have, and the one a project has no use for — so no HEAD, no repository.
# (FORBIDDEN_PATH_PARTS is compared with the name in lower case: keep what is in it in lower case.)
FORBIDDEN_PATH_PARTS = {"node_modules", "__pycache__", "head"}
FORBIDDEN_PATH_PREFIXES = (".git",)
ALLOWED_PATH_PARTS = {".gitignore", ".github", ".gitkeep"}


def validate_path(p):
    if not p or p.startswith("/"):
        return False
    for component in p.split("/"):
        if not component or component in (".", ".."):  # "." too: "a/./b" is "a/b" under another name
            return False
        if component in ALLOWED_PATH_PARTS:
            continue
        folded = component.lower()
        if folded in FORBIDDEN_PATH_PARTS:
            return False
        for prefix in FORBIDDEN_PATH_PREFIXES:
            if folded.startswith(prefix):
                return False
        for c in component:
            if ord(c) not in _valid_path_ords:
                return False
    return True


def _is_plain_name(s):
    """True for one plain name: only [A-Za-z0-9-._], and at least one char that is not a dot (so not "", ".", "..").

    The chars validate_path allows in a path component, looked up one by one in the allowlist: no regex, and
    not str.isalnum(), which says yes to every letter and digit Unicode has ("é", "²").
    """
    return isinstance(s, str) and bool(s.strip(".")) and all(ord(c) in _valid_path_ords for c in s)


_valid_code_dir_ords = (*_valid_path_ords, ord("/"))


def validate_code_dir(s):
    """Validate an absolute container path (e.g. /home/dev/workspace/x): allow [A-Za-z0-9.-_/] only.

    We own this value (it comes from our own config), so this is belt-and-suspenders — but a clean
    allowlist costs nothing and keeps code_dir boring before it reaches the remote git/python. Raises.
    """
    if not s or not s.startswith("/"):
        raise MikException(f"bad code_dir (want an absolute path): {s!r}")
    for comp in s.split("/"):
        if comp == "..":
            raise MikException(f"'..' not allowed in code_dir: {s!r}")
    for c in s:
        if ord(c) not in _valid_code_dir_ords:
            raise MikException(f"bad char {c!r} in code_dir: {s!r}")


def _flip_current_cmd(site_root, target):
    """The remote command that atomically points {site_root}/current at `target` (*relative to site_root*).

    `current` is a symlink and nothing more. rename(2) is the only atomic replace — symlink(2) refuses to
    overwrite — so the canonical move is to materialise the new link under a temp name, then rename it onto
    `current`. `ln -sfn` builds (or overwrites a crash-leftover of) that temp link in one (non-atomic) step
    (`-f` force, `-n` so it never descends into a leftover symlink-to-a-dir), and `mv -T` does the atomic
    rename, so a serving nginx never sees `current` momentarily absent. The temp name is fixed, so a crash
    leaves at most one stale link, which the next flip reclaims.

    Returned, not run: deploy_release puts it at the end of the very command that gives the release its
    name. Precondition: caller passes an already-validated, shell-safe `site_root` and a relative `target`
    composed from validated parts.
    """
    tmp = f"{site_root}/.mik-cur-tmp"
    return f"ln -sfn {target} {tmp} && mv -T {tmp} {site_root}/current"


def _owner_writes_cmd(path):
    """The remote command after which the ssh user can read, enter and write everything under `path`.

    Whatever modes a build came with: a read-only file cannot be copied over, and a read-only directory can
    neither be filled, nor renamed into another one, nor deleted. `chmod -R` gives a directory its bits
    before it goes into it, so one that could not even be entered is.
    """
    return f"chmod -R u+rwX {path}"


def _served_modes_cmd(path):
    """The remote command that leaves what is under `path` the way it is served: directories 755, files 444.

    The modes are set, not added to, so they do not depend on what the build had or on a umask. Readable by
    all: a containerized web server reads through the "other" bits. Files written by nobody: a release is
    not edited in place, and a file that is has to be made writable first, which is not done by accident (it
    stops no one who is the owner, and is not meant to). Directories stay writable by their owner, and only
    by it: one that is not cannot be renamed into releases/ (rename(2) has to write its `..`), and `rm -rf`
    cannot empty it. The owner is given its bits first (_owner_writes_cmd): find could not go through a
    directory it cannot read.
    """
    return (
        f"{_owner_writes_cmd(path)}"
        f" && find {path} -type d -exec chmod 755 '{{}}' +"
        f" && find {path} -type f -exec chmod 444 '{{}}' +"
    )


# What deploy_release owns under a site root, beside the `current` link. A directory's place says where it
# stands: being uploaded, uploaded and live at some point, being merged, merged and served at some point.
_SITE_DIRS = ("releases", "merged", "releasing", "merging")
_SITE_SURVEY_LINE = re.compile(
    r"now (?P<now>[0-9]+)"
    r"|current(?: (?P<current>(?:releases|merged)/[A-Za-z0-9]+))?"
    rf"|(?P<where>{'|'.join(_SITE_DIRS)}) d (?P<when>[0-9]+(?:\.[0-9]+)?) (?P<entry>[A-Za-z0-9]+)"
)


def _parse_site_survey(out):
    """What a remote look at {site_root} found: (now, current, releases, merged, unfinished).

    `releases` is [(date, name)], oldest first; `merged` is [name]; `unfinished` is what sits in releasing/
    and merging/, as paths relative to the site root; `current` is where the link leads ("" if there is
    none yet). One line per fact, as the survey command prints them, and every line has to be one of those
    expected: these directories are mik's own, and the names in them go into later remote commands (cp, mv,
    rm -rf). Anything else — a file, a directory made by hand, a name that is not plain letters and digits,
    a `current` that leads elsewhere — stops the deploy here, before anything is changed.
    """
    now, current, found = None, "", {where: [] for where in _SITE_DIRS}
    for line in out.decode(errors="replace").split("\n"):
        if not line:
            continue
        fact = _SITE_SURVEY_LINE.fullmatch(line)
        if fact is None:
            raise MikException(
                f"unexpected in the remote site root: {line!r}\n"
                f"mik expects `current` to lead to releases/<id> or merged/<id>, and nothing but release "
                f"directories (letters and digits) in {', '.join(f'{where}/' for where in _SITE_DIRS)}. "
                f"Move away what does not belong there, then deploy again."
            )
        if fact["now"]:
            now = int(fact["now"])
        elif fact["where"]:
            found[fact["where"]].append((float(fact["when"]), fact["entry"]))
        else:
            current = fact["current"] or ""
    if now is None:
        raise MikException(f"could not read the state of the remote site root:\n{out.decode(errors='replace')}")
    unfinished = [f"{where}/{entry}" for where in ("releasing", "merging") for _, entry in sorted(found[where])]
    return now, current, sorted(found["releases"]), sorted(entry for _, entry in found["merged"]), unfinished


def _forgotten_releases(releases, rid, serving):
    """The releases from before the one `current` leads to, when it leads to a release itself.

    `current` -> releases/S (and not merged/S) says that S was deployed to be served alone: since then,
    nothing else was. So history begins at S. What came before it is not merged under a later release —
    this is what makes a page removed with merge_seconds=0 stay removed — and is deleted, `keep` or not:
    left there, it would be picked up again one deploy later, when `current` no longer tells.
    """
    where, _, served = serving.partition("/")
    since = [when for when, entry in releases if where == "releases" and entry == served]
    return [entry for when, entry in sorted(releases) if since and when < since[0] and entry != rid]


def _releases_to_merge(releases, rid, now, merge_seconds):
    """The earlier releases whose files stay available under the new one, oldest first.

    `releases` is [(date, name)]: a release directory gets its name in the command that makes it live, and
    its own date is from the upload just before. A page that is open in somebody's browser was loaded from
    whatever was live at the time: so a tab up to merge_seconds old may hold any release that went live
    within that time, or the one that already was live when that time began — the newest of those from
    before. Nothing older.
    """
    if merge_seconds <= 0:
        return []
    others = [(when, entry) for when, entry in sorted(releases) if entry != rid]
    cut = now - merge_seconds
    before = [entry for when, entry in others if when < cut]
    within = [entry for when, entry in others if when >= cut]
    return before[-1:] + within


def _site_leftovers(releases, merged, rid, serving, merging, keep):
    """(releases, merged dirs) that nothing needs any more, once `rid` is live.

    Kept: the new release, the `keep` newest, whatever the next deploy may still have to merge (`merging`
    is what this one merged: the next one's window is a subset of it plus the new release), and — under
    either name — what was being served until a moment ago (`serving`, the old target of `current`). A
    server that follows `current` on a timer rather than per request is still reading from that directory
    for a few seconds after the flip, so it goes at the next deploy, not at this one.
    """
    others = [entry for _, entry in sorted(releases) if entry != rid]
    newest = others[max(len(others) - (keep - 1), 0) :]  # the new release is one of the `keep`
    was_dir, _, was = serving.partition("/")
    keep_releases = {rid, *merging, *newest} | ({was} if was_dir == "releases" else set())
    keep_merged = {rid} | ({was} if was_dir == "merged" else set())
    return (
        [entry for entry in others if entry not in keep_releases],
        [entry for entry in sorted(merged) if entry not in keep_merged],
    )


def _tree_kinds(src):
    """{path: "d" or "f"} for everything under a local artifact directory, paths relative to it."""
    kinds = {}
    for root, dirs, files in os.walk(str(src), followlinks=False):
        for names, kind in ((dirs, "d"), (files, "f")):
            for entry in names:
                kinds[os.path.relpath(os.path.join(root, entry), str(src))] = kind
    return kinds


def _parse_release_kinds(out, entries):
    """{release: {path: "d" or "f"}} for the releases about to be merged, from what the remote `find` printed.

    One `kind release/path` per file or directory, ended by a NUL: a file name may hold anything else, a
    newline included, and none of these names goes into a command — they are only compared. A release holds
    what scp put there, regular files and directories; anything else in one (a symlink, which `cp -rL` would
    follow to copy what it leads to into the web root) was not put there by mik, and stops the deploy.
    """
    kinds = {entry: {} for entry in entries}
    for record in out.split(b"\0"):
        if not record:
            continue
        kind, _, path = os.fsdecode(record).partition(" ")
        entry, _, inside = path.partition("/")
        if entry not in kinds or not inside:
            raise MikException(f"could not read what the remote releases hold: {_printable(path)!r}")
        if kind not in ("d", "f"):
            raise MikException(
                f"unexpected in the remote release {entry}: {_printable(inside)!r} is neither a regular file nor "
                f"a directory. mik uploads nothing else. Move it away, then deploy again."
            )
        kinds[entry][inside] = kind
    return kinds


def _merge_clashes(layers):
    """What stops `layers` from being copied over one another: [(path, release, kind, other release, its kind)].

    `layers` is [(release, {path: kind})], in the order they are merged. `cp -r` copies a file over a file
    and a directory into a directory; a name that is a file in one release and a directory in another it
    replaces in neither direction — it fails. Only the name where the two part is listed, not what is under.
    """
    first, clashes = {}, {}
    for entry, kinds in layers:
        for path, kind in kinds.items():
            was_kind, was_entry = first.setdefault(path, (kind, entry))
            if was_kind != kind:
                clashes.setdefault(path, (path, was_entry, was_kind, entry, kind))
    return [clashes[path] for path in sorted(clashes)]


def deploy_release(src, ssh_host, site_root, release_id, name, keep=5, merge_seconds=86400):
    """Zero-downtime deploy of an already-built artifact. No rsync, no shell pipes, no sudo.

    Config helper — the *deploy* half of build/deploy. `src` is a finished artifact directory (typically
    from latest_release()/resolve_release()); choosing, excluding and transforming files is the *build*
    step's job (see build_artifact), so this ships src as-is, then flips the `current` symlink the web
    server serves through.

    Runs entirely as the ssh user — *no sudo*. The web root must be owned/writable by that user (a one-time
    `chown -R <user> {site_root}`); a preflight check fails fast with that instruction if it isn't. A
    containerized web server serving from a bind mount reads files by their world-readable ("other") bits
    regardless of host ownership, which is why what is served is readable by all.

    Modes. Whatever the build had, a release ends as directories 755 and files 444 (see _served_modes_cmd),
    and so does a merge. While it is put together, everything in a merge is writable by the ssh user: the
    files copied from an earlier release come read-only, and the next one copied over them has to replace
    them. So a build with read-only files, or read-only directories, deploys like any other.

    What is on the remote. Four directories under {site_root}, all mik's own, and where a directory is
    says where it stands:
      releasing/{id}  being uploaded
      releases/{id}   the pristine build. It gets this name in the same command that flips `current`, so a
                      release that is in there went live.
      merging/{id}    a merge being put together
      merged/{id}     a merge that `current` was pointed at
    They must be on one filesystem (they are, unless one was mounted apart): going from releasing/ to
    releases/ is then a rename. `current` only ever leads to a directory that is complete.

    What is served. With merge_seconds > 0 (a day by default), `current` does not point at the release
    itself but at merged/{id}: the releases that went live in the last merge_seconds, plus the one that was
    live before that, copied over one another from oldest to newest, the new release last (so it wins on
    every name they share, index.html first of all). The next deploy merges from releases/, never from a
    merge, so a file leaves when its release leaves the window. With merge_seconds=0, `current` points at
    the clean release.

    Why merge. A browser that loaded index.html before the deploy still asks for the hashed bundles that
    page names, and a clean new release no longer has them: a 404, a broken tab. Under the merge, a tab up
    to merge_seconds old finds every bundle it can ask for. What that does not cover: a tab left open for
    longer, then asking for a lazy chunk for the first time. That tail needs the application to reload on
    a failed chunk load (once, not in a loop); the merge makes it rare, the handler makes it correct. Both
    rely on index.html being served `Cache-Control: no-cache`.

    What it costs. A file removed from a build keeps being served until the first deploy made more than
    merge_seconds after the one that removed it — the merge is only made when deploying. For a bundle
    nobody asks for, nothing; for a page that had to disappear, deploy with merge_seconds=0. That begins
    history again: the next deploy that merges sees `current` leading to a release served alone, merges
    nothing from before it, and deletes those earlier releases — whatever `keep` says.

    What is deleted, and when. Releases beyond the `keep` newest, unless a later merge may still need
    them; merged directories other than the new one. Never, in the same deploy, the directory that was
    being served until the flip: a server that looks at where `current` leads every few seconds, rather
    than on every request, is still reading from it for that long. It goes at the next deploy. One
    exception: shipping again the id that is live right now replaces that directory under its name, and
    requests get 404s while that takes.

    What cannot be merged. A name that is a file in one release and a directory in another (`docs`, then
    `docs/index.html`): cp replaces neither with the other. This is looked for before anything is uploaded
    — the releases about to be merged are listed and compared with the artifact — and the deploy is refused,
    naming them. Retrying would not help while both releases are in the window: deploy once with
    merge_seconds=0, and history begins again at that release (see above).

    When a deploy fails. Any step may: run it again. What a failed one left in releasing/ or merging/ is
    shown and, once you agree, deleted (the same would show if another deploy were running right now —
    then say no). It never went live and is never merged. Anything else that mik did not put in those
    four directories stops the deploy before it changes a thing.

    Inputs land in a remote shell and in paths, so they're validated up front. Needs GNU find and mv on the
    remote (Debian has them).
    """
    rid = str(release_id)
    if not (rid.isascii() and rid.isalnum()):  # lands in a remote shell + a path — keep it boring
        raise MikException(f"unsafe release_id: {rid!r}")
    keep, merge_seconds = int(keep), int(merge_seconds)
    if keep < 1:  # the new release itself counts: keeping none of them would delete what is live
        raise MikException("keep must be >= 1")
    if merge_seconds < 0:
        raise MikException("merge_seconds must be >= 0 (0 serves the release alone)")
    validate_code_dir(site_root)  # absolute, no '..', boring chars — it's interpolated into a remote target
    for part in ssh_host.split("@"):
        try:
            validate_name(part)
        except Exception as exc:
            raise MikException(f"unsafe ssh_host: {ssh_host!r}") from exc
    _assert_artifact_has_no_links(src)  # payload check, before any remote contact: scp -r/cp -rL deref links
    # Invariant from here on: rid is ascii alnum and site_root is a clean absolute path, so every remote
    # string composed below ({site_root}/releases/{rid}, releasing/{rid}, merged/{rid}, ...) is shell-safe by
    # construction, and so is every other release name: _parse_site_survey raises on any that is not.
    # That's why the sinks below interpolate without re-checking.
    # (`name` is a log label only — it no longer reaches a shell or a path — so it needs no validation.)
    releases_dir, merged_dir, releasing_dir, merging_dir = (f"{site_root}/{where}" for where in _SITE_DIRS)
    site_dirs = [releases_dir, merged_dir, releasing_dir, merging_dir]
    # 0. preflight: make the four directories and confirm they're writable AS THE SSH USER, so we fail with
    #    an actionable message instead of a cryptic scp/rm permission error mid-deploy. No sudo anywhere.
    preflight = " && ".join([f"mkdir -p {' '.join(site_dirs)}", *[f"test -w {path}" for path in site_dirs]])
    rc, err, _ = pop(["ssh", ssh_host, preflight])
    if rc != 0:
        raise MikException(
            f"{site_root} is not writable over ssh as {ssh_host} (rc={rc}). mik deploys without sudo — "
            f"own the web root with the deploy user, e.g. `ssh {ssh_host} sudo chown -R \\$USER {site_root}`."
        )
    # 1. look at what is there: the remote clock, where `current` leads, and everything in the four
    #    directories with its kind and date. Read-only; choosing happens here, in Python.
    survey = run_step(
        [
            "ssh",
            ssh_host,
            " && ".join(
                [
                    f"cd {site_root}",
                    "echo now $(date +%s)",
                    "echo current $(readlink current 2>/dev/null)",
                    f"find {' '.join(_SITE_DIRS)} -mindepth 1 -maxdepth 1 -printf '%h %y %T@ %f\\n'",
                ]
            ),
        ]
    )
    now, serving, releases, merged, unfinished = _parse_site_survey(survey)
    # 2. what an earlier deploy started and did not finish: shown, and deleted only once the user agrees —
    #    from here it cannot be told apart from another deploy that is running right now.
    if unfinished:
        print(f"warning: a deploy to {ssh_host}:{site_root} did not finish, or is still running. Left there:")
        for path in unfinished:
            print(f"  {path}")
        try:
            answer = input("Delete these and carry on? [y/N] ")
        except EOFError:  # nobody to ask
            answer = ""
        if answer.strip().lower() != "y":
            raise MikException(f"not deploying {name}: unfinished deploy left in {site_root} ({', '.join(unfinished)})")
        # made writable first: an upload that stopped halfway may hold a read-only directory, as the build
        # had it, and `rm -rf` cannot empty one
        left = " ".join(f"{site_root}/{path}" for path in unfinished)
        run_step(["ssh", ssh_host, f"{_owner_writes_cmd(left)} && rm -rf {left}"])
    # 3. what is to be merged, and whether it can be: the earlier releases are listed (read-only) and
    #    compared, here, with one another and with the artifact. A clash would make the merge fail at every
    #    try, so it is refused now, while nothing has been uploaded.
    forgotten = _forgotten_releases(releases, rid, serving) if merge_seconds > 0 else []
    remembered = [(when, entry) for when, entry in releases if entry not in forgotten]
    merging = _releases_to_merge(remembered, rid, now, merge_seconds)
    if merging:
        listing = run_step(
            ["ssh", ssh_host, f"cd {releases_dir} && find {' '.join(merging)} -mindepth 1 -printf '%y %p\\0'"]
        )
        held = _parse_release_kinds(listing, merging)
        clashes = _merge_clashes([*[(entry, held[entry]) for entry in merging], (rid, _tree_kinds(src))])
        if clashes:
            said = {"d": "a directory", "f": "a file"}
            lines = [
                f"  {_printable(path)}: {said[was]} in {entry}, {said[kind]} in {other}"
                for path, entry, was, other, kind in clashes[:10]
            ]
            if len(clashes) > 10:
                lines.append(f"  ... and {len(clashes) - 10} more")
            raise MikException(
                f"cannot merge release {rid} with the earlier ones (cp replaces neither a file with a directory "
                f"nor a directory with a file):\n" + "\n".join(lines) + "\n"
                f"Nothing was uploaded. Deploy {name} once with merge_seconds=0: this release is then served "
                f"alone (a page loaded before it may miss its old bundles), and later deploys merge from it on."
            )
    # 4. ship the built artifact as-is (scp = argv, no shell). releasing/ is empty by now, so the directory
    #    scp makes is the artifact itself.
    run_step(["scp", "-r", str(src), f"{ssh_host}:{releasing_dir}/{rid}"])
    # 5. get ready, beside what is served: the upload given the modes it is served with (directories 755,
    #    files 444) and, when merging, the merge — the earlier releases copied in from oldest to newest and
    #    this one last, so that it wins on shared names. What was copied is made writable before the next one
    #    is copied over it (a copy of a read-only file is read-only), and the merge gets its modes at the end.
    ready = [_served_modes_cmd(f"{releasing_dir}/{rid}")]
    go_live = [f"rm -rf {releases_dir}/{rid}", f"mv -T {releasing_dir}/{rid} {releases_dir}/{rid}"]
    target = f"releases/{rid}"
    if merge_seconds > 0:
        ready += [f"mkdir {merging_dir}/{rid}"]
        for entry in merging:
            ready += [
                f"cp -rL {releases_dir}/{entry}/. {merging_dir}/{rid}/",
                _owner_writes_cmd(f"{merging_dir}/{rid}"),
            ]
        ready += [f"cp -rL {releasing_dir}/{rid}/. {merging_dir}/{rid}/", _served_modes_cmd(f"{merging_dir}/{rid}")]
        go_live += [f"rm -rf {merged_dir}/{rid}", f"mv -T {merging_dir}/{rid} {merged_dir}/{rid}"]
        target = f"merged/{rid}"
    run_step(["ssh", ssh_host, " && ".join(ready)])
    # 6. go live, in one command: each directory takes its name (a rename; the `rm -rf` only finds something
    #    when this id was shipped before) and `current` flips to it (atomic rename, never absent). A release
    #    is named in releases/ here and nowhere else — that is what "it is in releases/" tells the next deploy.
    run_step(["ssh", ssh_host, " && ".join([*go_live, _flip_current_cmd(site_root, target)])])
    # 7. delete what nothing needs any more — never what was being served until a moment ago (best-effort;
    #    failure here must not fail the deploy)
    old_releases, old_merged = _site_leftovers(remembered, merged, rid, serving, merging, keep)
    doomed = [f"{releases_dir}/{entry}" for entry in [*forgotten, *old_releases]]
    doomed += [f"{merged_dir}/{entry}" for entry in old_merged]
    if doomed:
        try:
            run_step(["ssh", ssh_host, "rm -rf " + " ".join(doomed)])
        except MikException as exc:
            debug(f"prune failed (ignored): {exc}")
    print(f"deployed {name} -> {site_root}/current -> {target}" + (f" (over {', '.join(merging)})" if merging else ""))


# validate_path again, as source text: the listing script runs inside the pod, where mik.py is not there to
# import (no re, no imports beyond builtins). It only lets an honest pod skip odd names with a warning; what
# protects the local repo is validate_path itself, run here on whatever comes back (_checked_remote_files).
_REMOTE_VALIDATE_PATH = """
_vpo = (
    *range(ord("A"), ord("Z") + 1), *range(ord("a"), ord("z") + 1),
    *range(ord("0"), ord("9") + 1), ord("-"), ord("."), ord("_"),
)
_forbidden_parts = {"node_modules", "__pycache__", "head"}
_forbidden_prefixes = (".git",)
_allowed_parts = {".gitignore", ".github", ".gitkeep"}
def validate_path(p):
    if not p or p.startswith("/"):
        return False
    for comp in p.split("/"):
        if not comp or comp in (".", ".."):
            return False
        if comp in _allowed_parts:
            continue
        folded = comp.lower()
        if folded in _forbidden_parts:
            return False
        for pfx in _forbidden_prefixes:
            if folded.startswith(pfx):
                return False
        for c in comp:
            if ord(c) not in _vpo:
                return False
    return True
"""

# git does the listing, one file per line, so that what is ignored stays out:
#   -uall          every untracked file by its own path. Without it a new directory is one line ("?? dir/")
#                  and finding what is in it would be up to us — a walk, that knows nothing of .gitignore.
#   --no-renames   a rename that was staged in the pod ("R  old -> new", two paths in one line) comes as what
#                  it is to us: "D  old" and "A  new". One that was not staged already does (" D" and "??").
# What is left with a "/" at the end is a repository inside the repository: git does not look into it, and
# neither do we (validate_path refuses the name, it is shown as a warning).
REMOTE_SCRIPT_LIST = """
import subprocess, json, os, sys
{validate_path}
code_dir = {code_dir!r}
r = subprocess.run(
    ["git", "-C", code_dir, "status", "--porcelain", "-uall", "--no-renames"], capture_output=True, text=True
)
if r.returncode != 0:
    print(json.dumps({{"files": [], "errors": ["git status failed: " + r.stderr.strip()]}}))
    sys.exit(0)
files = []
errors = []
for line in r.stdout.split("\\n"):
    if not line:
        continue
    status_code = line[:2]
    path = line[3:]
    if "D" in status_code:
        s = "D"
    elif status_code == "??" or "A" in status_code:
        s = "A"
    else:
        s = "M"
    full_path = os.path.join(code_dir, path)
    if s != "D" and os.path.islink(full_path):
        errors.append("symlink rejected: " + path)
    elif not validate_path(path):
        errors.append("invalid path: " + path)
    else:
        files.append({{"path": path, "status": s}})
print(json.dumps({{"files": files, "errors": errors}}))
"""

REMOTE_SCRIPT_FETCH = """
import json, os, sys, base64
code_dir = {code_dir!r}
file_list = {file_list}
result = {{"files": {{}}, "deleted": []}}
for f in file_list:
    if f["status"] == "D":
        result["deleted"].append(f["path"])
        continue
    full = os.path.join(code_dir, f["path"])
    if os.path.islink(full):
        result.setdefault("errors", []).append(f["path"] + ": symlink rejected")
        continue
    try:
        with open(full, "rb") as fh:
            result["files"][f["path"]] = base64.b64encode(fh.read()).decode()
    except Exception as e:
        result.setdefault("errors", []).append(f["path"] + ": " + str(e))
print(base64.b64encode(json.dumps(result).encode()).decode())
"""


def _printable(s):
    """What a pod sent, made safe to print: no escape sequence gets to rewrite what is on the terminal."""
    return "".join(c for c in str(s) if c.isprintable())


def _is_dot_path(path):
    """True for a path with a name that starts with a dot in it (".envrc", ".vscode/tasks.json", "a/.hg/hgrc").

    Such a name is where tools keep what they read without being asked, and some of it they run: an editor's
    tasks, a hook manager's hooks, another version control's config, CI workflows. `ls` does not show them, and
    in a long list they are easy to read past — so dev-fetch-pod shows them in red before it asks.
    """
    return any(component.startswith(".") for component in path.split("/"))


def _checked_remote_files(files):
    """The file list a pod sent, refused as a whole unless every entry is a plain path inside the repo.

    The pod runs the same check on its side (_REMOTE_VALIDATE_PATH), but only to skip odd names with a
    warning: the pod is the one that is not trusted, and it can answer whatever it likes. So the check that
    counts is this one, made here, before the list is shown and long before anything is written.
    """
    if not isinstance(files, list):
        raise MikException("Bad file list from remote")
    for f in files:
        ok = isinstance(f, dict) and f.get("status") in ("M", "A", "D") and isinstance(f.get("path"), str)
        if not ok or not validate_path(f["path"]):
            raise MikException(f"Refusing the remote file list, bad entry: {f!r}")
    # One line per file: a path listed twice would be shown with two statuses and applied with the last, and a
    # path that is a file here and a directory there ("a", "a/b") cannot be both — applying it would stop
    # halfway. git says the second when a file became a directory: that one is to be done by hand.
    paths = [f["path"] for f in files]
    twice = sorted({path for path in paths if paths.count(path) > 1})
    if twice:
        raise MikException(f"Refusing the remote file list, listed more than once: {', '.join(twice)}")
    above = {path.rsplit("/", i)[0] for path in paths for i in range(1, path.count("/") + 1)}
    both = sorted(above & set(paths))
    if both:
        raise MikException(f"Refusing the remote file list, both a file and a directory in it: {', '.join(both)}")
    # Made again from the two checked fields: this list goes back into the fetch script, and anything else a
    # pod put beside them has no business travelling with it.
    return [{"path": f["path"], "status": f["status"]} for f in files]


def _local_destinations(local_repo, files):
    """{path: where it lands in the local repo} for the files a pod listed — refused if a symlink is on the way.

    validate_path keeps a path inside the repo as a name; a symlink already in the local repo (`vendor ->
    /somewhere/else`, one that is tracked, one that came with a pull) would still take `vendor/x` out of
    it, for a write as for a deletion. So every component is looked at, the last one included: nothing is
    written or deleted through a link, and a link is not replaced either. Whatever local_repo itself is, it is
    the config's to say.

    Nor into a repository that is already there. validate_path refuses HEAD, so a pod cannot make a directory
    one; but a bare repository the local repo already holds (a test fixture, `fixtures/x.git`) has its HEAD,
    and its `config` and `hooks/` are plain names. So a directory on the way that holds a HEAD is refused.

    Nor into one that has its own `.git` (a clone kept inside the local repo, a `git worktree`, a submodule):
    to the local repo that whole directory is one line of `git status` at most, the same before and after —
    what a pod wrote in it would be shown by neither `git status` nor `git diff` there.

    And what is there has to be what the path says: directories on the way, a regular file at the end (or
    nothing yet). Found here, before the question is asked, rather than by a write that fails halfway.
    """
    dests = {}
    for f in files:
        dest = Path(local_repo)
        components = f["path"].split("/")
        for depth, component in enumerate(components, 1):
            dest = dest / component
            if dest.is_symlink():
                raise MikException(
                    f"Refusing {f['path']}: {dest} is a symlink in the local repo, and mik neither writes nor "
                    f"deletes through one. Nothing was fetched."
                )
            if depth < len(components):
                if os.path.lexists(dest / "HEAD"):
                    raise MikException(
                        f"Refusing {f['path']}: {dest} holds a HEAD, which makes it a repository to git (its "
                        f"config and hooks are obeyed), and mik writes nothing into one. Nothing was fetched."
                    )
                if os.path.lexists(dest / ".git"):
                    raise MikException(
                        f"Refusing {f['path']}: {dest} holds a .git, which makes it a repository of its own (a "
                        f"clone, a worktree, a submodule): `git status` in {local_repo} would not show what was "
                        f"written in it. Nothing was fetched."
                    )
                if dest.exists() and not dest.is_dir():
                    raise MikException(f"Refusing {f['path']}: {dest} is not a directory here. Nothing was fetched.")
            elif dest.exists() and not dest.is_file():
                raise MikException(f"Refusing {f['path']}: {dest} is not a regular file here. Nothing was fetched.")
        dests[f["path"]] = dest
    return dests


def _locally_ignored(local_repo, paths, coming=None):
    """Those of `paths` that the local repo ignores, as git itself says (`git check-ignore`), in their order.

    Why it matters: what a pod sent is reviewed with `git status` / `git diff` in the local repo, and a file
    that is ignored there shows in neither. `.venv/lib/python3.13/site-packages/x.pth` is a plain path, and
    runs at the next `python`; `.env` is one a deletion would take away. A pod that is honest never lists
    such a file (its own `git status` leaves out what the same .gitignore ignores), so one that does is
    refused. A file that is tracked is not ignored, whatever .gitignore says: git shows it, and it is not
    returned here.

    The rules are git's own to read (.gitignore at every level, negations, .git/info/exclude, the user's
    core.excludesFile): none of that is done again here. So local_repo has to be a git repository, with git
    there to ask — if it cannot be asked, nothing is fetched. The paths go through stdin, NUL-ended: none
    is an argument.

    `coming` is {path: content, or None for a deletion}: what is about to be done to the local repo, and the
    .gitignore files in it are part of the rules. A pod could send a file and, with it, the .gitignore that
    hides it. So git is not asked in the local repo but in a work tree made for the question, which holds
    nothing but the .gitignore files a path depends on (those of the directories above it), each one as it
    would be afterwards: the one that is coming, none if it is being deleted, else the one that is there.
    The index, info/exclude and the config stay those of the local repo (--git-dir). The answer is then
    about the repo as it would be, and nothing was written to it to know.
    """
    if not paths:
        return []
    coming = coming or {}

    def git(*argv, **kw):
        try:
            return subprocess.run(["git", *argv], capture_output=True, **kw)
        except OSError as exc:
            raise MikException(
                f"could not run git to ask what {local_repo} ignores: {exc}. Nothing was fetched."
            ) from exc

    def refuse(asked):
        raise MikException(
            f"could not ask git what {local_repo} ignores (rc={asked.returncode}), is it a git repository? "
            f"Nothing was fetched.\n{_printable_lines(asked.stderr)}"
        )

    found = git("-C", str(local_repo), "rev-parse", "--absolute-git-dir", "--show-toplevel", "--show-prefix")
    where = os.fsdecode(found.stdout).split("\n")
    if found.returncode != 0 or len(where) != 4:  # three lines: a newline in one of these names is not read
        refuse(found)
    git_dir, toplevel, prefix = where[:3]  # prefix: local_repo from the top of the repository, "" or "sub/"
    listed = [prefix + path for path in paths]
    above = {""} | {path.rsplit("/", i)[0] + "/" for path in listed for i in range(1, path.count("/") + 1)}
    with tempfile.TemporaryDirectory() as tree:
        for directory in above:
            name = directory + ".gitignore"
            asked_of_pod = name[len(prefix) :] if name.startswith(prefix) else None
            if asked_of_pod in coming:
                rules = coming[asked_of_pod]
            else:  # a link is not read, as git itself does not for a .gitignore
                there = os.path.join(toplevel, name)
                rules = Path(there).read_bytes() if os.path.isfile(there) and not os.path.islink(there) else None
            if rules is not None:
                os.makedirs(os.path.join(tree, directory), exist_ok=True)
                Path(tree, name).write_bytes(rules)
        asked = git(
            f"--git-dir={git_dir}",
            f"--work-tree={tree}",
            "check-ignore",
            "--stdin",
            "-z",
            cwd=tree,
            input=b"".join(os.fsencode(path) + b"\0" for path in listed),
        )
    if asked.returncode == 1:  # git's way to say: none of them
        return []
    if asked.returncode != 0:
        refuse(asked)
    ignored = {os.fsdecode(path) for path in asked.stdout.split(b"\0") if path}
    return [path for path in paths if prefix + path in ignored]


def _locally_unwatched(local_repo, paths):
    """Those of `paths` that git was told not to look at in the local repo, in their order.

    `git update-index --skip-worktree` (a sparse checkout sets it too) and `--assume-unchanged` are flags on a
    tracked file, kept in the index: from then on `git status` and `git diff` say nothing of what happens to
    it. It is not ignored — `git check-ignore` has nothing to say of a tracked file — so this is asked apart,
    of `git ls-files -v`: a tag `S` is skip-worktree, a tag in lower case is assume-unchanged (`s` is both).
    Such a file is one where you keep a change of your own out of sight; a pod that lists it would replace
    that change, and what it wrote would not be shown either. So it is refused.

    The whole index is listed and compared here (NUL-ended, so a name may hold anything): no path a pod sent
    becomes an argument. A pod cannot set these flags — they are in .git — so this is asked once, before the
    question. As for _locally_ignored: if git cannot be asked, nothing is fetched.
    """
    if not paths:
        return []
    try:
        asked = subprocess.run(["git", "-C", str(local_repo), "ls-files", "-v", "-z"], capture_output=True)
    except OSError as exc:
        raise MikException(f"could not run git to ask what {local_repo} tracks: {exc}. Nothing was fetched.") from exc
    if asked.returncode != 0:
        raise MikException(
            f"could not ask git what {local_repo} tracks (rc={asked.returncode}), is it a git repository? "
            f"Nothing was fetched.\n{_printable_lines(asked.stderr)}"
        )
    unwatched = set()
    for record in asked.stdout.split(b"\0"):
        tag, _, path = os.fsdecode(record).partition(" ")
        if path and (tag == "S" or tag.islower()):
            unwatched.add(path)
    return [path for path in paths if path in unwatched]


def _locally_attributed(local_repo, paths):
    """Those of `paths` git has attributes for in the local repo, as [(path, [attribute names])], in their order.

    An attribute changes what `git diff` shows of a file, and what mik checks of a file a pod sent
    (_refuse_text_git_would_not_show_as_it_is) is made for git's plain rule only: a NUL in the first bytes
    and git shows nothing, else it shows the bytes. With `working-tree-encoding=UTF-16LE` a file that is
    full of NULs here — binary, to that check, and not looked into — is converted, and shown as a text with
    all that is in it. `diff` shows a binary file as text, a `filter` or a diff driver shows what a
    program made of it, `text` and `eol` leave a change of line ends out. Which attribute does what, and for
    which value, is not sorted out here: a path that has any is refused, and what is then needed is done by
    hand, or sorted out the day it is needed.

    Asked of git (`git check-attr -a`), which knows every place they come from: the .gitattributes of each
    directory, .git/info/attributes, your own attributes file and the system's. The paths go through stdin,
    NUL-ended: none is an argument. A pod cannot send a .gitattributes (validate_path refuses the name), so
    this is asked once, before the question. As for _locally_ignored: if git cannot be asked, nothing is
    fetched.
    """
    if not paths:
        return []
    try:
        asked = subprocess.run(
            ["git", "-C", str(local_repo), "check-attr", "--stdin", "-z", "-a"],
            capture_output=True,
            input=b"".join(os.fsencode(path) + b"\0" for path in paths),
        )
    except OSError as exc:
        raise MikException(
            f"could not run git to ask what attributes {local_repo} has: {exc}. Nothing was fetched."
        ) from exc
    answer = asked.stdout.split(b"\0")  # path, attribute, value, and again: three fields for each one that is set
    if asked.returncode != 0 or len(answer) % 3 != 1 or answer[-1]:
        raise MikException(
            f"could not ask git what attributes {local_repo} has (rc={asked.returncode}), is it a git repository? "
            f"Nothing was fetched.\n{_printable_lines(asked.stderr)}"
        )
    found = {}
    for i in range(0, len(answer) - 1, 3):
        found.setdefault(os.fsdecode(answer[i]), []).append(_printable(os.fsdecode(answer[i + 1])))
    return [(path, found[path]) for path in paths if path in found]


def _checked_remote_contents(payload, files):
    """What a pod sent for the confirmed `files`, as ({path: bytes}, [deleted paths]) — or refused as a whole.

    The answer has to be exactly what was confirmed: the same paths, each one the way it was shown (content
    for a modified or new file, a deletion for a deleted one), nothing more and nothing missing. Every content
    is decoded here, so that an answer that is wrong somewhere is refused before the first file is written,
    not found out halfway through.
    """
    contents, deleted, errors = None, None, None
    if isinstance(payload, dict):
        contents, deleted, errors = payload.get("files", {}), payload.get("deleted", []), payload.get("errors") or []
    shaped = isinstance(contents, dict) and isinstance(deleted, list) and isinstance(errors, list)
    if not shaped or not all(isinstance(fpath, str) for fpath in deleted):
        raise MikException("Bad fetch response")
    for err in errors:
        print(f"{Color.DIM.value}  warning: {_printable(err)}{Color.WHITE.value}")
    approved = {f["path"]: f["status"] for f in files}
    problems, decoded = [], {}
    for fpath, content in contents.items():
        if fpath not in approved:
            problems.append(f"unexpected path: {fpath}")
        elif approved[fpath] == "D":
            problems.append(f"was confirmed as deleted but got content: {fpath}")
        else:
            try:
                decoded[fpath] = base64.b64decode(content, validate=True)
            except (TypeError, ValueError):  # not a string, or not base64
                problems.append(f"content is not base64: {fpath}")
    for fpath in deleted:
        if fpath not in approved:
            problems.append(f"unexpected path: {fpath}")
        elif approved[fpath] != "D":
            problems.append(f"was confirmed as {approved[fpath]} but got deletion: {fpath}")
    received = set(contents) | set(deleted)
    for fpath, status in approved.items():
        if fpath not in received:
            problems.append(f"missing from response: {fpath} (was {status})")
    if problems:
        for p in problems:  # a path that was not confirmed was not checked either: it is not printed as it came
            print(f"{Color.RED.value}  {_printable(p)}{Color.WHITE.value}")
        raise MikException(f"{len(problems)} mismatch(es) with confirmed list, aborting")
    return decoded, deleted


# What a text file that comes from a pod may hold, as (first, last) code points, both included — beside the
# tab, the newline, and a carriage return that is right before a newline. An allowlist, and a short one: what
# is not in it is refused, and a config adds what its projects write in (the config may set another:
# POD_TEXT_RANGES = (*POD_TEXT_RANGES, (0x1F300, 0x1FAFF)) for emoji, say). Left out on purpose:
#   - every control character (ESC, backspace, a lone carriage return, DEL, the C1 ones): a terminal obeys
#     them, and `git diff` sends a file as it is — see _refuse_text_git_would_not_show_as_it_is;
#   - what cannot be seen, or changes the order of what is: the no-break and other spaces (U+00A0, U+2000…),
#     the soft hyphen (U+00AD), zero-width and direction marks (U+200B…U+200F, U+202A…U+202E, U+2066…U+2069),
#     variation selectors, the byte order mark, combining marks;
#   - every other alphabet: the Cyrillic letter U+0430 in a name is not the Latin "a" it looks like.
POD_TEXT_RANGES = (
    (0x20, 0x7E),  # ASCII, what is printed of it
    (0xA1, 0xAC),  # Latin-1 (é ç « » × °), from after the no-break space...
    (0xAE, 0xFF),  # ...and without the soft hyphen
    (0x100, 0x17F),  # Latin Extended-A (œ Œ)
    (0x2010, 0x2027),  # hyphens and dashes, curly quotes, daggers, bullets, the ellipsis
    (0x2190, 0x2426),  # arrows, mathematical operators, technical signs, pictures of the controls
    (0x2440, 0x244A),  # OCR
    (0x2460, 0x27BF),  # enclosed numbers, box drawing, blocks, shapes, symbols, dingbats
)

# How many of the characters refused in one file are said, each with its line: enough to add them in one go.
POD_TEXT_REFUSED_SAID = 20

# git calls a file binary when there is a NUL in its first 8000 bytes (buffer_is_binary), and only there: a NUL
# further down leaves it a text, shown by `git diff` like any other.
GIT_BINARY_FIRST_BYTES = 8000


def _is_binary_to_git(content):
    """True if git would call `content` binary — `git diff` then says that it differs, and shows none of it."""
    return b"\0" in content[:GIT_BINARY_FIRST_BYTES]


def _refuse_text_git_would_not_show_as_it_is(contents):
    """Refuse what a pod sent, as a whole, if a text file in it holds a character out of POD_TEXT_RANGES.

    What comes from a pod is reviewed with `git diff`, and `git diff` writes a file to the terminal as it is: a
    terminal does not show a control character, it obeys it. A line can hide its own end (`ESC[8m`, or black
    on black), write over itself (backspaces, a carriage return), or be shown in another order (a direction
    mark), and the pager git uses lets some of that through. The line that is run is then not the line that
    was read. Nothing of that is to be looked for at review time: it is refused here, before the first write.

    Only what git shows is checked, so the test for "binary" is git's own (_is_binary_to_git): of a binary
    file `git diff` shows nothing, there is nothing to hide in it, and an image is accepted as it comes. A
    text has to be UTF-8, with nothing but the tab, the newline, a carriage return right before a newline
    (line ends from Windows), and what POD_TEXT_RANGES lists. The whole file is looked at, not what changed
    in it: one that already holds such a character here is refused too, and is to be copied by hand.

    All of this is said of a terminal that reads UTF-8, and mik expects yours to: git sends bytes, and it is
    the terminal that makes characters of them. One that is set to an 8-bit charset reads others in the same
    bytes: U+00DB is in the ranges, it is C3 9B in UTF-8, and 9B alone is a control there (CSI, as ESC [ is).
    Only ASCII says the same to every terminal; POD_TEXT_RANGES can be cut down to it.
    """
    ranges = POD_TEXT_RANGES
    well_made = isinstance(ranges, (list, tuple)) and all(
        isinstance(r, (list, tuple))
        and len(r) == 2
        and all(type(code_point) is int for code_point in r)
        and 0 <= r[0] <= r[1] <= sys.maxunicode
        for r in ranges
    )
    if not well_made:
        raise MikException(
            "POD_TEXT_RANGES, in the config, has to be (first, last) pairs of code points. Nothing was written."
        )
    listed = "".join(f"{re.escape(chr(first))}-{re.escape(chr(last))}" for first, last in ranges)
    not_allowed = re.compile(f"[^\t\n{listed}]")
    refused = []
    for path, content in contents.items():
        if _is_binary_to_git(content):
            continue
        try:
            text = content.decode("utf-8").replace("\r\n", "\n")
        except UnicodeDecodeError as exc:
            refused.append(f"{path}, line {content.count(b'\n', 0, exc.start) + 1}: not UTF-8")
            continue
        # Each character that is refused is said once, where it is first found: what a file needs added to
        # POD_TEXT_RANGES is then known from one refusal, not found out one fetch after the other.
        first_found = sorted((text.index(char), char) for char in set(not_allowed.findall(text)))
        for at, char in first_found[:POD_TEXT_REFUSED_SAID]:
            name = "a control character" if unicodedata.category(char) == "Cc" else unicodedata.name(char, "no name")
            refused.append(f"{path}, line {text.count('\n', 0, at) + 1}: U+{ord(char):04X} ({name})")
        if len(first_found) > POD_TEXT_REFUSED_SAID:
            refused.append(f"{path}: and {len(first_found) - POD_TEXT_REFUSED_SAID} more")
    if refused:
        raise MikException(
            "Refusing what the pod sent: git would show these as text, and they hold what `git diff` would not "
            "show as it is (a control character is obeyed by the terminal, a letter of another alphabet "
            "passes for one of ours):\n  "
            + "\n  ".join(refused)
            + "\nNothing was written. (POD_TEXT_RANGES, in the config, if such a character is expected.)"
        )


def _is_text_here(dest):
    """True if `dest` is a file of the local repo that git shows as text (one that cannot be read is not said to be)."""
    try:
        with open(dest, "rb") as there:
            return not _is_binary_to_git(there.read(GIT_BINARY_FIRST_BYTES))
    except OSError:  # not there yet, or not ours to read: nothing to compare with
        return False


def _printable_lines(raw):
    """stderr of a command that ran on a remote or in a pod, made safe to print: its lines kept, each through
    _printable."""
    return "\n".join(_printable(line) for line in raw.decode(errors="replace").splitlines())


# The most a pod gets to answer, in bytes, on stdout as on stderr (the config may set another). What comes is
# held in memory, and files come in base64 twice over: 512 MiB of answer is some 288 MiB of files.
POD_OUTPUT_MAX_BYTES = 512 * 1024 * 1024


def _pop_capped(cmda, limit):
    """pop(), for a command whose output a pod writes: (returncode, stderr, stdout), each of `limit` bytes at most.

    Once more than that came on either, the command is killed and the answer refused: a pod does not get to
    fill the memory of this machine. stderr is read in a thread of its own — a command that fills one pipe
    while only the other is read never ends.
    """
    out, err, over = [], [], []

    def drain(pipe, chunks):
        held = 0
        while chunk := pipe.read1(1 << 16):
            held += len(chunk)
            if held > limit:
                over.append(held)
                proc.kill()
                return
            chunks.append(chunk)

    with subprocess.Popen(cmda, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as proc:
        side = Thread(target=drain, args=(proc.stderr, err), daemon=True)
        side.start()
        drain(proc.stdout, out)
        side.join()
    if over:
        raise MikException(
            f"the pod answered with more than {limit} bytes: refused, and nothing was fetched. "
            f"(POD_OUTPUT_MAX_BYTES, in the config, if that much is expected.)"
        )
    return proc.returncode, b"".join(err), b"".join(out)


def _run_remote_script(ssh_host, container, script):
    encoded = base64.b64encode(script.encode()).decode()
    return _pop_capped(
        ["ssh", ssh_host, f"docker exec {container} python3 -c \"import base64 as b;exec(b.b64decode('{encoded}'))\""],
        POD_OUTPUT_MAX_BYTES,
    )


def dev_fetch_pod(args):
    inst = instances_dict.get(args.instance)
    if not inst:
        raise MikException("Instance not found")
    machine = machines_dict.get(getattr(inst, "machine", None))
    if not machine or not machine.ssh_host:
        raise MikException("Instance has no machine with an ssh_host")
    project = projects_dict.get(getattr(inst, "project", None))
    if not project or not project.local_repo:
        raise MikException("Instance's project has no local_repo")
    container = inst.container
    code_dir = inst.code_dir
    if not container or not code_dir:
        raise MikException("Instance has no container/code_dir")
    local_repo = project.local_repo
    ssh_host = machine.ssh_host
    for part in ssh_host.split("@"):
        validate_name(part)
    validate_name(container)
    validate_code_dir(code_dir)
    # Pass 1: list changed files
    script = REMOTE_SCRIPT_LIST.format(
        validate_path=_REMOTE_VALIDATE_PATH,
        code_dir=code_dir,
    )
    c, e, r = _run_remote_script(ssh_host, container, script)
    if c != 0:
        raise MikException(f"SSH failed: {_printable_lines(e)}")
    try:
        data = json.loads(r.decode())
    except ValueError:  # not JSON, or not UTF-8
        data = None
    warnings = data.get("errors") or [] if isinstance(data, dict) else None
    if not isinstance(warnings, list):
        raise MikException(f"Bad response from remote: {r[:200]}")
    for err in warnings:
        print(f"{Color.DIM.value}  warning: {_printable(err)}{Color.WHITE.value}")
    files = _checked_remote_files(data.get("files", []))
    if not files:
        print("No changes found.")
        return
    dests = _local_destinations(local_repo, files)  # no symlink on the way, checked before the question is asked
    ignored = _locally_ignored(local_repo, [f["path"] for f in files])
    if ignored:
        raise MikException(
            f"Refusing the remote file list: the local repo ignores {', '.join(ignored)}. `git status` and "
            f"`git diff` would not show what was done to them, and a pod has no reason to list what is "
            f"ignored. Nothing was fetched."
        )
    unwatched = _locally_unwatched(local_repo, [f["path"] for f in files])
    if unwatched:
        raise MikException(
            f"Refusing the remote file list: git was told not to look at {', '.join(unwatched)} in the local "
            f"repo (git update-index --skip-worktree or --assume-unchanged). `git status` and `git diff` would "
            f"not show what was done to them, and what you keep there would be replaced. Nothing was fetched."
        )
    attributed = _locally_attributed(local_repo, [f["path"] for f in files])
    if attributed:
        raise MikException(
            f"Refusing the remote file list: git has attributes for "
            f"{', '.join(f'{path} ({", ".join(names)})' for path, names in attributed)} in the local repo (from a "
            f".gitattributes, .git/info/attributes or your own attributes file). An attribute changes what "
            f"`git diff` shows of a file, and mik only knows how to check what git shows without one. Nothing "
            f"was fetched."
        )
    # Display
    for f in files:
        color = Color.RED.value if f["status"] == "D" else Color.GREEN.value
        label = {"M": "modified", "A": "new", "D": "deleted"}.get(f["status"], f["status"])
        shown = f"{Color.RED.value}{f['path']}{Color.WHITE.value}" if _is_dot_path(f["path"]) else f["path"]
        print(f"  {color}{label:>10}{Color.WHITE.value}  {shown}")
    print(f"\n  {len(files)} file(s)")
    dotted = sum(_is_dot_path(f["path"]) for f in files)
    if dotted:
        print(
            f"  {Color.RED.value}{dotted} under a name that starts with a dot (in red){Color.WHITE.value}: tools "
            f"read those without being asked, and may run what is in them"
        )
    answer = input("\nApply these changes? [y/N] ")
    if answer.strip().lower() != "y":
        print("Aborted.")
        return
    # Pass 2: fetch contents
    file_list_json = json.dumps(files)
    script = REMOTE_SCRIPT_FETCH.format(code_dir=code_dir, file_list=file_list_json)
    c, e, r = _run_remote_script(ssh_host, container, script)
    if c != 0:
        raise MikException(f"SSH fetch failed: {_printable_lines(e)}")
    try:
        payload = json.loads(base64.b64decode(r.strip()))
    except Exception:
        raise MikException("Bad fetch response")
    # Preemptive check — reject entire response if it is not exactly the confirmed list, contents decoded
    contents, deleted_paths = _checked_remote_contents(payload, files)
    # And nothing in a text that `git diff` would not show as it is (a binary file is shown as such, and passes)
    _refuse_text_git_would_not_show_as_it_is(contents)
    # Asked again before the first write, now that the contents are here: the .gitignore files that came are
    # part of the rules, and one of them may hide a file that came with it. Judged as the repo would be.
    hidden = _locally_ignored(local_repo, [f["path"] for f in files], {**contents, **dict.fromkeys(deleted_paths)})
    if hidden:
        raise MikException(
            f"Refusing what the pod sent: with the .gitignore that comes with it, the local repo would ignore "
            f"{', '.join(hidden)}, and `git status` would not show them. Nothing was written."
        )
    # A file that is a text here and comes as a binary one is written like any other (a file that got its real
    # content at last, an image), but said: from then on `git diff` shows nothing of what is in it. Looked at
    # now, while what is here is still here.
    became_binary = [p for p, content in contents.items() if _is_binary_to_git(content) and _is_text_here(dests[p])]
    # Apply
    written = 0
    deleted = 0
    for fpath, content in contents.items():
        dest = dests[fpath]
        dest.parent.mkdir(parents=True, exist_ok=True)
        # Atomic write: same-dir temp + replace, so a failure mid-fetch can't leave a truncated file.
        fd, tmp_path = tempfile.mkstemp(dir=dest.parent, prefix=f".{dest.name}.", suffix=".tmp")
        try:
            try:
                os.write(fd, content)
            finally:
                os.close(fd)
            if dest.exists():
                os.chmod(tmp_path, dest.stat().st_mode & 0o7777)  # keep the tracked file's mode (e.g. exec bit)
            else:
                umask = os.umask(0)
                os.umask(umask)
                os.chmod(tmp_path, 0o666 & ~umask)  # mkstemp gives 0600; a new file should match a plain open()
            os.replace(tmp_path, dest)
        except BaseException:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise
        print(f"  {Color.GREEN.value}wrote{Color.WHITE.value}  {fpath}")
        written += 1
    for fpath in deleted_paths:
        dest = dests[fpath]
        if dest.exists():
            dest.unlink()
            print(f"  {Color.RED.value}deleted{Color.WHITE.value}  {fpath}")
            deleted += 1
        else:
            print(f"{Color.DIM.value}  already absent: {fpath}{Color.WHITE.value}")
    print(f"\nDone: {written} written, {deleted} deleted.")
    for fpath in became_binary:
        print(
            f"  {Color.RED.value}was a text here, came as a binary file{Color.WHITE.value}: {fpath} "
            f"(`git diff` will not show what is in it)"
        )


GITHUB_API = "https://api.github.com"
# Optional certificate pinning (paranoid mode). Set any of these in your config to pin the sha256 of that
# host's DER *leaf* cert; ROOT_CA_FILE optionally points at the CA bundle used to verify. Left None, mik
# behaves exactly as before (urllib's default SSL context, no pinning).
# A pin is a SHA256 hex digest (a str), or several of them (a list: any is accepted, as the old and the new
# certificate overlap during a rotation). NOTE: a leaf pin breaks the moment the host rotates its cert (GitHub /
# Let's Encrypt do, regularly) — a previously green deploy then fails with "cert pin/verify failed" until it
# is refreshed. The config is Python, so it can ask a command for the current ones instead of hardcoding
# them, e.g. tls-pin-get from https://github.com/c4ffein/crypto (an argv with a full path: no shell, no ~):
#   GITHUB_COM_CERT_SHA256 = run_step(["/home/me/.local/bin/tls-pin-get", "api.github.com"]).decode().split()
ROOT_CA_FILE = None
GITHUB_COM_CERT_SHA256 = None  # api.github.com (used by ci-status)
GITHUB_IO_CERT_SHA256 = None  # *.github.io, e.g. c4ffein.github.io release archives (used by config builds)
HEX_CHARS = frozenset("0123456789abcdef")
PIN_MAX_COUNT = 16  # the old and the new certificate overlap during a rotation: a few, never many

# Pipeline rollup states (good < pending/no_checks are informational < failure/fetch_error are red)
CI_GOOD = "good"
CI_FAILURE = "failure"
CI_PENDING = "pending"
CI_NO_CHECKS = "no_checks"
CI_FETCH_ERROR = "fetch_error"

# Ordered for the grouped ALL view: goods first, then reds, then the muted informational buckets last.
_CI_SECTIONS = [
    (CI_GOOD, "GOOD"),
    (CI_FAILURE, "PIPELINE FAILURES"),
    (CI_FETCH_ERROR, "FETCH FAILURES"),
    (CI_PENDING, "PENDING"),
    (CI_NO_CHECKS, "NO CHECKS"),
]
_CI_GLYPH = {
    CI_GOOD: (Color.GREEN, "✓"),
    CI_FAILURE: (Color.RED, "✗"),
    CI_FETCH_ERROR: (Color.RED, "⚠"),
    CI_PENDING: (Color.PURP, "•"),
    CI_NO_CHECKS: (Color.DIM, "•"),
}
# A red exit code is warranted for actionable problems; pending/no-checks are transient/informational.
_CI_RED_STATES = (CI_FAILURE, CI_FETCH_ERROR)


def make_pinned_ssl_context(pinned_sha_256, cafile=None, capath=None, cadata=None):
    """
    Returns an instance of a subclass of SSLContext that uses a subclass of SSLSocket
    that actually verifies the sha256 of the certificate during the TLS handshake
    pinned_sha_256 is a hex digest, or several of them: any is accepted (certificates overlap during a rotation)
    Tested with `python-version: [3.11, 3.12, 3.13, 3.14]`
    Original code can be found at https://github.com/c4ffein/python-snippets
    """

    pinned = frozenset((pinned_sha_256,) if isinstance(pinned_sha_256, str) else pinned_sha_256)

    class PinnedSSLSocket(SSLSocket):
        def check_pinned_cert(self):
            der_cert_bin = self.getpeercert(True)
            if sha256(der_cert_bin).hexdigest() not in pinned:
                raise SSLCertVerificationError("Incorrect certificate checksum")

        def do_handshake(self, *args, **kwargs):
            r = super().do_handshake(*args, **kwargs)
            self.check_pinned_cert()
            return r

    class PinnedSSLContext(SSLContext):
        sslsocket_class = PinnedSSLSocket

    def create_pinned_default_context(purpose=Purpose.SERVER_AUTH):
        if not isinstance(purpose, _ASN1Object):
            raise TypeError(purpose)
        if purpose == Purpose.SERVER_AUTH:  # Verify certs and host name in client mode
            context = PinnedSSLContext(PROTOCOL_TLS_CLIENT)
            context.verify_mode, context.check_hostname = CERT_REQUIRED, True
        elif purpose == Purpose.CLIENT_AUTH:
            context = PinnedSSLContext(PROTOCOL_TLS_SERVER)
        else:
            raise ValueError(purpose)
        context.verify_flags |= _ssl.VERIFY_X509_STRICT
        if cafile or capath or cadata:
            context.load_verify_locations(cafile, capath, cadata)
        elif context.verify_mode != CERT_NONE:
            context.load_default_certs(purpose)  # Try loading default system root CA certificates, may fail silently
        if hasattr(context, "keylog_filename"):  # OpenSSL 1.1.1 keylog file
            keylogfile = os.environ.get("SSLKEYLOGFILE")
            if keylogfile and not sys_flags.ignore_environment:
                context.keylog_filename = keylogfile
        return context

    return create_pinned_default_context()


def configured_pins(value, label="Certificate pin"):
    """
    The SHA256 pins that a configured pin accepts, as a tuple, for make_pinned_ssl_context.
    value is a hex digest, or a list of them. Anything else (no pin, something that is not a SHA256) is an
    error: no connection is made.
    """
    pins = (value,) if isinstance(value, str) else value
    if not isinstance(pins, (list, tuple)) or not all(isinstance(pin, str) for pin in pins):
        raise MikException(f"{label} must be a SHA256 or a list of them, got {type(value).__name__}")
    if not pins:
        raise MikException(f"{label} has no pin")
    if len(pins) > PIN_MAX_COUNT:
        raise MikException(f"{label} has more than {PIN_MAX_COUNT} pins")
    pins = tuple(pin.lower() for pin in pins)
    if any(len(pin) != 64 or any(c not in HEX_CHARS for c in pin) for pin in pins):
        raise MikException(f"{label} has something that is not a SHA256 (64 hex chars)")
    return pins


def pinned_urlopen(url, pinned_sha256=None, cafile=None, timeout=10):
    """Config helper: urlopen() with optional sha256 leaf-cert pinning and a custom CA bundle.

    Returns the response object (use as a context manager). `pinned_sha256` is a hex digest or a list of
    them (see configured_pins). `cafile` defaults to ROOT_CA_FILE. With no pin (None) it's a plain
    urlopen. Config build steps use it to fetch release archives (e.g. github.io) over https.

    https:// only, pin or not: over http:// or file:// there is no certificate, and a pin would be given
    for nothing without a word. (A redirect is followed as urlopen does: where the server that was verified
    sends you is that server's to say.)
    """
    target = url.full_url if isinstance(url, Request) else url
    if not (isinstance(target, str) and target.lower().startswith("https://")):
        raise MikException(f"pinned_urlopen fetches https:// URLs only, got {target!r}")
    context = None
    if pinned_sha256 is not None:
        context = make_pinned_ssl_context(configured_pins(pinned_sha256), cafile=cafile or ROOT_CA_FILE)
    return urlopen(url, timeout=timeout, context=context)


def _github_get_json(path):
    """Unauthenticated GET against the public GitHub REST API; returns parsed JSON.

    Raises MikException on any transport/HTTP error so callers can bucket the failure. A User-Agent is
    required by GitHub or it answers 403. If GITHUB_COM_CERT_SHA256 is set (in config), api.github.com's
    certificate is pinned (a bad pin is a MikException as well); ROOT_CA_FILE
    optionally supplies the CA bundle.
    """
    req = Request(
        f"{GITHUB_API}{path}",
        headers={"Accept": "application/vnd.github+json", "User-Agent": "mik"},
    )
    context = None
    if GITHUB_COM_CERT_SHA256 is not None:
        pins = configured_pins(GITHUB_COM_CERT_SHA256, "GITHUB_COM_CERT_SHA256")
        context = make_pinned_ssl_context(pins, cafile=ROOT_CA_FILE)
    try:
        with urlopen(req, timeout=10, context=context) as resp:
            return json.loads(resp.read().decode())
    except HTTPError as exc:
        raise MikException(f"{exc.code} {exc.reason}") from exc
    except URLError as exc:
        if isinstance(exc.reason, SSLCertVerificationError):
            raise MikException(f"cert pin/verify failed: {exc.reason}") from exc
        raise MikException(f"network error: {exc.reason}") from exc


def _split_github_repo(github_repo):
    """Split and validate an 'owner/repo' string, rejecting anything that isn't two clean path parts."""
    parts = github_repo.split("/")
    if len(parts) != 2 or not all(parts):
        raise MikException(f"Bad github_repo (want 'owner/repo'): {github_repo!r}")
    allowed = set(string.ascii_letters + string.digits + "-_.")
    for part in parts:
        # reject "."/".." too — they're valid char-wise but would be path traversal in the API URL
        if part in (".", "..") or not set(part) <= allowed:
            raise MikException(f"Bad github_repo component: {part!r}")
    return parts[0], parts[1]


def _is_plain_branch(branch):
    """True for a branch name that can go into the API URL as it is: plain names ([A-Za-z0-9-._]) between "/".

    The name is what the API answered, and whoever owns the repo chose it. git allows far more in one ("#",
    "%", any Unicode letter); none of that is quoted or guessed at here — such a branch is not checked.
    """
    return isinstance(branch, str) and all(_is_plain_name(part) for part in branch.split("/"))


def _rollup_check_runs(check_runs):
    """Aggregate a commit's check-runs into a single state, mirroring GitHub's green-check/red-cross."""
    if not check_runs:
        return CI_NO_CHECKS
    if any(c.get("status") != "completed" for c in check_runs):
        return CI_PENDING
    red = {"failure", "timed_out", "cancelled", "action_required"}
    if any(c.get("conclusion") in red for c in check_runs):
        return CI_FAILURE
    return CI_GOOD


def _fetch_ci_status(name, github_repo):
    """Resolve one project's default-branch pipeline state. Never raises — failures become CI_FETCH_ERROR."""
    try:
        owner, repo = _split_github_repo(github_repo)
        info = _github_get_json(f"/repos/{owner}/{repo}")
        branch = info.get("default_branch")
        if not branch:
            return {"name": name, "branch": None, "state": CI_FETCH_ERROR, "detail": "no default branch"}
        if not _is_plain_branch(branch):
            detail = f"unsupported default branch name: {branch!r}"
            return {"name": name, "branch": None, "state": CI_FETCH_ERROR, "detail": detail}
        data = _github_get_json(f"/repos/{owner}/{repo}/commits/{branch}/check-runs")
        return {"name": name, "branch": branch, "state": _rollup_check_runs(data.get("check_runs", [])), "detail": ""}
    except MikException as exc:
        return {"name": name, "branch": None, "state": CI_FETCH_ERROR, "detail": str(exc)}


def _fetch_all_ci(items):
    """Fan out _fetch_ci_status over (name, github_repo) pairs; order is preserved by ThreadPoolExecutor.map."""
    with ThreadPoolExecutor(max_workers=min(8, len(items))) as ex:
        return list(ex.map(lambda it: _fetch_ci_status(it[0], it[1]), items))


def _print_ci_line(result):
    color, glyph = _CI_GLYPH.get(result.get("state"), (Color.WHITE, "?"))
    branch = "".join(c for c in str(result.get("branch", None) or "") if c.isprintable())
    detail_text = "".join(c for c in str(result.get("detail", None) or "") if c.isprintable())
    detail = f"  {Color.DIM.value}{detail_text}{Color.WHITE.value}" if detail_text else ""
    name = result["name"].ljust(20)
    print(f"  {color.value}{glyph}{Color.WHITE.value} {name} {Color.DIM.value}{branch}{Color.WHITE.value}{detail}")


def _print_ci_grouped(results):
    by_state = {}
    for r in results:
        by_state.setdefault(r["state"], []).append(r)
    first = True
    for state, title in _CI_SECTIONS:
        group = sorted(by_state.get(state, []), key=lambda r: r["name"])
        if not group:
            continue
        if not first:
            print()
        first = False
        print(f"{title}\n{'─' * len(title)}")
        for r in group:
            _print_ci_line(r)


def ci_status(args):
    """Report default-branch pipeline state for one project, or for every project with a github_repo (ALL).

    Returns 1 if any reported project is a pipeline failure or couldn't be fetched, else 0 — so
    `mik ci-status ALL` doubles as a scriptable "is everything green?" gate.
    """
    projects = get_projects()
    target = args.project
    if target == "ALL":  # reserved keyword, case-sensitive — a project literally named "all" still works
        items = [(n, p.github_repo) for n, p in projects.items() if getattr(p, "github_repo", None)]
        if not items:
            print("No projects with a github_repo.")
            return
        results = _fetch_all_ci(items)
        _print_ci_grouped(results)
        return 1 if any(r["state"] in _CI_RED_STATES for r in results) else 0
    project = projects.get(target)
    if not project:
        raise MikException("Project not found")
    if not getattr(project, "github_repo", None):
        raise MikException("Project has no github_repo")
    result = _fetch_ci_status(target, project.github_repo)
    _print_ci_line(result)
    return 1 if result["state"] in _CI_RED_STATES else 0


# The names of mik's own that a config is meant to give a value to. Any other one it binds again is refused
# (see load_config).
CONFIG_SETTINGS = frozenset(
    {
        "ROOT_CA_FILE",
        "GITHUB_COM_CERT_SHA256",
        "GITHUB_IO_CERT_SHA256",
        "ARTIFACTS_DIR",
        "RUNS_DIR",
        "POD_OUTPUT_MAX_BYTES",
        "POD_TEXT_RANGES",
    }
)


def _refuse_config_others_can_write(f):
    """Refuse a config that somebody else could have written: it is run as Python, as you.

    As ssh does for ~/.ssh/config: the file is yours (or root's) and nobody else may write it. The same for
    the directory it is in — whoever can write there can put another file under that name — unless it is
    sticky (/tmp: there, a file of yours is renamed by nobody else). The file looked at is the one that is
    open (fstat), not whatever has its name by now.
    """
    ours = (os.geteuid(), 0)
    st = os.fstat(f.fileno())
    if st.st_uid not in ours or st.st_mode & 0o022:
        raise MikException(
            f"{CONFIG_FILE} is run as Python: it has to be yours, and writable by nobody else "
            f"(chmod go-w {CONFIG_FILE})"
        )
    st = os.stat(CONFIG_FILE.parent)
    if st.st_uid not in ours or (st.st_mode & 0o022 and not st.st_mode & stat.S_ISVTX):
        raise MikException(
            f"{CONFIG_FILE} is run as Python: its directory has to be yours, and writable by nobody else "
            f"(chmod go-w {CONFIG_FILE.parent})"
        )


def load_config():
    try:
        with CONFIG_FILE.open("r") as f:
            _refuse_config_others_can_write(f)
            file_content = f.read()
    except MikException:
        raise
    except Exception as exc:
        raise MikException(f"Can't read the config file: {CONFIG_FILE}") from exc
    own = dict(globals())
    try:
        exec(file_content, globals())
    except MikException:  # mik's own refusal (a duplicate name, a failed step...): it says what is wrong
        raise
    except Exception as exc:
        traceback.print_exc()
        raise MikException("Something wrong in the config file") from exc
    # The config runs in this namespace, so a helper it calls `build` or a variable it calls `debug` takes the
    # place of mik's: `mik build` would then run the config's function, without a word. Which names a config
    # binds is only known once it has run, so this is checked right after, before any command gets to run.
    # Importing what mik imports (os, Path, datetime...) binds the same object again and is fine.
    taken = sorted(n for n, v in own.items() if n not in CONFIG_SETTINGS and globals().get(n, own) is not v)
    if taken:
        raise MikException(
            f"The config file defines {', '.join(taken)}: mik has that name already, and the config would "
            f"replace it. Use another name there. (What a config may set: {', '.join(sorted(CONFIG_SETTINGS))}.)"
        )
    debug(f"loaded config from {CONFIG_FILE}")


def main(argv=None):
    def get_key_value_action_with_limited_keys(allowed_keys: list):
        class KeyValueAction(argparse.Action):
            def __call__(self, parser, namespace, values, option_string=None):
                for value in values:
                    key, _, val = value.partition("=")
                    if key not in allowed_keys or not val:  # a bare word, an unknown key, a key with no value
                        expected = " or ".join(f"{k}=NAME" for k in allowed_keys)
                        parser.error(f"expected {expected}, got {value!r}")  # usage + message, exits 2
                    setattr(namespace, key, val)

        return KeyValueAction

    # main
    parser = argparse.ArgumentParser(description="mik")
    parser.add_argument("--debug", action="store_true", help="enable debug output")
    subparsers = parser.add_subparsers(help="sub-command help", dest="command")  # dest needed to identify subcommand
    # sub-command: list (everything)
    subparsers.add_parser("list", help="list everything: instances and projects with their links")
    # sub-command: list-machines
    parser_list_machines = subparsers.add_parser("list-machines", help="list machines")
    parser_list_machines.add_argument("--show-instances", action="store_true", help="show each machine's instances")
    parser_list_machines.add_argument(
        "params",
        nargs="*",
        action=get_key_value_action_with_limited_keys(["project"]),
        help="project=NAME to filter machines running a project",
    )
    # sub-command: list-instances
    parser_list_instances = subparsers.add_parser("list-instances", help="list instances")
    parser_list_instances.add_argument(
        "--show-links", action="store_true", help="show each instance's project and machine"
    )
    parser_list_instances.add_argument(
        "params",
        nargs="*",
        action=get_key_value_action_with_limited_keys(["project", "machine"]),
        help="project=NAME and/or machine=NAME to filter instances",
    )
    # sub-command: list-projects
    parser_list_projects = subparsers.add_parser("list-projects", help="list projects")
    parser_list_projects.add_argument("--show-instances", action="store_true", help="show each project's instances")
    parser_list_projects.add_argument(
        "params",
        nargs="*",
        action=get_key_value_action_with_limited_keys(["machine"]),
        help="machine=NAME to filter projects with an instance on a machine",
    )
    # sub-command: deploy
    parser_deploy = subparsers.add_parser("deploy", help="deploy an instance")
    parser_deploy.add_argument("instance", metavar="INSTANCE")
    parser_deploy.add_argument(
        "release_id",
        metavar="RELEASE_ID",
        nargs="?",
        default=None,
        help="optional: ship/roll back to a specific local artifact (epoch or full name); Python deploys only",
    )
    # sub-command: build
    parser_build = subparsers.add_parser("build", help="build an instance's local artifact")
    parser_build.add_argument("instance", metavar="INSTANCE")
    # sub-command: dev-fetch-pod
    parser_dev_fetch_pod = subparsers.add_parser(
        "dev-fetch-pod", help="Fetch changed files from an instance's container"
    )
    parser_dev_fetch_pod.add_argument("instance", metavar="INSTANCE")
    # sub-command: ci-status
    parser_ci_status = subparsers.add_parser("ci-status", help="Check default-branch pipeline status (or ALL)")
    parser_ci_status.add_argument("project", metavar="PROJECT_OR_ALL")
    # sub-command: help
    parser_autocomplete = subparsers.add_parser("autocomplete", help="autocomplete help")
    parser_autocomplete.add_argument("autocomplete", metavar="INSTANCE_NAME_START")
    # parse
    args = parser.parse_args(argv)
    if args.debug:
        global DEBUG
        DEBUG = True
    if not args.command:
        parser.print_help()
        return
    load_config()
    return {
        "deploy": deploy,
        "build": build,
        "dev-fetch-pod": dev_fetch_pod,
        "ci-status": ci_status,
        "list": list_all,
        "list-machines": list_machines,
        "list-instances": list_instances,
        "list-projects": list_projects,
        "autocomplete": autocomplete,
    }[args.command](args)


def cli():
    """What the `mik` command runs, installed (the entry point in pyproject.toml) or as `python mik.py`.

    main(), with what mik expects to go wrong said in a line rather than a traceback. Returns the exit code.
    """
    try:
        return main()
    except KeyboardInterrupt:
        print("\n  !!  KeyboardInterrupt received  !!  \n", file=sys.stderr)
        return 130  # conventional 128 + SIGINT(2)
    except MikException as exc:  # the one place an error gets its colour, and it goes to stderr
        print(f"{Color.RED.value}\n  !!  {exc}  !!  \n{Color.WHITE.value}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    exit(cli())
