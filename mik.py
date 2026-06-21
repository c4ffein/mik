#!/usr/bin/env python3

import sys
import argparse
import json
from pathlib import Path
import subprocess
import shutil
import tarfile
import string
import base64
import os
import traceback
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from enum import Enum
from time import sleep
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
from typing import Optional
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from uuid import uuid4


# WARNING: this is quick and dirty, please don't judge current code quality


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


machines_dict = {}


class MachineMeta(type):
    def __new__(mcs, name, bases, namespace):
        if name == "Machine":
            return super().__new__(mcs, name, bases, namespace)
        if not namespace.get("name") or not namespace.get("ssh_host"):
            raise MikException(f"Machine {name} needs a name and an ssh_host")
        r = super().__new__(mcs, name, bases, namespace)
        machines_dict[namespace["name"]] = r
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
        instances_dict[namespace["name"]] = r
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
    get_remote_source: Optional[list] = None  # optional legacy script
    get_remote_source_shell: Optional[str] = None


projects_dict = {}


class ProjectMeta(type):
    def __new__(mcs, name, bases, namespace):
        if name == "Project":
            return super().__new__(mcs, name, bases, namespace)
        if not namespace.get("name"):
            raise MikException(f"No name for {name}")
        r = super().__new__(mcs, name, bases, namespace)
        projects_dict[namespace["name"]] = r
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
            raise MikException(f"{Color.RED.value}Project not found: {project_filter}{Color.WHITE.value}")
        names = [n for n in names if n in set(instances_for_project(project_filter))]
    machine_filter = getattr(args, "machine", None)
    if machine_filter:
        if machine_filter not in machines_dict:
            raise MikException(f"{Color.RED.value}Machine not found: {machine_filter}{Color.WHITE.value}")
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
            raise MikException(f"{Color.RED.value}Machine not found: {machine_filter}{Color.WHITE.value}")
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
            raise MikException(f"{Color.RED.value}Project not found: {project_filter}{Color.WHITE.value}")
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


def deploy(args):
    instance_name = args.instance
    inst = instances_dict.get(instance_name)
    if not inst:
        raise MikException(f"{Color.RED.value}Instance not found{Color.WHITE.value}")
    d = getattr(inst, "deploy", None)
    if callable(d):
        # Custom Python deploy (a classmethod on the Instance) — it runs and reports itself.
        # An optional RELEASE_ID forwards through for instances whose deploy ships a chosen artifact.
        release_id = getattr(args, "release_id", None)
        return d(release_id) if release_id is not None else d()
    release_id = getattr(args, "release_id", None)
    if release_id is not None:
        raise MikException(
            f"{Color.RED.value}{instance_name} has a script deploy; RELEASE_ID not supported{Color.WHITE.value}"
        )
    if not d:
        raise MikException(f"{Color.RED.value}Instance has no deploy script{Color.WHITE.value}")
    s = "\n".join(d)
    rc, _ = run_recorded("deploy", instance_name, s, getattr(inst, "deploy_shell", None) or "/bin/bash")
    if rc != 0:
        raise MikException(f"{Color.RED.value}deploy failed (rc={rc}){Color.WHITE.value}")


def build(args):
    """`build INSTANCE`: run an instance's build step, producing a local artifact (no remote side effects)."""
    instance_name = args.instance
    inst = instances_dict.get(instance_name)
    if not inst:
        raise MikException(f"{Color.RED.value}Instance not found{Color.WHITE.value}")
    b = getattr(inst, "build", None)
    if not callable(b):
        raise MikException(f"{Color.RED.value}Instance has no build step{Color.WHITE.value}")
    return b()


def get_remote_source(args):
    instance_name = args.instance
    inst = instances_dict.get(instance_name)
    if not inst:
        raise MikException(f"{Color.RED.value}Instance not found{Color.WHITE.value}")
    d = getattr(inst, "get_remote_source", None)
    if not d:
        raise MikException(f"{Color.RED.value}Instance has no get_remote_source script{Color.WHITE.value}")
    s = "\n".join(d)
    rc, _ = run_recorded(
        "get-remote-source", instance_name, s, getattr(inst, "get_remote_source_shell", None) or "/bin/bash"
    )
    if rc != 0:
        raise MikException(f"{Color.RED.value}get-remote-source failed (rc={rc}){Color.WHITE.value}")


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
        (RUNS_DIR / f"{run_id}.json").write_text(json.dumps(record, indent=2))
        debug(f"recorded run {run_id} (rc={returncode})")
        return run_id
    except Exception as exc:
        debug(f"failed to record run: {exc}")
        return None


def run_recorded(command, target, script, executable):
    """Run a shell script via run_and_capture and persist the result via record_run.

    Returns (returncode, output). Shared by deploy / get-remote-source so both stream live and leave
    an investigable trail under RUNS_DIR.
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
    """Config helper: the directory holding every release of one artifact category."""
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
    if not rid.isdigit():
        raise MikException(f"bad release_id (want epoch digits): {rid!r}")
    if not all(c.isalnum() or c in ".-_" for c in category):
        raise MikException(f"invalid category when building artifact: {category}")
    if not all(c.isalnum() or c in ".-_" for c in suffix):
        raise MikException(f"invalid suffix when building artifact: {suffix}")
    base = artifact_category_dir(category)
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
        if head.isdigit() and all(c.isalnum() or c in "-._" for c in p.name):
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
    overlap `cp -rL` both dereference symlinks — a stray link would copy its target straight into the public
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
    in the error, so config deploys stay locatable without a custom message per step.
    """
    c, e, r = pop(cmda)
    debug(f"step rc={c} cmd={cmda} err={e!r} out={r!r}")
    if c != 0:
        raise MikException(f"step failed (rc={c}): {' '.join(cmda)}\n{e.decode(errors='replace')}")
    if fail_on_stderr and e:
        raise MikException(f"step wrote to stderr: {' '.join(cmda)}\n{e.decode(errors='replace')}")
    return r


_valid_name_ords = (
    *range(ord("A"), ord("Z") + 1),
    *range(ord("a"), ord("z") + 1),
    *range(ord("0"), ord("9") + 1),
    ord("-"),
    ord("."),
)


def validate_name(s):
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

# Exact matches and prefixes that are forbidden in any path component
# .git prefix catches .git/, .gitattributes, .gitmodules, .githooks, etc.
FORBIDDEN_PATH_PARTS = {"node_modules", "__pycache__"}
FORBIDDEN_PATH_PREFIXES = (".git",)
ALLOWED_PATH_PARTS = {".gitignore"}


def validate_path(p):
    if not p or p.startswith("/"):
        return False
    for component in p.split("/"):
        if not component or component == "..":
            return False
        if component in ALLOWED_PATH_PARTS:
            continue
        if component in FORBIDDEN_PATH_PARTS:
            return False
        for prefix in FORBIDDEN_PATH_PREFIXES:
            if component.startswith(prefix):
                return False
        for c in component:
            if ord(c) not in _valid_path_ords:
                return False
    return True


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


def _flip_current(ssh_host, site_root, target):
    """Atomically point {site_root}/current at `target` (a path *relative to site_root*).

    rename(2) is the only atomic replace — symlink(2) refuses to overwrite — so the canonical move is to
    materialise the new link under a temp name, then rename it onto `current`. `ln -sfn` builds (or
    overwrites a crash-leftover of) that temp link in one (non-atomic) step (`-f` force, `-n` so it never
    descends into a leftover symlink-to-a-dir), and `mv -T` does the atomic rename, so a serving nginx never
    sees `current` momentarily absent. The temp name is fixed, so a crash leaves at most one stale link that
    the next flip reclaims — the two flips are sequential, never concurrent, so they can share it.

    No sudo: the web root is owned by the ssh user (see deploy_release). Precondition: caller passes
    already-validated, shell-safe `ssh_host`/`site_root` and a relative `target` composed from them.
    """
    tmp = f"{site_root}/.mik-cur-tmp"
    run_step(["ssh", ssh_host, f"ln -sfn {target} {tmp} && mv -T {tmp} {site_root}/current"])


def deploy_release(src, ssh_host, site_root, release_id, name, keep=5, overlap_seconds=30):
    """Atomic zero-downtime deploy of an already-built artifact. No rsync, no shell pipes, no sudo.

    Config helper — the *deploy* half of build/deploy. `src` is a finished artifact directory (typically
    from latest_release()/resolve_release()); choosing, excluding and transforming files is the *build*
    step's job (see build_artifact), so this ships src as-is. It scp's src into {site_root}/releases/{id},
    makes it world-readable, then flips the `current` symlink the web server serves through — picked up on
    the next request, no reload. Fresh dir per release => no stale files; the artifact we serve long-term
    is always one pristine release.

    Runs entirely as the ssh user — *no sudo*. The web root must be owned/writable by that user (a one-time
    `chown -R <user> {site_root}`); a preflight check fails fast with that instruction if it isn't. A
    containerized web server serving from a bind mount reads files by their world-readable ("other") bits
    regardless of host ownership, which is why each release is `chmod -R a+rX`'d before it's served.

    When overlap_seconds > 0, `current` is first flipped for that many seconds to a *transient union* of
    the previous release and the new one (new winning on shared names like index.html), then flipped to
    the clean new release. This covers the race where a browser fetched the old index.html moments before
    the deploy and then requests an old hashed bundle the clean release no longer has: during the window
    both old and new hashed assets are served while index.html is already the new one. The union is never
    served long-term — so every served-forever release is still a single, individually-built artifact.

    What the overlap actually covers (i.e. when this helper is sufficient on its own). A 404 only happens
    when a browser holds an OLD index.html and then requests an OLD bundle the now-current release dropped.
    Two cases, given index.html is served `Cache-Control: no-cache` (else the browser reuses a hard-cached
    old index and nothing server-side can help):
      - Eager bundles (no code-splitting — the common static-site case): the only exposure is a tab caught
        *mid-initial-load* when the flip lands, a seconds-wide race (a frozen, fully-loaded tab already has
        its bundles and is safe). overlap_seconds=30 comfortably contains that race => SUFFICIENT, this is
        effectively zero-downtime on its own.
      - Lazy / code-split chunks (`import()` on navigation, React.lazy): a tab can sit open for hours, then
        request an old chunk for the first time. The window is unbounded => this overlap is only PARTIAL;
        the tail needs a client-side reload-on-ChunkLoadError / vite:preloadError handler, which then owns
        correctness and makes the overlap mere polish.

    Inputs land in a remote shell and in paths, so they're validated up front. Needs GNU head/xargs on
    the remote (Debian has both).
    """
    rid = str(release_id)
    if not rid.isalnum():  # lands in a remote shell + a path — keep it boring
        raise MikException(f"unsafe release_id: {rid!r}")
    if int(keep) < 1:  # keep=0 => GNU `head -n -0` prints every line => prune would delete the live release
        raise MikException("keep must be >= 1")
    validate_code_dir(site_root)  # absolute, no '..', boring chars — it's interpolated into a remote target
    for part in ssh_host.split("@"):
        try:
            validate_name(part)
        except Exception as exc:
            raise MikException(f"unsafe ssh_host: {ssh_host!r}") from exc
    _assert_artifact_has_no_links(src)  # payload check, before any remote contact: scp -r/cp -rL deref links
    # Invariant from here on: rid is alnum and site_root is a clean absolute path, so every remote string
    # composed below ({site_root}/releases/{rid}, .mik-STAGING-{rid}, .mik-OVERLAP-{rid}, ...) is shell-safe
    # by construction. That's why the sinks below — including _flip_current — interpolate without re-checking.
    # (`name` is a log label only — it no longer reaches a shell or a path — so it needs no validation.)
    releases_dir = f"{site_root}/releases"  # holds every release for this instance, plus current's targets
    new_release_dir = f"{releases_dir}/{rid}"  # the immutable release we ultimately serve
    new_release_rel = f"releases/{rid}"  # same dir, relative to site_root — the symlink target
    staging_dir = f"{releases_dir}/.mik-STAGING-{rid}"  # transient upload target (dotfile: ignored by prune)
    overlap_dir = f"{releases_dir}/.mik-OVERLAP-{rid}"  # transient previous-∪-new union (dotfile: ignored by prune)
    overlap_rel = f"releases/.mik-OVERLAP-{rid}"  # the union dir, relative to site_root — the symlink target
    # 0. preflight: make releases/ and confirm it's writable AS THE SSH USER, so we fail with an actionable
    #    message instead of a cryptic scp/rm permission error mid-deploy. Everything below runs without sudo.
    rc, err, _ = pop(["ssh", ssh_host, f"mkdir -p {releases_dir} && test -w {releases_dir}"])
    if rc != 0:
        raise MikException(
            f"{releases_dir} is not writable over ssh as {ssh_host} (rc={rc}). mik deploys without sudo — "
            f"own the web root with the deploy user, e.g. `ssh {ssh_host} sudo chown -R \\$USER {site_root}`."
        )
    # 1. ship the built artifact as-is (scp = argv, no shell), clearing any half-done previous attempt
    run_step(["ssh", ssh_host, f"rm -rf {staging_dir}"])
    run_step(["scp", "-r", str(src), f"{ssh_host}:{staging_dir}"])
    # 2. make the upload world-readable (a containerized server reads by 'other' bits), then promote it to a
    #    fresh immutable release dir — same filesystem, so the mv is an atomic rename. `a+rX` before the mv
    #    means the release is born readable: `current` never points at a not-yet-chmod'd dir.
    run_step(
        [
            "ssh",
            ssh_host,
            " && ".join(
                [
                    f"chmod -R a+rX {staging_dir}",
                    f"rm -rf {new_release_dir} {overlap_dir}",  # clear leftovers from a crashed run of this rid
                    f"mv {staging_dir} {new_release_dir}",
                ]
            ),
        ]
    )
    # 3. optional transient overlap: serve (previous ∪ new, new winning) — see the docstring for what this
    #    window does and doesn't cover. `current` still points at the previous release here, so `current/.`
    #    seeds the union with the old files; first deploy => the `|| true` leaves it empty and the union is
    #    just the new release (the sleep is then a harmless no-op).
    if overlap_seconds and overlap_seconds > 0:
        run_step(
            [
                "ssh",
                ssh_host,
                " && ".join(
                    [
                        f"mkdir -p {overlap_dir}",
                        f"cp -rL {site_root}/current/. {overlap_dir}/ 2>/dev/null || true",
                        f"cp -rL {new_release_dir}/. {overlap_dir}/",  # merge new in — new wins on shared names
                        f"chmod -R a+rX {overlap_dir}",
                    ]
                ),
            ]
        )
        _flip_current(ssh_host, site_root, overlap_rel)
        sleep(overlap_seconds)
    # 4. flip `current` to the clean release (atomic rename, never absent), then drop the overlap dir
    _flip_current(ssh_host, site_root, new_release_rel)
    if overlap_seconds and overlap_seconds > 0:
        run_step(["ssh", ssh_host, f"rm -rf {overlap_dir}"])
    # 5. prune old releases (best-effort; failure here must not fail the deploy)
    prune = f"cd {releases_dir} && ls -1 | sort -n | head -n -{int(keep)} | xargs -r -I REPLACE rm -rf REPLACE"
    try:
        run_step(["ssh", ssh_host, prune])
    except MikException as exc:
        debug(f"prune failed (ignored): {exc}")
    print(f"deployed {name} -> {site_root}/current (release {rid})")


# This is the validation logic inlined as a string for remote scripts (no re, no imports beyond builtins)
_REMOTE_VALIDATE_PATH = """
_vpo = (
    *range(ord("A"), ord("Z") + 1), *range(ord("a"), ord("z") + 1),
    *range(ord("0"), ord("9") + 1), ord("-"), ord("."), ord("_"),
)
_forbidden_parts = {"node_modules", "__pycache__"}
_forbidden_prefixes = (".git",)
_allowed_parts = {".gitignore"}
def validate_path(p):
    if not p or p.startswith("/"):
        return False
    for comp in p.split("/"):
        if not comp or comp == "..":
            return False
        if comp in _allowed_parts:
            continue
        if comp in _forbidden_parts:
            return False
        for pfx in _forbidden_prefixes:
            if comp.startswith(pfx):
                return False
        for c in comp:
            if ord(c) not in _vpo:
                return False
    return True
"""

REMOTE_SCRIPT_LIST = """
import subprocess, json, os, sys
{validate_path}
code_dir = {code_dir!r}
r = subprocess.run(["git", "-C", code_dir, "status", "--porcelain"], capture_output=True, text=True)
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
    if status_code == "??" and path.endswith("/"):
        full = os.path.join(code_dir, path)
        for root, dirs, fnames in os.walk(full, followlinks=False):
            for fn in fnames:
                full_path = os.path.join(root, fn)
                fp = os.path.relpath(full_path, code_dir)
                if os.path.islink(full_path):
                    errors.append("symlink rejected: " + fp)
                elif not validate_path(fp):
                    errors.append("invalid path: " + fp)
                else:
                    files.append({{"path": fp, "status": "A"}})
            dirs[:] = [d for d in dirs if not os.path.islink(os.path.join(root, d))]
    else:
        if "D" in status_code:
            s = "D"
        elif status_code == "??":
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


def _run_remote_script(ssh_host, container, script):
    encoded = base64.b64encode(script.encode()).decode()
    c, e, r = pop(
        ["ssh", ssh_host, f"docker exec {container} python3 -c \"import base64 as b;exec(b.b64decode('{encoded}'))\""]
    )
    return c, e, r


def dev_fetch_pod(args):
    inst = instances_dict.get(args.instance)
    if not inst:
        raise MikException(f"{Color.RED.value}Instance not found{Color.WHITE.value}")
    machine = machines_dict.get(getattr(inst, "machine", None))
    if not machine or not machine.ssh_host:
        raise MikException(f"{Color.RED.value}Instance has no machine with an ssh_host{Color.WHITE.value}")
    project = projects_dict.get(getattr(inst, "project", None))
    if not project or not project.local_repo:
        raise MikException(f"{Color.RED.value}Instance's project has no local_repo{Color.WHITE.value}")
    container = inst.container
    code_dir = inst.code_dir
    if not container or not code_dir:
        raise MikException(f"{Color.RED.value}Instance has no container/code_dir{Color.WHITE.value}")
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
        raise MikException(f"{Color.RED.value}SSH failed: {e.decode()}{Color.WHITE.value}")
    try:
        data = json.loads(r.decode())
    except json.JSONDecodeError:
        raise MikException(f"{Color.RED.value}Bad response from remote: {r[:200]}{Color.WHITE.value}")
    if data.get("errors"):
        for err in data["errors"]:
            print(f"{Color.DIM.value}  warning: {err}{Color.WHITE.value}")
    files = data.get("files", [])
    if not files:
        print("No changes found.")
        return
    # Display
    for f in files:
        color = Color.RED.value if f["status"] == "D" else Color.GREEN.value
        label = {"M": "modified", "A": "new", "D": "deleted"}.get(f["status"], f["status"])
        print(f"  {color}{label:>10}{Color.WHITE.value}  {f['path']}")
    print(f"\n  {len(files)} file(s)")
    answer = input("\nApply these changes? [y/N] ")
    if answer.strip().lower() != "y":
        print("Aborted.")
        return
    # Pass 2: fetch contents
    file_list_json = json.dumps(files)
    script = REMOTE_SCRIPT_FETCH.format(code_dir=code_dir, file_list=file_list_json)
    c, e, r = _run_remote_script(ssh_host, container, script)
    if c != 0:
        raise MikException(f"{Color.RED.value}SSH fetch failed: {e.decode()}{Color.WHITE.value}")
    try:
        payload = json.loads(base64.b64decode(r.strip()))
    except Exception:
        raise MikException(f"{Color.RED.value}Bad fetch response{Color.WHITE.value}")
    if payload.get("errors"):
        for err in payload["errors"]:
            print(f"{Color.DIM.value}  warning: {err}{Color.WHITE.value}")
    # Preemptive check — reject entire response if paths or statuses don't match confirmed list
    approved = {f["path"]: f["status"] for f in files}
    problems = []
    for fpath in payload.get("files", {}):
        if fpath not in approved:
            problems.append(f"unexpected path: {fpath}")
        elif approved[fpath] == "D":
            problems.append(f"was confirmed as deleted but got content: {fpath}")
    for fpath in payload.get("deleted", []):
        if fpath not in approved:
            problems.append(f"unexpected path: {fpath}")
        elif approved[fpath] != "D":
            problems.append(f"was confirmed as {approved[fpath]} but got deletion: {fpath}")
    received = set(payload.get("files", {}).keys()) | set(payload.get("deleted", []))
    for fpath, status in approved.items():
        if fpath not in received:
            problems.append(f"missing from response: {fpath} (was {status})")
    if problems:
        for p in problems:
            print(f"{Color.RED.value}  {p}{Color.WHITE.value}")
        raise MikException(
            f"{Color.RED.value}{len(problems)} mismatch(es) with confirmed list, aborting{Color.WHITE.value}"
        )
    # Apply
    local = Path(local_repo)
    written = 0
    deleted = 0
    for fpath, content_b64 in payload.get("files", {}).items():
        dest = local / fpath
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(base64.b64decode(content_b64))
        print(f"  {Color.GREEN.value}wrote{Color.WHITE.value}  {fpath}")
        written += 1
    for fpath in payload.get("deleted", []):
        dest = local / fpath
        if dest.exists():
            dest.unlink()
            print(f"  {Color.RED.value}deleted{Color.WHITE.value}  {fpath}")
            deleted += 1
        else:
            print(f"{Color.DIM.value}  already absent: {fpath}{Color.WHITE.value}")
    print(f"\nDone: {written} written, {deleted} deleted.")


GITHUB_API = "https://api.github.com"
# Optional certificate pinning (paranoid mode). Set any of these in your config to pin the sha256 of that
# host's DER *leaf* cert; ROOT_CA_FILE optionally points at the CA bundle used to verify. Left None, mik
# behaves exactly as before (urllib's default SSL context, no pinning).
# NOTE: a leaf pin breaks the moment the host rotates its cert (GitHub / Let's Encrypt do, regularly) — a
# previously green deploy then fails with "cert pin/verify failed" until you refresh the sha below.
ROOT_CA_FILE = None
GITHUB_COM_CERT_SHA256 = None  # api.github.com (used by ci-status)
GITHUB_IO_CERT_SHA256 = None  # *.github.io, e.g. c4ffein.github.io release archives (used by config builds)

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
    Tested with `python-version: [3.8, 3.9, 3.10, 3.11, 3.12, 3.13]`
    Original code can be found at https://github.com/c4ffein/python-snippets
    """

    class PinnedSSLSocket(SSLSocket):
        def check_pinned_cert(self):
            der_cert_bin = self.getpeercert(True)
            if sha256(der_cert_bin).hexdigest() != pinned_sha_256:
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


def pinned_urlopen(url, pinned_sha256=None, cafile=None, timeout=10):
    """Config helper: urlopen() with optional sha256 leaf-cert pinning and a custom CA bundle.

    Returns the response object (use as a context manager). `cafile` defaults to ROOT_CA_FILE. With no pin
    it's a plain urlopen. Config build steps use it to fetch release archives (e.g. github.io) over https.
    """
    context = make_pinned_ssl_context(pinned_sha256, cafile=cafile or ROOT_CA_FILE) if pinned_sha256 else None
    return urlopen(url, timeout=timeout, context=context)


def _github_get_json(path):
    """Unauthenticated GET against the public GitHub REST API; returns parsed JSON.

    Raises MikException on any transport/HTTP error so callers can bucket the failure. A User-Agent is
    required by GitHub or it answers 403. If GITHUB_COM_CERT_SHA256 is set (in config), api.github.com's
    certificate is pinned; ROOT_CA_FILE optionally supplies the CA bundle.
    """
    req = Request(
        f"{GITHUB_API}{path}",
        headers={"Accept": "application/vnd.github+json", "User-Agent": "mik"},
    )
    context = make_pinned_ssl_context(GITHUB_COM_CERT_SHA256, cafile=ROOT_CA_FILE) if GITHUB_COM_CERT_SHA256 else None
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
        raise MikException(f"{Color.RED.value}Project not found{Color.WHITE.value}")
    if not getattr(project, "github_repo", None):
        raise MikException(f"{Color.RED.value}Project has no github_repo{Color.WHITE.value}")
    result = _fetch_ci_status(target, project.github_repo)
    _print_ci_line(result)
    return 1 if result["state"] in _CI_RED_STATES else 0


def load_config():
    try:
        with CONFIG_FILE.open("r") as f:
            file_content = f.read()
    except Exception as exc:
        raise MikException(f"Can't read the config file: {CONFIG_FILE}") from exc
    try:
        exec(file_content, globals())
    except Exception as exc:
        traceback.print_exc()
        raise MikException("Something wrong in the config file") from exc
    debug(f"loaded config from {CONFIG_FILE}")


def main(argv=None):
    def get_key_value_action_with_limited_keys(allowed_keys: list):
        class KeyValueAction(argparse.Action):
            def __call__(self, parser, namespace, values, option_string=None):
                for value in values:
                    key, val = value.split("=", 1)
                    if key not in allowed_keys:
                        raise MikException(f"Unknow parameter: {key}")
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
    # sub-command: get-remote-source
    parser_get_remote_source = subparsers.add_parser("get-remote-source", help="run an instance's get_remote_source")
    parser_get_remote_source.add_argument("instance", metavar="INSTANCE")
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
    args = parser.parse_args()
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
        "get-remote-source": get_remote_source,
    }[args.command](args)


if __name__ == "__main__":
    try:
        exit(main())
    except KeyboardInterrupt:
        print("\n  !!  KeyboardInterrupt received  !!  \n")
        exit(130)  # conventional 128 + SIGINT(2)
    except MikException as exc:
        print(f"{Color.RED.value}\n  !!  {exc}  !!  \n{Color.WHITE.value}")
        exit(1)
    except Exception:
        raise
