#!/usr/bin/env python3

import sys
import argparse
import json
from pathlib import Path
import subprocess
import string
import base64
import traceback
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from enum import Enum
from sys import exit
from typing import Optional, TypedDict
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from uuid import uuid4


# WARNING: this is quick and dirty, please don't judge current code quality


# Your ~/.config/mik/config.py is exec'd into this module's namespace (see load_config), so every name
# defined here is callable from your config. __all__ documents that config-facing surface and keeps these
# helpers from reading as "unused" — they are public API for config authors, not dead code.
__all__ = [
    "Instance",
    "Project",
    "MikException",
    "Color",
    "debug",
    "pop",
    "run_step",
    "run_and_capture",
    "record_run",
    "sanr",
    "recursed",
]


# TODOs
# - backup system
# - system to easily pull trees
# - custom tasks graph + state for each + all race conditions handled
# - update system, track remote versions
# - reboot command
# - better data model, deploy a project to an instance, let an instance backup multiple projects...


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


instances_dict = {}


class InstanceMeta(type):
    def __new__(mcs, name, bases, namespace):
        if name == "Instance":  # this is the base class, we can skip
            return super().__new__(mcs, name, bases, namespace)
        if not namespace.get("name") or not namespace.get("data"):
            raise MikException(f"No name or data for {name}")
        instances_dict[namespace["name"]] = namespace["data"]
        r = super().__new__(mcs, name, bases, namespace)
        instances_dict[namespace["name"]]["object"] = r
        return r


class Instance(metaclass=InstanceMeta):
    name = None
    data = {}


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


# ssh-host has a hyphen, so the functional TypedDict form is required (class syntax can't express it).
DevConfig = TypedDict("DevConfig", {"container": str, "code_dir": str, "ssh-host": str})


class Project(metaclass=ProjectMeta):
    name: Optional[str] = None
    local_repo: Optional[str] = None
    github_repo: Optional[str] = None  # "owner/repo" — checked over the public GitHub API, no auth
    dev: Optional[DevConfig] = None


def get_projects():
    if not projects_dict:
        raise MikException("No projects data")
    return projects_dict


def get_instances():
    instances = instances_dict
    if not instances:
        raise MikException("No instances data")
    return instances


def list_instances(args):
    instances = get_instances()
    for i in instances:
        print(i)


def autocomplete(args):
    instances = get_instances()
    for i in instances:
        if i.startswith(args.autocomplete):
            print(i)


def deploy(args):
    instances = get_instances()
    instance_name = args.instance
    i = instances.get(instance_name)
    if not i:
        raise MikException(f"{Color.RED.value}Instance not found{Color.WHITE.value}")
    obj = i["object"]
    sub = getattr(args, "sub", None)
    if sub:
        # An explicitly requested sub-deploy must exist; never fall back silently.
        method_name = f"deploy_{sub}"
        deploy_method = getattr(obj, method_name, None)
        if deploy_method is None:
            raise MikException(f"{Color.RED.value}Instance has no {method_name} method{Color.WHITE.value}")
        return deploy_method()
    # No sub: prefer a deploy() method on the object, else fall back to the shell script.
    deploy_method = getattr(obj, "deploy", None)
    if deploy_method is not None:
        return deploy_method()
    d = i.get("deploy")
    if not d:
        raise MikException(f"{Color.RED.value}Instance has no deploy script{Color.WHITE.value}")
    s = "\n".join(d)
    rc, _ = run_recorded("deploy", instance_name, s, i.get("deploy_shell") or "/bin/bash")
    if rc != 0:
        raise MikException(f"{Color.RED.value}deploy failed (rc={rc}){Color.WHITE.value}")


def get_remote_source(args):
    instances = get_instances()
    instance_name = args.instance
    i = instances.get(instance_name)
    if not i:
        raise MikException(f"{Color.RED.value}Instance not found{Color.WHITE.value}")
    d = i.get("get-remote-source")
    if not d:
        raise MikException(f"{Color.RED.value}Instance has no get-remote-source script{Color.WHITE.value}")
    s = "\n".join(d)
    rc, _ = run_recorded("get-remote-source", instance_name, s, i.get("get_remote_source_shell") or "/bin/bash")
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


def recursed(func, args, instances):
    """Config helper: run `func` over every instance, collecting results (or the raised Exception)."""
    ret = {}
    for instance_name in instances:

        class A:
            instance = instance_name

        try:
            ret[instance_name] = func(A)
        except Exception as e:
            ret[instance_name] = e
    return ret


def pop(cmda):
    """Config helper: run an argv list, capturing stdout/stderr separately.

    returns value of last fail, so covers ssh fail, sudo fail, one of the remaining commands fail...
    """
    proc = subprocess.Popen(cmda, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    r, e = proc.communicate()
    return proc.returncode, e, r


def run_step(cmda, fail_on_stderr=True):
    """Config helper: run an argv list via pop(), raising MikException on rc!=0 (or on any stderr).

    Note fail_on_stderr=True is strict — many tools write to stderr on success, so pass False for those.
    """
    c, e, r = pop(cmda)
    debug(f"step rc={c} cmd={cmda} err={e!r} out={r!r}")
    if c != 0:
        raise MikException(f"step failed (rc={c}): {e.decode(errors='replace')}")
    if fail_on_stderr and e:
        raise MikException(f"step succeeded (rc=0) but wrote to stderr: {e.decode(errors='replace')}")
    return r


def sanr(bs):
    """Config helper: assert `bs[:-1]` is ASCII alphanumeric and decode it (sanitises an ssh'd username)."""
    sshed_user = bs[:-1]
    for i in sshed_user:
        if i not in (map(lambda c: ord(c), string.ascii_letters + string.digits)):
            raise Exception("Bad san")
    return str(sshed_user, "utf-8")  # or fstrings will fail...


_valid_name_ords = (
    *range(ord("A"), ord("Z") + 1),
    *range(ord("a"), ord("z") + 1),
    *range(ord("0"), ord("9") + 1),
    ord("-"),
    ord("."),
)


def validate_name(s):
    metone = False
    for i in range(len(s)):
        if ord(s[i]) not in _valid_name_ords:
            raise Exception(f"Bad char {ord(s[i])} printed {s[i]}")
        if s[i] != ".":
            metone = True
    if not metone:
        raise Exception("Need at least one char that is not a dot")


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
    projects = get_projects()
    project = projects.get(args.project)
    if not project:
        raise MikException(f"{Color.RED.value}Project not found{Color.WHITE.value}")
    if not project.dev:
        raise MikException(f"{Color.RED.value}Project has no dev config{Color.WHITE.value}")
    if not project.local_repo:
        raise MikException(f"{Color.RED.value}Project has no local_repo{Color.WHITE.value}")
    container = project.dev["container"]
    code_dir = project.dev["code_dir"]
    local_repo = project.local_repo
    ssh_host = project.dev.get("ssh-host")
    if not ssh_host:
        raise MikException(f"{Color.RED.value}Project dev has no ssh-host{Color.WHITE.value}")
    for part in ssh_host.split("@"):
        validate_name(part)
    validate_name(container)
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


def _github_get_json(path):
    """Unauthenticated GET against the public GitHub REST API; returns parsed JSON.

    Raises MikException on any transport/HTTP error so callers can bucket the failure. A User-Agent is
    required by GitHub or it answers 403.
    """
    req = Request(
        f"{GITHUB_API}{path}",
        headers={"Accept": "application/vnd.github+json", "User-Agent": "mik"},
    )
    try:
        with urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode())
    except HTTPError as exc:
        raise MikException(f"{exc.code} {exc.reason}") from exc
    except URLError as exc:
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
    color, glyph = _CI_GLYPH.get(result["state"], (Color.WHITE, "?"))
    branch = result["branch"] or ""
    detail = f"  {Color.DIM.value}{result['detail']}{Color.WHITE.value}" if result["detail"] else ""
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

    Returns -1 if any reported project is a pipeline failure or couldn't be fetched, else 0 — so
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
        return -1 if any(r["state"] in _CI_RED_STATES for r in results) else 0
    project = projects.get(target)
    if not project:
        raise MikException(f"{Color.RED.value}Project not found{Color.WHITE.value}")
    if not getattr(project, "github_repo", None):
        raise MikException(f"{Color.RED.value}Project has no github_repo{Color.WHITE.value}")
    result = _fetch_ci_status(target, project.github_repo)
    _print_ci_line(result)
    return -1 if result["state"] in _CI_RED_STATES else 0


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
    # sub-command: list
    subparsers.add_parser("list", help="list-instances help")
    # sub-command: deploy
    parser_deploy = subparsers.add_parser("deploy", help="deploy help")
    parser_deploy.add_argument("instance", metavar="INSTANCE")
    expected_params = {"sub": "Only deploy a specific part of the project"}
    param_help = "Available parameters:\n"
    for key, desc in expected_params.items():
        param_help += f"  {key}=VALUE    {desc}\n"
    parser_deploy.add_argument(
        "params", nargs="*", action=get_key_value_action_with_limited_keys(list(expected_params)), help=param_help
    )
    # sub-command: get-remote-source
    parser_deploy = subparsers.add_parser("get-remote-source", help="get-remote-source help")
    parser_deploy.add_argument("instance", metavar="INSTANCE")
    # sub-command: dev-fetch-pod
    parser_dev_fetch_pod = subparsers.add_parser("dev-fetch-pod", help="Fetch changed files from remote container")
    parser_dev_fetch_pod.add_argument("project", metavar="PROJECT")
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
        "dev-fetch-pod": dev_fetch_pod,
        "ci-status": ci_status,
        "list": list_instances,
        "autocomplete": autocomplete,
        "get-remote-source": get_remote_source,
    }[args.command](args)


if __name__ == "__main__":
    try:
        exit(main())
    except KeyboardInterrupt:
        print("\n  !!  KeyboardInterrupt received  !!  \n")
        exit(-2)
    except MikException as exc:
        print(f"{Color.RED.value}\n  !!  {exc}  !!  \n{Color.WHITE.value}")
        exit(-1)
    except Exception:
        raise
