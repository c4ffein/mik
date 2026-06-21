# MIK
KISS 1 command deploy

<p align="center">
  <a href="https://pypi.org/project/mik/" alt="PyPI">
      <img src="https://img.shields.io/pypi/v/mik?color=blueviolet" /></a>
  <a href="https://pypi.org/project/mik/" alt="Python Versions">
      <img src="https://img.shields.io/pypi/pyversions/mik?color=blueviolet" /></a>
  <a href="https://pypi.org/project/mik/" alt="PyPI Format">
      <img src="https://img.shields.io/pypi/format/mik?color=blueviolet" /></a>
  <a href="https://pypi.org/project/mik/" alt="License">
      <img src="https://img.shields.io/pypi/l/mik?color=blueviolet" /></a>
</p>

A tiny personal helper to deploy projects and pull dev changes back out of
remote containers — driven by a single Python config file.

## ⚠️ Warning
This is a proof-of-concept built around my own setup (docker, ssh). It works
for me because I know exactly what it does — I don't recommend using it as-is.
Read the source before pointing it at anything you care about. (Your config is
`exec`'d into mik's namespace, so it can do anything Python can.)

## Config

mik loads `~/.config/mik/config.py`. It's a **Python** file: mik defines the
base `Machine`, `Instance` and `Project` classes first, then runs your config,
so you just subclass them. **Defining a subclass registers it** — there's no
list to maintain.

The data model is three classes linked by name (the instance carries the
foreign keys; there is no join table):

- **`Machine`** — a real box you SSH into. Hosts N instances.
- **`Project`** — the thing you develop (one repo). Has N instances (its deployments).
- **`Instance`** — one project deployed on one machine, in one container.

```python
# ~/.config/mik/config.py

class Vps(Machine):
    name = "vps"                         # name used by list-machines / filters
    ssh_host = "debian@vps-xxxx"         # "user@host", used by dev-fetch-pod

class MyProject(Project):
    name = "myproject"
    local_repo = "/home/me/code/myproject"   # where dev-fetch-pod writes fetched files
    github_repo = "me/myproject"             # "owner/repo", for ci-status (public GitHub API, no auth)

class MyServer(Instance):
    name = "myserver"                    # the name you pass on the command line
    project = "myproject"                # -> a Project name
    machine = "vps"                      # -> a Machine name
    container = "myproject-web-1"         # docker container on the remote (for dev-fetch-pod)
    code_dir = "/app"                     # the git checkout inside that container (for dev-fetch-pod)
    deploy = [                            # shell lines run LOCALLY for `mik deploy myserver`
        "cd ~/code/myserver",
        "make deploy",
    ]
    # deploy_shell = "/bin/bash"          # optional interpreter for the deploy lines (default /bin/bash)
    # get_remote_source = ["..."]         # optional shell lines for `mik get-remote-source`
```

### Python deploy / build steps

Instead of a `deploy` *list*, you can define `deploy` as a **method** (a
classmethod is cleanest). It's called with no arguments — or one argument when
a `RELEASE_ID` is passed on the CLI — and is responsible for running and
reporting itself. A `build` method works the same way and is what `mik build`
runs to produce a local artifact:

```python
class MyServer(Instance):
    name = "myserver"
    project = "myproject"
    machine = "vps"

    @classmethod
    def build(cls):
        # produce an immutable local artifact (no remote side effects)
        return build_artifact("myserver-dist", "dist", lambda staging: ...)

    @classmethod
    def deploy(cls, release_id=None):
        # ship latest_release("myserver-dist") — or resolve_release(..., release_id) to roll back
        ...
```

mik exposes a set of helpers in the config namespace for exactly this: a local
artifact store (`build_artifact`, `latest_release`, `resolve_release`,
`prune_artifacts`, `artifact_category_dir`), shell runners (`run_step`, `pop`,
`run_and_capture`, `record_run`), and `pinned_urlopen` / `make_pinned_ssl_context`
for fetching over TLS with optional leaf-cert pinning. See `mik.py` (`__all__`)
for the full list.

## Commands

```
──────────────────────────── overview ─────────────────────────────
  mik list                              ==> machines, projects and instances, each with their links

──────────────────────────── machines ─────────────────────────────
  mik list-machines [--show-instances]  ==> machine names (or each machine's instances)
    + project=NAME                      ==> only machines running an instance of that project

──────────────────────────── projects ─────────────────────────────
  mik list-projects [--show-instances]  ==> project names (or each project's instances)
    + machine=NAME                      ==> only projects with an instance on that machine
  mik ci-status <project>               ==> default-branch pipeline status via the GitHub API
  mik ci-status ALL                     ==> grouped status for every project with a github_repo
                                            (exits non-zero if any are failing/unfetchable)

──────────────────────────── instances ────────────────────────────
  mik list-instances [--show-links]     ==> instance names (or each instance's project + machine)
    + project=NAME machine=NAME         ==> filter by project and/or machine
  mik deploy <instance>                 ==> run the instance's deploy() method or "deploy" script
    + <RELEASE_ID>                      ==> ship/roll back to a local artifact (Python deploys only)
  mik build <instance>                  ==> run the instance's build() method (local artifact, no remote)
  mik get-remote-source <instance>      ==> run the instance's get_remote_source script
  mik dev-fetch-pod <instance>          ==> pull changed files out of the instance's remote container
  mik autocomplete <prefix>             ==> instance names starting with <prefix>

──────────────────────────── global ───────────────────────────────
  --debug                               ==> print debug output to stderr (e.g. mik --debug deploy x)
```

### `dev-fetch-pod`
Resolves the instance's `machine.ssh_host`, `container` and `code_dir`, runs
`git status` inside the remote container over ssh, shows you the changed / new
/ deleted files, and — only after you confirm — fetches their contents and
writes them into the project's `local_repo`. Paths are validated on both ends
(no absolute paths, no `..`, no `.git/`, symlinks rejected) and the fetched set
is checked against exactly what you confirmed before anything is written.

### Run records
`deploy` and `get-remote-source` stream their output live while capturing it,
and persist one JSON record per run (combined output, return code, timing)
under `~/.local/state/mik/runs/` for later inspection.
