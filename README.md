# MIK
KISS project and server management

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

## ⚠ Warning
This is a proof-of-concept built around my own setup (docker, ssh). It works
for me because I know exactly what it does — I don't recommend using it as-is.
Read the source before pointing it at anything you care about. (Your config is
`exec`'d into mik's namespace, so it can do anything Python can.)

## Config

mik loads `~/.config/mik/config.py`. It's a **Python** file: mik defines the
base `Machine`, `Instance` and `Project` classes first, then runs your config,
so you just subclass them. **Defining a subclass registers it** — there's no
list to maintain (two machines, projects or instances with the same name is an
error).

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
    deploy = [                            # shell lines run LOCALLY for `mik deploy myserver`, under
        "cd ~/code/myserver",             # `set -e`: a line that fails stops the deploy there
        "make deploy",
    ]
    # deploy_shell = "/bin/bash"          # optional interpreter for the deploy lines (default /bin/bash;
    #                                     # `set -e` is only added for sh, bash, dash, ksh, zsh)
```

Because the config runs in mik's namespace, a name of mik's own that it defines again (a
helper called `build`, say) would replace mik's: that is refused when the config is loaded,
naming it. The settings a config is meant to give a value to are the exception
(`ROOT_CA_FILE`, `GITHUB_COM_CERT_SHA256`, `GITHUB_IO_CERT_SHA256`, `ARTIFACTS_DIR`, `RUNS_DIR`,
`POD_OUTPUT_MAX_BYTES`, `POD_TEXT_RANGES`).

And because it is run as Python, a config that somebody else could have written is not loaded:
the file and its directory have to be yours (or root's) and writable by nobody else, as ssh
wants for `~/.ssh/config` (`chmod go-w` them).

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
`run_and_capture`, `record_run`), `deploy_release` (zero-downtime static deploy:
ships a directory to the remote as an immutable release and atomically flips the
`current` symlink the web server serves through; what it points at is the new
release merged over those that were live in the last day, so a page loaded
before the deploy still finds its hashed bundles),
and `pinned_urlopen` / `make_pinned_ssl_context`
for fetching over TLS (`https://` URLs only) with optional leaf-cert pinning (a pin is a SHA256, or a
list of them: the config can ask a command for the current ones, such as `tls-pin-get`
from [crypto](https://github.com/c4ffein/crypto)). Each helper's full
signature and semantics live in its docstring in `mik.py` (see `__all__` for the
list; a `mik help <command>` surfacing them is on the TODO list).

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
  mik dev-fetch-pod <instance>          ==> pull changed files out of the instance's remote container
  mik autocomplete <prefix>             ==> instance names starting with <prefix>

──────────────────────────── global ───────────────────────────────
  --debug                               ==> print debug output to stderr (e.g. mik --debug deploy x)
```

### `dev-fetch-pod`
Resolves the instance's `machine.ssh_host`, `container` and `code_dir`, runs
`git status` inside the remote container over ssh, shows you the changed / new
/ deleted files (what the pod's `.gitignore` ignores stays out; a rename is a
deletion and a new file), and — only after you confirm — fetches their contents
and writes them into the project's `local_repo`. Paths are validated on both ends
(no absolute paths, no `..`, no `.git/` in any case, no `HEAD` — what makes a
directory a repository to git — symlinks rejected, in the pod and in the local repo:
nothing is written or deleted through one) and the fetched set
is checked against exactly what you confirmed before anything is written.

What comes from the pod is then yours to review with `git status` / `git diff`, so a path that
git would not show there is refused: `local_repo` has to be a git repository, and a path it
ignores (`.venv/…`, `.env`: asked of `git check-ignore`, tracked files are not ignored) is not
written or deleted. That is asked twice: before the question, with the `.gitignore` files that
are there, and again before the first write, with those that came — so a pod cannot send a file
together with the `.gitignore` that hides it. A tracked file that git was told not to look at
(`git update-index --skip-worktree` or `--assume-unchanged`) is refused as well: a change to it
would show in neither, and it is where you keep one of your own. Nothing is written into a directory that holds a
`HEAD` either (a bare repository already in the local repo, a test fixture), nor into one that has
its own `.git` (a clone, a worktree, a submodule: `git status` in the local repo does not look into
it), a path may be listed once and not as both a file and a directory, and a pod's answer is at most
`POD_OUTPUT_MAX_BYTES` (512 MiB unless the config says otherwise).

In the list you are asked about, a path with a name that starts with a dot (`.envrc`,
`.vscode/tasks.json`, `.github/workflows/…`) is shown in red: tools read those without being
asked, and may run what is in them.

`git diff` writes a file to the terminal as it is, and a terminal does not show a control
character: it obeys it. A line can hide its own end (`ESC[8m`, black on black), write over itself
(backspaces, a carriage return) or be shown in another order (a direction mark) — what is run is
then not what was read. So a text that comes from a pod is checked before anything is written: it
has to be UTF-8, with nothing in it but tabs, newlines (a carriage return right before one is
fine) and the characters of `POD_TEXT_RANGES` — an allowlist, and a short one: ASCII, Latin-1 and
Latin Extended-A letters, dashes and curly quotes, arrows, box drawing and symbols. No control
character, nothing that cannot be seen (no-break space, zero-width and direction marks, variation
selectors), no other alphabet (the Cyrillic U+0430 passes for a Latin `a`), no emoji. One such
character anywhere in a file, changed by the pod or not, and nothing is fetched: each one is said
once, with the file and the line it is first found on. What your projects do write in, the config adds:

```python
POD_TEXT_RANGES = (*POD_TEXT_RANGES, (0x1F300, 0x1FAFF), (0x0660, 0x0669))  # emoji, Arabic-Indic digits
```

All of this is said of a terminal that reads UTF-8, and mik expects yours to (`locale charmap`,
and what the terminal itself is set to): git sends bytes, and it is the terminal that makes
characters of them. One set to an 8-bit charset reads others in the same bytes — `Û` is in the
ranges, it is `C3 9B` in UTF-8, and `9B` alone is a control there. Only ASCII says the same to
every terminal: `POD_TEXT_RANGES = ((0x20, 0x7E),)` if yours is not UTF-8.

A binary file is not looked into: `git diff` shows nothing of it, so there is nothing to hide in
it. Binary is what git calls binary — a NUL in the first 8000 bytes; a NUL further down leaves the
file a text, and it is refused. A file that is a text in the local repo and comes as a binary one
is written like any other (an image that got its real content), and said in red once all is
written: from then on `git diff` only says that it differs.

That is git's plain rule, and an attribute changes it: with `working-tree-encoding=UTF-16LE` a
file that is full of NULs on disk is converted and shown as a text, `diff` shows a binary file
as one, a `filter` or a diff driver shows what a program made of it, `text` and `eol` leave a
change of line ends out. Which attribute does what is not sorted out: a path git has any
attribute for (asked of `git check-attr -a`, so from a `.gitattributes`, `.git/info/attributes`,
your own attributes file or the system's) is refused before the question, and is to be copied by
hand. A local repo with a `.gitattributes` is fetched into for the paths it says nothing of.

### Run records
A script `deploy` (a list of shell lines) streams its output live while
capturing it, and persists one JSON record per run (combined output, return
code, timing) under `~/.local/state/mik/runs/` for later inspection. A Python
`deploy` gets the same from `run_and_capture` + `record_run`.

## Help

Raw `mik --help` output (kept in sync with the code by `test.py`, rendered at 80 columns):

```
usage: mik [-h] [--debug]
           {list,list-machines,list-instances,list-projects,deploy,build,dev-fetch-pod,ci-status,autocomplete} ...

mik

positional arguments:
  {list,list-machines,list-instances,list-projects,deploy,build,dev-fetch-pod,ci-status,autocomplete}
                        sub-command help
    list                list everything: instances and projects with their
                        links
    list-machines       list machines
    list-instances      list instances
    list-projects       list projects
    deploy              deploy an instance
    build               build an instance's local artifact
    dev-fetch-pod       Fetch changed files from an instance's container
    ci-status           Check default-branch pipeline status (or ALL)
    autocomplete        autocomplete help

options:
  -h, --help            show this help message and exit
  --debug               enable debug output
```
