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
Read the source before pointing it at anything you care about.

## Config

mik loads `~/.config/mik/config.py`. It's a **Python** file (not JSON — older
docs said otherwise): mik defines the base `Instance` and `Project` classes
first, then runs your config, so you just subclass them. Defining a subclass
registers it.

```python
# ~/.config/mik/config.py

class MyServer(Instance):
    name = "myserver"                # the name you pass on the command line
    data = {
        "ssh-host": "debian@vps-xxxx",   # ssh target, if your deploy/source scripts need it
        "deploy": [                      # shell lines run locally for `mik deploy myserver`
            "cd ~/code/myserver",
            "make deploy",
        ],
        # "deploy_shell": "/bin/bash",          # optional, interpreter for the deploy lines
        # "get-remote-source": ["..."],         # shell lines run for `mik get-remote-source`
    }

    # Instead of a "deploy" script you can define a method (called with no args):
    # def deploy(): ...
    # And per-part sub-deploys, reachable via `mik deploy myserver sub=web`:
    # def deploy_web(): ...

class MyProject(Project):
    name = "myproject"
    local_repo = "/home/me/code/myproject"   # where dev-fetch-pod writes fetched files
    dev = {
        "ssh-host": "debian@vps-xxxx",
        "container": "myproject-web-1",      # docker container on the remote
        "code_dir": "/app",                  # the git checkout inside that container
    }
```

## Commands

```
──────────────────────────── instances ────────────────────────────
  mik list                          ==> list every instance in the config
  mik autocomplete <prefix>         ==> like list, but only names starting with <prefix>
  mik deploy <instance>             ==> run the instance's deploy() method or "deploy" script
    + sub=<part>                    ==> run deploy_<part>() instead (errors if it doesn't exist)
  mik get-remote-source <instance>  ==> run the instance's "get-remote-source" script

──────────────────────────── projects ─────────────────────────────
  mik dev-fetch-pod <project>       ==> pull changed files out of the project's remote
                                        container (git status → confirm → fetch) into local_repo

──────────────────────────── global ───────────────────────────────
  --debug                           ==> print debug output to stderr (e.g. mik --debug deploy x)
```

### `dev-fetch-pod`
Runs `git status` inside the remote container over ssh, shows you the changed /
new / deleted files, and — only after you confirm — fetches their contents and
applies them to `local_repo`. Paths are validated on both ends (no absolute
paths, no `..`, no `.git/`, symlinks rejected) and the fetched set is checked
against exactly what you confirmed before anything is written.
