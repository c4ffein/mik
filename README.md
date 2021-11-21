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

Just a PoC for now but still usable, just populate a json file in `~/.local/share/mik/instances.json` according to this pattern

```
{
  "instances": {
    "instance1": {
      "deploy": [
        "cd ~/the/project/dir",
        "make"
      ]
    },
    "instance2": {
      "deploy": [
        "cd ~/the/project/dir2",
        "make"
      ]
    }
  }
}
```

## Commands
### `deploy`
`mik deploy $instance` executes the according shell commands
### `list`
`mik list` lists all recorded instances in the config file
### `autocomplete`
`mik autocomplete $instance_name_begin` same as `list` but only the instances whith a name starting with `$instance_name_begin`
