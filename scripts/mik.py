#!/usr/bin/env python3

import os
import sys
import argparse
import json
from pathlib import Path
import subprocess


class tcolors:
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


class MikException(Exception):
    pass


def load_json():
    with open(Path.home() / ".local/share/mik/instances.json") as json_file:
        return json.load(json_file)


def get_instances():
    j = load_json()
    instances = j.get("instances")
    if not instances: print(f"{tcolors.FAIL}No instances data{tcolors.ENDC}"); raise MikException
    return instances


def list(args):
    instances = get_instances()
    for i in instances: print(i)


def autocomplete(args):
    instances = get_instances()
    for i in instances:
        if i.startswith(args.autocomplete): print(i)


def deploy(args):
    instances = get_instances()
    instance_name = args.instance
    i = instances.get(instance_name)
    if not i: print(f"{tcolors.FAIL}Instance not found{tcolors.ENDC}"); raise MikException
    d = i.get("deploy")
    if not d: print(f"{tcolors.FAIL}Instance has no deploy script{tcolors.ENDC}"); raise MikException
    s = "\n".join(d)
    try:
        o = subprocess.check_output(s, shell=True, executable=i.get("deploy_shell") or "/bin/bash")
    except subprocess.CalledProcessError:
        return (-2)
    print(o)


def main(argv=None):

    parser = argparse.ArgumentParser(description=f"mik")
    subparsers = parser.add_subparsers(help='sub-command help', dest="command")  # dest needed to identify subcommand

    parser_deploy = subparsers.add_parser('deploy', help='deploy help')
    parser_deploy.add_argument("instance", metavar="INSTANCE")

    parser_list = subparsers.add_parser('list', help='list-instances help')

    parser_autocomplete = subparsers.add_parser('autocomplete', help='autocomplete help')
    parser_autocomplete.add_argument("autocomplete", metavar="INSTANCE_NAME_START")

    args=parser.parse_args()
    base_url = os.getcwd()

    if not args.command: parser.print_help(); return
    try:
        return {"deploy": deploy, "list": list, "autocomplete": autocomplete}[args.command](args)
    except MikException: return -1


if __name__ == '__main__':
    sys.exit(main())
