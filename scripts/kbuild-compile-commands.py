#!/usr/bin/env python3
"""Write a compilation database for the module's kernel sources from kbuild's own records.

kbuild saves the exact flags it compiled with in a hidden .<object>.o.cmd file next to every
object. Those are the flags that matter -- they carry every -I of the tree the module was built
against, plus the target and the language settings -- so a tool reading this database analyses
the module the way it was really compiled, instead of with guessed include paths.

Usage: kbuild-compile-commands.py <kmi> [output]
"""
import glob
import json
import os
import re
import sys

SOURCES = ('main.c', 'hooks.c', 'policy.c', 'patch.c', 'netlink.c')


def commands(kmi):
    """Yield one (source path, command line) per kernel source of one KMI."""
    for saved in sorted(glob.glob(f'build/kmi/{kmi}/.*.o.cmd')):
        text = open(saved, errors='replace').read().replace('\\\n', ' ')
        match = re.search(r'^(?:saved)?cmd_\S+ := (.*)$', text, re.M)
        if not match:
            continue
        line = match.group(1)
        source = re.search(r'(\S+\.c)\s*$', line)
        if not source:
            continue
        name = os.path.basename(source.group(1))
        if name not in SOURCES:
            continue
        # The tree's own clang takes a flag this clang-tidy does not know; it only asks the
        # compiler to zero auto variables, which is not what is being analysed here.
        line = line.replace(
            ' -enable-trivial-auto-var-init-zero-knowing-it-will-be-removed-from-clang', '')
        path = os.path.abspath('src/' + name)
        yield path, line.replace(source.group(1), path)


def main(argv):
    kmi = argv[1]
    output = argv[2] if len(argv) > 2 else 'build/tidy/kernel/compile_commands.json'
    directory = os.path.abspath('/opt/ddk/kdir/' + kmi)
    database = [{'directory': directory, 'command': line, 'file': path}
                for path, line in commands(kmi)]
    os.makedirs(os.path.dirname(output), exist_ok=True)
    with open(output, 'w') as out:
        json.dump(database, out, indent=1)
    print(f'{len(database)} translation unit(s) for {kmi}')
    return 0 if database else 1


if __name__ == '__main__':
    sys.exit(main(sys.argv))
