#!/usr/bin/env python3

import yaml
import subprocess
import string

from glob import glob
from sys import argv

hardcoded_nids = [
	("0x79F8E492", "module_stop"),
	("0x913482A9", "module_exit"),
	("0x935CD196", "module_start"),
]

fnids = open(argv[1])
fout = open(argv[2], "w")

for entry in hardcoded_nids:
	fout.write("{} {}\n".format(entry[0], entry[1]))

nids = yaml.safe_load(fnids)
fnids.close()

modules = nids["modules"]
for module in modules:
    libraries = modules[module]["libraries"]
    for library in libraries:
        try:
            functis = libraries[library]["functions"]
        except:
            continue
        for functi in functis:
            nid = hex(functis[functi])
            fout.write("{} {}\n".format(nid, functi))

fout.close()

