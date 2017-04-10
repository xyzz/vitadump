#!/usr/bin/env python3

import yaml
import subprocess
import string

from glob import glob
from sys import argv


fnids = open(argv[1])
fout = open(argv[2], "w")

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

