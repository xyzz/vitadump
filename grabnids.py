#!/usr/bin/env python3

import subprocess
import string

from glob import glob
from sys import argv

fout = open(argv[2], "w")


for filename in glob(argv[1] + "*_stub.a"):
    cmd = "readelf --wide --symbols {} | grep INID".format(filename)
    output = subprocess.check_output(cmd, shell=True).decode("utf-8").split("\n")

    for line in output[:-1]:
        if "__" not in line:
            libname = line.split(" ")[-1].split("_")[-1]
            print(libname, "<=", filename)
            continue
        s = line.split(" ")
        nid, name = s[5], s[-1]
        pos = name.find(libname) + len(libname) + 2
        while name[pos] in string.digits:
            pos += 1
        name = name[pos+1:]
        fout.write("{} {}\n".format(nid, name))

fout.close()
