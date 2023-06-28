#!/usr/bin/env python3
# athanasios@akostopoulos.com

import os

def parse_directory(dname):
    with os.scandir(dname) as it:
        for entry in it:
            if entry.name.endswith(".dylib"):
                parse_lib(os.path.relpath(entry.name))
            elif entry.is_dir():
                parse_directory(os.path.join(dname,entry.name))
            else:
                pass #print("[-] Useless: " + entry.name)

def parse_lib(dylib):
    print(dylib)

parse_directory("./goat")
