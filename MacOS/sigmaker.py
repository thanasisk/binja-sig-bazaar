#!/usr/bin/env python3
# athanasios@akostopoulos.com

import os
import sys
import multiprocessing as mp
import time
import binaryninja

sys.path.append(os.path.join(os.getenv('HOME'),"code/sigkit"))

try:
    import Vector35_sigkit
except ModuleNotFoundError:
    try:
        import sigkit
    except ModuleNotFoundError:
        print(sys.path)
        sys.exit(-1)

results = mp.Queue()
lock = mp.Lock()
def safe_print(msg, l):
    l.acquire()
    try:
        print(msg)
    finally:
        l.release()

def parse_directory(dname):
    res = []
    with os.scandir(dname) as it:
        for entry in it:
            if entry.name.endswith(".dylib"):
                 res.append(os.path.join(dname, entry.name))
            elif entry.is_dir():
                parse_directory(os.path.join(dname,entry.name))
    return res

def parse_lib(dylib):
    global lock
    safe_print(dylib, lock)
    global results
    safe_print(dylib, lock)
    with binaryninja.open_view(dylib) as bv:
        guess_relocs = len(bv.relocation_ranges) == 0
        for func in bv.functions:
            if bv.get_symbol_at(func.start) is None: continue
            node, info = sigkit.generate_function_signature(func, guess_relocs)
            results.put((node, info))
            safe_print("Processed " + func.name, lock)

def main():
    pool = mp.Pool(mp.cpu_count())
    libs = parse_directory("./goat")
    if len(libs) < 1:
        print("No libs found?!?")
        sys.exit(-2)

    for result in pool.map(parse_lib, libs):
        print(result)

main()
