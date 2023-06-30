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

#results = mp.Queue()
lock = mp.Lock()

def safe_print(msg, l):
    l.acquire()
    try:
        print(msg)
    finally:
        l.release()

def somewhat_safe_serialize(obj, fname, l):
    l.acquire()
    try:
        with open(fname, "wb") as f:
            f.write(pickle.dump(obj))
    finally:
        l.release()

def parse_directory(dname):
    results = []
    with os.scandir(dname) as it:
        for entry in it:
            if entry.name.endswith(".dylib"):
                results.append(os.path.join(dname, entry.name))
            elif entry.is_dir():
                parse_directory(os.path.join(dname,entry.name))
    return results

def parse_lib(dylib):
    func_info = {}
    global lock
    safe_print(dylib, lock)
    global results
    safe_print(dylib, lock)
    with binaryninja.open_view(dylib) as bv:
        guess_relocs = len(bv.relocation_ranges) == 0
        for func in bv.functions:
            if bv.get_symbol_at(func.start) is None: continue
            node, info = sigkit.generate_function_signature(func, guess_relocs)
            #results.put((node, info))
            safe_print("Processed " + func.name, lock)
            func_info[node] = info
            somewhat_safe_serialize(func_info, os.path.join("/tmp",func.name+".sig"), lock)

def main():
    libs = []
    pool = mp.Pool(mp.cpu_count())
    for path, directories, files in os.walk("./goat"):
        fpath = os.path.relpath(path, os.getcwd())
        tmp = parse_directory(fpath)
        if tmp != []:
            for lib in tmp:
                libs.append(lib)
    if len(libs) < 1:
        print("No libs found?!?")
        sys.exit(-2)
    print(len(libs))
    for result in pool.map(parse_lib, libs):
        print(result)

main()
