#!/usr/bin/env python3
# athanasios@akostopoulos.com

import os
import sys
import multiprocessing as mp
import time
import binaryninja
import pickle
import argparse

# assumes that sigkit is git cloned at $HOME/code/sigkit
sys.path.append(os.path.join(os.getenv('HOME'),"code/sigkit"))

try:
    import Vector35_sigkit
except ModuleNotFoundError:
    try:
        import sigkit
    except ModuleNotFoundError:
        print("failed to import sigkit")
        print(sys.path)
        sys.exit(-1)

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
            pickle.dump(obj, f)
    finally:
        l.release()

def parse_directory(dname, postfix):
    results = []
    with os.scandir(dname) as it:
        for entry in it:
            if entry.name.endswith(postfix):
                results.append(os.path.join(dname, entry.name))
            elif entry.is_dir():
                parse_directory(os.path.join(dname,entry.name), postfix)
    return results

def parse_lib(dylib) -> list:
    func_info = {}
    results = []
    global lock
    safe_print(dylib, lock)
    with binaryninja.open_view(dylib) as bv:
        guess_relocs = len(bv.relocation_ranges) == 0
        for func in bv.functions:
            if bv.get_symbol_at(func.start) is None: continue
            node, info = sigkit.generate_function_signature(func, guess_relocs)
            safe_print("Processed " + func.name, lock)
            func_info[node] = info
            func_info['name'] = func.name
            results.append(func_info)
    return results


def check_output_dir(odir) -> None:
    if os.path.exists(odir):
        print(f"{odir} already exists! Aborting!")
        sys.exit(-4)
    try:
        os.mkdir(odir)
    except PermissionError as e:
        print(e)
        sys.exit(-5)
    except FileNotFoundError as err:
        print(err)
        sys.exit(-6)

def main() -> int:
    flock = mp.Lock()
    parser = argparse.ArgumentParser()
    parser.add_argument("-s",  "--scan", help="directory to recursively scan for libraries")
    parser.add_argument("-o", "--output", help="output directory - must NOT exist", default="./lol")
    parser.add_argument("-t","--libtype", help="type of libraries to parse - valid values .a|.dylib",default=".dylib")
    args = parser.parse_args()
    outdir = args.output
    scandir = args.scan
    libtype = args.libtype
    check_output_dir(outdir)
    libs = []
    pool = mp.Pool(mp.cpu_count())
    for path, directories, files in os.walk(scandir):
        fpath = os.path.relpath(path, os.getcwd())
        tmp = parse_directory(fpath, libtype)
        if tmp != []:
            for lib in tmp:
                libs.append(lib)
    if len(libs) < 1:
        print("No libs found?!?")
        sys.exit(-2)
    libs = set(libs)
    for sig in pool.map(parse_lib, libs):
        somewhat_safe_serialize(sig, os.path.join(os.path.abspath(outdir),sig['name']+".sig"), flock)
    return 0

if __name__ == "__main__":
    sys.exit(main())
