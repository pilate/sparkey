"""Benchmarks the sparkey Python bindings.

Only uses the API shared with spotify/sparkey-python, so the same script can
measure both: run it once per implementation with a different PYTHONPATH and
compare the output. Operations only the new bindings have are skipped
elsewhere.

    python python/bench/bench.py [--entries N] [--lookups N]
"""

import argparse
import os
import random
import shutil
import tempfile
import time

import sparkey


def best_of(runs, fn):
    best = None
    for _ in range(runs):
        start = time.perf_counter()
        fn()
        elapsed = time.perf_counter() - start
        best = elapsed if best is None else min(best, elapsed)
    return best


def report(name, seconds, count):
    print(f"  {name:<28} {count / seconds:>14,.0f} ops/s {seconds / count * 1e9:>10,.0f} ns/op")


def run(directory, compression, entries, lookups, runs):
    label = {0: "none", 1: "snappy", 2: "zstd"}[compression]
    print(f"compression={label} entries={entries:,} lookups={lookups:,}")
    hashfile = os.path.join(directory, f"bench-{label}.spi")
    logfile = os.path.join(directory, f"bench-{label}.spl")
    keys = [b"key_%d" % i for i in range(entries)]
    values = [b"value_%d" % i for i in range(entries)]
    block_size = 4096 if compression else 0

    def write():
        writer = sparkey.LogWriter(logfile, compression_type=compression, compression_block_size=block_size)
        put = writer.put
        for key, value in zip(keys, values):
            put(key, value)
        writer.close()

    report("put", best_of(runs, write), entries)
    if hasattr(sparkey.LogWriter, "update"):
        def write_update():
            writer = sparkey.LogWriter(logfile, compression_type=compression, compression_block_size=block_size)
            writer.update(zip(keys, values))
            writer.close()
        report("update (bulk put)", best_of(runs, write_update), entries)

    report("writehash", best_of(1, lambda: sparkey.writehash(hashfile, logfile)), entries)

    # Build fresh key objects in lookup order: reusing the objects in keys
    # would add a cache miss per lookup just to read the key.
    rng = random.Random(42)
    picks = [rng.randrange(entries) for _ in range(lookups)]
    hits = [b"key_%d" % i for i in picks]
    str_hits = ["key_%d" % i for i in picks]
    misses = [b"miss_%d" % i for i in range(lookups)]

    reader = sparkey.HashReader(hashfile, logfile)

    def get_hits():
        get = reader.get
        for key in hits:
            get(key)

    def subscript_hits():
        for key in hits:
            reader[key]

    def get_str_hits():
        get = reader.get
        for key in str_hits:
            get(key)

    def get_misses():
        get = reader.get
        for key in misses:
            get(key)

    def contains_hits():
        for key in hits:
            key in reader

    def iterate():
        for _ in reader:
            pass

    report("get (hit)", best_of(runs, get_hits), lookups)
    report("reader[key] (hit)", best_of(runs, subscript_hits), lookups)
    report("get (str key, hit)", best_of(runs, get_str_hits), lookups)
    report("get (miss)", best_of(runs, get_misses), lookups)
    report("key in reader (hit)", best_of(runs, contains_hits), lookups)
    if hasattr(reader, "get_many"):
        report("get_many (hit)", best_of(runs, lambda: reader.get_many(hits)), lookups)
    report("iterate hash", best_of(runs, iterate), entries)

    def iterate_log():
        log = sparkey.LogReader(logfile)
        for _ in log:
            pass
        log.close()

    report("iterate log", best_of(runs, iterate_log), entries)
    reader.close()

    assert sparkey.HashReader(hashfile, logfile).get(keys[-1]) == values[-1]
    print()


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--entries", type=int, default=1_000_000)
    parser.add_argument("--lookups", type=int, default=1_000_000)
    parser.add_argument("--runs", type=int, default=3, help="report the best of this many runs")
    parser.add_argument("--compression", choices=["none", "snappy", "zstd"], nargs="*", default=["none", "snappy"])
    args = parser.parse_args()

    print(f"sparkey from {os.path.dirname(sparkey.__file__)}")
    directory = tempfile.mkdtemp(prefix="sparkey-bench-")
    try:
        for name in args.compression:
            compression = {"none": 0, "snappy": 1, "zstd": 2}[name]
            run(directory, compression, args.entries, args.lookups, args.runs)
    finally:
        shutil.rmtree(directory)


if __name__ == "__main__":
    main()
