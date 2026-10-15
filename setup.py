"""Builds the sparkey Python extension, with libsparkey compiled into it.

Project metadata lives in pyproject.toml. snappy and zstd are found with
pkg-config when it is available, otherwise they are linked as -lsnappy -lzstd.
"""

import shlex
import subprocess

from setuptools import Extension, setup

LIBRARY_SOURCES = [
    "src/MurmurHash3.c",
    "src/buf.c",
    "src/compress.c",
    "src/endiantools.c",
    "src/hashalgorithms.c",
    "src/hashheader.c",
    "src/hashiter.c",
    "src/hashreader.c",
    "src/hashwriter.c",
    "src/logheader.c",
    "src/logreader.c",
    "src/logwriter.c",
    "src/returncodes.c",
    "src/util.c",
]


def pkg_config(*packages):
    try:
        cflags = subprocess.check_output(["pkg-config", "--cflags", *packages], text=True)
        libs = subprocess.check_output(["pkg-config", "--libs", *packages], text=True)
    except (OSError, subprocess.CalledProcessError):
        return {"include_dirs": [], "library_dirs": [], "libraries": ["snappy", "zstd"]}
    flags = {"include_dirs": [], "library_dirs": [], "libraries": []}
    for flag in shlex.split(cflags) + shlex.split(libs):
        if flag.startswith("-I"):
            flags["include_dirs"].append(flag[2:])
        elif flag.startswith("-L"):
            flags["library_dirs"].append(flag[2:])
        elif flag.startswith("-l"):
            flags["libraries"].append(flag[2:])
    return flags


flags = pkg_config("snappy", "libzstd")
flags["include_dirs"].insert(0, "src")

setup(
    ext_modules=[
        Extension(
            "sparkey._sparkey",
            sources=["python/sparkey/_sparkey.c", *LIBRARY_SOURCES],
            depends=["src/sparkey.h", "src/sparkey-internal.h"],
            extra_compile_args=["-O3", "-fvisibility=hidden"],
            **flags,
        )
    ],
)
