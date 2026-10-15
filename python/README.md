sparkey for Python
==================

Fast Python bindings for [sparkey](https://github.com/pilate/sparkey): a
CPython C extension with libsparkey compiled in. The API is that of
[spotify/sparkey-python](https://github.com/spotify/sparkey-python), so existing
code keeps working with `import sparkey`.

Installing
----------
Needs a C compiler, the Python headers and the snappy and zstd development
files (`libsnappy-dev` and `libzstd-dev` on Debian and Ubuntu). From the root of
this repository:

    pip install .

Python 3.10 or newer is required; libsparkey itself does not need to be
installed. Tested on Linux. Uninstall `sparkey-python` first, since both
install a module named `sparkey`.

Usage
-----
```python
import sparkey

with sparkey.HashWriter("data.spi") as writer:  # log goes to data.spl
    writer.put(b"key", b"value")
    writer["other"] = "str is stored as UTF-8"
    writer.update({b"a": b"1", b"b": b"2"})  # fastest way to write many entries
    del writer[b"a"]
# close() wrote the hash file

with sparkey.HashReader("data.spi") as reader:
    reader[b"key"]                   # b"value", KeyError if missing
    reader.get(b"missing", b"")      # b"" (default None)
    reader.get_many([b"key", b"b"])  # [b"value", b"2"]
    b"key" in reader, len(reader)    # True, 3
    for key, value in reader:        # live entries, in log order
        ...

with sparkey.LogReader("data.spl") as log:
    for key, value, type_ in log:    # every entry, type_ is IterType.PUT or DELETE
        ...
```

Keys and values can be `bytes`, `str` (stored as UTF-8) or any bytes-like
object; values are returned as `bytes`. Writers take
`compression_type=sparkey.Compression.SNAPPY` or `ZSTD` and a
`compression_block_size`. A lookup decompresses a whole block, so keep blocks
small when random lookups matter.

Performance
-----------
Measured with `python/bench/bench.py` on one laptop (Python 3.12), 1,000,000
entries such as `b"key_123" -> b"value_123"`, random lookups, uncompressed:

| Operation              | sparkey-python | these bindings | speedup |
|------------------------|---------------:|---------------:|--------:|
| `put`                  |       1,254 ns |          75 ns |     17x |
| `update` (vs `put`)    |       1,254 ns |          53 ns |     24x |
| `get`, key exists      |       4,060 ns |         263 ns |     15x |
| `get_many` (vs `get`)  |       4,060 ns |         189 ns |     21x |
| `get`, key missing     |       1,587 ns |         145 ns |     11x |
| `key in reader`        |       1,607 ns |         224 ns |      7x |
| iterate a `HashReader` |       6,270 ns |         216 ns |     29x |
| iterate a `LogReader`  |       6,000 ns |          89 ns |     67x |

Lookups in uncompressed logs read the memory-mapped files directly, and
`get_many` prefetches 16 keys at a time so their cache misses overlap. With
snappy and 4 KB blocks a lookup takes about 7 us (11 us with sparkey-python),
nearly all of it decompression.

Readers can be shared between threads; a writer must be used by one thread at
a time. Lookups hold the GIL. Opening files and writing hash files release it.
Free-threaded Python builds keep the GIL enabled for this module.

Differences from sparkey-python
-------------------------------
Additions: `get(key, default)`, `get_many()`, `items()`, `keys()` and
`values()` on readers, `update()` on writers, context managers and `closed`,
`Compression.ZSTD`, an optional `logfile` (defaults to the hash filename with
`.spl`), `os.PathLike` paths, and a `code` attribute on `SparkeyException`.

Changes:

* Python 3 only.
* `HashWriter.get()` sees the entries of every `flush()`, not only the first.
* `HashWriter.close()` releases the writer even when writing the hash fails.
* An invalid `compression_type` raises `SparkeyException` instead of writing
  a broken log.
* `HashWriter` is a subclass of `LogWriter`.
* Iterators have no `next()` method (use `next(iterator)`), and hash iterators
  no `get()` or `getAsString()`.

Testing
-------
    pip install . pytest
    pytest
