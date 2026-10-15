import os
import pathlib
import random
import threading
import weakref
from collections import OrderedDict

import pytest

import sparkey

COMPRESSIONS = [
    (sparkey.Compression.NONE, 0),
    (sparkey.Compression.SNAPPY, 64),
    (sparkey.Compression.SNAPPY, 4096),
    (sparkey.Compression.ZSTD, 64),
]
COMPRESSION_IDS = ["none", "snappy-64", "snappy-4096", "zstd-64"]


def random_ops(seed, count=3000):
    """Returns a list of ("put", key, value) / ("delete", key) operations and the resulting dict."""
    rng = random.Random(seed)
    ops = []
    model = {}
    for i in range(count):
        key = b"k%d" % rng.randrange(count // 2)
        if rng.random() < 0.1:
            ops.append(("delete", key))
            model.pop(key, None)
        else:
            # Some values are larger than the smallest compression block.
            size = rng.choice([0, 1, 10, 100, 300])
            value = bytes(rng.getrandbits(8) for _ in range(size))
            ops.append(("put", key, value))
            model[key] = value
    return ops, model


def write_ops(writer, ops):
    for op in ops:
        if op[0] == "put":
            writer.put(op[1], op[2])
        else:
            writer.delete(op[1])


@pytest.mark.parametrize("compression,block_size", COMPRESSIONS, ids=COMPRESSION_IDS)
@pytest.mark.parametrize("hash_size", [0, 4, 8])
def test_matches_dict(hashfile, logfile, compression, block_size, hash_size):
    ops, model = random_ops(1)
    with sparkey.HashWriter(hashfile, logfile, compression_type=compression,
                            compression_block_size=block_size, hash_size=hash_size) as writer:
        write_ops(writer, ops)

    with sparkey.HashReader(hashfile, logfile) as reader:
        assert len(reader) == len(model)
        for key, value in model.items():
            assert reader[key] == value
            assert reader.get(key) == value
            assert key in reader
        for i in range(2000):
            missing = b"missing%d" % i
            assert missing not in reader
            assert reader.get(missing) is None
            with pytest.raises(KeyError):
                reader[missing]

        # Iteration yields live entries in log order of their last put.
        expected = OrderedDict()
        for op in ops:
            if op[0] == "put":
                expected.pop(op[1], None)
                expected[op[1]] = op[2]
            else:
                expected.pop(op[1], None)
        assert list(reader) == list(expected.items())
        assert list(reader.items()) == list(expected.items())
        assert list(reader.iteritems()) == list(expected.items())
        assert list(reader.keys()) == list(expected.keys())
        assert list(reader.values()) == list(expected.values())

        keys = list(model) + [b"missing"]
        assert reader.get_many(keys) == [model[k] for k in model] + [None]
        assert reader.get_many(keys, b"dflt")[-1] == b"dflt"

    with sparkey.LogReader(logfile) as log:
        entries = list(log)
    assert len(entries) == len(ops)
    for entry, op in zip(entries, ops):
        if op[0] == "put":
            assert entry == (op[1], op[2], sparkey.IterType.PUT)
        else:
            assert entry == (op[1], b"", sparkey.IterType.DELETE)


@pytest.mark.parametrize("compression,block_size", COMPRESSIONS, ids=COMPRESSION_IDS)
def test_large_keys_and_values(hashfile, logfile, compression, block_size):
    # Keys and values spanning several compression blocks.
    items = {
        b"small": b"x",
        b"K" * 1000: b"V" * 100000,
        os.urandom(500): os.urandom(20000),
        b"": b"empty key",
        b"empty value": b"",
    }
    with sparkey.HashWriter(hashfile, logfile, compression_type=compression,
                            compression_block_size=block_size) as writer:
        writer.update(items)
    with sparkey.HashReader(hashfile, logfile) as reader:
        for key, value in items.items():
            assert reader[key] == value
        assert dict(reader) == items


def test_key_types(hashfile, logfile):
    with sparkey.HashWriter(hashfile, logfile) as writer:
        writer.put(b"bytes", b"1")
        writer.put("str", "2")
        writer.put(bytearray(b"bytearray"), bytearray(b"3"))
        writer.put(memoryview(b"xmemoryview")[1:], memoryview(b"4"))
        writer["unicode é中"] = "é"
    with sparkey.HashReader(hashfile, logfile) as reader:
        assert reader["bytes"] == b"1"
        assert reader[b"str"] == b"2"
        assert reader[bytearray(b"bytearray")] == b"3"
        assert reader[memoryview(b"memoryview")] == b"4"
        assert reader["unicode é中"] == "é".encode()
        assert reader.getAsString("unicode é中") == "é"
        assert reader.getAsString("nope") is None
        assert reader.has_key("str")
        assert not reader.has_key("nope")
        with pytest.raises(sparkey.SparkeyException):
            reader.get(1)
        with pytest.raises(sparkey.SparkeyException):
            1 in reader
        with pytest.raises(sparkey.SparkeyException):
            reader.get_many([b"bytes", 1])
    with sparkey.LogWriter(logfile) as writer:
        with pytest.raises(sparkey.SparkeyException):
            writer.put(b"key", 1)
        with pytest.raises(sparkey.SparkeyException):
            writer.put(None, b"value")
        with pytest.raises(sparkey.SparkeyException):
            writer.delete(1)
        with pytest.raises(sparkey.SparkeyException):
            writer.update([(b"key", 1)])
        with pytest.raises(TypeError):
            writer.put(b"only key")


def test_get_default(hashfile, logfile):
    with sparkey.HashWriter(hashfile, logfile) as writer:
        writer["a"] = "1"
    with sparkey.HashReader(hashfile, logfile) as reader:
        assert reader.get("a", 5) == b"1"
        assert reader.get("b", 5) == 5
        with pytest.raises(TypeError):
            reader.get()
        with pytest.raises(TypeError):
            reader.get("a", 1, 2)


def test_update(hashfile, logfile):
    class Mapping:
        def items(self):
            return [("m1", "v1"), ("m2", "v2")]

    with sparkey.HashWriter(hashfile, logfile) as writer:
        writer.update({"d1": "v1"})
        writer.update([("l1", "v1"), ["l2", "v2"]])
        writer.update((("t1", "v1"),))
        writer.update((k, v) for k, v in [("g1", "v1")])
        writer.update(Mapping())
        with pytest.raises(ValueError):
            writer.update([("a", "b", "c")])
        with pytest.raises(TypeError):
            writer.update([1])
        with pytest.raises(TypeError):
            writer.update(1)
    with sparkey.HashReader(hashfile, logfile) as reader:
        assert sorted(reader.keys()) == [b"d1", b"g1", b"l1", b"l2", b"m1", b"m2", b"t1"]


def test_delete(hashfile, logfile):
    with sparkey.HashWriter(hashfile, logfile) as writer:
        writer["a"] = "1"
        writer["b"] = "2"
        del writer["a"]
        writer.delete("b")
        writer["b"] = "3"
    with sparkey.HashReader(hashfile, logfile) as reader:
        assert "a" not in reader
        assert reader["b"] == b"3"
        assert len(reader) == 1


def test_closed_objects(hashfile, logfile):
    writer = sparkey.HashWriter(hashfile, logfile)
    writer["a"] = "1"
    writer.close()
    assert writer.closed
    writer.close()
    with pytest.raises(sparkey.SparkeyException):
        writer["a"] = "2"
    with pytest.raises(sparkey.SparkeyException):
        writer.flush()

    reader = sparkey.HashReader(hashfile, logfile)
    iterator = iter(reader)
    values = reader.values()
    assert next(values) == b"1"
    reader.close()
    assert reader.closed
    reader.close()
    for call in (lambda: reader["a"], lambda: reader.get("a"), lambda: "a" in reader, lambda: len(reader),
                 lambda: reader.get_many(["a"]), lambda: iter(reader), lambda: next(iterator)):
        with pytest.raises(sparkey.SparkeyException, match="closed"):
            call()

    log = sparkey.LogReader(logfile)
    log_iter = iter(log)
    log.close()
    with pytest.raises(sparkey.SparkeyException, match="closed"):
        next(log_iter)


def test_iterator_close(hashfile, logfile):
    with sparkey.HashWriter(hashfile, logfile) as writer:
        writer.update({"a": "1", "b": "2"})
    with sparkey.HashReader(hashfile, logfile) as reader:
        iterator = sparkey.HashIterator(reader)
        assert next(iterator) == (b"a", b"1")
        iterator.close()
        assert list(iterator) == []
        log_iter = sparkey.LogIter(sparkey.LogReader(logfile))
        assert next(log_iter) == (b"a", b"1", sparkey.IterType.PUT)


def test_iterator_outlives_reader_reference(hashfile, logfile):
    with sparkey.HashWriter(hashfile, logfile) as writer:
        writer.update({"a": "1", "b": "2"})
    iterator = iter(sparkey.HashReader(hashfile, logfile))
    assert list(iterator) == [(b"a", b"1"), (b"b", b"2")]
    assert list(iter(sparkey.LogReader(logfile))) == [(b"a", b"1", 0), (b"b", b"2", 0)]


def test_errors(tmp_path, hashfile, logfile):
    with pytest.raises(sparkey.SparkeyException) as info:
        sparkey.HashReader(str(tmp_path / "missing.spi"), str(tmp_path / "missing.spl"))
    assert info.value.code == -100
    assert "missing.spi" in str(info.value)
    with pytest.raises(sparkey.SparkeyException):
        sparkey.LogReader(str(tmp_path / "missing.spl"))
    with pytest.raises(sparkey.SparkeyException):
        sparkey.LogWriter(str(tmp_path / "missing.spl"), mode="APPEND")
    with pytest.raises(sparkey.SparkeyException) as info:
        sparkey.LogWriter(logfile, mode="BOGUS")
    assert info.value.code is None
    with pytest.raises(sparkey.SparkeyException) as info:
        sparkey.LogWriter(logfile, compression_type=7)
    assert info.value.code == -210
    with pytest.raises(sparkey.SparkeyException) as info:
        sparkey.LogWriter(logfile, compression_type=sparkey.Compression.SNAPPY, compression_block_size=1)
    assert info.value.code == -209
    with pytest.raises(sparkey.SparkeyException) as info:
        sparkey.HashWriter(hashfile, logfile, hash_size=3)
    assert info.value.code == -307
    with pytest.raises(sparkey.SparkeyException) as info:
        sparkey.writehash(hashfile, logfile, hash_size=3)
    with pytest.raises(sparkey.SparkeyException):
        sparkey.LogReader(1)
    with pytest.raises(sparkey.SparkeyException):
        sparkey.HashReader(hashfile, 1)
    with pytest.raises(ValueError):
        sparkey.HashReader(str(tmp_path / "noextension"))
    assert sparkey.SparkeyException.code is None


def test_mismatched_files(tmp_path):
    a = sparkey.HashWriter(str(tmp_path / "a.spi"))
    a["x"] = "1"
    a.close()
    b = sparkey.HashWriter(str(tmp_path / "b.spi"))
    b["x"] = "1"
    b.close()
    with pytest.raises(sparkey.SparkeyException) as info:
        sparkey.HashReader(str(tmp_path / "a.spi"), str(tmp_path / "b.spl"))
    assert info.value.code == -305


def test_paths(tmp_path):
    hashfile = tmp_path / "data.spi"
    with sparkey.HashWriter(hashfile) as writer:
        writer["a"] = "1"
    assert (tmp_path / "data.spl").exists()
    with sparkey.HashReader(hashfile) as reader:
        assert reader["a"] == b"1"
        assert "data.spi" in repr(reader)
    with sparkey.HashReader(bytes(hashfile), pathlib.Path(tmp_path / "data.spl")) as reader:
        assert reader["a"] == b"1"
    sparkey.writehash(hashfile)
    sparkey.writehash(hashfile, logfile=tmp_path / "data.spl", hash_size=8)
    assert "closed" in repr(reader)


def test_hash_writer_reads_flushed_data(hashfile, logfile):
    writer = sparkey.HashWriter(hashfile, logfile)
    writer["a"] = "1"
    writer.flush()
    assert writer["a"] == b"1"
    assert writer.get("b") is None
    writer["b"] = "2"
    writer.flush()
    assert writer["b"] == b"2"
    assert list(writer) == [(b"a", b"1"), (b"b", b"2")]
    assert list(writer.iteritems()) == [(b"a", b"1"), (b"b", b"2")]
    assert writer["c"] is None
    writer.close()
    assert writer.closed


def test_hash_writer_destroy(hashfile, logfile):
    with sparkey.HashWriter(hashfile, logfile) as writer:
        writer["a"] = "1"
    writer = sparkey.HashWriter(hashfile, logfile, mode="APPEND")
    writer["b"] = "2"
    writer.destroy()
    with sparkey.HashReader(hashfile, logfile) as reader:
        # The log has b, but the hash was not rebuilt.
        assert "b" not in reader
        assert len(list(sparkey.LogReader(logfile))) == 2
    sparkey.writehash(hashfile, logfile)
    with sparkey.HashReader(hashfile, logfile) as reader:
        assert reader["b"] == b"2"


def test_log_appended_after_hash(hashfile, logfile):
    with sparkey.HashWriter(hashfile, logfile) as writer:
        writer["a"] = "1"
    with sparkey.LogWriter(logfile, mode="APPEND") as writer:
        writer["b"] = "2"
    with sparkey.HashReader(hashfile, logfile) as reader:
        assert reader["a"] == b"1"
        assert "b" not in reader
        assert list(reader) == [(b"a", b"1")]


def test_weakref_and_subclass(hashfile, logfile):
    class Writer(sparkey.HashWriter):
        pass

    class Reader(sparkey.HashReader):
        def double(self, key):
            return self[key] * 2

    with Writer(hashfile, logfile) as writer:
        writer["a"] = "1"
    assert isinstance(writer, sparkey.LogWriter)
    reader = Reader(hashfile, logfile)
    assert reader.double("a") == b"11"
    ref = weakref.ref(reader)
    del reader
    assert ref() is None


@pytest.mark.parametrize("compression,block_size", COMPRESSIONS[:2], ids=COMPRESSION_IDS[:2])
def test_threads(hashfile, logfile, compression, block_size):
    items = {b"key%d" % i: b"value%d" % i for i in range(5000)}
    with sparkey.HashWriter(hashfile, logfile, compression_type=compression,
                            compression_block_size=block_size) as writer:
        writer.update(items)
    reader = sparkey.HashReader(hashfile, logfile)
    errors = []

    def work(seed):
        rng = random.Random(seed)
        keys = list(items)
        try:
            for _ in range(20000):
                key = rng.choice(keys)
                if reader[key] != items[key]:
                    errors.append(key)
        except Exception as e:  # pragma: no cover
            errors.append(e)

    threads = [threading.Thread(target=work, args=(i,)) for i in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []
    reader.close()


def test_reader_holding_its_iterator_is_collected(hashfile, logfile):
    import gc

    class Reader(sparkey.HashReader):
        pass

    with sparkey.HashWriter(hashfile, logfile) as writer:
        writer["a"] = "1"
    reader = Reader(hashfile, logfile)
    reader.iterator = iter(reader)
    ref = weakref.ref(reader)
    del reader
    gc.collect()
    assert ref() is None


def test_subclass_with_own_init(hashfile, logfile):
    # Natural with sparkey-python's pure Python classes, so it must keep working.
    class Writer(sparkey.HashWriter):
        def __init__(self, base, note):
            super().__init__(base + ".spi", base + ".spl")
            self.note = note

    class Reader(sparkey.HashReader):
        def __init__(self, hashfile, logfile, max_items):
            super().__init__(hashfile, logfile)
            self.max_items = max_items

    base = hashfile[:-4]
    with Writer(base, "n") as writer:
        writer["a"] = "1"
    assert writer.note == "n"
    reader = Reader(hashfile, logfile, 10)
    assert reader.max_items == 10
    assert reader["a"] == b"1"


def test_reinit_and_uninitialized(hashfile, logfile, tmp_path):
    with sparkey.HashWriter(hashfile, logfile) as writer:
        writer["a"] = "1"
    other = str(tmp_path / "other.spi")
    with sparkey.HashWriter(other) as writer:
        writer["b"] = "2"

    reader = sparkey.HashReader(hashfile, logfile)
    reader.__init__(other)
    assert reader["b"] == b"2"
    assert "a" not in reader
    with pytest.raises(sparkey.SparkeyException):
        reader.__init__(str(tmp_path / "missing.spi"))
    assert reader.closed

    for cls in (sparkey.HashReader, sparkey.LogReader, sparkey.LogWriter, sparkey.HashWriter):
        obj = cls.__new__(cls)
        assert obj.closed
        assert "closed" in repr(obj)
    with pytest.raises(sparkey.SparkeyException):
        sparkey.HashReader.__new__(sparkey.HashReader).get("a")
    with pytest.raises(sparkey.SparkeyException):
        sparkey.HashWriter.__new__(sparkey.HashWriter).put("a", "b")

    # LogWriter.__init__ on a HashWriter leaves it without a hash file.
    writer = sparkey.HashWriter.__new__(sparkey.HashWriter)
    sparkey.LogWriter.__init__(writer, logfile)
    with pytest.raises(sparkey.SparkeyException):
        writer.flush()
    writer.destroy()


def test_keyword_arguments(hashfile, logfile):
    # The argument names are those of sparkey-python.
    with sparkey.LogWriter(logfile) as writer:
        writer.put(key=b"a", value=b"0")
        writer.put(b"b", value=b"0")
        writer.delete(key=b"b")
        with pytest.raises(TypeError):
            writer.put(k=b"a", v=b"1")
        with pytest.raises(TypeError):
            writer.put(b"a", b"1", value=b"2")
        with pytest.raises(TypeError):
            writer.put(key=b"a")
        with pytest.raises(TypeError):
            writer.put(b"a", b"1", b"2")
        with pytest.raises(TypeError):
            writer.put(key=b"a", val=b"1")
    with sparkey.HashWriter(hashfile, logfile, mode="APPEND") as writer:
        writer.put(k=b"a", v=b"1")
        writer.put(b"b", v=b"2")
        writer.put(b"c", b"3")
        writer.delete(k=b"c")
        with pytest.raises(TypeError):
            writer.put(key=b"a", value=b"1")
        with pytest.raises(TypeError):
            writer.delete(key=b"a")
    with sparkey.HashReader(hashfile, logfile) as reader:
        assert reader.get(key=b"a") == b"1"
        assert reader.get(b"x", default=5) == 5
        assert reader.getAsString(key=b"b") == "2"
        assert reader.has_key(key=b"a")
        assert reader.get_many(keys=[b"a", b"x"], default=0) == [b"1", 0]
        with pytest.raises(TypeError):
            reader.get(default=1)


def test_hash_writer_contains(hashfile, logfile):
    writer = sparkey.HashWriter(hashfile, logfile)
    writer["a"] = "1"
    writer.flush()
    assert "a" in writer
    assert "b" not in writer
    writer.close()
    with pytest.raises(sparkey.SparkeyException):
        "a" in writer


def test_unclosed_writer_reports_flush_errors(tmp_path):
    import gc
    import sys

    path = tmp_path / "gone"
    path.mkdir()
    writer = sparkey.LogWriter(str(path / "x.spl"))
    writer["a"] = "1"
    # Make the final flush fail by closing the writer's file descriptor under it.
    fds = set(os.listdir("/proc/self/fd"))
    seen = []
    old_hook = sys.unraisablehook
    sys.unraisablehook = seen.append
    try:
        for fd in fds:
            try:
                if os.readlink(f"/proc/self/fd/{fd}") == str(path / "x.spl"):
                    os.close(int(fd))
            except OSError:
                pass
        del writer
        gc.collect()
    finally:
        sys.unraisablehook = old_hook
    assert len(seen) == 1
    assert isinstance(seen[0].exc_value, sparkey.SparkeyException)
