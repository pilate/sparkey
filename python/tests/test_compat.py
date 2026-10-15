"""The tests of spotify/sparkey-python, ported to pytest.

They check that code written for the old ctypes bindings keeps working.
"""

import binascii

import sparkey

BINARY_KEYS = [
    "a7cb5f92f019fda84d5dd73c257d6f724402d56a",
    "0fae6c3bec0e162343afee39009c8b7e7ad77747",
    "1bff07d74a2080e1ce2b90b12f30f581f993b56f",
    "d04d6442f15527716e89d012018718d124ac5897",
    "7b3605d73c5426f0600acd73535c1a7c96c4ffb9",
    "23c7102024d4aeb4b641db7370083a87586dea43",
    "3fa47cce74af2e39a67d3bf559d8ba2c81688963",
    "280ed99d30b701b97d436b3ac57231e9e38e8a4a",
    "6706a6c6c7ea2f4cfe1eb8dd786427675c4cbb4b",
    "a8a39e52b08763ce1610400f0e789b798e89b885",
    "2d70d150c52804485bc04367155ae4a2ff89768f",
    "28547a874f734dc7062c859e8409a39d7903f9f1",
    "8906ee2fcc0f62f782a9c95557bb785e9145cc33",
    "cec120769a81c544ff171ff21c5b66217103f038",
    "f6a714ad3b43963fe38ab3541286f9440ae96d16",
    "a715a608f9baf1c26e0c59c72592a2b19412270b",
    "30f7286d1100f4c115add1df87312e00a6b71012",
    "059c6aa8b39796b9e6c10a70ac84a209eeed3c81",
    "f9f982ba4ea5906e455cef05036700948ed4c576",
]


def test_smoke(hashfile, logfile):
    writer = sparkey.LogWriter(logfile)
    for i in range(10):
        writer.put("key%d" % i, "value%d" % i)
    writer.close()

    reader = sparkey.LogReader(logfile)
    for i, (key, value, type_) in enumerate(reader):
        assert key == b"key%d" % i
        assert value == b"value%d" % i
        assert type_ == sparkey.IterType.PUT
    assert i == 9
    reader.close()

    sparkey.writehash(hashfile, logfile)

    hashreader = sparkey.HashReader(hashfile, logfile)
    assert len(hashreader) == 10
    for i in range(10):
        assert b"key%d" % i in hashreader
    assert b"key_miss" not in hashreader

    for i, (key, value) in enumerate(hashreader):
        assert key == b"key%d" % i
        assert value == b"value%d" % i
    assert i == 9

    assert hashreader.get("key0") == b"value0"
    assert hashreader.get("key9") == b"value9"
    assert hashreader.get("key10") is None
    hashreader.close()


def test_append(hashfile, logfile):
    keys = ("a", "b", "c")
    writer = sparkey.HashWriter(hashfile, logfile)
    for key in keys:
        writer.put(key, "value")
    writer.close()
    reader = sparkey.HashReader(hashfile, logfile)
    for key in keys:
        assert reader[key] == b"value"
    reader.close()

    for i in range(10):
        writer = sparkey.HashWriter(hashfile, logfile, mode="APPEND")
        for key in keys:
            writer.put(key, "value%d" % i)
        writer.close()
        reader = sparkey.HashReader(hashfile, logfile)
        for key in keys:
            assert reader[key] == b"value%d" % i
        reader.close()


def test_recreate(hashfile, logfile):
    keys = ("a", "b", "c")
    for _ in range(10):
        writer = sparkey.HashWriter(hashfile, logfile)
        for key in keys:
            writer.put(key, "value")
        writer.close()

        reader = sparkey.HashReader(hashfile, logfile)
        assert len(reader) == 3
        for key in keys:
            assert reader[key] == b"value"
        reader.close()


def test_binary_key_and_value(hashfile, logfile):
    writer = sparkey.HashWriter(hashfile, logfile)
    for key in BINARY_KEYS:
        writer.put(binascii.unhexlify(key), binascii.unhexlify(key))
    writer.close()

    reader = sparkey.HashReader(hashfile, logfile)
    for key in BINARY_KEYS:
        raw = binascii.unhexlify(key)
        assert reader[raw] == raw
        assert reader.get(raw) == raw
    reader.close()


def test_binary_key(hashfile, logfile):
    writer = sparkey.HashWriter(hashfile, logfile)
    for key in BINARY_KEYS:
        writer.put(binascii.unhexlify(key), "value")
    writer.flush()

    for key in BINARY_KEYS:
        raw = binascii.unhexlify(key)
        assert writer.getAsString(raw) == "value"
        assert writer[raw] == b"value"
        assert writer.get(raw) == b"value"
    writer.close()

    reader = sparkey.HashReader(hashfile, logfile)
    for key in BINARY_KEYS:
        raw = binascii.unhexlify(key)
        assert reader.getAsString(raw) == "value"
        assert reader[raw] == b"value"
        assert reader.get(raw) == b"value"
    reader.close()


def test_compression_constants():
    assert sparkey.Compression.NONE == 0
    assert sparkey.Compression.SNAPPY == 1
    assert sparkey.IterType.PUT == 0
    assert sparkey.IterType.DELETE == 1
    assert sparkey.IterState.ACTIVE == 1
