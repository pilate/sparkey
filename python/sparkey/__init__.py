"""Fast Python bindings for the sparkey key/value store, compatible with spotify/sparkey-python."""

from ._sparkey import (
    HashIterator,
    HashReader,
    HashWriter,
    LogIter,
    LogReader,
    LogWriter,
    SparkeyException,
    writehash,
)

__version__ = "2.0.2"


class Compression:
    """Compression types for LogWriter and HashWriter."""

    NONE = 0
    SNAPPY = 1
    ZSTD = 2


class IterState:
    NEW = 0
    ACTIVE = 1
    CLOSED = 2
    INVALID = 3


class IterType:
    """Entry types yielded by iterating a LogReader."""

    PUT = 0
    DELETE = 1


__all__ = [
    "Compression",
    "HashIterator",
    "HashReader",
    "HashWriter",
    "IterState",
    "IterType",
    "LogIter",
    "LogReader",
    "LogWriter",
    "SparkeyException",
    "writehash",
]
