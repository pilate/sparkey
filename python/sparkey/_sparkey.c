/*
 * CPython extension for sparkey.
 *
 * libsparkey is compiled into this module, so lookups can read the hash and
 * log mmaps directly instead of going through the public iterator API. For
 * uncompressed logs a lookup is: hash the key, probe the hash table, parse the
 * entry header and copy the value into a new bytes object. Compressed logs go
 * through sparkey_hash_get with an iterator that is reused across lookups, so
 * repeated lookups in the same block skip decompression.
 *
 * Lookups and iteration keep the GIL: they take well under a microsecond, which
 * is less than releasing and reacquiring it would cost. Opening files, flushing
 * writers and writing hash files release it.
 */

#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include <stdlib.h>
#include <string.h>

#include "sparkey.h"
#include "sparkey-internal.h"

static PyObject *SparkeyException;

static PyTypeObject LogWriterType;
static PyTypeObject HashWriterType;
static PyTypeObject LogReaderType;
static PyTypeObject HashReaderType;
static PyTypeObject LogIterType;
static PyTypeObject HashIterType;

/* Errors */

static PyObject *raise_code(sparkey_returncode code, PyObject *path) {
  PyObject *msg;
  if (path != NULL) {
    PyObject *decoded = PyUnicode_DecodeFSDefaultAndSize(PyBytes_AS_STRING(path), PyBytes_GET_SIZE(path));
    if (decoded == NULL) {
      return NULL;
    }
    msg = PyUnicode_FromFormat("%s: %R", sparkey_errstring(code), decoded);
    Py_DECREF(decoded);
  } else {
    msg = PyUnicode_FromString(sparkey_errstring(code));
  }
  if (msg == NULL) {
    return NULL;
  }
  PyObject *exc = PyObject_CallOneArg(SparkeyException, msg);
  Py_DECREF(msg);
  if (exc == NULL) {
    return NULL;
  }
  PyObject *code_obj = PyLong_FromLong(code);
  if (code_obj == NULL || PyObject_SetAttrString(exc, "code", code_obj) < 0) {
    Py_XDECREF(code_obj);
    Py_DECREF(exc);
    return NULL;
  }
  Py_DECREF(code_obj);
  PyErr_SetObject(SparkeyException, exc);
  Py_DECREF(exc);
  return NULL;
}

static PyObject *raise_closed(const char *what) {
  PyErr_Format(SparkeyException, "%s is closed", what);
  return NULL;
}

static PyObject *raise_corrupt(void) {
  PyErr_SetString(SparkeyException, "Corrupt sparkey log: entry out of bounds");
  return NULL;
}

/* Keys and values: bytes, str (UTF-8 encoded) or anything with the buffer protocol */

typedef struct {
  const char *ptr;
  Py_ssize_t len;
  int has_view;
  Py_buffer view;
} databuf;

static inline int databuf_get(PyObject *obj, databuf *d, const char *what) {
  if (PyBytes_CheckExact(obj)) {
    d->ptr = PyBytes_AS_STRING(obj);
    d->len = PyBytes_GET_SIZE(obj);
    d->has_view = 0;
    return 0;
  }
  if (PyUnicode_Check(obj)) {
    d->ptr = PyUnicode_AsUTF8AndSize(obj, &d->len);
    d->has_view = 0;
    return d->ptr == NULL ? -1 : 0;
  }
  if (PyObject_GetBuffer(obj, &d->view, PyBUF_SIMPLE) < 0) {
    if (PyErr_ExceptionMatches(PyExc_TypeError)) {
      PyErr_Format(SparkeyException, "%s must be bytes, str or a bytes-like object, not %.100s",
                   what, Py_TYPE(obj)->tp_name);
    }
    return -1;
  }
  d->ptr = d->view.buf;
  d->len = d->view.len;
  d->has_view = 1;
  return 0;
}

static inline void databuf_release(databuf *d) {
  if (d->has_view) {
    PyBuffer_Release(&d->view);
  }
}

/* Paths: str, bytes or os.PathLike, converted to bytes in the filesystem encoding */

static int path_get(PyObject *obj, PyObject **out) {
  if (PyUnicode_FSConverter(obj, out)) {
    return 0;
  }
  if (PyErr_ExceptionMatches(PyExc_TypeError)) {
    PyErr_Format(SparkeyException, "filename must be str, bytes or os.PathLike, not %.100s", Py_TYPE(obj)->tp_name);
  }
  return -1;
}

/* Builds the log filename that belongs to a hash filename (x.spi -> x.spl). */
static PyObject *derive_log_filename(PyObject *hashfile) {
  char *name = sparkey_create_log_filename(PyBytes_AS_STRING(hashfile));
  if (name == NULL) {
    PyErr_SetString(PyExc_ValueError, "logfile is required when hashfile does not end in .spi");
    return NULL;
  }
  PyObject *res = PyBytes_FromString(name);
  free(name);
  return res;
}

/* Formats "<name 'path'>" or "<name 'path' (closed)>" for reprs. */
static PyObject *path_repr(const char *name, PyObject *path, int closed) {
  if (path == NULL) {
    return PyUnicode_FromFormat("<%s (closed)>", name);
  }
  PyObject *decoded = PyUnicode_DecodeFSDefaultAndSize(PyBytes_AS_STRING(path), PyBytes_GET_SIZE(path));
  if (decoded == NULL) {
    return NULL;
  }
  PyObject *res = PyUnicode_FromFormat("<%s %R%s>", name, decoded, closed ? " (closed)" : "");
  Py_DECREF(decoded);
  return res;
}

/*
 * Parses METH_FASTCALL | METH_KEYWORDS arguments by position or name into
 * out[0..count), of which the first `required` must be given. Missing optional
 * arguments are left NULL.
 */
static int parse_args(const char *fname, PyObject *const *args, Py_ssize_t nargs, PyObject *kwnames,
                      const char *const *names, int required, int count, PyObject **out) {
  if (nargs > count) {
    PyErr_Format(PyExc_TypeError, "%s() takes at most %d arguments (%zd given)", fname, count, nargs);
    return -1;
  }
  for (int i = 0; i < count; i++) {
    out[i] = i < nargs ? args[i] : NULL;
  }
  if (kwnames != NULL) {
    for (Py_ssize_t k = 0; k < PyTuple_GET_SIZE(kwnames); k++) {
      PyObject *name = PyTuple_GET_ITEM(kwnames, k);
      int i = 0;
      while (i < count && PyUnicode_CompareWithASCIIString(name, names[i]) != 0) {
        i++;
      }
      if (i == count) {
        PyErr_Format(PyExc_TypeError, "%s() got an unexpected keyword argument %R", fname, name);
        return -1;
      }
      if (out[i] != NULL) {
        PyErr_Format(PyExc_TypeError, "%s() got multiple values for argument '%s'", fname, names[i]);
        return -1;
      }
      out[i] = args[nargs + k];
    }
  }
  for (int i = 0; i < required; i++) {
    if (out[i] == NULL) {
      PyErr_Format(PyExc_TypeError, "%s() missing required argument '%s'", fname, names[i]);
      return -1;
    }
  }
  return 0;
}

/* Reads the rest of the current key or value from a log iterator into a new bytes object. */
static PyObject *read_chunked(sparkey_logiter *iter, sparkey_logreader *log, uint64_t len, int value) {
  if (len > (uint64_t) PY_SSIZE_T_MAX) {
    return PyErr_NoMemory();
  }
  uint8_t *chunk = NULL;
  uint64_t chunklen = 0;
  sparkey_returncode rc = value
    ? sparkey_logiter_valuechunk(iter, log, len, &chunk, &chunklen)
    : sparkey_logiter_keychunk(iter, log, len, &chunk, &chunklen);
  if (rc != SPARKEY_SUCCESS) {
    return raise_code(rc, NULL);
  }
  if (chunklen == len) {
    return PyBytes_FromStringAndSize((const char *) chunk, (Py_ssize_t) len);
  }
  /* The key or value continues in the next compression block. */
  PyObject *res = PyBytes_FromStringAndSize(NULL, (Py_ssize_t) len);
  if (res == NULL) {
    return NULL;
  }
  uint8_t *dst = (uint8_t *) PyBytes_AS_STRING(res);
  memcpy(dst, chunk, chunklen);
  uint64_t rest = 0;
  rc = value
    ? sparkey_logiter_fill_value(iter, log, len - chunklen, dst + chunklen, &rest)
    : sparkey_logiter_fill_key(iter, log, len - chunklen, dst + chunklen, &rest);
  if (rc != SPARKEY_SUCCESS) {
    Py_DECREF(res);
    return raise_code(rc, NULL);
  }
  if (chunklen + rest != len) {
    Py_DECREF(res);
    return raise_code(SPARKEY_UNEXPECTED_EOF, NULL);
  }
  return res;
}

/* Little endian loads for the hash table */

static inline uint64_t load_le32(const uint8_t *p) {
  uint32_t v;
  memcpy(&v, p, sizeof(v));
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
  v = __builtin_bswap32(v);
#endif
  return v;
}

static inline uint64_t load_le64(const uint8_t *p) {
  uint64_t v;
  memcpy(&v, p, sizeof(v));
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
  v = __builtin_bswap64(v);
#endif
  return v;
}

/* Reads a VLQ number from data[*pos..end). Returns -1 if it runs past end. */
static inline int read_vlq(const uint8_t *data, uint64_t end, uint64_t *pos, uint64_t *out) {
  uint64_t p = *pos;
  uint64_t res = 0;
  unsigned shift = 0;
  while (1) {
    if (p >= end || shift > 63) {
      return -1;
    }
    uint8_t b = data[p++];
    res |= (uint64_t) (b & 0x7f) << shift;
    if (!(b & 0x80)) {
      break;
    }
    shift += 7;
  }
  *pos = p;
  *out = res;
  return 0;
}

/* ------------------------------------------------------------------------- */
/* HashReader */

typedef struct {
  PyObject_HEAD
  sparkey_hashreader *reader; /* NULL when closed */
  sparkey_logiter *iter;      /* reused by lookups in compressed logs */
  PyObject *hashfile;         /* bytes */
  PyObject *logfile;          /* bytes */
  PyObject *weakreflist;

  /* Copied from the reader so lookups need no pointer chasing. */
  uint64_t (*hash)(const uint8_t *data, uint64_t len, uint32_t seed);
  const uint8_t *table;
  uint64_t capacity;
  const uint8_t *log;
  uint64_t log_end;
  uint64_t entry_mask;
  uint32_t seed;
  uint32_t hash_size;
  uint32_t addr_size;
  uint32_t slot_size;
  uint32_t entry_bits;
  int compressed;
} HashReaderObject;

#define HR_CHECK_OPEN(self, ret) \
  do { if ((self)->reader == NULL) { raise_closed("HashReader"); return ret; } } while (0)

/*
 * Looks up a key with the given hash in a hash over an uncompressed log,
 * mirroring sparkey_hash_get. Returns 1 if found, with the value copied into a
 * new bytes object in *out unless out is NULL, 0 if not found and -1 with an
 * exception set.
 */
static int hr_get_uncompressed(HashReaderObject *self, uint64_t hash, const uint8_t *key, uint64_t keylen,
                               PyObject **out) {
  const uint64_t cap = self->capacity;
  const uint8_t *log = self->log;
  const uint64_t end = self->log_end;
  uint64_t slot = hash % cap;
  const uint8_t *p = self->table + slot * self->slot_size;
  uint64_t displacement = 0;

  while (1) {
    uint64_t hash2 = self->hash_size == 4 ? load_le32(p) : load_le64(p);
    uint64_t addr = self->addr_size == 4 ? load_le32(p + self->hash_size) : load_le64(p + self->hash_size);
    if (addr == 0) {
      return 0;
    }
    if (hash2 == hash) {
      uint64_t pos = addr >> self->entry_bits;
      uint64_t skip = addr & self->entry_mask;
      uint64_t a, b, klen, vlen;
      while (1) {
        if (read_vlq(log, end, &pos, &a) < 0 || read_vlq(log, end, &pos, &b) < 0) {
          goto corrupt;
        }
        klen = a == 0 ? b : a - 1;
        vlen = a == 0 ? 0 : b;
        if (klen > end - pos || vlen > end - pos - klen) {
          goto corrupt;
        }
        if (skip == 0) {
          break;
        }
        pos += klen + vlen;
        skip--;
      }
      if (a == 0) {
        /* The hash table never points at deletes. */
        goto corrupt;
      }
      if (klen == keylen && memcmp(log + pos, key, keylen) == 0) {
        if (out != NULL && (*out = PyBytes_FromStringAndSize((const char *) log + pos + klen, (Py_ssize_t) vlen)) == NULL) {
          return -1;
        }
        return 1;
      }
    }
    uint64_t other_displacement = (cap + slot - hash2 % cap) % cap;
    if (displacement > other_displacement || displacement >= cap) {
      return 0;
    }
    displacement++;
    slot++;
    if (slot >= cap) {
      slot = 0;
      p = self->table;
    } else {
      p += self->slot_size;
    }
  }

corrupt:
  raise_corrupt();
  return -1;
}

/*
 * Looks up a key. Returns 1 if found (with a new reference to the value in
 * *out, unless out is NULL), 0 if not found and -1 with an exception set.
 */
static int hr_lookup(HashReaderObject *self, PyObject *keyobj, PyObject **out) {
  HR_CHECK_OPEN(self, -1);
  databuf key;
  if (databuf_get(keyobj, &key, "key") < 0) {
    return -1;
  }
  const uint8_t *k = (const uint8_t *) key.ptr;
  uint64_t klen = (uint64_t) key.len;
  int found;
  if (!self->compressed) {
    found = hr_get_uncompressed(self, self->hash(k, klen, self->seed), k, klen, out);
  } else {
    sparkey_returncode rc = sparkey_hash_get(self->reader, k, klen, self->iter);
    if (rc != SPARKEY_SUCCESS) {
      raise_code(rc, NULL);
      found = -1;
    } else if (sparkey_logiter_state(self->iter) != SPARKEY_ITER_ACTIVE) {
      found = 0;
    } else {
      found = 1;
      if (out != NULL) {
        *out = read_chunked(self->iter, sparkey_hash_getreader(self->reader), sparkey_logiter_valuelen(self->iter), 1);
        if (*out == NULL) {
          found = -1;
        }
      }
    }
  }
  databuf_release(&key);
  return found;
}

static void hr_close(HashReaderObject *self) {
  sparkey_logiter_close(&self->iter);
  sparkey_hash_close(&self->reader);
  self->table = NULL;
  self->log = NULL;
}

/*
 * Files are opened in __init__ rather than __new__, so that subclasses can
 * define __init__ with their own arguments, as they could with the pure Python
 * classes of sparkey-python. Calling __init__ again closes the open files first.
 */
static int HashReader_init(HashReaderObject *self, PyObject *args, PyObject *kwds) {
  static char *kwlist[] = {"hashfile", "logfile", NULL};
  PyObject *hashobj, *logobj = Py_None;
  if (!PyArg_ParseTupleAndKeywords(args, kwds, "O|O:HashReader", kwlist, &hashobj, &logobj)) {
    return -1;
  }
  hr_close(self);
  Py_CLEAR(self->hashfile);
  Py_CLEAR(self->logfile);
  if (path_get(hashobj, &self->hashfile) < 0) {
    return -1;
  }
  if (logobj == Py_None) {
    self->logfile = derive_log_filename(self->hashfile);
    if (self->logfile == NULL) {
      return -1;
    }
  } else if (path_get(logobj, &self->logfile) < 0) {
    return -1;
  }

  /* Other threads can see self while the GIL is released, so only publish the reader once it is set up. */
  sparkey_hashreader *r = NULL;
  sparkey_returncode rc;
  const char *hashname = PyBytes_AS_STRING(self->hashfile);
  const char *logname = PyBytes_AS_STRING(self->logfile);
  Py_BEGIN_ALLOW_THREADS
  rc = sparkey_hash_open(&r, hashname, logname);
  Py_END_ALLOW_THREADS
  if (rc != SPARKEY_SUCCESS) {
    raise_code(rc, self->hashfile);
    return -1;
  }
  /* Another thread may have reinitialized self while the GIL was released. */
  hr_close(self);
  self->reader = r;
  self->compressed = sparkey_uses_compressor(r->log.header.compression_type);
  if (self->compressed) {
    rc = sparkey_logiter_create(&self->iter, &r->log);
    if (rc != SPARKEY_SUCCESS) {
      raise_code(rc, NULL);
      goto error;
    }
  }
  self->hash = r->header.hash_algorithm.hash;
  self->table = r->data + r->header.header_size;
  self->capacity = r->header.hash_capacity;
  self->log = r->log.data;
  self->log_end = r->log.data_len;
  self->seed = r->header.hash_seed;
  self->hash_size = r->header.hash_size;
  self->addr_size = r->header.address_size;
  self->slot_size = r->header.hash_size + r->header.address_size;
  self->entry_bits = r->header.entry_block_bits;
  self->entry_mask = r->header.entry_block_bitmask;
  if (self->capacity == 0 || self->hash == NULL || (self->addr_size != 4 && self->addr_size != 8)) {
    raise_code(SPARKEY_HASH_HEADER_CORRUPT, self->hashfile);
    goto error;
  }
  return 0;

error:
  hr_close(self);
  return -1;
}

static void HashReader_dealloc(HashReaderObject *self) {
  if (self->weakreflist != NULL) {
    PyObject_ClearWeakRefs((PyObject *) self);
  }
  hr_close(self);
  Py_CLEAR(self->hashfile);
  Py_CLEAR(self->logfile);
  Py_TYPE(self)->tp_free((PyObject *) self);
}

static PyObject *HashReader_close(HashReaderObject *self, PyObject *Py_UNUSED(ignored)) {
  hr_close(self);
  Py_RETURN_NONE;
}

static const char *const key_default_names[] = {"key", "default"};

static PyObject *HashReader_get(HashReaderObject *self, PyObject *const *args, Py_ssize_t nargs, PyObject *kwnames) {
  PyObject *key, *dflt;
  if (kwnames == NULL && nargs == 1) {
    key = args[0];
    dflt = Py_None;
  } else {
    PyObject *parsed[2];
    if (parse_args("get", args, nargs, kwnames, key_default_names, 1, 2, parsed) < 0) {
      return NULL;
    }
    key = parsed[0];
    dflt = parsed[1] != NULL ? parsed[1] : Py_None;
  }
  PyObject *value;
  int found = hr_lookup(self, key, &value);
  if (found > 0) {
    return value;
  }
  if (found < 0) {
    return NULL;
  }
  return Py_NewRef(dflt);
}

static PyObject *HashReader_getAsString(HashReaderObject *self, PyObject *const *args, Py_ssize_t nargs,
                                        PyObject *kwnames) {
  PyObject *key;
  if (parse_args("getAsString", args, nargs, kwnames, key_default_names, 1, 1, &key) < 0) {
    return NULL;
  }
  PyObject *value;
  int found = hr_lookup(self, key, &value);
  if (found > 0) {
    PyObject *res = PyUnicode_FromEncodedObject(value, "utf-8", NULL);
    Py_DECREF(value);
    return res;
  }
  if (found < 0) {
    return NULL;
  }
  Py_RETURN_NONE;
}

/*
 * Number of keys get_many works on at once. Their hash slots and log entries
 * are prefetched before any of them is read, so the cache misses of a batch
 * overlap instead of happening one after another.
 */
#define GET_MANY_BATCH 16

static int hr_get_many_uncompressed(HashReaderObject *self, PyObject **keys, Py_ssize_t n, PyObject *dflt,
                                    PyObject *res) {
  databuf bufs[GET_MANY_BATCH];
  uint64_t hashes[GET_MANY_BATCH];
  const uint8_t *log = self->log;

  for (Py_ssize_t start = 0; start < n; start += GET_MANY_BATCH) {
    int count = n - start < GET_MANY_BATCH ? (int) (n - start) : GET_MANY_BATCH;
    for (int i = 0; i < count; i++) {
      if (databuf_get(keys[start + i], &bufs[i], "key") < 0) {
        while (i-- > 0) {
          databuf_release(&bufs[i]);
        }
        return -1;
      }
      hashes[i] = self->hash((const uint8_t *) bufs[i].ptr, (uint64_t) bufs[i].len, self->seed);
      __builtin_prefetch(self->table + (hashes[i] % self->capacity) * self->slot_size);
    }
    /* Prefetch the log entry the first probed slot points at. */
    for (int i = 0; i < count; i++) {
      const uint8_t *p = self->table + (hashes[i] % self->capacity) * self->slot_size;
      uint64_t addr = self->addr_size == 4 ? load_le32(p + self->hash_size) : load_le64(p + self->hash_size);
      uint64_t pos = addr >> self->entry_bits;
      if (addr != 0 && pos < self->log_end) {
        __builtin_prefetch(log + pos);
      }
    }
    int failed = 0;
    for (int i = 0; i < count; i++) {
      PyObject *value;
      int found = failed ? -1 : hr_get_uncompressed(self, hashes[i], (const uint8_t *) bufs[i].ptr,
                                                    (uint64_t) bufs[i].len, &value);
      databuf_release(&bufs[i]);
      if (found < 0) {
        failed = 1;
        continue;
      }
      if (found == 0) {
        value = Py_NewRef(dflt);
      }
      PyList_SET_ITEM(res, start + i, value);
    }
    if (failed) {
      return -1;
    }
  }
  return 0;
}

static PyObject *HashReader_get_many(HashReaderObject *self, PyObject *const *args, Py_ssize_t nargs,
                                     PyObject *kwnames) {
  static const char *const names[] = {"keys", "default"};
  PyObject *parsed[2];
  if (parse_args("get_many", args, nargs, kwnames, names, 1, 2, parsed) < 0) {
    return NULL;
  }
  HR_CHECK_OPEN(self, NULL);
  PyObject *dflt = parsed[1] != NULL ? parsed[1] : Py_None;
  PyObject *seq = PySequence_Fast(parsed[0], "get_many expects an iterable of keys");
  if (seq == NULL) {
    return NULL;
  }
  Py_ssize_t n = PySequence_Fast_GET_SIZE(seq);
  PyObject *res = PyList_New(n);
  if (res == NULL) {
    Py_DECREF(seq);
    return NULL;
  }
  PyObject **keys = PySequence_Fast_ITEMS(seq);
  if (!self->compressed) {
    if (hr_get_many_uncompressed(self, keys, n, dflt, res) < 0) {
      Py_CLEAR(res);
    }
  } else {
    for (Py_ssize_t i = 0; i < n; i++) {
      PyObject *value;
      int found = hr_lookup(self, keys[i], &value);
      if (found < 0) {
        Py_CLEAR(res);
        break;
      }
      if (found == 0) {
        value = Py_NewRef(dflt);
      }
      PyList_SET_ITEM(res, i, value);
    }
  }
  Py_DECREF(seq);
  return res;
}

static PyObject *HashReader_subscript(HashReaderObject *self, PyObject *key) {
  PyObject *value;
  int found = hr_lookup(self, key, &value);
  if (found > 0) {
    return value;
  }
  if (found == 0) {
    PyErr_SetObject(PyExc_KeyError, key);
  }
  return NULL;
}

static int HashReader_contains(HashReaderObject *self, PyObject *key) {
  return hr_lookup(self, key, NULL);
}

static PyObject *HashReader_has_key(HashReaderObject *self, PyObject *const *args, Py_ssize_t nargs,
                                    PyObject *kwnames) {
  PyObject *key;
  if (parse_args("has_key", args, nargs, kwnames, key_default_names, 1, 1, &key) < 0) {
    return NULL;
  }
  int found = hr_lookup(self, key, NULL);
  if (found < 0) {
    return NULL;
  }
  return PyBool_FromLong(found);
}

static Py_ssize_t HashReader_len(HashReaderObject *self) {
  HR_CHECK_OPEN(self, -1);
  return (Py_ssize_t) sparkey_hash_numentries(self->reader);
}

static PyObject *iter_create(PyObject *owner, int mode);

enum { ITER_LOG, ITER_ITEMS, ITER_KEYS, ITER_VALUES };

static PyObject *HashReader_iter(HashReaderObject *self) {
  return iter_create((PyObject *) self, ITER_ITEMS);
}

static PyObject *HashReader_items(HashReaderObject *self, PyObject *Py_UNUSED(ignored)) {
  return iter_create((PyObject *) self, ITER_ITEMS);
}

static PyObject *HashReader_keys(HashReaderObject *self, PyObject *Py_UNUSED(ignored)) {
  return iter_create((PyObject *) self, ITER_KEYS);
}

static PyObject *HashReader_values(HashReaderObject *self, PyObject *Py_UNUSED(ignored)) {
  return iter_create((PyObject *) self, ITER_VALUES);
}

static PyObject *return_self(PyObject *self, PyObject *Py_UNUSED(ignored)) {
  return Py_NewRef(self);
}

static PyObject *call_close(PyObject *self, PyObject *const *Py_UNUSED(args), Py_ssize_t Py_UNUSED(nargs)) {
  PyObject *res = PyObject_CallMethod(self, "close", NULL);
  if (res == NULL) {
    return NULL;
  }
  Py_DECREF(res);
  Py_RETURN_FALSE;
}

static PyObject *HashReader_closed(HashReaderObject *self, void *Py_UNUSED(closure)) {
  return PyBool_FromLong(self->reader == NULL);
}

static PyObject *HashReader_repr(HashReaderObject *self) {
  return path_repr(Py_TYPE(self)->tp_name, self->hashfile, self->reader == NULL);
}

static PyMethodDef HashReader_methods[] = {
  {"get", (PyCFunction) (void (*)(void)) HashReader_get, METH_FASTCALL | METH_KEYWORDS,
   "get($self, key, default=None)\n--\n\nReturn the value for key as bytes, or default if the key is missing."},
  {"getAsString", (PyCFunction) (void (*)(void)) HashReader_getAsString, METH_FASTCALL | METH_KEYWORDS,
   "getAsString($self, key)\n--\n\nReturn the value for key decoded as UTF-8, or None if the key is missing."},
  {"get_many", (PyCFunction) (void (*)(void)) HashReader_get_many, METH_FASTCALL | METH_KEYWORDS,
   "get_many($self, keys, default=None)\n--\n\nLook up several keys and return a list of values, with default for missing keys."},
  {"has_key", (PyCFunction) (void (*)(void)) HashReader_has_key, METH_FASTCALL | METH_KEYWORDS,
   "has_key($self, key)\n--\n\nReturn True if the key exists."},
  {"iteritems", (PyCFunction) HashReader_items, METH_NOARGS,
   "iteritems($self)\n--\n\nIterate over (key, value) pairs of all live entries."},
  {"items", (PyCFunction) HashReader_items, METH_NOARGS,
   "items($self)\n--\n\nIterate over (key, value) pairs of all live entries."},
  {"keys", (PyCFunction) HashReader_keys, METH_NOARGS,
   "keys($self)\n--\n\nIterate over the keys of all live entries."},
  {"values", (PyCFunction) HashReader_values, METH_NOARGS,
   "values($self)\n--\n\nIterate over the values of all live entries."},
  {"close", (PyCFunction) HashReader_close, METH_NOARGS,
   "close($self)\n--\n\nClose the reader. Closing a closed reader does nothing."},
  {"__enter__", (PyCFunction) return_self, METH_NOARGS, NULL},
  {"__exit__", (PyCFunction) (void (*)(void)) call_close, METH_FASTCALL, NULL},
  {NULL}
};

static PyGetSetDef HashReader_getset[] = {
  {"closed", (getter) HashReader_closed, NULL, "True if the reader is closed.", NULL},
  {NULL}
};

static PyMappingMethods HashReader_as_mapping = {
  .mp_length = (lenfunc) HashReader_len,
  .mp_subscript = (binaryfunc) HashReader_subscript,
};

static PySequenceMethods HashReader_as_sequence = {
  .sq_length = (lenfunc) HashReader_len,
  .sq_contains = (objobjproc) HashReader_contains,
};

static PyTypeObject HashReaderType = {
  PyVarObject_HEAD_INIT(NULL, 0)
  .tp_name = "sparkey.HashReader",
  .tp_doc = PyDoc_STR(
    "HashReader(hashfile, logfile=None)\n--\n\n"
    "Open a hash file and its log file for lookups and iteration.\n\n"
    "logfile defaults to hashfile with .spi replaced by .spl. Iterating a\n"
    "HashReader yields (key, value) pairs of all live entries."),
  .tp_basicsize = sizeof(HashReaderObject),
  .tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
  .tp_new = PyType_GenericNew,
  .tp_init = (initproc) HashReader_init,
  .tp_dealloc = (destructor) HashReader_dealloc,
  .tp_repr = (reprfunc) HashReader_repr,
  .tp_as_mapping = &HashReader_as_mapping,
  .tp_as_sequence = &HashReader_as_sequence,
  .tp_iter = (getiterfunc) HashReader_iter,
  .tp_methods = HashReader_methods,
  .tp_getset = HashReader_getset,
  .tp_weaklistoffset = offsetof(HashReaderObject, weakreflist),
};

/* ------------------------------------------------------------------------- */
/* LogReader */

typedef struct {
  PyObject_HEAD
  sparkey_logreader *log; /* NULL when closed */
  PyObject *logfile;      /* bytes */
  PyObject *weakreflist;
} LogReaderObject;

/* Opens the file in __init__, like HashReader_init. */
static int LogReader_init(LogReaderObject *self, PyObject *args, PyObject *kwds) {
  static char *kwlist[] = {"filename", NULL};
  PyObject *fileobj;
  if (!PyArg_ParseTupleAndKeywords(args, kwds, "O:LogReader", kwlist, &fileobj)) {
    return -1;
  }
  sparkey_logreader_close(&self->log);
  Py_CLEAR(self->logfile);
  if (path_get(fileobj, &self->logfile) < 0) {
    return -1;
  }
  sparkey_logreader *log = NULL;
  sparkey_returncode rc;
  const char *name = PyBytes_AS_STRING(self->logfile);
  Py_BEGIN_ALLOW_THREADS
  rc = sparkey_logreader_open(&log, name);
  Py_END_ALLOW_THREADS
  if (rc != SPARKEY_SUCCESS) {
    raise_code(rc, self->logfile);
    return -1;
  }
  /* Another thread may have reinitialized self while the GIL was released. */
  sparkey_logreader_close(&self->log);
  self->log = log;
  return 0;
}

static void LogReader_dealloc(LogReaderObject *self) {
  if (self->weakreflist != NULL) {
    PyObject_ClearWeakRefs((PyObject *) self);
  }
  sparkey_logreader_close(&self->log);
  Py_CLEAR(self->logfile);
  Py_TYPE(self)->tp_free((PyObject *) self);
}

static PyObject *LogReader_close(LogReaderObject *self, PyObject *Py_UNUSED(ignored)) {
  sparkey_logreader_close(&self->log);
  Py_RETURN_NONE;
}

static PyObject *LogReader_iter(LogReaderObject *self) {
  return iter_create((PyObject *) self, ITER_LOG);
}

static PyObject *LogReader_closed(LogReaderObject *self, void *Py_UNUSED(closure)) {
  return PyBool_FromLong(self->log == NULL);
}

static PyObject *LogReader_repr(LogReaderObject *self) {
  return path_repr(Py_TYPE(self)->tp_name, self->logfile, self->log == NULL);
}

static PyMethodDef LogReader_methods[] = {
  {"close", (PyCFunction) LogReader_close, METH_NOARGS,
   "close($self)\n--\n\nClose the reader. Closing a closed reader does nothing."},
  {"__enter__", (PyCFunction) return_self, METH_NOARGS, NULL},
  {"__exit__", (PyCFunction) (void (*)(void)) call_close, METH_FASTCALL, NULL},
  {NULL}
};

static PyGetSetDef LogReader_getset[] = {
  {"closed", (getter) LogReader_closed, NULL, "True if the reader is closed.", NULL},
  {NULL}
};

static PyTypeObject LogReaderType = {
  PyVarObject_HEAD_INIT(NULL, 0)
  .tp_name = "sparkey.LogReader",
  .tp_doc = PyDoc_STR(
    "LogReader(filename)\n--\n\n"
    "Open a log file for iteration. Iterating yields (key, value, type)\n"
    "for every entry, where type is IterType.PUT or IterType.DELETE."),
  .tp_basicsize = sizeof(LogReaderObject),
  .tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
  .tp_new = PyType_GenericNew,
  .tp_init = (initproc) LogReader_init,
  .tp_dealloc = (destructor) LogReader_dealloc,
  .tp_repr = (reprfunc) LogReader_repr,
  .tp_iter = (getiterfunc) LogReader_iter,
  .tp_methods = LogReader_methods,
  .tp_getset = LogReader_getset,
  .tp_weaklistoffset = offsetof(LogReaderObject, weakreflist),
};

/* ------------------------------------------------------------------------- */
/* LogIter and HashIterator */

typedef struct {
  PyObject_HEAD
  PyObject *owner;        /* LogReaderObject for ITER_LOG, HashReaderObject otherwise */
  sparkey_logiter *iter;  /* NULL once exhausted or closed */
  int mode;
} IterObject;

/* Returns the owner's log reader, and its hash reader for hash iterators, or NULL if closed. */
static sparkey_logreader *iter_owner(IterObject *it, sparkey_hashreader **hr) {
  if (it->mode == ITER_LOG) {
    *hr = NULL;
    sparkey_logreader *log = ((LogReaderObject *) it->owner)->log;
    if (log == NULL) {
      raise_closed("LogReader");
    }
    return log;
  }
  *hr = ((HashReaderObject *) it->owner)->reader;
  if (*hr == NULL) {
    raise_closed("HashReader");
    return NULL;
  }
  return sparkey_hash_getreader(*hr);
}

static PyObject *iter_create(PyObject *owner, int mode) {
  IterObject *it = PyObject_GC_New(IterObject, mode == ITER_LOG ? &LogIterType : &HashIterType);
  if (it == NULL) {
    return NULL;
  }
  Py_INCREF(owner);
  it->owner = owner;
  it->iter = NULL;
  it->mode = mode;
  sparkey_hashreader *hr;
  sparkey_logreader *log = iter_owner(it, &hr);
  if (log == NULL) {
    Py_DECREF(it);
    return NULL;
  }
  sparkey_returncode rc = sparkey_logiter_create(&it->iter, log);
  if (rc != SPARKEY_SUCCESS) {
    Py_DECREF(it);
    return raise_code(rc, NULL);
  }
  PyObject_GC_Track(it);
  return (PyObject *) it;
}

static PyObject *Iter_next(IterObject *it) {
  if (it->iter == NULL) {
    return NULL;
  }
  sparkey_hashreader *hr;
  sparkey_logreader *log = iter_owner(it, &hr);
  if (log == NULL) {
    return NULL;
  }
  sparkey_logiter *iter = it->iter;
  sparkey_returncode rc = hr != NULL ? sparkey_logiter_hashnext(iter, hr) : sparkey_logiter_next(iter, log);
  if (rc != SPARKEY_SUCCESS) {
    return raise_code(rc, NULL);
  }
  if (sparkey_logiter_state(iter) != SPARKEY_ITER_ACTIVE) {
    sparkey_logiter_close(&it->iter);
    return NULL;
  }

  if (it->mode == ITER_KEYS) {
    return read_chunked(iter, log, sparkey_logiter_keylen(iter), 0);
  }
  if (it->mode == ITER_VALUES) {
    return read_chunked(iter, log, sparkey_logiter_valuelen(iter), 1);
  }
  PyObject *res = PyTuple_New(it->mode == ITER_LOG ? 3 : 2);
  if (res == NULL) {
    return NULL;
  }
  PyObject *key = read_chunked(iter, log, sparkey_logiter_keylen(iter), 0);
  if (key == NULL) {
    Py_DECREF(res);
    return NULL;
  }
  PyTuple_SET_ITEM(res, 0, key);
  PyObject *value = read_chunked(iter, log, sparkey_logiter_valuelen(iter), 1);
  if (value == NULL) {
    Py_DECREF(res);
    return NULL;
  }
  PyTuple_SET_ITEM(res, 1, value);
  if (it->mode == ITER_LOG) {
    PyObject *type = PyLong_FromLong(sparkey_logiter_type(iter));
    if (type == NULL) {
      Py_DECREF(res);
      return NULL;
    }
    PyTuple_SET_ITEM(res, 2, type);
  }
  return res;
}

static void Iter_dealloc(IterObject *it) {
  PyObject_GC_UnTrack(it);
  sparkey_logiter_close(&it->iter);
  Py_CLEAR(it->owner);
  PyObject_GC_Del(it);
}

/* A reader subclass can hold its own iterator, so iterators take part in GC. */
static int Iter_traverse(IterObject *it, visitproc visit, void *arg) {
  Py_VISIT(it->owner);
  return 0;
}

static PyObject *Iter_close(IterObject *it, PyObject *Py_UNUSED(ignored)) {
  sparkey_logiter_close(&it->iter);
  Py_RETURN_NONE;
}

static PyObject *LogIter_new(PyTypeObject *Py_UNUSED(type), PyObject *args, PyObject *kwds) {
  static char *kwlist[] = {"logreader", NULL};
  PyObject *owner;
  if (!PyArg_ParseTupleAndKeywords(args, kwds, "O!:LogIter", kwlist, &LogReaderType, &owner)) {
    return NULL;
  }
  return iter_create(owner, ITER_LOG);
}

static PyObject *HashIter_new(PyTypeObject *Py_UNUSED(type), PyObject *args, PyObject *kwds) {
  static char *kwlist[] = {"hashreader", NULL};
  PyObject *owner;
  if (!PyArg_ParseTupleAndKeywords(args, kwds, "O!:HashIterator", kwlist, &HashReaderType, &owner)) {
    return NULL;
  }
  return iter_create(owner, ITER_ITEMS);
}

static PyMethodDef Iter_methods[] = {
  {"close", (PyCFunction) Iter_close, METH_NOARGS,
   "close($self)\n--\n\nStop the iteration and free its resources."},
  {NULL}
};

static PyTypeObject LogIterType = {
  PyVarObject_HEAD_INIT(NULL, 0)
  .tp_name = "sparkey.LogIter",
  .tp_doc = PyDoc_STR("LogIter(logreader)\n--\n\nIterator over (key, value, type) for every entry in a log."),
  .tp_basicsize = sizeof(IterObject),
  .tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HAVE_GC,
  .tp_new = LogIter_new,
  .tp_traverse = (traverseproc) Iter_traverse,
  .tp_dealloc = (destructor) Iter_dealloc,
  .tp_iter = PyObject_SelfIter,
  .tp_iternext = (iternextfunc) Iter_next,
  .tp_methods = Iter_methods,
};

static PyTypeObject HashIterType = {
  PyVarObject_HEAD_INIT(NULL, 0)
  .tp_name = "sparkey.HashIterator",
  .tp_doc = PyDoc_STR("HashIterator(hashreader)\n--\n\nIterator over the live entries of a hash."),
  .tp_basicsize = sizeof(IterObject),
  .tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HAVE_GC,
  .tp_new = HashIter_new,
  .tp_traverse = (traverseproc) Iter_traverse,
  .tp_dealloc = (destructor) Iter_dealloc,
  .tp_iter = PyObject_SelfIter,
  .tp_iternext = (iternextfunc) Iter_next,
  .tp_methods = Iter_methods,
};

/* ------------------------------------------------------------------------- */
/* LogWriter */

typedef struct {
  PyObject_HEAD
  sparkey_logwriter *writer; /* NULL when closed */
  PyObject *logfile;         /* bytes */
  PyObject *weakreflist;
} LogWriterObject;

#define LW_CHECK_OPEN(self, ret) \
  do { if ((self)->writer == NULL) { raise_closed("Writer"); return ret; } } while (0)

static int lw_open(LogWriterObject *self, PyObject *mode, int compression_type, int compression_block_size) {
  int append;
  if (mode == NULL || (PyUnicode_Check(mode) && PyUnicode_CompareWithASCIIString(mode, "NEW") == 0)) {
    append = 0;
  } else if (PyUnicode_Check(mode) && PyUnicode_CompareWithASCIIString(mode, "APPEND") == 0) {
    append = 1;
  } else {
    PyErr_Format(SparkeyException, "Invalid mode %S, expected 'NEW' or 'APPEND'", mode);
    return -1;
  }
  /* sparkey_logwriter_create does not check the type itself. */
  if (compression_type < SPARKEY_COMPRESSION_NONE || compression_type > SPARKEY_COMPRESSION_ZSTD) {
    raise_code(SPARKEY_INVALID_COMPRESSION_TYPE, NULL);
    return -1;
  }
  sparkey_logwriter *writer = NULL;
  sparkey_returncode rc;
  const char *name = PyBytes_AS_STRING(self->logfile);
  Py_BEGIN_ALLOW_THREADS
  if (append) {
    rc = sparkey_logwriter_append(&writer, name);
  } else {
    rc = sparkey_logwriter_create(&writer, name, (sparkey_compression_type) compression_type, compression_block_size);
  }
  Py_END_ALLOW_THREADS
  if (rc != SPARKEY_SUCCESS) {
    raise_code(rc, self->logfile);
    return -1;
  }
  /* Another thread may have reinitialized self while the GIL was released. */
  sparkey_logwriter_close(&self->writer);
  self->writer = writer;
  return 0;
}

/*
 * Closes a writer that is being reinitialized or deallocated. Like a __del__
 * method, it reports errors through sys.unraisablehook, since a failed final
 * flush loses data.
 */
static void lw_close_unraisable(LogWriterObject *self) {
  if (self->writer == NULL) {
    return;
  }
  PyObject *type, *value, *tb;
  PyErr_Fetch(&type, &value, &tb);
  sparkey_returncode rc = sparkey_logwriter_close(&self->writer);
  if (rc != SPARKEY_SUCCESS) {
    raise_code(rc, self->logfile);
    PyErr_WriteUnraisable(NULL);
  }
  PyErr_Restore(type, value, tb);
}

/* Opens the file in __init__, like HashReader_init. */
static int LogWriter_init(LogWriterObject *self, PyObject *args, PyObject *kwds) {
  static char *kwlist[] = {"filename", "mode", "compression_type", "compression_block_size", NULL};
  PyObject *fileobj, *mode = NULL;
  int compression_type = SPARKEY_COMPRESSION_NONE, compression_block_size = 0;
  if (!PyArg_ParseTupleAndKeywords(args, kwds, "O|Oii:LogWriter", kwlist,
                                   &fileobj, &mode, &compression_type, &compression_block_size)) {
    return -1;
  }
  lw_close_unraisable(self);
  Py_CLEAR(self->logfile);
  if (path_get(fileobj, &self->logfile) < 0) {
    return -1;
  }
  return lw_open(self, mode, compression_type, compression_block_size);
}

static void LogWriter_dealloc(LogWriterObject *self) {
  if (self->weakreflist != NULL) {
    PyObject_ClearWeakRefs((PyObject *) self);
  }
  lw_close_unraisable(self);
  Py_CLEAR(self->logfile);
  Py_TYPE(self)->tp_free((PyObject *) self);
}

static inline int lw_put(LogWriterObject *self, PyObject *keyobj, PyObject *valueobj) {
  LW_CHECK_OPEN(self, -1);
  databuf key, value;
  if (databuf_get(keyobj, &key, "key") < 0) {
    return -1;
  }
  if (databuf_get(valueobj, &value, "value") < 0) {
    databuf_release(&key);
    return -1;
  }
  sparkey_returncode rc = sparkey_logwriter_put(self->writer, (uint64_t) key.len, (const uint8_t *) key.ptr,
                                                (uint64_t) value.len, (const uint8_t *) value.ptr);
  databuf_release(&value);
  databuf_release(&key);
  if (rc != SPARKEY_SUCCESS) {
    raise_code(rc, NULL);
    return -1;
  }
  return 0;
}

static int lw_delete(LogWriterObject *self, PyObject *keyobj) {
  LW_CHECK_OPEN(self, -1);
  databuf key;
  if (databuf_get(keyobj, &key, "key") < 0) {
    return -1;
  }
  sparkey_returncode rc = sparkey_logwriter_delete(self->writer, (uint64_t) key.len, (const uint8_t *) key.ptr);
  databuf_release(&key);
  if (rc != SPARKEY_SUCCESS) {
    raise_code(rc, NULL);
    return -1;
  }
  return 0;
}

/*
 * put() and delete() take the argument names of sparkey-python, which are
 * key/value on LogWriter and k/v on HashWriter.
 */
static const char *const lw_put_names[] = {"key", "value"};
static const char *const hw_put_names[] = {"k", "v"};

static PyObject *writer_put(LogWriterObject *self, PyObject *const *args, Py_ssize_t nargs, PyObject *kwnames,
                            const char *const *names) {
  int res;
  if (kwnames == NULL && nargs == 2) {
    res = lw_put(self, args[0], args[1]);
  } else {
    PyObject *parsed[2];
    if (parse_args("put", args, nargs, kwnames, names, 2, 2, parsed) < 0) {
      return NULL;
    }
    res = lw_put(self, parsed[0], parsed[1]);
  }
  if (res < 0) {
    return NULL;
  }
  Py_RETURN_NONE;
}

static PyObject *writer_delete(LogWriterObject *self, PyObject *const *args, Py_ssize_t nargs, PyObject *kwnames,
                               const char *const *names) {
  PyObject *key;
  if (parse_args("delete", args, nargs, kwnames, names, 1, 1, &key) < 0) {
    return NULL;
  }
  if (lw_delete(self, key) < 0) {
    return NULL;
  }
  Py_RETURN_NONE;
}

static PyObject *LogWriter_put(LogWriterObject *self, PyObject *const *args, Py_ssize_t nargs, PyObject *kwnames) {
  return writer_put(self, args, nargs, kwnames, lw_put_names);
}

static PyObject *LogWriter_delete(LogWriterObject *self, PyObject *const *args, Py_ssize_t nargs, PyObject *kwnames) {
  return writer_delete(self, args, nargs, kwnames, lw_put_names);
}

static PyObject *HashWriter_put(LogWriterObject *self, PyObject *const *args, Py_ssize_t nargs, PyObject *kwnames) {
  return writer_put(self, args, nargs, kwnames, hw_put_names);
}

static PyObject *HashWriter_delete(LogWriterObject *self, PyObject *const *args, Py_ssize_t nargs, PyObject *kwnames) {
  return writer_delete(self, args, nargs, kwnames, hw_put_names);
}

static int LogWriter_ass_subscript(LogWriterObject *self, PyObject *key, PyObject *value) {
  return value == NULL ? lw_delete(self, key) : lw_put(self, key, value);
}

/* Puts one (key, value) pair from an iterable passed to update(). */
static int lw_put_pair(LogWriterObject *self, PyObject *item) {
  if (PyTuple_CheckExact(item) && PyTuple_GET_SIZE(item) == 2) {
    return lw_put(self, PyTuple_GET_ITEM(item, 0), PyTuple_GET_ITEM(item, 1));
  }
  PyObject *pair = PySequence_Fast(item, "update expects (key, value) pairs");
  if (pair == NULL) {
    return -1;
  }
  int res;
  if (PySequence_Fast_GET_SIZE(pair) != 2) {
    PyErr_Format(PyExc_ValueError, "update expects (key, value) pairs, got a sequence of length %zd",
                 PySequence_Fast_GET_SIZE(pair));
    res = -1;
  } else {
    res = lw_put(self, PySequence_Fast_GET_ITEM(pair, 0), PySequence_Fast_GET_ITEM(pair, 1));
  }
  Py_DECREF(pair);
  return res;
}

static PyObject *LogWriter_update(LogWriterObject *self, PyObject *arg) {
  LW_CHECK_OPEN(self, NULL);
  if (PyDict_CheckExact(arg)) {
    Py_ssize_t pos = 0;
    PyObject *key, *value;
    while (PyDict_Next(arg, &pos, &key, &value)) {
      Py_INCREF(key);
      Py_INCREF(value);
      int res = lw_put(self, key, value);
      Py_DECREF(key);
      Py_DECREF(value);
      if (res < 0) {
        return NULL;
      }
    }
    Py_RETURN_NONE;
  }

  /* Other mappings are read through items(), anything else must yield pairs. */
  PyObject *iterable;
  if (!PyList_CheckExact(arg) && !PyTuple_CheckExact(arg) && PyObject_HasAttrString(arg, "items")) {
    iterable = PyObject_CallMethod(arg, "items", NULL);
    if (iterable == NULL) {
      return NULL;
    }
  } else {
    Py_INCREF(arg);
    iterable = arg;
  }

  if (PyList_CheckExact(iterable) || PyTuple_CheckExact(iterable)) {
    PyObject *seq = iterable;
    for (Py_ssize_t i = 0; i < PySequence_Fast_GET_SIZE(seq); i++) {
      PyObject *item = PySequence_Fast_GET_ITEM(seq, i);
      Py_INCREF(item);
      int res = lw_put_pair(self, item);
      Py_DECREF(item);
      if (res < 0) {
        Py_DECREF(seq);
        return NULL;
      }
    }
    Py_DECREF(seq);
    Py_RETURN_NONE;
  }

  PyObject *iter = PyObject_GetIter(iterable);
  Py_DECREF(iterable);
  if (iter == NULL) {
    return NULL;
  }
  PyObject *item;
  while ((item = PyIter_Next(iter)) != NULL) {
    int res = lw_put_pair(self, item);
    Py_DECREF(item);
    if (res < 0) {
      Py_DECREF(iter);
      return NULL;
    }
  }
  Py_DECREF(iter);
  if (PyErr_Occurred()) {
    return NULL;
  }
  Py_RETURN_NONE;
}

static PyObject *LogWriter_flush(LogWriterObject *self, PyObject *Py_UNUSED(ignored)) {
  LW_CHECK_OPEN(self, NULL);
  sparkey_returncode rc = sparkey_logwriter_flush(self->writer);
  if (rc != SPARKEY_SUCCESS) {
    return raise_code(rc, self->logfile);
  }
  Py_RETURN_NONE;
}

static PyObject *LogWriter_close(LogWriterObject *self, PyObject *Py_UNUSED(ignored)) {
  sparkey_returncode rc = sparkey_logwriter_close(&self->writer);
  if (rc != SPARKEY_SUCCESS) {
    return raise_code(rc, self->logfile);
  }
  Py_RETURN_NONE;
}

static PyObject *LogWriter_closed(LogWriterObject *self, void *Py_UNUSED(closure)) {
  return PyBool_FromLong(self->writer == NULL);
}

static PyObject *LogWriter_repr(LogWriterObject *self) {
  return path_repr(Py_TYPE(self)->tp_name, self->logfile, self->writer == NULL);
}

static PyMethodDef LogWriter_methods[] = {
  {"put", (PyCFunction) (void (*)(void)) LogWriter_put, METH_FASTCALL | METH_KEYWORDS,
   "put($self, key, value)\n--\n\nAppend a key/value pair to the log."},
  {"delete", (PyCFunction) (void (*)(void)) LogWriter_delete, METH_FASTCALL | METH_KEYWORDS,
   "delete($self, key)\n--\n\nAppend a delete of key to the log."},
  {"update", (PyCFunction) LogWriter_update, METH_O,
   "update($self, items, /)\n--\n\nPut every pair from a mapping or an iterable of (key, value) pairs."},
  {"flush", (PyCFunction) LogWriter_flush, METH_NOARGS,
   "flush($self)\n--\n\nWrite pending entries to the log file."},
  {"close", (PyCFunction) LogWriter_close, METH_NOARGS,
   "close($self)\n--\n\nFlush and close the writer. Closing a closed writer does nothing."},
  {"__enter__", (PyCFunction) return_self, METH_NOARGS, NULL},
  {"__exit__", (PyCFunction) (void (*)(void)) call_close, METH_FASTCALL, NULL},
  {NULL}
};

static PyGetSetDef LogWriter_getset[] = {
  {"closed", (getter) LogWriter_closed, NULL, "True if the writer is closed.", NULL},
  {NULL}
};

static PyMappingMethods LogWriter_as_mapping = {
  .mp_ass_subscript = (objobjargproc) LogWriter_ass_subscript,
};

static PyTypeObject LogWriterType = {
  PyVarObject_HEAD_INIT(NULL, 0)
  .tp_name = "sparkey.LogWriter",
  .tp_doc = PyDoc_STR(
    "LogWriter(filename, mode='NEW', compression_type=Compression.NONE, compression_block_size=0)\n--\n\n"
    "Create (mode='NEW') or append to (mode='APPEND') a log file.\n\n"
    "Keys and values may be bytes, str (encoded as UTF-8) or bytes-like objects.\n"
    "A writer must only be used by one thread at a time."),
  .tp_basicsize = sizeof(LogWriterObject),
  .tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
  .tp_new = PyType_GenericNew,
  .tp_init = (initproc) LogWriter_init,
  .tp_dealloc = (destructor) LogWriter_dealloc,
  .tp_repr = (reprfunc) LogWriter_repr,
  .tp_as_mapping = &LogWriter_as_mapping,
  .tp_methods = LogWriter_methods,
  .tp_getset = LogWriter_getset,
  .tp_weaklistoffset = offsetof(LogWriterObject, weakreflist),
};

/* ------------------------------------------------------------------------- */
/* HashWriter: a LogWriter that also writes the hash file on flush and close */

typedef struct {
  LogWriterObject base;
  PyObject *hashfile; /* bytes */
  PyObject *reader;   /* HashReader opened on demand by get(), dropped by flush() */
  int hash_size;
} HashWriterObject;

static sparkey_returncode write_hash(PyObject *hashfile, PyObject *logfile, int hash_size) {
  sparkey_returncode rc;
  const char *hashname = PyBytes_AS_STRING(hashfile);
  const char *logname = PyBytes_AS_STRING(logfile);
  Py_BEGIN_ALLOW_THREADS
  rc = sparkey_hash_write(hashname, logname, hash_size);
  Py_END_ALLOW_THREADS
  return rc;
}

/* Opens the file in __init__, like HashReader_init. Reinitializing does not write the hash of the old log. */
static int HashWriter_init(HashWriterObject *self, PyObject *args, PyObject *kwds) {
  static char *kwlist[] = {"hashfile", "logfile", "mode", "compression_type", "compression_block_size", "hash_size", NULL};
  PyObject *hashobj, *logobj = Py_None, *mode = NULL;
  int compression_type = SPARKEY_COMPRESSION_NONE, compression_block_size = 0, hash_size = 0;
  if (!PyArg_ParseTupleAndKeywords(args, kwds, "O|OOiii:HashWriter", kwlist, &hashobj, &logobj, &mode,
                                   &compression_type, &compression_block_size, &hash_size)) {
    return -1;
  }
  /* Fail now rather than when close() writes the hash. */
  if (hash_size != 0 && hash_size != 4 && hash_size != 8) {
    raise_code(SPARKEY_HASH_SIZE_INVALID, NULL);
    return -1;
  }
  Py_CLEAR(self->reader);
  lw_close_unraisable(&self->base);
  Py_CLEAR(self->hashfile);
  Py_CLEAR(self->base.logfile);
  self->hash_size = hash_size;
  if (path_get(hashobj, &self->hashfile) < 0) {
    return -1;
  }
  if (logobj == Py_None) {
    self->base.logfile = derive_log_filename(self->hashfile);
    if (self->base.logfile == NULL) {
      return -1;
    }
  } else if (path_get(logobj, &self->base.logfile) < 0) {
    return -1;
  }
  return lw_open(&self->base, mode, compression_type, compression_block_size);
}

/* LogWriter.__init__ can open a HashWriter without a hash file; treat that as closed. */
#define HW_CHECK_OPEN(self, ret) \
  do { LW_CHECK_OPEN(&(self)->base, ret); if ((self)->hashfile == NULL) { raise_closed("Writer"); return ret; } } while (0)

static void HashWriter_dealloc(HashWriterObject *self) {
  Py_CLEAR(self->reader);
  Py_CLEAR(self->hashfile);
  LogWriter_dealloc(&self->base);
}

static PyObject *HashWriter_flush(HashWriterObject *self, PyObject *Py_UNUSED(ignored)) {
  HW_CHECK_OPEN(self, NULL);
  sparkey_returncode rc = sparkey_logwriter_flush(self->base.writer);
  if (rc != SPARKEY_SUCCESS) {
    return raise_code(rc, self->base.logfile);
  }
  rc = write_hash(self->hashfile, self->base.logfile, self->hash_size);
  /* Reopen the reader on the next get() so that it sees the new entries. */
  Py_CLEAR(self->reader);
  if (rc != SPARKEY_SUCCESS) {
    return raise_code(rc, self->hashfile);
  }
  Py_RETURN_NONE;
}

static PyObject *HashWriter_destroy(HashWriterObject *self, PyObject *Py_UNUSED(ignored)) {
  Py_CLEAR(self->reader);
  sparkey_returncode rc = sparkey_logwriter_close(&self->base.writer);
  if (rc != SPARKEY_SUCCESS) {
    return raise_code(rc, self->base.logfile);
  }
  Py_RETURN_NONE;
}

static PyObject *HashWriter_close(HashWriterObject *self, PyObject *Py_UNUSED(ignored)) {
  if (self->base.writer == NULL) {
    Py_RETURN_NONE;
  }
  PyObject *res = HashWriter_flush(self, NULL);
  if (res == NULL) {
    /* Still release the writer, but report the flush error. */
    PyObject *type, *value, *tb;
    PyErr_Fetch(&type, &value, &tb);
    Py_CLEAR(self->reader);
    sparkey_logwriter_close(&self->base.writer);
    PyErr_Restore(type, value, tb);
    return NULL;
  }
  Py_DECREF(res);
  return HashWriter_destroy(self, NULL);
}

/* Returns a borrowed reference to the reader of the hash as of the last flush, opening it if needed. */
static HashReaderObject *hw_reader(HashWriterObject *self) {
  HW_CHECK_OPEN(self, NULL);
  if (self->reader == NULL) {
    PyObject *reader = PyObject_CallFunctionObjArgs((PyObject *) &HashReaderType, self->hashfile, self->base.logfile, NULL);
    if (reader == NULL) {
      return NULL;
    }
    /* Opening releases the GIL, so another thread may have opened one meanwhile. */
    if (self->reader == NULL) {
      self->reader = reader;
    } else {
      Py_DECREF(reader);
    }
  }
  return (HashReaderObject *) self->reader;
}

static PyObject *HashWriter_get(HashWriterObject *self, PyObject *const *args, Py_ssize_t nargs, PyObject *kwnames) {
  HashReaderObject *reader = hw_reader(self);
  if (reader == NULL) {
    return NULL;
  }
  return HashReader_get(reader, args, nargs, kwnames);
}

static PyObject *HashWriter_getAsString(HashWriterObject *self, PyObject *const *args, Py_ssize_t nargs,
                                        PyObject *kwnames) {
  HashReaderObject *reader = hw_reader(self);
  if (reader == NULL) {
    return NULL;
  }
  return HashReader_getAsString(reader, args, nargs, kwnames);
}

static int HashWriter_contains(HashWriterObject *self, PyObject *key) {
  HashReaderObject *reader = hw_reader(self);
  if (reader == NULL) {
    return -1;
  }
  return HashReader_contains(reader, key);
}

/* Like get(key): returns None for a missing key, as sparkey-python does. */
static PyObject *HashWriter_subscript(HashWriterObject *self, PyObject *key) {
  HashReaderObject *reader = hw_reader(self);
  if (reader == NULL) {
    return NULL;
  }
  PyObject *value;
  int found = hr_lookup(reader, key, &value);
  if (found < 0) {
    return NULL;
  }
  if (!found) {
    Py_RETURN_NONE;
  }
  return value;
}

static PyObject *HashWriter_iter(HashWriterObject *self) {
  HashReaderObject *reader = hw_reader(self);
  if (reader == NULL) {
    return NULL;
  }
  return iter_create((PyObject *) reader, ITER_ITEMS);
}

static PyObject *HashWriter_iteritems(HashWriterObject *self, PyObject *Py_UNUSED(ignored)) {
  return HashWriter_iter(self);
}

static PyMethodDef HashWriter_methods[] = {
  {"put", (PyCFunction) (void (*)(void)) HashWriter_put, METH_FASTCALL | METH_KEYWORDS,
   "put($self, k, v)\n--\n\nAppend a key/value pair to the log."},
  {"delete", (PyCFunction) (void (*)(void)) HashWriter_delete, METH_FASTCALL | METH_KEYWORDS,
   "delete($self, k)\n--\n\nAppend a delete of k to the log."},
  {"flush", (PyCFunction) HashWriter_flush, METH_NOARGS,
   "flush($self)\n--\n\nWrite pending entries to the log file and rebuild the hash file."},
  {"close", (PyCFunction) HashWriter_close, METH_NOARGS,
   "close($self)\n--\n\nFlush, rebuild the hash file and close the writer."},
  {"finish", (PyCFunction) HashWriter_close, METH_NOARGS,
   "finish($self)\n--\n\nSame as close()."},
  {"destroy", (PyCFunction) HashWriter_destroy, METH_NOARGS,
   "destroy($self)\n--\n\nClose the log writer without rebuilding the hash file."},
  {"get", (PyCFunction) (void (*)(void)) HashWriter_get, METH_FASTCALL | METH_KEYWORDS,
   "get($self, key, default=None)\n--\n\nLook up a key in the hash as of the last flush()."},
  {"getAsString", (PyCFunction) (void (*)(void)) HashWriter_getAsString, METH_FASTCALL | METH_KEYWORDS,
   "getAsString($self, key)\n--\n\nLike get(), but decode the value as UTF-8."},
  {"iteritems", (PyCFunction) HashWriter_iteritems, METH_NOARGS,
   "iteritems($self)\n--\n\nIterate over (key, value) pairs in the hash as of the last flush()."},
  {NULL}
};

static PyMappingMethods HashWriter_as_mapping = {
  .mp_subscript = (binaryfunc) HashWriter_subscript,
  .mp_ass_subscript = (objobjargproc) LogWriter_ass_subscript,
};

static PySequenceMethods HashWriter_as_sequence = {
  .sq_contains = (objobjproc) HashWriter_contains,
};

static PyTypeObject HashWriterType = {
  PyVarObject_HEAD_INIT(NULL, 0)
  .tp_name = "sparkey.HashWriter",
  .tp_doc = PyDoc_STR(
    "HashWriter(hashfile, logfile=None, mode='NEW', compression_type=Compression.NONE,\n"
    "           compression_block_size=0, hash_size=0)\n--\n\n"
    "A LogWriter that also writes the hash file on flush() and close().\n\n"
    "logfile defaults to hashfile with .spi replaced by .spl. hash_size is 4\n"
    "or 8 (bytes), or 0 to pick one from the number of entries."),
  .tp_basicsize = sizeof(HashWriterObject),
  .tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
  .tp_base = &LogWriterType,
  .tp_init = (initproc) HashWriter_init,
  .tp_dealloc = (destructor) HashWriter_dealloc,
  .tp_as_mapping = &HashWriter_as_mapping,
  .tp_as_sequence = &HashWriter_as_sequence,
  .tp_iter = (getiterfunc) HashWriter_iter,
  .tp_methods = HashWriter_methods,
};

/* ------------------------------------------------------------------------- */
/* Module */

static PyObject *sparkey_writehash(PyObject *Py_UNUSED(module), PyObject *args, PyObject *kwds) {
  static char *kwlist[] = {"hashfile", "logfile", "hash_size", NULL};
  PyObject *hashobj, *logobj = Py_None, *hashfile = NULL, *logfile = NULL;
  int hash_size = 0;
  if (!PyArg_ParseTupleAndKeywords(args, kwds, "O|Oi:writehash", kwlist, &hashobj, &logobj, &hash_size)) {
    return NULL;
  }
  if (path_get(hashobj, &hashfile) < 0) {
    return NULL;
  }
  if (logobj == Py_None) {
    logfile = derive_log_filename(hashfile);
  } else if (path_get(logobj, &logfile) < 0) {
    logfile = NULL;
  }
  if (logfile == NULL) {
    Py_DECREF(hashfile);
    return NULL;
  }
  sparkey_returncode rc = write_hash(hashfile, logfile, hash_size);
  PyObject *res = rc == SPARKEY_SUCCESS ? Py_NewRef(Py_None) : raise_code(rc, hashfile);
  Py_DECREF(hashfile);
  Py_DECREF(logfile);
  return res;
}

static PyMethodDef module_methods[] = {
  {"writehash", (PyCFunction) (void (*)(void)) sparkey_writehash, METH_VARARGS | METH_KEYWORDS,
   "writehash(hashfile, logfile=None, hash_size=0)\n--\n\n"
   "Write a hash file for a log file, atomically replacing an existing one.\n"
   "Does nothing if the hash file is already up to date with the log."},
  {NULL}
};

static struct PyModuleDef sparkey_module = {
  PyModuleDef_HEAD_INIT,
  .m_name = "sparkey._sparkey",
  .m_doc = "Fast bindings for the sparkey key/value store.",
  .m_size = -1,
  .m_methods = module_methods,
};

PyMODINIT_FUNC PyInit__sparkey(void) {
  PyObject *m = PyModule_Create(&sparkey_module);
  if (m == NULL) {
    return NULL;
  }

  SparkeyException = PyErr_NewExceptionWithDoc(
    "sparkey.SparkeyException",
    "Raised when a sparkey operation fails. The code attribute holds the\n"
    "sparkey return code, when there is one.",
    NULL, NULL);
  if (SparkeyException == NULL || PyObject_SetAttrString(SparkeyException, "code", Py_None) < 0 ||
      PyModule_AddObjectRef(m, "SparkeyException", SparkeyException) < 0) {
    goto error;
  }
  PyTypeObject *types[] = {
    &HashReaderType, &LogReaderType, &LogIterType, &HashIterType, &LogWriterType, &HashWriterType,
  };
  for (size_t i = 0; i < sizeof(types) / sizeof(types[0]); i++) {
    if (PyModule_AddType(m, types[i]) < 0) {
      goto error;
    }
  }
  return m;

error:
  Py_DECREF(m);
  return NULL;
}
