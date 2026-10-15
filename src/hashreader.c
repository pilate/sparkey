/*
* Copyright (c) 2012-2013 Spotify AB
*
* Licensed under the Apache License, Version 2.0 (the "License"); you may not
* use this file except in compliance with the License. You may obtain a copy of
* the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
* WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
* License for the specific language governing permissions and limitations under
* the License.
*/
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>

#include "hashheader.h"
#include "hashiter.h"
#include "util.h"
#include "endiantools.h"
#include "sparkey.h"
#include "sparkey-internal.h"

#define MAGIC_VALUE_HASHREADER (0x75103df9)

sparkey_returncode sparkey_hash_open(sparkey_hashreader **reader_ref, const char *hash_filename, const char *log_filename) {
  RETHROW(correct_endian_platform());

  sparkey_returncode returncode;

  sparkey_hashreader *reader = malloc(sizeof(sparkey_hashreader));
  if (reader == NULL) {
    return SPARKEY_INTERNAL_ERROR;
  }

  reader->open_status = 0;
  reader->fd = -1;

  TRY(sparkey_load_hashheader(&reader->header, hash_filename), free_reader);
  TRY(sparkey_logreader_open_noalloc(&reader->log, log_filename), free_reader);
  if (reader->header.file_identifier != reader->log.header.file_identifier) {
    returncode = SPARKEY_FILE_IDENTIFIER_MISMATCH;
    goto close_reader;
  }
  if (reader->header.data_end > reader->log.header.data_end) {
    returncode = SPARKEY_HASH_HEADER_CORRUPT;
    goto close_reader;
  }
  if (reader->header.max_key_len > reader->log.header.max_key_len) {
    returncode = SPARKEY_HASH_HEADER_CORRUPT;
    goto close_reader;
  }
  if (reader->header.max_value_len > reader->log.header.max_value_len) {
    returncode = SPARKEY_HASH_HEADER_CORRUPT;
    goto close_reader;
  }

  reader->fd = open(hash_filename, O_RDONLY);
  if (reader->fd < 0) {
    int e = errno;
    returncode = sparkey_open_returncode(e);
    goto close_reader;
  }

  reader->data_len = reader->header.header_size + reader->header.hash_capacity * (reader->header.hash_size + reader->header.address_size);

  struct stat s;
  if (fstat(reader->fd, &s) < 0) {
    returncode = sparkey_open_returncode(errno);
    goto close_reader;
  }
  if (reader->data_len > (uint64_t) s.st_size) {
    returncode = SPARKEY_HASH_TOO_SMALL;
    goto close_reader;
  }

  reader->data = mmap(NULL, reader->data_len, PROT_READ, MAP_SHARED, reader->fd, 0);
  if (reader->data == MAP_FAILED) {
    returncode = SPARKEY_MMAP_FAILED;
    goto close_reader;
  }

  *reader_ref = reader;
  reader->open_status = MAGIC_VALUE_HASHREADER;
  return SPARKEY_SUCCESS;

close_reader:
  // sparkey_hash_close only closes the hash file of a fully opened reader.
  if (reader->fd >= 0) {
    close(reader->fd);
  }
  sparkey_hash_close(&reader);
  return returncode;

free_reader:
  free(reader);
  return returncode;
}

void sparkey_hash_close(sparkey_hashreader **reader_ref) {
  if (reader_ref == NULL) {
    return;
  }
  sparkey_hashreader *reader = *reader_ref;
  if (reader == NULL) {
    return;
  }

  sparkey_logreader_close_nodealloc(&reader->log);

  if (reader->open_status == MAGIC_VALUE_HASHREADER) {
    reader->open_status = 0;
    if (reader->data != NULL) {
      munmap(reader->data, reader->data_len);
      reader->data = NULL;
    }
    close(reader->fd);
    reader->fd = -1;
  }

  free(reader);
  *reader_ref = NULL;
}

static sparkey_returncode assert_reader_open(sparkey_hashreader *reader) {
  if (reader->open_status != MAGIC_VALUE_HASHREADER) {
    return SPARKEY_HASH_CLOSED;
  }
  return SPARKEY_SUCCESS;
}

sparkey_returncode sparkey_hash_get(sparkey_hashreader *reader, const uint8_t *key, uint64_t keylen, sparkey_logiter *iter) {
  RETHROW(assert_reader_open(reader));
  uint64_t hash = reader->header.hash_algorithm.hash(key, keylen, reader->header.hash_seed);
  uint64_t wanted_slot = capacity_mod(&reader->header, hash);

  int slot_size = reader->header.address_size + reader->header.hash_size;
  uint64_t pos = wanted_slot * slot_size;

  uint64_t displacement = 0;
  uint64_t slot = wanted_slot;

  uint8_t *hashtable = reader->data + reader->header.header_size;

  while (1) {
    uint64_t hash2 = reader->header.hash_algorithm.read_hash(hashtable, pos);
    uint64_t position2 = read_addr(hashtable, pos + reader->header.hash_size, reader->header.address_size);
    if (position2 == 0) {
      iter->state = SPARKEY_ITER_INVALID;
      return SPARKEY_SUCCESS;
    }
    int entry_index2 = (int) (position2) & reader->header.entry_block_bitmask;
    position2 >>= reader->header.entry_block_bits;
    if (hash == hash2) {
      RETHROW(sparkey_logiter_seek(iter, &reader->log, position2));
      RETHROW(sparkey_logiter_skip(iter, &reader->log, entry_index2));
      RETHROW(sparkey_logiter_next(iter, &reader->log));
      uint64_t keylen2 = iter->keylen;
      if (iter->type != SPARKEY_ENTRY_PUT) {
        iter->state = SPARKEY_ITER_INVALID;
        return SPARKEY_INTERNAL_ERROR;
      }
      if (keylen == keylen2) {
        uint64_t pos2 = 0;
        int equals = 1;
        while (pos2 < keylen) {
          uint8_t *buf2;
          uint64_t len2;
          RETHROW(sparkey_logiter_keychunk(iter, &reader->log, keylen, &buf2, &len2));
          if (memcmp(&key[pos2], buf2, len2) != 0) {
            equals = 0;
            break;
          }
          pos2 += len2;
        }
        if (equals) {
          return SPARKEY_SUCCESS;
        }
      }
    }
    uint64_t other_displacement = displacement_of(&reader->header, slot, hash2);
    if (displacement > other_displacement) {
      iter->state = SPARKEY_ITER_INVALID;
      return SPARKEY_SUCCESS;
    }
    pos += slot_size;
    displacement++;
    slot++;
    if (slot >= reader->header.hash_capacity) {
      pos = 0;
      slot = 0;
    }
  }
  iter->state = SPARKEY_ITER_INVALID;
  return SPARKEY_INTERNAL_ERROR;
}

// Reads a VLQ that must end before buf[end]. Returns 0 if it does not.
static inline int read_vlq_before(const uint8_t *buf, uint64_t end, uint64_t *pos, uint64_t *value) {
  uint64_t res = 0;
  for (int shift = 0; shift < 64 && *pos < end; shift += 7) {
    uint8_t c = buf[(*pos)++];
    res |= (uint64_t) (c & 0x7f) << shift;
    if (c < 0x80) {
      *value = res;
      return 1;
    }
  }
  return 0;
}

// Returns whether the hash table points to the put at position, which has
// the given key hash.
static int put_is_live(sparkey_hashreader *reader, uint8_t *hashtable, int slot_size, uint64_t hash, uint64_t position) {
  uint64_t slot = capacity_mod(&reader->header, hash);
  uint64_t pos = slot * slot_size;
  uint64_t displacement = 0;

  while (1) {
    uint64_t hash2 = reader->header.hash_algorithm.read_hash(hashtable, pos);
    uint64_t position2 = read_addr(hashtable, pos + reader->header.hash_size, reader->header.address_size);
    if (position2 == 0) {
      return 0;
    }
    if (position == position2) {
      return 1;
    }
    uint64_t other_displacement = displacement_of(&reader->header, slot, hash2);
    if (displacement > other_displacement) {
      return 0;
    }
    pos += slot_size;
    displacement++;
    slot++;
    if (slot >= reader->header.hash_capacity) {
      pos = 0;
      slot = 0;
    }
  }
}

#define HASHNEXT_UNKNOWN (0)
#define HASHNEXT_HASHED (1)
#define HASHNEXT_LIVE (2)
#define HASHNEXT_DEAD (3)

// Looking up each put in a large hash table is a cache miss, and looking them
// up one at a time leaves a scan waiting on each in turn. This looks up all
// the puts in the current block at once, from the current entry on: it
// hashes their keys and starts loading their slots, so that the misses
// overlap, before reading any of them. Puts whose keys continue in the next
// block are left to sparkey_logiter_hashnext.
// The block must be fully decompressed and the current key not yet read.
static void lookup_block(sparkey_logiter *iter, sparkey_hashreader *reader, uint8_t *hashtable, int slot_size) {
  iter->hashnext_block = 0;
  uint64_t capacity = reader->log.header.max_entries_per_block;
  if (iter->hashnext_capacity < capacity) {
    free(iter->hashnext_hashes);
    iter->hashnext_hashes = NULL;
    iter->hashnext_capacity = 0;
    if (capacity > SIZE_MAX / (sizeof(uint64_t) + 1)) {
      return;
    }
    iter->hashnext_hashes = malloc(capacity * (sizeof(uint64_t) + 1));
    if (iter->hashnext_hashes == NULL) {
      return;
    }
    iter->hashnext_capacity = capacity;
  }
  if (iter->hashnext_hashes == NULL) {
    return;
  }
  uint64_t *hashes = iter->hashnext_hashes;
  uint8_t *state = (uint8_t *) (hashes + iter->hashnext_capacity);

  const uint8_t *buf = iter->compression_buf;
  uint64_t end = iter->block_len;
  uint64_t pos = iter->block_offset;
  uint64_t keylen = iter->keylen;
  uint64_t valuelen = iter->valuelen;
  int put = iter->type == SPARKEY_ENTRY_PUT;
  uint64_t n = 0;
  while (n < iter->hashnext_capacity) {
    state[n] = HASHNEXT_UNKNOWN;
    if (keylen > end - pos) {
      n++;
      break;
    }
    if (put) {
      hashes[n] = reader->header.hash_algorithm.hash(&buf[pos], keylen, reader->header.hash_seed);
      state[n] = HASHNEXT_HASHED;
#if defined(__GNUC__)
      __builtin_prefetch(&hashtable[capacity_mod(&reader->header, hashes[n]) * slot_size]);
#endif
    }
    n++;
    pos += keylen;
    if (valuelen >= end - pos) {
      break;
    }
    pos += valuelen;
    uint64_t a, b;
    if (!read_vlq_before(buf, end, &pos, &a) || !read_vlq_before(buf, end, &pos, &b)) {
      break;
    }
    put = a != 0;
    keylen = put ? a - 1 : b;
    valuelen = put ? b : 0;
  }

  uint64_t first_position = iter->entry_block_position << reader->header.entry_block_bits;
  for (uint64_t i = 0; i < n; i++) {
    if (state[i] == HASHNEXT_HASHED) {
      state[i] = put_is_live(reader, hashtable, slot_size, hashes[i], first_position | i) ? HASHNEXT_LIVE : HASHNEXT_DEAD;
    }
  }
  iter->hashnext_block = iter->entry_block_position;
  iter->hashnext_data_end = reader->header.data_end;
  iter->hashnext_count = n;
}

sparkey_returncode sparkey_logiter_hashnext(sparkey_logiter *iter, sparkey_hashreader *reader) {
  RETHROW(assert_reader_open(reader));

  uint8_t *hashtable = reader->data + reader->header.header_size;
  int slot_size = reader->header.address_size + reader->header.hash_size;

  // If every put in the indexed part of the log added a key, none was
  // overwritten or deleted, so they are all live and need no lookup.
  int all_puts_live = reader->header.num_entries == reader->header.num_puts;

  while (1) {
    RETHROW(sparkey_logiter_next(iter, &reader->log));
    if (iter->state != SPARKEY_ITER_ACTIVE) {
      return SPARKEY_SUCCESS;
    }
    if (!all_puts_live && iter->entry_count == 0 && iter->block_decoded >= iter->block_len &&
        reader->log.header.compression_type != SPARKEY_COMPRESSION_NONE) {
      lookup_block(iter, reader, hashtable, slot_size);
    }
    if (iter->type != SPARKEY_ENTRY_PUT) {
      continue;
    }
    if (all_puts_live && iter->entry_block_position < reader->header.data_end) {
      return SPARKEY_SUCCESS;
    }

    // Which puts are live depends only on the log up to the end of the part
    // that the hash file indexes, so earlier lookups of the block still hold.
    if (iter->hashnext_block == iter->entry_block_position &&
        iter->hashnext_data_end == reader->header.data_end &&
        (uint64_t) iter->entry_count < iter->hashnext_count) {
      uint8_t state = ((uint8_t *) (iter->hashnext_hashes + iter->hashnext_capacity))[iter->entry_count];
      if (state == HASHNEXT_LIVE) {
        return SPARKEY_SUCCESS;
      }
      if (state == HASHNEXT_DEAD) {
        continue;
      }
    }

    uint64_t position = (iter->entry_block_position << reader->header.entry_block_bits) | iter->entry_count;
    uint64_t key_hash;
    RETHROW(sparkey_iter_hash(&reader->header, iter, &reader->log, &key_hash));
    if (put_is_live(reader, hashtable, slot_size, key_hash, position)) {
      RETHROW(sparkey_logiter_reset(iter, &reader->log));
      return SPARKEY_SUCCESS;
    }
  }
}

sparkey_logreader * sparkey_hash_getreader(sparkey_hashreader *reader) {
  return &reader->log;
}

uint64_t sparkey_hash_numentries(sparkey_hashreader *reader) {
  return reader->header.num_entries;
}

uint64_t sparkey_hash_numcollisions(sparkey_hashreader *reader) {
  return reader->header.hash_collisions;
}

