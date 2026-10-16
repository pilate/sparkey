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
#ifndef SPARKEY_HASHHEADER_H_INCLUDED
#define SPARKEY_HASHHEADER_H_INCLUDED

#include <stdint.h>
#include "endiantools.h"

#include "sparkey.h"
#include "hashalgorithms.h"

#define HASH_MAGIC_NUMBER (0x9a11318f)
#define HASH_MAJOR_VERSION (1)
#define HASH_MINOR_VERSION (1)
#define HASH_HEADER_SIZE (112)

typedef struct {
  uint32_t major_version;
  uint32_t minor_version;
  uint32_t file_identifier;
  uint32_t hash_seed;
  uint32_t header_size;

  uint64_t data_end;
  uint64_t max_key_len;
  uint64_t max_value_len;

  uint64_t garbage_size;
  uint64_t num_entries;
  uint32_t address_size;
  uint32_t hash_size;
  uint64_t hash_capacity;
  uint64_t max_displacement;
  uint64_t num_puts;
  uint32_t entry_block_bits;
  uint32_t entry_block_bitmask;
  uint64_t hash_collisions;
  uint64_t total_displacement;
  sparkey_hash_algorithm hash_algorithm;
#ifdef __SIZEOF_INT128__
  // Set by set_capacity_fastmod, for computing hash % hash_capacity.
  __extension__ unsigned __int128 capacity_fastmod;
#endif
} sparkey_hashheader;

/**
 * fills up a hashheader struct based on the contents at the beginning of the file.
 * @param header header struct to fill
 * @param filename a hash file
 * @returns an error code if it could not load the file.
 */
sparkey_returncode sparkey_load_hashheader(sparkey_hashheader *header, const char *filename);

/**
 * Dumps a human readable representation of the header to stdout
 * @param header an initialized header struct
 */
void print_hashheader(sparkey_hashheader *header);

/**
 * Writes a header to the current position in the file
 * @param fd a file descripter pointing to a file open for writing
 * @param header the header to write
 * @returns an error code if it could not write to file.
 */
sparkey_returncode write_hashheader(int fd, sparkey_hashheader *header);

// hash_capacity must not be 0.
static inline void set_capacity_fastmod(sparkey_hashheader *hash_header) {
#ifdef __SIZEOF_INT128__
  hash_header->capacity_fastmod = (__extension__ (unsigned __int128) -1) / hash_header->hash_capacity + 1;
#else
  (void) hash_header;
#endif
}

// Returns hash % hash_capacity. This is needed for every slot probed and a
// 64-bit division is slow, so where 128-bit integers are available it
// multiplies instead (Lemire, Kaser and Kurz, "Faster Remainder by Direct
// Computation", 2019).
static inline uint64_t capacity_mod(sparkey_hashheader *hash_header, uint64_t hash) {
#ifdef __SIZEOF_INT128__
  __extension__ unsigned __int128 low = hash_header->capacity_fastmod * hash;
  __extension__ unsigned __int128 bottom = ((low & UINT64_MAX) * hash_header->hash_capacity) >> 64;
  __extension__ unsigned __int128 top = (low >> 64) * hash_header->hash_capacity;
  return (bottom + top) >> 64;
#else
  return hash % hash_header->hash_capacity;
#endif
}

// Starts loading the slot a hash starts probing from. This is a macro because
// GCC drops calls to a function that does nothing but prefetch, as it has no
// side effects.
#if defined(__GNUC__)
#define PREFETCH_SLOT(hashtable, hash_header, hash) \
  __builtin_prefetch(&(hashtable)[capacity_mod((hash_header), (hash)) * ((hash_header)->address_size + (hash_header)->hash_size)])
#else
#define PREFETCH_SLOT(hashtable, hash_header, hash) ((void) 0)
#endif

static inline uint64_t displacement_of(sparkey_hashheader *hash_header, uint64_t slot, uint64_t hash) {
  uint64_t wanted_slot = capacity_mod(hash_header, hash);
  return slot >= wanted_slot ? slot - wanted_slot : hash_header->hash_capacity + slot - wanted_slot;
}

static inline uint64_t read_addr(uint8_t *hashtable, uint64_t pos, int address_size) {
  switch (address_size) {
  case 4: return read_little_endian32(hashtable, pos);
  case 8: return read_little_endian64(hashtable, pos);
  }
  return -1;
}

static inline void write_addr(uint8_t *buf, uint64_t value, int address_size) {
  switch (address_size) {
  case 4: write_little_endian32(buf, value); return;
  case 8: write_little_endian64(buf, value); return;
  }
}


#endif

