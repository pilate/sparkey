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
#ifndef SPARKEY_INTERNAL_H
#define SPARKEY_INTERNAL_H
#include <stdint.h>

#include "sparkey.h"

#include "logheader.h"
#include "hashheader.h"
#include "buf.h"

struct sparkey_logreader {
  uint32_t open_status;
  sparkey_logheader header;
  int fd;

  uint64_t data_len;
  uint8_t *data;
};

struct sparkey_logiter {
  uint32_t open_status;
  uint32_t file_identifier;

  // position in reader
  uint64_t block_position;
  uint64_t next_block_position;
  uint64_t block_offset;
  uint64_t block_len;
  int entry_count;

  // compression buffer
  int compression_buf_allocated;
  uint8_t *compression_buf;
  // Created by the decompressor on first use, if it needs one.
  sparkey_compression_type compression_type;
  void *decompress_context;

  // Snappy blocks are decompressed lazily: only the first block_decoded
  // bytes of compression_buf are valid, and snappy_next is the next
  // compressed byte to decode. block_decoded is UINT64_MAX for blocks that
  // are available in full.
  uint64_t block_decoded;
  const uint8_t *snappy_next;
  const uint8_t *snappy_end;

  // current entry
  uint64_t entry_block_position;
  uint64_t entry_block_offset;
  sparkey_entry_type type;
  sparkey_iter_state state;
  uint64_t keylen;
  uint64_t valuelen;
  uint64_t key_remaining;
  uint64_t value_remaining;

  // sparkey_logiter_hashnext looks up the puts of many entries at once.
  // For hashnext_capacity entries, one allocation at hashnext_hashes holds
  // their key hashes, their addresses and whether each is live, in a hash
  // file that indexes the log up to hashnext_data_end. Only the first
  // hashnext_count are set, and the entries before hashnext_cursor are
  // already passed.
  uint64_t *hashnext_hashes;
  uint64_t *hashnext_addresses;
  uint8_t *hashnext_states;
  uint64_t hashnext_capacity;
  uint64_t hashnext_data_end;
  uint64_t hashnext_count;
  uint64_t hashnext_cursor;
};

struct sparkey_logwriter {
  uint32_t open_status;
  sparkey_logheader header;
  int fd;

  sparkey_buf block_buf;
  uint32_t max_compressed_size;
  uint8_t *compressed;
  sparkey_buf file_buf;
  int flushed;

  int entry_count;
};

struct sparkey_hashreader {
  uint32_t open_status;
  sparkey_hashheader header;
  sparkey_logreader log;

  int fd;

  uint64_t data_len;
  uint8_t *data;

};

sparkey_returncode sparkey_logreader_open_noalloc(sparkey_logreader *log, const char *filename);
void sparkey_logreader_close_nodealloc(sparkey_logreader *log);

// decompress may store a context in *context, initially NULL, to reuse for
// later blocks. It is freed with free_context.
struct sparkey_compressor {
  uint32_t (*max_compressed_size)(uint32_t block_size);
  sparkey_returncode (*decompress)(void **context, uint8_t *input, uint32_t compressed_size, uint8_t *output, uint32_t *uncompressed_size);
  sparkey_returncode (*compress)(uint8_t *input, uint32_t uncompressed_size, uint8_t *output, uint32_t *compressed_size);
  void (*free_context)(void *context);
};

extern struct sparkey_compressor sparkey_compressors[3];
int sparkey_uses_compressor(sparkey_compression_type t);

// Bytes that sparkey_snappy_decompress_upto may write past the end of the
// decompressed data. Output buffers must be this much larger than the block.
#define SPARKEY_SNAPPY_SLACK (32)

/**
 * Reads the uncompressed length at the start of a snappy block and advances
 * *src past it.
 */
sparkey_returncode sparkey_snappy_read_length(const uint8_t **src, const uint8_t *src_end, uint32_t *len);

/**
 * Continues decompressing a snappy block until at least want bytes of out
 * (or all out_len bytes, if fewer) are decompressed.
 * @param src the next compressed byte to decode, advanced past the bytes used.
 * @param out_pos the number of bytes of out already decompressed, updated.
 */
sparkey_returncode sparkey_snappy_decompress_upto(const uint8_t **src, const uint8_t *src_end, uint8_t *out, uint64_t out_len, uint64_t *out_pos, uint64_t want);

#endif
