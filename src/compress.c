/*
* Copyright (c) 2012-2020 Spotify AB
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

#include "sparkey-internal.h"
#include "sparkey.h"
#include "endiantools.h"

#include <snappy-c.h>
#include <zstd.h>


static uint32_t sparkey_snappy_max_compressed_size(uint32_t block_size) {
  return snappy_max_compressed_length(block_size);
}

static sparkey_returncode sparkey_snappy_compress(uint8_t *input, uint32_t uncompressed_size, uint8_t *output, uint32_t *compressed_size) {
  size_t rsize = *compressed_size;
  snappy_status status = snappy_compress((char *) input, uncompressed_size, (char *) output, &rsize);
  *compressed_size = rsize;
  if (status == SNAPPY_OK) {
    return SPARKEY_SUCCESS;
  }
  return SPARKEY_INTERNAL_ERROR;
}

static uint32_t sparkey_zstd_max_compressed_size(uint32_t block_size) {
  return ZSTD_compressBound(block_size);
}

static sparkey_returncode sparkey_zstd_decompress(uint8_t *input, uint32_t compressed_size, uint8_t *output, uint32_t *uncompressed_size) {
  size_t ret = ZSTD_decompress(output, *uncompressed_size, input, compressed_size);
  if (ZSTD_isError(ret)) {
    return SPARKEY_INTERNAL_ERROR;
  }
  *uncompressed_size = ret;
  return SPARKEY_SUCCESS;
}

static sparkey_returncode sparkey_zstd_compress(uint8_t *input, uint32_t uncompressed_size, uint8_t *output, uint32_t *compressed_size) {
  size_t ret = ZSTD_compress(output, *compressed_size, input, uncompressed_size, 3);
  if (ZSTD_isError(ret)) {
    return SPARKEY_INTERNAL_ERROR;
  }
  *compressed_size = ret;
  return SPARKEY_SUCCESS;
}

struct sparkey_compressor sparkey_compressors[] = {
  {
    .max_compressed_size = NULL,
  },
  {
    .max_compressed_size = sparkey_snappy_max_compressed_size,
    // No decompress: the log iterator uses sparkey_snappy_decompress_upto.
    .compress = sparkey_snappy_compress,
  },
  {
    .max_compressed_size = sparkey_zstd_max_compressed_size,
    .decompress = sparkey_zstd_decompress,
    .compress = sparkey_zstd_compress,
  },
};

int sparkey_uses_compressor(sparkey_compression_type t) {
  switch (t) {
    case SPARKEY_COMPRESSION_SNAPPY:
    case SPARKEY_COMPRESSION_ZSTD:
      return 1;
    default:
      return 0;
  }
}

/*
 * The log iterator decompresses snappy blocks incrementally, so that a hash
 * lookup only decompresses its block up to the entry it reads instead of the
 * whole block. libsnappy cannot stop part way, so the decoder is implemented
 * here. The format is described in snappy's format_description.txt.
 */

sparkey_returncode sparkey_snappy_read_length(const uint8_t **src, const uint8_t *src_end, uint32_t *len) {
  const uint8_t *ip = *src;
  uint32_t result = 0;
  for (int shift = 0; shift <= 28; shift += 7) {
    if (ip >= src_end) {
      return SPARKEY_INTERNAL_ERROR;
    }
    uint8_t c = *ip++;
    if (shift == 28 && c > 0x0f) {
      return SPARKEY_INTERNAL_ERROR;
    }
    result |= (uint32_t) (c & 0x7f) << shift;
    if (c < 0x80) {
      *src = ip;
      *len = result;
      return SPARKEY_SUCCESS;
    }
  }
  return SPARKEY_INTERNAL_ERROR;
}

sparkey_returncode sparkey_snappy_decompress_upto(const uint8_t **src, const uint8_t *src_end, uint8_t *out, uint64_t out_len, uint64_t *out_pos, uint64_t want) {
  const uint8_t *ip = *src;
  uint8_t *op = out + *out_pos;
  uint8_t *op_end = out + out_len;
  uint8_t *op_want = out + (want < out_len ? want : out_len);

  // Short copies write whole words, which can run up to
  // SPARKEY_SNAPPY_SLACK bytes past op_end. Bytes past op are overwritten
  // later, and are never part of the decompressed data until then.
  while (op < op_want) {
    if (ip >= src_end) {
      return SPARKEY_INTERNAL_ERROR;
    }
    uint8_t tag = *ip++;
    uint64_t len;
    uint64_t offset;
    switch (tag & 3) {
    case 0:
      len = (tag >> 2) + 1;
      if (len <= 32 && src_end - ip >= 32) {
        if (len > (uint64_t) (op_end - op)) {
          return SPARKEY_INTERNAL_ERROR;
        }
        memcpy(op, ip, 32);
        op += len;
        ip += len;
        continue;
      }
      if (len > 60) {
        uint64_t extra = len - 60;
        if ((uint64_t) (src_end - ip) < extra) {
          return SPARKEY_INTERNAL_ERROR;
        }
        len = 0;
        for (uint64_t i = 0; i < extra; i++) {
          len |= (uint64_t) ip[i] << (8 * i);
        }
        len++;
        ip += extra;
      }
      if (len > (uint64_t) (src_end - ip) || len > (uint64_t) (op_end - op)) {
        return SPARKEY_INTERNAL_ERROR;
      }
      memcpy(op, ip, len);
      op += len;
      ip += len;
      continue;
    case 1:
      if (ip >= src_end) {
        return SPARKEY_INTERNAL_ERROR;
      }
      len = 4 + ((tag >> 2) & 7);
      offset = ((uint64_t) (tag >> 5) << 8) | *ip++;
      break;
    case 2:
      if (src_end - ip < 2) {
        return SPARKEY_INTERNAL_ERROR;
      }
      len = (tag >> 2) + 1;
      offset = ip[0] | ((uint64_t) ip[1] << 8);
      ip += 2;
      break;
    default:
      if (src_end - ip < 4) {
        return SPARKEY_INTERNAL_ERROR;
      }
      len = (tag >> 2) + 1;
      offset = read_little_endian32(ip, 0);
      ip += 4;
      break;
    }
    if (offset == 0 || offset > (uint64_t) (op - out) || len > (uint64_t) (op_end - op)) {
      return SPARKEY_INTERNAL_ERROR;
    }
    const uint8_t *from = op - offset;
    uint8_t *stop = op + len;
    if (offset >= 8) {
      // Each word is read from output that is already written. Most copies
      // are at most 16 bytes long.
      memcpy(op, from, 8);
      memcpy(op + 8, from + 8, 8);
      for (uint64_t i = 16; i < len; i += 8) {
        memcpy(op + i, from + i, 8);
      }
    } else {
      while (op < stop) {
        *op++ = *from++;
      }
    }
    op = stop;
  }
  // A complete block must use all of its input, as libsnappy requires.
  if (op == op_end && ip != src_end) {
    return SPARKEY_INTERNAL_ERROR;
  }
  *src = ip;
  *out_pos = op - out;
  return SPARKEY_SUCCESS;
}
