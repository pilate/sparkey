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
#ifndef ENDIANTOOLS_H_INCLUDED
#define ENDIANTOOLS_H_INCLUDED

#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>

#if defined(__linux)
#include <byteswap.h>
#elif defined(__APPLE__)
#include <libkern/OSByteOrder.h>
#define bswap_32 OSSwapInt32
#define bswap_64 OSSwapInt64
#else
#error "no byteswap.h or libkern/OSByteOrder.h"
#endif

#include "sparkey.h"

typedef union {
  uint32_t i;
  uint8_t c[4];
} endian_union;

/**
 * Writes count bytes of buf to a file with file descriptor fd
 * @param fd file descriptor of a file to write to.
 * @param buf bytes to write to file.
 * Must point to a block of memory at least count long.
 * @param count number of bytes to write.
 * @returns SPARKEY_SUCCESS if all goes well, otherwise a sparkey error code.
 */
sparkey_returncode write_full(int fd, uint8_t *buf, size_t count);

/**
 * Write a 32 bit value to buf in little endian.
 * @param buf buf to write to. Must be at least 4 bytes long.
 * @param value the value to write.
 */
static inline void write_little_endian32(uint8_t *buf, uint32_t value) {
  buf[0] = (value >> 0) & 0xFF;
  buf[1] = (value >> 8) & 0xFF;
  buf[2] = (value >> 16) & 0xFF;
  buf[3] = (value >> 24) & 0xFF;
}

/**
 * Write a 32 bit value to file in little endian.
 * @param fd file descriptor of file open for write.
 * @param value the value to write.
 * @returns SPARKEY_SUCCESS if all goes well, a sparkey error if the
 * writing to file fails.
 */
sparkey_returncode fwrite_little_endian32(int fd, uint32_t value);

/**
 * Write a 64 bit value to buf in little endian.
 * @param buf buf to write to. Must be at least 8 bytes long.
 * @param value the value to write.
 */
static inline void write_little_endian64(uint8_t *buf, uint64_t value) {
  buf[0] = (value >> 0) & 0xFF;
  buf[1] = (value >> 8) & 0xFF;
  buf[2] = (value >> 16) & 0xFF;
  buf[3] = (value >> 24) & 0xFF;
  buf[4] = (value >> 32) & 0xFF;
  buf[5] = (value >> 40) & 0xFF;
  buf[6] = (value >> 48) & 0xFF;
  buf[7] = (value >> 56) & 0xFF;
}

/**
 * Write a 64 bit value to file in little endian.
 * @param fd file descriptor of file open for write.
 * @param value the value to write.
 * @returns SPARKEY_SUCCESS if all goes well, a sparkey error if the
 * writing to file fails.
 */
sparkey_returncode fwrite_little_endian64(int fd, uint64_t value);
// glibc defines both __LITTLE_ENDIAN and __BIG_ENDIAN on every platform, so
// they cannot be used to detect the byte order.
#if defined(__BYTE_ORDER__) ? __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__ : defined(__LITTLE_ENDIAN__)
static inline uint32_t read_little_endian32(const uint8_t * array, uint64_t pos) {
  uint32_t value;
  memcpy(&value, array + pos, sizeof(value));
  return value;
}

static inline uint64_t read_little_endian64(const uint8_t * array, uint64_t pos) {
  uint64_t value;
  memcpy(&value, array + pos, sizeof(value));
  return value;
}
#elif defined(__BYTE_ORDER__) ? __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__ : defined(__BIG_ENDIAN__)
static inline uint32_t read_little_endian32(const uint8_t * array, uint64_t pos) {
  uint32_t value;
  memcpy(&value, array + pos, sizeof(value));
  return bswap_32(value);
}

static inline uint64_t read_little_endian64(const uint8_t * array, uint64_t pos) {
  uint64_t value;
  memcpy(&value, array + pos, sizeof(value));
  return bswap_64(value);
}
#else
#error "cannot determine the byte order: neither __BYTE_ORDER__ nor __LITTLE_ENDIAN__/__BIG_ENDIAN__ is defined"
#endif
sparkey_returncode correct_endian_platform(void);

sparkey_returncode fread_little_endian32(FILE *fp, uint32_t *res);
sparkey_returncode fread_little_endian64(FILE *fp, uint64_t *res);

#endif /* ENDIAN_H_INCLUDED */

