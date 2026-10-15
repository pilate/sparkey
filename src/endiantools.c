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
#include <stddef.h>
#include <errno.h>
#include <string.h>
#include <inttypes.h>

#include "util.h"
#include "endiantools.h"
#include "sparkey.h"

static sparkey_returncode _write_full(int fd, uint8_t *buf, size_t count) {
  while (count > 0) {
    ssize_t actual = write(fd, buf, count);
    if (actual < 0) {
      switch (errno) {
      case EINTR:
      case EAGAIN: continue;
      case ENOSPC: return SPARKEY_OUT_OF_DISK;
      case EFBIG: return SPARKEY_FILE_SIZE_EXCEEDED;
      case EBADF: return SPARKEY_FILE_CLOSED;
      default:
        fprintf(stderr, "_write_full():%d bug: actual_written = %"PRIu64", wanted = %"PRIu64", errno = %d\n", __LINE__, (uint64_t)actual, (uint64_t)count, errno);
        return SPARKEY_INTERNAL_ERROR;
      }
    }
    count -= actual;
    buf += actual;
  }
  return SPARKEY_SUCCESS;
}

sparkey_returncode write_full(int fd, uint8_t *buf, size_t count) {
  const size_t block_size = 256*1024*1024;
  size_t fullruns = count / block_size;
  while (fullruns > 0) {
    RETHROW(_write_full(fd, buf, block_size));
    buf += block_size;
    fullruns--;
  }
  return _write_full(fd, buf, count % block_size);
}

sparkey_returncode fwrite_little_endian32(int fd, uint32_t value) {
  uint8_t buf[4];
  write_little_endian32(buf, value);
  return write_full(fd, buf, 4);
}

sparkey_returncode fwrite_little_endian64(int fd, uint64_t value) {
  uint8_t buf[8];
  write_little_endian64(buf, value);
  return write_full(fd, buf, 8);
}

sparkey_returncode correct_endian_platform(void) {
	return SPARKEY_SUCCESS;
}

sparkey_returncode fread_little_endian32(FILE *fp, uint32_t *res) {
  uint8_t data[4];
  int count = fread(data, 4, 1, fp);
  if (count < 1) {
    return SPARKEY_UNEXPECTED_EOF;
  }
  *res = read_little_endian32(data, 0);
  return SPARKEY_SUCCESS;
}

sparkey_returncode fread_little_endian64(FILE *fp, uint64_t *res) {
  uint8_t data[8];
  int count = fread(data, 8, 1, fp);
  if (count < 1) {
    return SPARKEY_UNEXPECTED_EOF;
  }
  *res = read_little_endian64(data, 0);
  return SPARKEY_SUCCESS;
}

