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
#include <string.h>

#include "sparkey.h"
#include "sparkey-internal.h"
#include "hashiter.h"

sparkey_returncode sparkey_iter_hash(sparkey_hashheader *hash_header, sparkey_logiter *iter, sparkey_logreader *log, uint64_t *hash) {
  uint8_t *buf;
  uint64_t len;
  RETHROW(sparkey_logiter_keychunk(iter, log, iter->keylen, &buf, &len));
  if (len == iter->keylen) {
    *hash = hash_header->hash_algorithm.hash(buf, len, hash_header->hash_seed);
    return SPARKEY_SUCCESS;
  }

  uint8_t *keybuf = malloc(iter->keylen);
  if (keybuf == NULL) {
    return SPARKEY_INTERNAL_ERROR;
  }
  memcpy(keybuf, buf, len);
  uint64_t len2;
  sparkey_returncode returncode = sparkey_logiter_fill_key(iter, log, iter->keylen - len, keybuf + len, &len2);
  if (returncode == SPARKEY_SUCCESS && len + len2 != iter->keylen) {
    returncode = SPARKEY_UNEXPECTED_EOF;
  }
  if (returncode == SPARKEY_SUCCESS) {
    *hash = hash_header->hash_algorithm.hash(keybuf, iter->keylen, hash_header->hash_seed);
  }
  free(keybuf);
  return returncode;
}

