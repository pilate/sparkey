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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>

#include "sparkey.h"

static int max(int a, int b) {
  return a > b ? a : b;
}

static void _assert_equals(const char *file, int line, int expected, int actual) {
  if (expected != actual) {
    printf("%s:%d: Expected %d but got %d\n", file, line, expected, actual);
    exit(1);
  }
}

#define assert_equals(expected, actual) _assert_equals(__FILE__, __LINE__, expected, actual)

static void _assert_str_equals(const char *file, int line, const char *expected, const char *actual) {
  if (expected == NULL && actual != NULL) {
    printf("%s:%d: Expected NULL but got '%s'\n", file, line, actual);
    exit(1);
  }
  if (expected != NULL && actual == NULL) {
    printf("%s:%d: Expected '%s' but got NULL\n", file, line, expected);
    exit(1);
  }
  if (expected != NULL && actual != NULL && strcmp(expected, actual)) {
    printf("%s:%d: Expected '%s' but got '%s'\n", file, line, expected, actual);
    exit(1);
  }
}

#define assert_str_equals(expected, actual) _assert_str_equals(__FILE__, __LINE__, expected, actual)

void verify(sparkey_compression_type compression, int blocksize, int hashsize, int num_puts, int num_deletes, int num_puts2) {
  int expected_puts = max(0, num_puts - max(num_deletes, num_puts2));
  int expected_total = expected_puts + num_puts2;

  // write some data to the log
  sparkey_logwriter *mywriter;
  assert_equals(SPARKEY_SUCCESS, sparkey_logwriter_create(&mywriter, "test.spl", compression, blocksize));

  for (int i = 0; i < num_puts; i++) {
    char key[100];
    char value[100];
    sprintf(key, "key_%d", i);
    sprintf(value, "value_%d", i);
    assert_equals(SPARKEY_SUCCESS, sparkey_logwriter_put(mywriter, strlen(key), (uint8_t*) key, strlen(value), (uint8_t*) value));
  }

  for (int i = 0; i < num_deletes; i++) {
    char key[100];
    sprintf(key, "key_%d", i);
    assert_equals(SPARKEY_SUCCESS, sparkey_logwriter_delete(mywriter, strlen(key), (uint8_t*) key));
  }

  for (int i = 0; i < num_puts2; i++) {
    char key[100];
    char value[100];
    sprintf(key, "key_%d", i);
    sprintf(value, "newvalue_%d", i);
    assert_equals(SPARKEY_SUCCESS, sparkey_logwriter_put(mywriter, strlen(key), (uint8_t*) key, strlen(value), (uint8_t*) value));
  }

  assert_equals(SPARKEY_SUCCESS, sparkey_logwriter_close(&mywriter));

  // verify correct log iteration
  sparkey_logreader *myreader;
  assert_equals(SPARKEY_SUCCESS, sparkey_logreader_open(&myreader, "test.spl"));
  sparkey_logiter *myiter;
  assert_equals(SPARKEY_SUCCESS, sparkey_logiter_create(&myiter, myreader));

  int visited = 0;
  while (1) {
    assert_equals(SPARKEY_SUCCESS, sparkey_logiter_next(myiter, myreader));
    if (sparkey_logiter_state(myiter) != SPARKEY_ITER_ACTIVE) {
      break;
    }
    visited++;
    uint64_t wanted_keylen = sparkey_logiter_keylen(myiter);

    // one extra byte to account for the extra \0 at the end, as we're going to compare it as a string.
    // By using calloc we also ensure that it initializes to 0 directly.
    uint8_t *keybuf = calloc(1 + wanted_keylen, 1);

    uint64_t actual_keylen;
    assert_equals(SPARKEY_SUCCESS, sparkey_logiter_fill_key(myiter, myreader, wanted_keylen, keybuf, &actual_keylen));
    assert_equals(wanted_keylen, actual_keylen);

    uint64_t wanted_valuelen = sparkey_logiter_valuelen(myiter);
    uint8_t *valuebuf = calloc(1 + wanted_valuelen, 1);
    uint64_t actual_valuelen;
    assert_equals(SPARKEY_SUCCESS, sparkey_logiter_fill_value(myiter, myreader, wanted_valuelen, valuebuf, &actual_valuelen));
    assert_equals(wanted_valuelen, actual_valuelen);

    sparkey_entry_type expected_type;
    int expected_id;
    const char *expected_value_prefix;
    if (visited <= num_puts) {
      expected_type = SPARKEY_ENTRY_PUT;
      expected_id = visited - 1;
      expected_value_prefix = "value";
    } else if (visited <= num_puts + num_deletes) {
      expected_type = SPARKEY_ENTRY_DELETE;
      expected_id = visited - num_puts - 1;
      expected_value_prefix = "UNUSED";
    } else {
      expected_type = SPARKEY_ENTRY_PUT;
      expected_id = visited - num_puts - num_deletes - 1;
      expected_value_prefix = "newvalue";
    }
    assert_equals(expected_type, sparkey_logiter_type(myiter));
    char expected_key[100];
    char expected_value[100];
    sprintf(expected_key, "key_%d", expected_id);
    sprintf(expected_value, "%s_%d", expected_value_prefix, expected_id);

    assert_str_equals(expected_key, (char*) keybuf);
    if (expected_type == SPARKEY_ENTRY_PUT) {
      assert_str_equals(expected_value, (char*) valuebuf);
    }

    free(keybuf);
    free(valuebuf);
  }
  assert_equals(num_puts + num_deletes + num_puts2, visited);
  sparkey_logreader_close(&myreader);
  sparkey_logiter_close(&myiter);

  // create the hash
  assert_equals(SPARKEY_SUCCESS, sparkey_hash_write("test.spi", "test.spl", hashsize));

  // verify hash iteration
  sparkey_hashreader *myhashreader;
  assert_equals(SPARKEY_SUCCESS, sparkey_hash_open(&myhashreader, "test.spi", "test.spl"));
  myreader = sparkey_hash_getreader(myhashreader);
  assert_equals(SPARKEY_SUCCESS, sparkey_logiter_create(&myiter, myreader));

  visited = 0;
  while (1) {
    assert_equals(SPARKEY_SUCCESS, sparkey_logiter_hashnext(myiter, myhashreader));
    if (sparkey_logiter_state(myiter) != SPARKEY_ITER_ACTIVE) {
      break;
    }
    visited++;
    uint64_t wanted_keylen = sparkey_logiter_keylen(myiter);
    uint8_t *keybuf = calloc(1 + wanted_keylen, 1);
    uint64_t actual_keylen;
    assert_equals(SPARKEY_SUCCESS, sparkey_logiter_fill_key(myiter, myreader, wanted_keylen, keybuf, &actual_keylen));
    assert_equals(wanted_keylen, actual_keylen);

    uint64_t wanted_valuelen = sparkey_logiter_valuelen(myiter);
    uint8_t *valuebuf = calloc(1 + wanted_valuelen, 1);
    uint64_t actual_valuelen;
    assert_equals(SPARKEY_SUCCESS, sparkey_logiter_fill_value(myiter, myreader, wanted_valuelen, valuebuf, &actual_valuelen));
    assert_equals(wanted_valuelen, actual_valuelen);

    assert_equals(SPARKEY_ENTRY_PUT, sparkey_logiter_type(myiter));

    int expected_id;
    const char *expected_value_prefix;
    if (visited <= expected_puts) {
      expected_id = max(num_deletes, num_puts2) + visited - 1;
      expected_value_prefix = "value";
    } else {
      expected_id = visited - expected_puts - 1;
      expected_value_prefix = "newvalue";

    }
    char expected_key[100];
    char expected_value[100];
    sprintf(expected_key, "key_%d", expected_id);
    sprintf(expected_value, "%s_%d", expected_value_prefix, expected_id);

    assert_str_equals(expected_key, (char*) keybuf);
    assert_str_equals(expected_value, (char*) valuebuf);

    free(keybuf);
    free(valuebuf);
  }
  assert_equals(expected_total, visited);

  // verify random access
  for (int i = 0; i < max(num_puts, num_puts2) + 100; i++) {
    char key[100];
    char expected_value[100];
    sprintf(key, "key_%d", i);
    assert_equals(SPARKEY_SUCCESS, sparkey_hash_get(myhashreader, (uint8_t*) key, strlen(key), myiter));
    if (i < num_puts2) {
      assert_equals(SPARKEY_ITER_ACTIVE, sparkey_logiter_state(myiter));
      sprintf(expected_value, "newvalue_%d", i);
    } else if (i >= num_deletes && i < num_puts) {
      assert_equals(SPARKEY_ITER_ACTIVE, sparkey_logiter_state(myiter));
      sprintf(expected_value, "value_%d", i);
    } else {
      assert_equals(SPARKEY_ITER_INVALID, sparkey_logiter_state(myiter));
    }

    if (sparkey_logiter_state(myiter) == SPARKEY_ITER_ACTIVE) {
      uint64_t wanted_valuelen = sparkey_logiter_valuelen(myiter);
      uint8_t *valuebuf = calloc(1 + wanted_valuelen, 1);
      uint64_t actual_valuelen;
      assert_equals(SPARKEY_SUCCESS, sparkey_logiter_fill_value(myiter, myreader, wanted_valuelen, valuebuf, &actual_valuelen));
      assert_equals(wanted_valuelen, actual_valuelen);

      assert_str_equals(expected_value, (char*) valuebuf);
      free(valuebuf);
    }
  }
  sparkey_hash_close(&myhashreader);
  sparkey_logiter_close(&myiter);
}

void verify_files_closed(void) {
  // Verify that SPARKEY_FILE_IDENTIFIER_MISMATCH is returned appropriately.
  sparkey_logwriter *writer;
  assert_equals(SPARKEY_SUCCESS, sparkey_logwriter_create(&writer, "test1.spl",
    SPARKEY_COMPRESSION_NONE, 4096));
  assert_equals(SPARKEY_SUCCESS, sparkey_logwriter_close(&writer));
  assert_equals(1, writer == NULL);

  assert_equals(SPARKEY_SUCCESS, sparkey_logwriter_create(&writer, "test2.spl",
    SPARKEY_COMPRESSION_NONE, 4096));
  assert_equals(SPARKEY_SUCCESS, sparkey_logwriter_close(&writer));
  assert_equals(1, writer == NULL);

  // Now create a hash for test1.
  assert_equals(SPARKEY_SUCCESS, sparkey_hash_write("test1.spi", "test1.spl", 0));

  // and try to open the wrong files:
  sparkey_hashreader* reader;
  sparkey_returncode rc = sparkey_hash_open(
    &reader,
    "test1.spi",
    "test2.spl"
  );

  assert_equals(SPARKEY_FILE_IDENTIFIER_MISMATCH, rc);
}

// Writes key<i> -> value<i> for i in [from, to), creating the log if from is 0.
static void write_entries(const char *log_filename, int from, int to) {
  sparkey_logwriter *writer;
  if (from == 0) {
    assert_equals(SPARKEY_SUCCESS, sparkey_logwriter_create(&writer, log_filename, SPARKEY_COMPRESSION_NONE, 0));
  } else {
    assert_equals(SPARKEY_SUCCESS, sparkey_logwriter_append(&writer, log_filename));
  }
  for (int i = from; i < to; i++) {
    char key[32];
    char value[32];
    snprintf(key, sizeof(key), "key%d", i);
    snprintf(value, sizeof(value), "value%d", i);
    assert_equals(SPARKEY_SUCCESS, sparkey_logwriter_put(writer, strlen(key), (uint8_t *) key, strlen(value), (uint8_t *) value));
  }
  assert_equals(SPARKEY_SUCCESS, sparkey_logwriter_close(&writer));
}

// Checks that key<i> maps to value<i> for i in [from, to).
static void verify_reader_entries(sparkey_hashreader *reader, int from, int to) {
  sparkey_logiter *iter;
  sparkey_logreader *logreader = sparkey_hash_getreader(reader);
  assert_equals(SPARKEY_SUCCESS, sparkey_logiter_create(&iter, logreader));
  for (int i = from; i < to; i++) {
    char key[32];
    char expected[32];
    uint8_t value[32];
    uint64_t len;
    snprintf(key, sizeof(key), "key%d", i);
    snprintf(expected, sizeof(expected), "value%d", i);
    assert_equals(SPARKEY_SUCCESS, sparkey_hash_get(reader, (uint8_t *) key, strlen(key), iter));
    assert_equals(SPARKEY_ITER_ACTIVE, sparkey_logiter_state(iter));
    assert_equals(SPARKEY_SUCCESS, sparkey_logiter_fill_value(iter, logreader, sizeof(value) - 1, value, &len));
    value[len] = '\0';
    assert_str_equals(expected, (char *) value);
  }
  sparkey_logiter_close(&iter);
}

static void verify_entries(const char *hash_filename, const char *log_filename, int from, int to) {
  sparkey_hashreader *reader;
  assert_equals(SPARKEY_SUCCESS, sparkey_hash_open(&reader, hash_filename, log_filename));
  verify_reader_entries(reader, from, to);
  sparkey_hash_close(&reader);
}

// Counts the files in the current directory whose name starts with prefix.
static int count_files(const char *prefix) {
  int count = 0;
  DIR *dir = opendir(".");
  struct dirent *entry;
  while ((entry = readdir(dir)) != NULL) {
    if (strncmp(entry->d_name, prefix, strlen(prefix)) == 0) {
      count++;
    }
  }
  closedir(dir);
  return count;
}

void verify_truncated_hash_rebuild(void) {
  // Updating a hash file that is smaller than its header says used to hang.
  // It should be rebuilt from scratch instead.
  write_entries("truncated.spl", 0, 100);
  assert_equals(SPARKEY_SUCCESS, sparkey_hash_write("truncated.spi", "truncated.spl", 0));
  assert_equals(0, truncate("truncated.spi", 200));
  write_entries("truncated.spl", 100, 110);
  assert_equals(SPARKEY_SUCCESS, sparkey_hash_write("truncated.spi", "truncated.spl", 0));
  verify_entries("truncated.spi", "truncated.spl", 0, 110);
}

void verify_hash_rewrite(void) {
  // A hash file is replaced atomically: readers that already have it open keep
  // seeing the old version, and no temporary files are left behind.
  write_entries("rewrite.spl", 0, 100);
  assert_equals(SPARKEY_SUCCESS, sparkey_hash_write("rewrite.spi", "rewrite.spl", 0));
  sparkey_hashreader *old_reader;
  assert_equals(SPARKEY_SUCCESS, sparkey_hash_open(&old_reader, "rewrite.spi", "rewrite.spl"));
  write_entries("rewrite.spl", 100, 200);
  assert_equals(SPARKEY_SUCCESS, sparkey_hash_write("rewrite.spi", "rewrite.spl", 0));
  verify_reader_entries(old_reader, 0, 100);
  sparkey_hash_close(&old_reader);
  verify_entries("rewrite.spi", "rewrite.spl", 0, 200);
  assert_equals(0, count_files("rewrite.spi.tmp"));

  // Failures are reported and clean up after themselves.
  assert_equals(SPARKEY_FILE_NOT_FOUND, sparkey_hash_write("no-such-dir/rewrite.spi", "rewrite.spl", 0));
  rmdir("directory.spi");
  assert_equals(0, mkdir("directory.spi", 0755));
  assert_equals(SPARKEY_FILE_IS_DIRECTORY, sparkey_hash_write("directory.spi", "rewrite.spl", 0));
  assert_equals(0, count_files("directory.spi.tmp"));
  assert_equals(0, rmdir("directory.spi"));
}

// Returns the number of open file descriptors. If it changes after some
// operation, that operation leaked a file descriptor.
static int count_open_fds(void) {
  int count = 0;
  for (int fd = 0; fd < 1024; fd++) {
    if (fcntl(fd, F_GETFD) != -1) {
      count++;
    }
  }
  return count;
}

// Creates a file that is too short to hold a sparkey header.
static void write_short_file(const char *filename) {
  FILE *fp = fopen(filename, "w");
  fputs("ab", fp);
  fclose(fp);
}

void verify_failed_header_loads_close_files(void) {
  write_short_file("short.spl");
  write_short_file("short.spi");
  int fds = count_open_fds();
  for (int i = 0; i < 10; i++) {
    sparkey_logreader *logreader;
    sparkey_hashreader *hashreader;
    sparkey_logwriter *logwriter;
    assert_equals(SPARKEY_UNEXPECTED_EOF, sparkey_logreader_open(&logreader, "short.spl"));
    assert_equals(SPARKEY_UNEXPECTED_EOF, sparkey_logwriter_append(&logwriter, "short.spl"));
    assert_equals(SPARKEY_UNEXPECTED_EOF, sparkey_hash_open(&hashreader, "short.spi", "short.spl"));
  }
  assert_equals(fds, count_open_fds());
}

void verify_failed_hash_open_closes_files(void) {
  write_entries("toosmall.spl", 0, 100);
  assert_equals(SPARKEY_SUCCESS, sparkey_hash_write("toosmall.spi", "toosmall.spl", 0));
  assert_equals(0, truncate("toosmall.spi", 200));
  int fds = count_open_fds();
  for (int i = 0; i < 10; i++) {
    sparkey_hashreader *reader;
    assert_equals(SPARKEY_HASH_TOO_SMALL, sparkey_hash_open(&reader, "toosmall.spi", "toosmall.spl"));
  }
  assert_equals(fds, count_open_fds());
}

void verify_hash_write_up_to_date(void) {
  // Writing a hash file that is already up to date does nothing. This used to
  // leak the hash table, which the sanitizer CI job detects.
  write_entries("uptodate.spl", 0, 100);
  assert_equals(SPARKEY_SUCCESS, sparkey_hash_write("uptodate.spi", "uptodate.spl", 0));
  assert_equals(SPARKEY_SUCCESS, sparkey_hash_write("uptodate.spi", "uptodate.spl", 0));
  verify_entries("uptodate.spi", "uptodate.spl", 0, 100);
}

void verify_logwriter_double_close(void) {
  // Closing a writer twice used to dereference NULL.
  sparkey_logwriter *writer;
  assert_equals(SPARKEY_SUCCESS, sparkey_logwriter_create(&writer, "doubleclose.spl", SPARKEY_COMPRESSION_NONE, 0));
  assert_equals(SPARKEY_SUCCESS, sparkey_logwriter_close(&writer));
  assert_equals(SPARKEY_SUCCESS, sparkey_logwriter_close(&writer));
  assert_equals(SPARKEY_SUCCESS, sparkey_logwriter_close(NULL));
}

int main(void) {
  verify(SPARKEY_COMPRESSION_NONE, 0, 0, 0, 0, 0);
  verify(SPARKEY_COMPRESSION_NONE, 0, 0, 1, 0, 0);
  verify(SPARKEY_COMPRESSION_NONE, 0, 0, 100, 0, 0);
  verify(SPARKEY_COMPRESSION_NONE, 0, 0, 0, 100, 0);
  verify(SPARKEY_COMPRESSION_NONE, 0, 0, 0, 0, 100);
  verify(SPARKEY_COMPRESSION_NONE, 0, 0, 100, 10, 5);

  for (sparkey_compression_type t = SPARKEY_COMPRESSION_SNAPPY; t <= SPARKEY_COMPRESSION_ZSTD; t++) {
    verify(t, 10, 0, 100, 0, 0);
    verify(t, 20, 0, 100, 0, 0);
    verify(t, 100, 0, 100, 0, 0);
    verify(t, 100, 0, 1000, 0, 0);
    verify(t, 1000, 0, 1000, 0, 0);

    verify(t, 100, 0, 1000, 100, 0);
    verify(t, 100, 0, 1000, 100, 50);

    verify(t, 100, 4, 1000, 0, 0);
    verify(t, 100, 8, 1000, 0, 0);
  }

  verify_files_closed();
  verify_truncated_hash_rebuild();
  verify_hash_rewrite();
  verify_failed_header_loads_close_files();
  verify_failed_hash_open_closes_files();
  verify_hash_write_up_to_date();
  verify_logwriter_double_close();

  printf("Success!\n");
}

