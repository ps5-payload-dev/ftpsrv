/* Copyright (C) 2026 Rui Nelson
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/* Run with: cc -Wall -Werror -I. test/test-io.c -o /tmp/test-io && /tmp/test-io
 * Script the syscalls so short transfers and interruptions are deterministic.
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>

#include "io.h"

static ssize_t test_read(int fd, void* buf, size_t n);
static ssize_t test_write(int fd, const void* buf, size_t n);
static ssize_t test_pread(int fd, void* buf, size_t n, off_t off);
static ssize_t test_pwrite(int fd, const void* buf, size_t n, off_t off);

#define read test_read
#define write test_write
#define pread test_pread
#define pwrite test_pwrite
#include "../io.c"
#undef read
#undef write
#undef pread
#undef pwrite

#define CHECK(condition) do { \
  if(!(condition)) { \
    fprintf(stderr, "line %d: %s\n", __LINE__, #condition); \
    exit(1); \
  } \
} while(0)

enum operation { READ, WRITE, PREAD, PWRITE };

struct step {
  ssize_t result;
  int error;
};

static const unsigned char payload[] = "abcdef";
static unsigned char buffer[sizeof(payload)];
static enum operation operation;
static const struct step* script;
static size_t script_len;
static size_t calls;
static size_t completed;
static size_t requested;
static int tests;

static ssize_t
transfer(enum operation op, int fd, const void* buf, size_t n, off_t off) {
  const struct step* step;

  CHECK(op == operation);
  CHECK(fd == 42);
  CHECK(buf == buffer + completed);
  CHECK(n == requested - completed);
  if(op == PREAD || op == PWRITE) {
    CHECK(off == (off_t)(4096 + completed));
  }
  CHECK(calls < script_len);
  step = &script[calls++];
  if(step->result < 0) {
    errno = step->error;
    return -1;
  }

  CHECK((size_t)step->result <= n);
  if(op == READ || op == PREAD) {
    memcpy((void*)buf, payload + completed, step->result);
  } else {
    CHECK(!memcmp(buf, payload + completed, step->result));
  }
  completed += step->result;
  return step->result;
}

static ssize_t
test_read(int fd, void* buf, size_t n) {
  return transfer(READ, fd, buf, n, 0);
}

static ssize_t
test_write(int fd, const void* buf, size_t n) {
  return transfer(WRITE, fd, buf, n, 0);
}

static ssize_t
test_pread(int fd, void* buf, size_t n, off_t off) {
  return transfer(PREAD, fd, buf, n, off);
}

static ssize_t
test_pwrite(int fd, const void* buf, size_t n, off_t off) {
  return transfer(PWRITE, fd, buf, n, off);
}

static void
run_case(enum operation op, const struct step* steps, size_t len, size_t n,
	 int expected_errno) {
  int result = -1;

  operation = op;
  script = steps;
  script_len = len;
  requested = n;
  calls = completed = 0;
  memset(buffer, 0, sizeof(buffer));
  if(op == WRITE || op == PWRITE) {
    memcpy(buffer, payload, n);
  }
  errno = 0;

  switch(op) {
  case READ:
    result = io_nread(42, buffer, n);
    break;
  case WRITE:
    result = io_nwrite(42, buffer, n);
    break;
  case PREAD:
    result = io_pread(42, buffer, n, 4096);
    break;
  case PWRITE:
    result = io_pwrite(42, buffer, n, 4096);
    break;
  }

  CHECK(result == (expected_errno ? -1 : 0));
  if(expected_errno) {
    CHECK(errno == expected_errno);
  } else {
    CHECK(completed == n);
  }
  CHECK(calls == len);
  CHECK(!memcmp(buffer, payload, completed));
  tests++;
}

int
main(void) {
  static const struct step partial[] = {
    {-1, EINTR}, {2, 0}, {-1, EINTR}, {1, 0}, {3, 0}
  };
  static const struct step no_progress[] = {{0, 0}};
  static const struct step short_file[] = {{2, 0}, {0, 0}};
  static const struct step failed[] = {{-1, EACCES}};
  static const struct step failed_after_partial[] = {{2, 0}, {-1, ENOSPC}};

  for(enum operation op=READ; op<=PWRITE; op++) {
    run_case(op, partial, sizeof(partial) / sizeof(*partial), 6, 0);
    run_case(op, no_progress, 1, 6, EIO);
    run_case(op, short_file, 2, 6, EIO);
    run_case(op, failed, 1, 6, EACCES);
    run_case(op, failed_after_partial, 2, 6, ENOSPC);
    run_case(op, NULL, 0, 0, 0);
  }

  printf("%d I/O regression cases passed\n", tests);
  return 0;
}
