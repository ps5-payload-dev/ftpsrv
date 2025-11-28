/* Copyright (C) 2025 John Törnblom

This program is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 3, or (at your option) any
later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; see the file COPYING. If not, see
<http://www.gnu.org/licenses/>.  */

#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/errno.h>

#include "io.h"


int
io_nread(int fd, void* buf, size_t n) {
  int r;

  if((r=read(fd, buf, n)) < 0) {
    return -1;
  }

  if(r != n) {
    errno = EIO;
    return -1;
  }

  return 0;
}


int
io_nwrite(int fd, const void* buf, size_t n) {
  int r;

  if((r=write(fd, buf, n)) < 0) {
    return -1;
  }

  if(r != n) {
    errno = EIO;
    return -1;
  }

  return 0;
}


int
io_ncopy(int fd_in, int fd_out, size_t size) {
  size_t copied = 0;
  char buf[0x4000];
  ssize_t n;

  while(copied < size) {
    n = size - copied;
    if(n > sizeof(buf)) {
      n = sizeof(buf);
    }

    if(io_nread(fd_in, buf, n)) {
      return -1;
    }
    if(io_nwrite(fd_out, buf, n)) {
      return -1;
    }

    copied += n;
  }

  return 0;
}


int
io_pread(int fd, void* buf, size_t n, off_t off) {
  int r;

  if((r=pread(fd, buf, n, off)) < 0) {
    return -1;
  }

  if(r != n) {
    errno = EIO;
    return -1;
  }

  return 0;
}


int
io_pwrite(int fd, const void* buf, size_t n, off_t off) {
  int r;

  if((r=pwrite(fd, buf, n, off)) < 0) {
    return -1;
  }

  if(r != n) {
    errno = EIO;
    return -1;
  }

  return 0;
}


int
io_pcopy(int fd_in, int fd_out, off_t off_in, off_t off_out, size_t size) {
  size_t copied = 0;
  void* buf;
  ssize_t n;

  if(!(buf=malloc(IO_COPY_BUFSIZE))) {
    return -1;
  }

  while(copied < size) {
    n = size - copied;
    if(n > IO_COPY_BUFSIZE) {
      n = IO_COPY_BUFSIZE;
    }

    if(io_pread(fd_in, buf, n, off_in)) {
      free(buf);
      return -1;
    }
    if(io_pwrite(fd_out, buf, n, off_out)) {
      free(buf);
      return -1;
    }

    off_out += n;
    off_in += n;
    copied += n;
  }

  free(buf);
  return 0;
}

