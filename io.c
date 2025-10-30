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

