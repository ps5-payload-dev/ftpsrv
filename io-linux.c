/* Copyright (C) 2026 John Törnblom

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

#include <sys/sendfile.h>
#include <sys/errno.h>

#include "io.h"


int
io_sendfile(int in_fd, int out_fd, off_t offset, size_t n) {
  size_t copied = 0;
  ssize_t r;

  while (copied < n) {
    size_t count = n - copied;
    if(count > IO_COPY_BUFSIZE) {
      count = IO_COPY_BUFSIZE;
    }

    if((r=sendfile(out_fd, in_fd, &offset, count)) < 0) {
      if(errno == EINTR) {
        continue;
      }
      return -1;
    }
    if(r == 0) {
      errno = EPIPE;
      return -1;
    }

    copied += r;
  }

  return 0;
}

