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

#include <sys/socket.h>
#include <sys/errno.h>

#include "io.h"


int
io_sendfile(int fd, int s, off_t offset, size_t n) {
  off_t copied = 0;
  off_t sbytes = 0;
  size_t nbytes;

  while (copied < n) {
    nbytes = n - copied;
    if(nbytes > IO_COPY_BUFSIZE) {
      nbytes = IO_COPY_BUFSIZE;
    }

    if(sendfile(fd, s, offset, nbytes, 0, &sbytes, 0) < 0) {
      if(errno == EINTR) {
	continue;
      }
      return -1;
    }

    if(sbytes == 0) {
      errno = EPIPE;
      return -1;
    }

    copied += sbytes;
    offset += sbytes;
  }

  return 0;
}

