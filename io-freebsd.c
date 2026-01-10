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
  size_t copied = 0;

  while (copied < n) {
    size_t nbytes = n - copied;
    if(nbytes > IO_COPY_BUFSIZE) {
      nbytes = IO_COPY_BUFSIZE;
    }

    off_t sbytes = 0;

    int rc = sendfile(fd, s, offset, nbytes, NULL, &sbytes, 0); // may be SF_NOCACHE?
    if (sbytes > 0) {
        copied += (size_t)sbytes;
        offset += sbytes;
      }
    
    if (rc == 0) {
      if (sbytes == 0) {
        // no progress and successful (EOF/truncate)?
        errno = EIO;
        return -1;
      }
      continue;
    }

    if (errno == EINTR) {
        continue;
    }

    if (errno == EAGAIN
#ifdef EWOULDBLOCK
        || errno == EWOULDBLOCK
#endif
#ifdef ETIMEDOUT
        || errno == ETIMEDOUT
#endif
    ) {
        // was progress, try again
        if (sbytes > 0) {
            continue;
        }
        // no progess?
        return -1;
    }
    return -1; 
  }
  return 0;
}

