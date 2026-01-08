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

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/errno.h>

#include "io.h"


int
io_nread(int fd, void* buf, size_t n) {
  size_t off = 0;

  while(off < n) {
    ssize_t r = read(fd, (char*)buf + off, n - off);
    if(r < 0) {
      if(errno == EINTR) {
	continue;
      }
      return -1;
    }
    if(!r) {
      errno = EIO;
      return -1;
    }
    off += (size_t)r;
  }

  return 0;
}


int
io_nwrite(int fd, const void* buf, size_t n) {
  size_t off = 0;

  while(off < n) {
    ssize_t r = write(fd, (const char*)buf + off, n - off);
    if(r < 0) {
      if(errno == EINTR) {
	continue;
      }
      return -1;
    }
    if(!r) {
      errno = EIO;
      return -1;
    }
    off += (size_t)r;
  }

  return 0;
}


int
io_ncopy(int fd_in, int fd_out, size_t size) {
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

    if(io_nread(fd_in, buf, n)) {
      free(buf);
      return -1;
    }
    if(io_nwrite(fd_out, buf, n)) {
      free(buf);
      return -1;
    }

    copied += n;
  }

  free(buf);
  return 0;
}


int
io_pread(int fd, void* buf, size_t n, off_t off) {
  size_t done = 0;

  while(done < n) {
    ssize_t r = pread(fd, (char*)buf + done, n - done, off + (off_t)done);
    if(r < 0) {
      if(errno == EINTR) {
	continue;
      }
      return -1;
    }
    if(!r) {
      errno = EIO;
      return -1;
    }
    done += (size_t)r;
  }

  return 0;
}


int
io_pwrite(int fd, const void* buf, size_t n, off_t off) {
  size_t done = 0;

  while(done < n) {
    ssize_t r = pwrite(fd, (const char*)buf + done, n - done, off + (off_t)done);
    if(r < 0) {
      if(errno == EINTR) {
	continue;
      }
      return -1;
    }
    if(!r) {
      errno = EIO;
      return -1;
    }
    done += (size_t)r;
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


int
io_ncopy_buf(int fd_in, int fd_out, size_t size, void *buf, size_t bufsize) {
  size_t copied = 0;
  ssize_t n;

  if(!buf || !bufsize) {
    errno = EINVAL;
    return -1;
  }

  while(copied < size) {
    n = size - copied;
    if(n > (ssize_t)bufsize) {
      n = (ssize_t)bufsize;
    }

    if(io_nread(fd_in, buf, (size_t)n)) {
      return -1;
    }
    if(io_nwrite(fd_out, buf, (size_t)n)) {
      return -1;
    }

    copied += (size_t)n;
  }

  return 0;
}


int
io_set_socket_opts(int fd, int is_data) {
  int rc = 0;
  int buf = is_data ? IO_SOCK_DATA_BUFSIZE : IO_SOCK_CTRL_BUFSIZE;

  if(setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &buf, sizeof(buf)) < 0) {
    rc = -1;
  }
  if(setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &buf, sizeof(buf)) < 0) {
    rc = -1;
  }

#ifdef TCP_NOPUSH
  if(is_data) {
    int one = 1;
    if(setsockopt(fd, IPPROTO_TCP, TCP_NOPUSH, &one, sizeof(one)) < 0) {
      rc = -1;
    }
  }
#endif

#ifdef TCP_NODELAY
  if(!is_data) {
    int one = 1;
    if(setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)) < 0) {
      rc = -1;
    }
  }
#endif

  return rc;
}
