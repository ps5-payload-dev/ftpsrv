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
#include <string.h>
#include <unistd.h>

#include <sys/errno.h>
#include <sys/socket.h>

#include "io.h"


int
io_nread(int fd, void* buf, size_t n) {
  int r;

  while((r=read(fd, buf, n)) < 0) {
    if(errno == EINTR) {
      continue;
    }
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

  while((r=write(fd, buf, n)) < 0) {
    if(errno == EINTR) {
      continue;
    }
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
  int r;

  while((r=pread(fd, buf, n, off)) < 0) {
    if(errno == EINTR) {
      continue;
    }
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

  while((r=pwrite(fd, buf, n, off)) < 0) {
    if(errno == EINTR) {
      continue;
    }
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


/**
 * Encode the header of a block.
 **/
static void
io_block_header(unsigned char* hdr, unsigned char desc, size_t n) {
  hdr[0] = desc;
  hdr[1] = (n >> 8) & 0xff;
  hdr[2] = n & 0xff;
}


/**
 * Send the gathered data as a block, followed by an EOF block if requested,
 * with a single write.
 **/
static int
io_block_flush(io_block_writer_t* w, int eof) {
  size_t size = 0;

  if(w->len) {
    io_block_header(w->buf, 0, w->len);
    size = IO_BLOCK_HDRSIZE + w->len;
  }
  if(eof) {
    io_block_header(w->buf + size, IO_BLOCK_EOF, 0);
    size += IO_BLOCK_HDRSIZE;
  }

  w->len = 0;
  if(!size) {
    return 0;
  }

  return io_nwrite(w->fd, w->buf, size);
}


void
io_block_writer_init(io_block_writer_t* w, int fd, void* buf) {
  w->fd = fd;
  w->buf = buf;
  w->len = 0;
}


int
io_block_write(io_block_writer_t* w, const void* buf, size_t n) {
  const unsigned char* data = buf;
  size_t count;

  while(n) {
    // a full block is sent only when more data follows, so that the last one
    // goes out with the EOF block
    if(w->len == IO_BLOCK_MAXSIZE && io_block_flush(w, 0)) {
      return -1;
    }

    count = IO_BLOCK_MAXSIZE - w->len;
    if(count > n) {
      count = n;
    }

    memcpy(w->buf + IO_BLOCK_HDRSIZE + w->len, data, count);
    w->len += count;
    data += count;
    n -= count;
  }

  return 0;
}


int
io_block_write_eof(io_block_writer_t* w) {
  return io_block_flush(w, 1);
}


void
io_block_reader_init(io_block_reader_t* r, int fd) {
  memset(r, 0, sizeof(*r));
  r->fd = fd;
}


/**
 * Receive up to N bytes from a block mode stream, where a connection closed by
 * the peer is an error (the stream ends with an EOF block).
 **/
static ssize_t
io_block_recv(int fd, void* buf, size_t n) {
  ssize_t r;

  while((r=recv(fd, buf, n, 0)) < 0) {
    if(errno == EINTR) {
      continue;
    }
    return -1;
  }

  if(!r) {
    errno = EPIPE;
    return -1;
  }

  return r;
}


ssize_t
io_block_read(io_block_reader_t* r, void* buf, size_t n) {
  ssize_t len;

  while(1) {
    // receive the header of the next block, possibly in several pieces
    if(r->hdrlen < IO_BLOCK_HDRSIZE) {
      if((len=io_block_recv(r->fd, r->hdr + r->hdrlen,
			    IO_BLOCK_HDRSIZE - r->hdrlen)) < 0) {
	return -1;
      }
      r->hdrlen += len;
      if(r->hdrlen < IO_BLOCK_HDRSIZE) {
	continue;
      }

      if(r->hdr[0] & ~(IO_BLOCK_EOR | IO_BLOCK_EOF | IO_BLOCK_ERRORS |
		       IO_BLOCK_RESTART)) {
	errno = EBADMSG;
	return -1;
      }
      r->left = (r->hdr[1] << 8) | r->hdr[2];
    }

    // nothing follows the EOF block
    if(!r->left) {
      if(r->hdr[0] & IO_BLOCK_EOF) {
	return 0;
      }
      r->hdrlen = 0;
      continue;
    }

    if((len=io_block_recv(r->fd, buf, r->left < n ? r->left : n)) < 0) {
      return -1;
    }
    r->left -= len;

    // the data of a restart marker is not part of the file
    if(!(r->hdr[0] & IO_BLOCK_RESTART)) {
      return len;
    }
  }
}
