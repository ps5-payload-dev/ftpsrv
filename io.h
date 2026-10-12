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

#pragma once

#include <stddef.h>
#include <sys/types.h>


/**
 * Size of the buffer used for copying data from one file descriptor to another.
 **/
#define IO_COPY_BUFSIZE 0x100000


/**
 * Read exactly N bytes from the given file descriptor.
 **/
int io_nread(int fd, void* buf, size_t n);


/**
 * Write exactly N bytes to the given file descriptor.
 **/
int io_nwrite(int fd, const void* buf, size_t n);


/**
 * Copy exactly N bytes from one file descriptor to another.
 **/
int io_ncopy(int fd_in, int fd_out, size_t size);


/**
 * Copy exactly N bytes from a file descriptor to a socket.
 **/
int io_sendfile(int fd, int sock, off_t off, size_t n);


/**
 * Read exactly N bytes from the given file descriptor without affecting its
 * position.
 **/
int io_pread(int fd, void* buf, size_t n, off_t off);


/**
 * Write exactly N bytes to the given file descriptor without affecting its
 * position.
 **/
int io_pwrite(int fd, const void* buf, size_t n, off_t off);


/**
 * Copy exactly N bytes from one file descriptor to another without afftecting
 * their positions.
 **/
int io_pcopy(int fd_in, int fd_out, off_t off_in, off_t off_out, size_t n);


/**
 * Descriptor flags of block mode (MODE B, RFC 959 section 3.4.2) blocks.
 **/
#define IO_BLOCK_EOR     0x80
#define IO_BLOCK_EOF     0x40
#define IO_BLOCK_ERRORS  0x20
#define IO_BLOCK_RESTART 0x10


/**
 * Size of a block header (a descriptor and a big-endian 16-bit byte count),
 * and the largest number of data bytes a block can carry.
 **/
#define IO_BLOCK_HDRSIZE 3
#define IO_BLOCK_MAXSIZE 0xffff


/**
 * Size of the buffer used by a block writer: a full block followed by an EOF
 * block.
 **/
#define IO_BLOCK_BUFSIZE (IO_BLOCK_HDRSIZE + IO_BLOCK_MAXSIZE + IO_BLOCK_HDRSIZE)


/**
 * State of a block mode stream being written.
 **/
typedef struct io_block_writer {
  int fd;
  unsigned char* buf;
  size_t len;
} io_block_writer_t;


/**
 * State of a block mode stream being read.
 **/
typedef struct io_block_reader {
  int fd;
  unsigned char hdr[IO_BLOCK_HDRSIZE];
  size_t hdrlen;
  size_t left;
} io_block_reader_t;


/**
 * Prepare to write a block mode stream to a socket. Data is gathered in the
 * given buffer of IO_BLOCK_BUFSIZE bytes, and sent in blocks of at most
 * IO_BLOCK_MAXSIZE bytes.
 **/
void io_block_writer_init(io_block_writer_t* w, int fd, void* buf);


/**
 * Write N bytes of data to a block mode stream.
 **/
int io_block_write(io_block_writer_t* w, const void* buf, size_t n);


/**
 * Write the remaining data and an EOF block to a block mode stream.
 **/
int io_block_write_eof(io_block_writer_t* w);


/**
 * Prepare to read a block mode stream from a socket.
 **/
void io_block_reader_init(io_block_reader_t* r, int fd);


/**
 * Read up to N (N > 0) bytes of data from a block mode stream, without reading
 * past its EOF block. Returns the number of bytes read, 0 once the EOF block
 * has been read, or -1 on error, with errno set to EBADMSG for an invalid
 * descriptor, and to EPIPE when the connection was closed before the EOF block.
 **/
ssize_t io_block_read(io_block_reader_t* r, void* buf, size_t n);
