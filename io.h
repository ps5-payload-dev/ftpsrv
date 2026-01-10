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


/**
 * Size of the buffer used for copying data from one file descriptor to another.
 **/
#ifndef IO_COPY_BUFSIZE
#define IO_COPY_BUFSIZE (1024 * 1024)
#endif

#ifndef IO_SOCK_DATA_BUFSIZE
#define IO_SOCK_DATA_BUFSIZE (1024 * 1024)
#endif

#ifndef IO_SOCK_CTRL_BUFSIZE
#define IO_SOCK_CTRL_BUFSIZE (64 * 1024)
#endif


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
int io_ncopy(int fd_in, int fd_out, size_t n);


/**
 * Copy exactly N bytes using a caller-provided buffer.
 **/
int io_ncopy_buf(int fd_in, int fd_out, size_t n, void *buf, size_t bufsize);


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
 * Apply socket buffer sizes and latency settings.
 **/
int io_set_socket_opts(int fd, int is_data);
