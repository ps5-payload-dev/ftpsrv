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

