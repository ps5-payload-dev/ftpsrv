/* Copyright (C) 2024 John Törnblom

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

#include <errno.h>
#include <stdio.h>

#if defined(__PROSPERO__)
#include <ps5/klog.h>
#elif defined( __ORBIS__)
#include <ps4/klog.h>
#else
#define klog_puts(s)
#define klog_printf(s, ...)
#endif

/**
 * Log to stdout and klog
 **/
#define FTP_LOG_PUTS(s) {				\
    puts(s);						\
    klog_puts(s);					\
  }

#define FTP_LOG_PRINTF(s, ...) {			\
    printf(s, __VA_ARGS__);				\
    klog_printf(s, __VA_ARGS__);			\
  }

#define FTP_LOG_PERROR(s) {						\
    printf("%s:%d:%s: %s\n", __FILE__, __LINE__, s, strerror(errno));	\
    klog_printf("%s:%d:%s: %s\n", __FILE__, __LINE__, s, strerror(errno)); \
  }
