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

#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <sys/_iovec.h>
#include <sys/mount.h>

#include "cmd.h"
#include "self.h"


/**
 * Convenient macros for nmount.
 **/
#define IOVEC_SIZE(x) (sizeof(x) / sizeof(struct iovec))
#define IOVEC_ENTRY(x) {x ? x : 0, x ? strlen(x)+1 : 0}


/**
 * Remount read-only mount points with write permissions.
 **/
int
ftp_cmd_MTRW(ftp_env_t *env, const char* arg) {
  struct iovec iov_sys[] = {
    IOVEC_ENTRY("from"),      IOVEC_ENTRY("/dev/da0x4.crypt"),
    IOVEC_ENTRY("fspath"),    IOVEC_ENTRY("/system"),
    IOVEC_ENTRY("fstype"),    IOVEC_ENTRY("exfatfs"),
    IOVEC_ENTRY("large"),     IOVEC_ENTRY("yes"),
    IOVEC_ENTRY("timezone"),  IOVEC_ENTRY("static"),
    IOVEC_ENTRY("async"),     IOVEC_ENTRY(NULL),
    IOVEC_ENTRY("ignoreacl"), IOVEC_ENTRY(NULL),
  };

  struct iovec iov_sysex[] = {
    IOVEC_ENTRY("from"),      IOVEC_ENTRY("/dev/da0x5.crypt"),
    IOVEC_ENTRY("fspath"),    IOVEC_ENTRY("/system_ex"),
    IOVEC_ENTRY("fstype"),    IOVEC_ENTRY("exfatfs"),
    IOVEC_ENTRY("large"),     IOVEC_ENTRY("yes"),
    IOVEC_ENTRY("timezone"),  IOVEC_ENTRY("static"),
    IOVEC_ENTRY("async"),     IOVEC_ENTRY(NULL),
    IOVEC_ENTRY("ignoreacl"), IOVEC_ENTRY(NULL),
  };

  if(nmount(iov_sys, IOVEC_SIZE(iov_sys), MNT_UPDATE)) {
    return ftp_perror(env);
  }

  if(nmount(iov_sysex, IOVEC_SIZE(iov_sysex), MNT_UPDATE)) {
    return ftp_perror(env);
  }

  return ftp_active_printf(env, "226 /system and /system_ex remounted\r\n");
}


/**
 * Retreive an ELF file embedded within a SELF file.
 **/
int
ftp_cmd_RETR_SELF2ELF(ftp_env_t *env, const char* arg) {
  char self[PATH_MAX];
  char elf[PATH_MAX];
  int err;

  ftp_abspath(env, self, arg);
  if(!env->self2elf || self_is_valid(self) != 1) {
    return ftp_cmd_RETR(env, arg);
  }

  ftp_active_printf(env, "150-Extracting an ELF from %s\r\n", self);
  snprintf(elf, sizeof(elf), "/user/temp/tmpftpsrv-%d-%d", getpid(),
	   env->active_fd);
  if(self_extract_elf(self, elf)) {
    err = ftp_perror(env);
    unlink(elf);
    return err;
  }

  err = ftp_cmd_RETR(env, elf);
  unlink(elf);

  return err;
}


/*
  Local Variables:
  c-file-style: "gnu"
  End:
*/
