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

#include <elf.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <sys/_iovec.h>
#include <sys/mount.h>
#include <sys/syscall.h>

#include "cmd.h"
#include "io.h"
#include "self.h"


#define IOVEC_ENTRY(x) {x ? x : 0, \
			x ? strlen(x)+1 : 0}
#define IOVEC_SIZE(x) (sizeof(x) / sizeof(struct iovec))


/**
 * Remount read-only mount points with write permissions.
 **/
int
ftp_cmd_MTRW(ftp_env_t *env, const char* arg) {
  struct iovec iov_sys[] = {
    IOVEC_ENTRY("from"),      IOVEC_ENTRY("/dev/ssd0.system"),
    IOVEC_ENTRY("fspath"),    IOVEC_ENTRY("/system"),
    IOVEC_ENTRY("fstype"),    IOVEC_ENTRY("exfatfs"),
    IOVEC_ENTRY("large"),     IOVEC_ENTRY("yes"),
    IOVEC_ENTRY("timezone"),  IOVEC_ENTRY("static"),
    IOVEC_ENTRY("async"),     IOVEC_ENTRY(NULL),
    IOVEC_ENTRY("ignoreacl"), IOVEC_ENTRY(NULL),
  };

  struct iovec iov_sysex[] = {
    IOVEC_ENTRY("from"),      IOVEC_ENTRY("/dev/ssd0.system_ex"),
    IOVEC_ENTRY("fspath"),    IOVEC_ENTRY("/system_ex"),
    IOVEC_ENTRY("fstype"),    IOVEC_ENTRY("exfatfs"),
    IOVEC_ENTRY("large"),     IOVEC_ENTRY("yes"),
    IOVEC_ENTRY("timezone"),  IOVEC_ENTRY("static"),
    IOVEC_ENTRY("async"),     IOVEC_ENTRY(NULL),
    IOVEC_ENTRY("ignoreacl"), IOVEC_ENTRY(NULL),
  };

  if(syscall(SYS_nmount, iov_sys, IOVEC_SIZE(iov_sys), MNT_UPDATE)) {
    return ftp_perror(env);
  }

  if(syscall(SYS_nmount, iov_sysex, IOVEC_SIZE(iov_sysex), MNT_UPDATE)) {
    return ftp_perror(env);
  }
  return ftp_active_printf(env, "226 /system and /system_ex remounted\r\n");
}


/**
 * TODO: SELF decryption on prospero, just copy the SELF file for now.
 **/
static int
self2elf(const char* self_path, const char* elf_path) {
  self_head_t head;
  int self_fd;
  int elf_fd;
  int ret;

  // Open the SELF file for reading
  if((self_fd=open(self_path, O_RDONLY, 0)) < 0) {
    return -1;
  }

  // Read the SELF header
  if(io_nread(self_fd, &head, sizeof(head))) {
    close(self_fd);
    return -1;
  }

  // Rewind self_fd
  if(lseek(self_fd, 0, SEEK_SET)) {
    close(self_fd);
    return -1;
  }

  // Open the ELF file for writing
  if((elf_fd=open(elf_path, O_RDWR | O_CREAT | O_TRUNC, 0755, 0)) < 0) {
    close(self_fd);
    return -1;
  }

  ret = io_ncopy(self_fd, elf_fd, head.file_size);

  close(self_fd);
  close(elf_fd);

  return ret;
}


/**
 * Check if a file is a PS4 or PS5 SELF file.
 **/
static int
is_self(const char* path) {
  self_head_t head;
  Elf64_Ehdr ehdr;
  int r = 0;
  int fd;

  if((fd=open(path, O_RDONLY, 0)) < 0) {
    r = 0;

  } else if(io_nread(fd, &head, sizeof(head))) {
    r = 0;

  } else if(head.magic != SELF_PS4_MAGIC && head.magic != SELF_PS5_MAGIC) {
    r = 0;

  } else if(lseek(fd, head.num_entries * sizeof(self_entry_t), SEEK_CUR) < 0) {
    r = 0;

  } else if(io_nread(fd, &ehdr, sizeof(ehdr))) {
    r = 0;

  } else if(ehdr.e_ident[0] != 0x7f || ehdr.e_ident[1] != 'E' ||
	    ehdr.e_ident[2] != 'L'  || ehdr.e_ident[3] != 'F') {
    r = 0;

  } else {
    r = 1;
  }

  close(fd);

  return r;
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
  if(!is_self(self)) {
    return ftp_cmd_RETR(env, arg);
  }

  snprintf(elf, sizeof(elf), "/user/temp/tmpftpsrv-%d-%d", getpid(),
	   env->active_fd);
  if(self2elf(self, elf)) {
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
