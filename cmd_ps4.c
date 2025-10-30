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
#include <sys/mman.h>
#include <sys/errno.h>

#include "cmd.h"
#include "io.h"


/**
 * Convenient macros for nmount.
 **/
#define IOVEC_SIZE(x) (sizeof(x) / sizeof(struct iovec))
#define IOVEC_ENTRY(x) {x ? x : 0, x ? strlen(x)+1 : 0}


/**
 * Flag for mmap used to decrypted PS4 SELF files.
 **/
#define MAP_SELF 0x80000


/**
 * Data structure for PS4 SELF header.
 **/
typedef struct self_head {
  uint8_t magic[4];
  uint8_t version;
  uint8_t mode;
  uint8_t endian;
  uint8_t attrs;
  uint32_t key_type;
  uint16_t header_size;
  uint16_t meta_size;
  uint64_t file_size;
  uint16_t num_entries;
  uint16_t flags;
} self_head_t;


/**
 * Data structure present in SELF files that encodes additional information
 * about segments in the embedded ELF file.
 **/
typedef struct self_entry {
  struct __attribute__((packed)) {
    uint8_t is_ordered: 1;
    uint8_t is_encrypted: 1;
    uint8_t is_signed: 1;
    uint8_t is_compressed: 1;
    uint8_t unknown0 : 4;
    uint8_t window_bits : 3;
    uint8_t has_blocks : 1;
    uint8_t block_bits : 4;
    uint8_t has_digest : 1;
    uint8_t has_extents : 1;
    uint8_t unknown1 : 2;
    uint16_t segment_index : 16;
    uint32_t unknown2 : 28;
  } props;
  uint64_t offset;
  uint64_t enc_size;
  uint64_t dec_size;
} self_entry_t;


/**
 * Decrypt and copy an ELF segment.
 **/
static int
decrypt_segment(int self_fd, int elf_fd, const Elf64_Phdr* phdr, size_t ind) {
  off_t self_pos = lseek(self_fd, 0, SEEK_CUR);
  off_t elf_pos = lseek(elf_fd, 0, SEEK_CUR);
  uint8_t* data;
  char tmp;

  if(lseek(self_fd, 0, SEEK_SET) < 0) {
    return -1;
  }
  if(lseek(elf_fd, phdr->p_offset, SEEK_SET) < 0) {
    return -1;
  }

  if((data=mmap(0, phdr->p_filesz, PROT_READ, MAP_PRIVATE | MAP_SELF,
		self_fd, ind << 32)) == MAP_FAILED) {
    return -1;
  }

  // ensure kernel is mapping the segments
  memcpy(&tmp, data, 1);

  if(io_nwrite(elf_fd, data, phdr->p_filesz)) {
    munmap(data, phdr->p_filesz);
    return -1;
  }

  munmap(data, phdr->p_filesz);

  if(lseek(self_fd, self_pos, SEEK_SET) < 0) {
    return -1;
  }
  if(lseek(elf_fd, elf_pos, SEEK_SET) < 0) {
    return -1;
  }

  return 0;
}


/**
 * Copy an ELF segment.
 **/
static int
copy_segment(int from_fd, off_t from_start, int to_fd, off_t to_start,
	     size_t size) {
  off_t from_cur;
  off_t to_cur;

  if((from_cur=lseek(from_fd, 0, SEEK_CUR)) < 0) {
    return -1;
  }
  if((to_cur=lseek(to_fd, 0, SEEK_CUR)) < 0) {
    return -1;
  }

  if(lseek(from_fd, from_start, SEEK_SET) < 0) {
    return -1;
  }
  if(lseek(to_fd, to_start, SEEK_SET) < 0) {
    return -1;
  }

  if(io_ncopy(from_fd, to_fd, size)) {
    return -1;
  }

  if(lseek(from_fd, from_cur, SEEK_SET) < 0) {
    return -1;
  }
  if(lseek(to_fd, to_cur, SEEK_SET) < 0) {
    return -1;
  }

  return 0;
}


/**
 * Extract the ELF file embedded within ther given SELF file.
 **/
static int
self2elf(const char* self_path, const char* elf_path) {
  self_entry_t* entries;
  self_entry_t* entry;
  self_head_t head;
  Elf64_Ehdr ehdr;
  Elf64_Phdr phdr;
  off_t elf_off;
  int self_fd;
  int elf_fd;

  // Open the SELF file for reading
  if((self_fd=open(self_path, O_RDONLY, 0)) < 0) {
    return -1;
  }

  // Read the SELF header
  if(io_nread(self_fd, &head, sizeof(head))) {
    close(self_fd);
    return -1;
  }

  // Sanity check the SELF header
  if(head.magic[0] != 0x4f || head.magic[1] != 0x15 ||
     head.magic[2] != 0x3d || head.magic[3] != 0x1d) {
    close(self_fd);
    errno = ENOEXEC;
    return -1;
  }

  // Read SELF entries
  if(!(entries=calloc(head.num_entries, sizeof(self_entry_t)))) {
    close(self_fd);
    return -1;
  }
  if(io_nread(self_fd, entries, head.num_entries * sizeof(self_entry_t))) {
    close(self_fd);
    free(entries);
    return -1;
  }

  // Read the ELF header bundled within the SELF file
  elf_off = lseek(self_fd, 0, SEEK_CUR);
  if(io_nread(self_fd, &ehdr, sizeof(ehdr))) {
    close(self_fd);
    free(entries);
    return -1;
  }

  // Sanity check the ELF header
  if(ehdr.e_ident[0] != 0x7f || ehdr.e_ident[1] != 'E' ||
     ehdr.e_ident[2] != 'L'  || ehdr.e_ident[3] != 'F') {
    close(self_fd);
    free(entries);
    errno = ENOEXEC;
    return -1;
  }

  // Drop section headers
  ehdr.e_shnum = 0;
  ehdr.e_shoff = 0;
  ehdr.e_shentsize = 0;
  ehdr.e_shstrndx = 0;

  // Skip ahead to the ELF program headers
  if(lseek(self_fd, elf_off + ehdr.e_phoff, SEEK_SET) < 0) {
    close(self_fd);
    free(entries);
    return -1;
  }

  // Open the ELF file for writing
  if((elf_fd=open(elf_path, O_RDWR | O_CREAT | O_TRUNC, 0755, 0)) < 0) {
    perror(elf_path);
    close(self_fd);
    free(entries);
    return -1;
  }

  // Write the ELF header
  if(io_nwrite(elf_fd, &ehdr, sizeof(ehdr))) {
    close(self_fd);
    close(elf_fd);
    free(entries);
    return -1;
  }

  // Enumerate ELF program headers
  for(int i=0; i<ehdr.e_phnum; i++) {
    if(io_nread(self_fd, &phdr, sizeof(phdr))) {
      close(self_fd);
      close(elf_fd);
      free(entries);
      return -1;
    }
    if(io_nwrite(elf_fd, &phdr, sizeof(phdr))) {
      close(self_fd);
      close(elf_fd);
      free(entries);
      return -1;
    }

    if(!phdr.p_filesz) {
      continue;
    }
    if(phdr.p_type == 0x6FFFFF01) { // PT_SCE_VERSION
      // Version segment is appended at the end of the SELF file in plaintext
      if(copy_segment(self_fd, head.file_size, elf_fd, phdr.p_offset,
		      phdr.p_filesz)) {
	close(self_fd);
	close(elf_fd);
	free(entries);
	return -1;
      }
      continue;
    }

    // Find the SELF entry for this program header
    entry = 0;
    for(int j=0; j<head.num_entries; j++) {
      if(entries[j].props.segment_index == i &&
	 entries[j].props.has_blocks) {
	entry = &entries[j];
	break;
      }
    }
    if(!entry) {
      continue;
    }

    if(entry->props.is_encrypted) {
      if(decrypt_segment(self_fd, elf_fd, &phdr, i)) {
	close(self_fd);
	close(elf_fd);
	free(entries);
	return -1;
      }
    } else {
      if(copy_segment(self_fd, entry->offset, elf_fd, phdr.p_offset,
		      phdr.p_filesz)) {
	close(self_fd);
	close(elf_fd);
	free(entries);
	return -1;
      }
    }
  }

  close(self_fd);
  close(elf_fd);
  free(entries);

  return 0;
}


/**
 * Check if a file is a SELF file.
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

  } else if(head.magic[0] != 0x4f || head.magic[1] != 0x15 ||
	    head.magic[2] != 0x3d || head.magic[3] != 0x1d) {
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
  if(!is_self(self)) {
    return ftp_cmd_RETR(env, arg);
  }

  snprintf(elf, sizeof(elf), "/user/temp/ftpsrv.self2elf%d", env->active_fd);
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
