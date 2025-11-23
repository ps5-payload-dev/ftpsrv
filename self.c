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
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/mman.h>
#include <sys/stat.h>

#include "io.h"
#include "self.h"
#include "sha256.h"


/**
 * This global lock is used to address race conditions that may occur when
 * threads atempt to read several SELF files at the same time.
 **/
static pthread_mutex_t g_mutex = PTHREAD_MUTEX_INITIALIZER;


/**
 * Decrypt and copy an ELF segment.
 **/
static int
decrypt_segment(int self_fd, int elf_fd, const Elf64_Phdr* phdr, size_t ind) {
  uint8_t* data = MAP_FAILED;
  int err = 0;

  pthread_mutex_lock(&g_mutex);

  if((data=self_map_segment(self_fd, phdr, ind)) == MAP_FAILED) {
    err = -1;

  } else if(mlock(data, phdr->p_filesz)) {
    err = -1;

  } else if(io_pwrite(elf_fd, data, phdr->p_filesz, phdr->p_offset)) {
    err = -1;
  }

  if(data != MAP_FAILED) {
    munmap(data, phdr->p_filesz);
  }

  pthread_mutex_unlock(&g_mutex);

  return err;
}


/**
 * Copy a plaintext ELF segment.
 **/
static int
copy_segment(int from_fd, off_t from_start, int to_fd, off_t to_start,
	     size_t size) {
  return io_pcopy(from_fd, to_fd, from_start, to_start, size);
}


/**
 * Compute the SHA256 sum of a file.
 **/
static int
sha256sum(int fd, uint8_t hash[SHA256_BLOCK_SIZE]) {
  uint8_t buf[0x1000] = {0};
  SHA256_CTX sha256;
  struct stat st;
  off_t n;

  if(fstat(fd, &st)) {
    return -1;
  }

  sha256_init(&sha256);
  for(off_t off=0; off<st.st_size;) {
    if((n=pread(fd, buf, sizeof(buf), off)) < 0) {
      return -1;
    }
    sha256_update(&sha256, buf, n);
    off += n;
  }
  sha256_final(&sha256, hash);

  return 0;
}


/**
 * Add zero padding between off and off+len.
 **/
static int
zeropad(int fd, off_t off, off_t len) {
  char buf[0x1000] = {0};
  struct stat st;
  size_t n;

  if(fstat(fd, &st)) {
    return -1;
  }

  if(st.st_size >= off+len) {
    return 0;
  }

  for(off_t i=st.st_size; i<off+len; i+=sizeof(buf)) {
    n = sizeof(buf);
    if(i+n > off+len) {
      n = off+len-i;
    }
    if(io_pwrite(fd, buf, n, i)) {
      return -1;
    }
  }

  return 0;
}


static size_t
self_get_elfsize_fd(int fd) {
  self_head_t head;
  Elf64_Ehdr ehdr;
  Elf64_Phdr phdr;
  off_t elf_off;
  size_t size = 0;

  if(io_nread(fd, &head, sizeof(head))) {
    return 0;
  }

  if(head.magic != SELF_PS4_MAGIC && head.magic != SELF_PS5_MAGIC) {
    return 0;
  }

  if(lseek(fd, head.num_entries * sizeof(self_entry_t), SEEK_CUR) < 0) {
    return 0;
  }

  elf_off = lseek(fd, 0, SEEK_CUR);
  if(io_nread(fd, &ehdr, sizeof(ehdr))) {
    return 0;
  }

  if(ehdr.e_ident[0] != 0x7f || ehdr.e_ident[1] != 'E' ||
     ehdr.e_ident[2] != 'L'  || ehdr.e_ident[3] != 'F') {
    return 0;
  }

  if(lseek(fd, elf_off + ehdr.e_phoff, SEEK_SET) < 0) {
    return 0;
  }

  for(int i=0; i<ehdr.e_phnum; i++) {
    if(io_nread(fd, &phdr, sizeof(phdr))) {
      return 0;
    }
    if(phdr.p_offset + phdr.p_filesz > size) {
      size = phdr.p_offset + phdr.p_filesz;
    }
  }

  return size;
}


size_t
self_get_elfsize(const char* path) {
  size_t size;
  int fd;

  if((fd=open(path, O_RDONLY, 0)) < 0) {
    return -1;
  }

  size = self_get_elfsize_fd(fd);
  close(fd);

  return size;
}


int
self_extract_elf(int self_fd, int elf_fd) {
  uint8_t hash[SHA256_BLOCK_SIZE];
  self_exinfo_t extinfo;
  self_entry_t* entries;
  self_entry_t* entry;
  self_head_t head;
  Elf64_Ehdr ehdr;
  Elf64_Phdr phdr;
  size_t elf_size;
  off_t elf_off;
  off_t off;

  // Ensure wholes in the ELF file are all zeroed out
  elf_size = self_get_elfsize_fd(self_fd);
  if(zeropad(elf_fd, 0, elf_size)) {
    return -1;
  }
  lseek(self_fd, 0, SEEK_SET);

  // Read the SELF header
  if(io_nread(self_fd, &head, sizeof(head))) {
    return -1;
  }

  // Sanity check the SELF header
  if(head.magic != SELF_PS4_MAGIC && head.magic != SELF_PS5_MAGIC) {
    errno = ENOEXEC;
    return -1;
  }

  // Read SELF entries
  if(!(entries=calloc(head.num_entries, sizeof(self_entry_t)))) {
    return -1;
  }
  if(io_nread(self_fd, entries, head.num_entries * sizeof(self_entry_t))) {
    free(entries);
    return -1;
  }

  // Remember the position of the ELF header bundled within the SELF file
  if((elf_off=lseek(self_fd, 0, SEEK_CUR)) < 0) {
    free(entries);
    return -1;
  }

  // Read the ELF header
  if(io_nread(self_fd, &ehdr, sizeof(ehdr))) {
    free(entries);
    return -1;
  }

  // Sanity check the ELF header
  if(ehdr.e_ident[0] != 0x7f || ehdr.e_ident[1] != 'E' ||
     ehdr.e_ident[2] != 'L'  || ehdr.e_ident[3] != 'F') {
    free(entries);
    errno = ENOEXEC;
    return -1;
  }

#if 0
  // Drop section headers
  ehdr.e_shnum = 0;
  ehdr.e_shoff = 0;
#endif

  // Skip ahead to the ELF program headers
  if(lseek(self_fd, elf_off + ehdr.e_phoff, SEEK_SET) < 0) {
    free(entries);
    return -1;
  }

  // Write the ELF header
  if(io_nwrite(elf_fd, &ehdr, sizeof(ehdr))) {
    free(entries);
    return -1;
  }

  // Enumerate ELF program headers
  elf_size = ehdr.e_phoff + ehdr.e_phnum * sizeof(phdr);
  for(int i=0; i<ehdr.e_phnum; i++) {
    if(io_nread(self_fd, &phdr, sizeof(phdr))) {
      free(entries);
      return -1;
    }
    if(io_nwrite(elf_fd, &phdr, sizeof(phdr))) {
      free(entries);
      return -1;
    }

    if(!phdr.p_filesz) {
      continue;
    }

    // PT_SCE_VERSION segment is appended at the end of the SELF file
    if(phdr.p_type == 0x6fffff01) {
      if(copy_segment(self_fd, head.file_size, elf_fd, phdr.p_offset,
		      phdr.p_filesz)) {
#if 0 // Some FSELFs are missing the version data, ignore error
	free(entries);
	return -1;
#endif
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

    // Decrypt and/or copy the segment
    if(entry->props.is_encrypted || entry->props.is_compressed) {
      if(decrypt_segment(self_fd, elf_fd, &phdr, i)) {
	free(entries);
	return -1;
      }
    } else if(copy_segment(self_fd, entry->offset, elf_fd, phdr.p_offset,
			   phdr.p_filesz)) {
      free(entries);
      return -1;
    }
  }

  free(entries);

  // Compute the SHA256 sum of the ELF
  if(sha256sum(elf_fd, hash)) {
    return -1;
  }

  // Seek to the SELF extended info
  if((off=lseek(self_fd, 0, SEEK_CUR)) < 0) {
    return -1;
  }
  off = (((off) + (0x10-1)) & ~(0x10-1));
  if(lseek(self_fd, off, SEEK_SET) < 0) {
    return -1;
  }

  // Read the SELF extended info
  if(io_nread(self_fd, &extinfo, sizeof(extinfo))) {
    return -1;
  }

  // Compare the computed ELF SHA256 sum with the expected one
  // available in the SELF extended info
  if(memcmp(hash, extinfo.digest, sizeof(hash))) {
    errno = EBADMSG;
    return -1;
  }

  return 0;
}


int
self_is_valid(const char* path) {
  self_head_t head;
  ssize_t n;
  int fd;

  if((fd=open(path, O_RDONLY, 0)) < 0) {
    return -1;
  }

  if((n=read(fd, &head, sizeof(head))) < 0) {
    close(fd);
    return -1;
  }

  if(n != sizeof(head)) {
    close(fd);
    return 0;
  }

  if(head.magic != SELF_PS4_MAGIC && head.magic != SELF_PS5_MAGIC) {
    close(fd);
    return 0;
  }

  close(fd);
  return 1;
}


/*
  Local Variables:
  c-file-style: "gnu"
  End:
*/
