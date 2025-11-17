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
#include <stdlib.h>
#include <unistd.h>

#include <sys/mman.h>
#include <sys/stat.h>

#include "io.h"
#include "self.h"


/**
 * Fill wholes in a file between off and off+len with zeroes.
 **/
static int
zeropad(int fd, off_t off, off_t len) {
  char buf[0x4000];
  struct stat st;
  size_t n;
  long cur;

  if((cur=lseek(fd, 0, SEEK_CUR)) < 0) {
    return -1;
  }

  if(fstat(fd, &st)) {
    return -1;
  }

  if(st.st_size >= off+len) {
    return 0;
  }

  if(lseek(fd, 0, SEEK_END) < 0) {
    return -1;
  }

  for(off_t i=st.st_size; i<off+len; i+=sizeof(buf)) {
    n = sizeof(buf);
    if(i+n > off+len) {
      n = off+len-i;
    }
    if(io_nwrite(fd, buf, n)) {
      return -1;
    }
  }

  if(lseek(fd, cur, SEEK_SET) < 0) {
    return -1;
  }

  return 0;
}


/**
 * Decrypt and copy an ELF segment.
 **/
static int
decrypt_segment(int self_fd, int elf_fd, const Elf64_Phdr* phdr, size_t ind) {
  off_t self_pos = lseek(self_fd, 0, SEEK_CUR);
  off_t elf_pos = lseek(elf_fd, 0, SEEK_CUR);
  uint8_t* data;

  if(lseek(self_fd, 0, SEEK_SET) < 0) {
    return -1;
  }
  if(lseek(elf_fd, phdr->p_offset, SEEK_SET) < 0) {
    return -1;
  }

  if((data=self_map_segment(self_fd, phdr, ind)) == MAP_FAILED) {
    return -1;
  }

  if(mlock(data, phdr->p_filesz)) {
    munmap(data, phdr->p_filesz);
    return -1;
  }

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
 * Copy a plaintext ELF segment.
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


static int
self_extract_elf_fd(int self_fd, int elf_fd) {
  self_entry_t* entries;
  self_entry_t* entry;
  self_head_t head;
  Elf64_Ehdr ehdr;
  Elf64_Phdr phdr;
  off_t elf_off;

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
  return 0;
}


int
self_extract_elf(const char* self_path, const char* elf_path) {
  size_t elf_size = self_get_elfsize(self_path);
  int self_fd;
  int elf_fd;
  int res;

  // Open the ELF file for writing
  if((elf_fd=open(elf_path, O_RDWR | O_CREAT | O_TRUNC, 0755, 0)) < 0) {
    return -1;
  }

  // Fill the ELF file with zeroes. Normally, we could use ftruncate here, but
  // it seems that files stored on exfat partitions are not zeroed out correctly.
  if(zeropad(elf_fd, 0, elf_size)) {
    close(elf_fd);
    return -1;
  }

  // Open the SELF file for reading
  if((self_fd=open(self_path, O_RDONLY, 0)) < 0) {
    close(elf_fd);
    return -1;
  }

  // Extract the ELF file
  res = self_extract_elf_fd(self_fd, elf_fd);

  close(self_fd);
  close(elf_fd);

  return res;
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


size_t
self_get_elfsize(const char* path) {
  self_head_t head;
  Elf64_Ehdr ehdr;
  Elf64_Phdr phdr;
  off_t elf_off;
  size_t size = 0;
  int fd;

  if((fd=open(path, O_RDONLY, 0)) < 0) {
    return 0;
  }

  if(io_nread(fd, &head, sizeof(head))) {
    close(fd);
    return 0;
  }

  if(head.magic != SELF_PS4_MAGIC && head.magic != SELF_PS5_MAGIC) {
    close(fd);
    return 0;
  }

  if(lseek(fd, head.num_entries * sizeof(self_entry_t), SEEK_CUR) < 0) {
    close(fd);
    return 0;
  }

  elf_off = lseek(fd, 0, SEEK_CUR);
  if(io_nread(fd, &ehdr, sizeof(ehdr))) {
    close(fd);
    return 0;
  }

  if(ehdr.e_ident[0] != 0x7f || ehdr.e_ident[1] != 'E' ||
     ehdr.e_ident[2] != 'L'  || ehdr.e_ident[3] != 'F') {
    close(fd);
    return 0;
  }

  if(ehdr.e_shoff > ehdr.e_phoff) {
    close(fd);
    return ehdr.e_shoff;
  }

  if(lseek(fd, elf_off + ehdr.e_phoff, SEEK_SET) < 0) {
    close(fd);
    return 0;
  }

  for(int i=0; i<ehdr.e_phnum; i++) {
    if(io_nread(fd, &phdr, sizeof(phdr))) {
      close(fd);
      return 0;
    }
    if(!phdr.p_filesz) {
      continue;
    }
    if(phdr.p_offset + phdr.p_filesz > size) {
      size = phdr.p_offset + phdr.p_filesz;
    }
  }

  close(fd);

  return size;
}


/*
  Local Variables:
  c-file-style: "gnu"
  End:
*/
