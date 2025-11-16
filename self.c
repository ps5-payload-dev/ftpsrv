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

#include "io.h"
#include "self.h"


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


int
self_extract_elf(const char* self_path, const char* elf_path) {
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
  if(head.magic != SELF_PS4_MAGIC && head.magic != SELF_PS5_MAGIC) {
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
#if 0
  ehdr.e_shnum = 0;
  ehdr.e_shoff = 0;
#endif

  // Skip ahead to the ELF program headers
  if(lseek(self_fd, elf_off + ehdr.e_phoff, SEEK_SET) < 0) {
    close(self_fd);
    free(entries);
    return -1;
  }

  // Open the ELF file for writing
  if((elf_fd=open(elf_path, O_RDWR | O_CREAT | O_TRUNC, 0755, 0)) < 0) {
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
	close(self_fd);
	close(elf_fd);
	free(entries);
	return -1;
      }
    } else if(copy_segment(self_fd, entry->offset, elf_fd, phdr.p_offset,
			   phdr.p_filesz)) {
      close(self_fd);
      close(elf_fd);
      free(entries);
      return -1;
    }
  }

  close(self_fd);
  close(elf_fd);
  free(entries);

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
