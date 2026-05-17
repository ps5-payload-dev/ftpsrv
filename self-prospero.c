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

// Derived from https://github.com/idlesauce/ps5-self-pager


#include <elf.h>
#include <errno.h>

#include <sys/mman.h>

#include <ps5/kernel.h>

#include "self.h"


/**
 *
 **/
#define SUPERPAGE_SIZE 0x200000


/**
 *
 **/
static intptr_t KERNEL_ADDRESS_PAGER_OPS_VNODE = 0;
static intptr_t KERNEL_ADDRESS_PAGER_OPS_SELF  = 0;


/**
 *
 **/
static void*
mmap_self(void *addr, size_t len, int prot, int flags, int fd, off_t offset) {
  void *data;

  if(!KERNEL_ADDRESS_PAGER_TABLE ||
     !KERNEL_ADDRESS_PAGER_OPS_VNODE ||
     !KERNEL_ADDRESS_PAGER_OPS_SELF) {
    errno = ENOSYS;
    return MAP_FAILED;
  }

  // make vnode pagerops point to selfpagerops
  if(kernel_setlong(KERNEL_ADDRESS_PAGER_TABLE + 2*8,
		    KERNEL_ADDRESS_PAGER_OPS_SELF)) {
    return MAP_FAILED;
  }

  data = mmap(addr, len, prot, flags, fd, offset);

  // restore vnode pagerops
  if(kernel_setlong(KERNEL_ADDRESS_PAGER_TABLE + 2*8,
		    KERNEL_ADDRESS_PAGER_OPS_VNODE)) {
    return MAP_FAILED;
  }

  return data;
}


void*
self_map_segment(int fd, const Elf64_Phdr *phdr, size_t ind) {
  off_t offset = ind << 32;
  uint64_t aligned_vaddr;

  if(kernel_get_fw_version() >= 0x9000000) {
    // for example, for this segment:
    // Index  Type     VirtAddr     FileSize   MemSize    Align
    // 8      PT_LOAD  0xedf7e10    0xce8b98   0xce8b98   0x4000
    // the kernel expects 0x1f4000 in the lower 32 bits, by providing 0 it tells
    // us in the klogs:
    //    self_pager.c(122) self_pager_seg_decode_pindex: off=0, diff=0x1f4000
    aligned_vaddr = phdr->p_vaddr & ~(phdr->p_align - 1);
    offset |= aligned_vaddr & (SUPERPAGE_SIZE - 1);
  }

  return mmap_self(0, phdr->p_filesz, PROT_READ,
		   MAP_PRIVATE | MAP_ALIGNED(phdr->p_align),
		   fd, offset);
}


/**
 * Resolve kernel ponters that we need.
 **/
static void __attribute__((constructor))
self_prospero_constructor(void) {
  if(!KERNEL_ADDRESS_PAGER_TABLE) {
    return;
  }
  
  KERNEL_ADDRESS_PAGER_OPS_VNODE = kernel_getlong(KERNEL_ADDRESS_PAGER_TABLE + 2 * 8);
  KERNEL_ADDRESS_PAGER_OPS_SELF = kernel_getlong(KERNEL_ADDRESS_PAGER_TABLE + 7 * 8);
}


/*
  Local Variables:
  c-file-style: "gnu"
  End:
*/
