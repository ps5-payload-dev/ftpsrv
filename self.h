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

#include <elf.h>
#include <stdint.h>


/**
 * Magic integer (little endian) that all PS4 or PS5 SELF files starts with.
 **/
#define SELF_PS4_MAGIC 0x1D3D154F
#define SELF_PS5_MAGIC 0xEEF51454


/**
 * Data structure for PS4 and PS5 SELF file headers.
 **/
typedef struct self_head {
  uint32_t magic;
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
 * Data structure present in PS4 and PS5 SELF files that encodes additional
 * information about segments in the embedded ELF file.
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
 * Data structure that captures extended information associated with an ELF file.
 **/
typedef struct self_exinfo {
  uint64_t authid;
  uint64_t type;
  uint64_t app_version;
  uint64_t fw_version;
  uint8_t digest[0x20];
} self_exinfo_t;


/**
 *
 **/
void* self_map_segment(int fd, const Elf64_Phdr *phdr, size_t ind);


/**
 * Extract the ELF embedded within the given SELF.
 **/
int self_extract_elf(int self_fd, int elf_fd);
int self_extract_elf_ex(int self_fd, int elf_fd, int verify);


/**
 * Check if the given path is a SELF file.
 **/
int self_is_valid(const char* path);


/**
 * Compute the size of the ELF file embedded within the given SELF file.
 **/
size_t self_get_elfsize(const char* path);
