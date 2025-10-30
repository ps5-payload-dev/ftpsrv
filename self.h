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

#include <stdint.h>


/**
 * Magic integer (little endian) that all SELF files starts with.
 **/
#define SELF_PS4_MAGIC 0x1D3D154F
#define SELF_PS5_MAGIC 0xEEF51454


/**
 * Data structure for SELF file headers.
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

