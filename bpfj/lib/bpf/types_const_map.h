// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#ifdef __cplusplus
#include <linux/types.h>
#endif

#include "bpfj/lib/bpf/types_heap.h"

// Immutable open-addressing map built entirely before it is read. The map and
// all of its storage occupy one arena heap block:
//
//   header | slot-to-entry indexes | dense keys | dense values
//
// A zero slot is empty; occupied slots hold dense entry indexes plus one.
// Four slots per possible entry keep probes short without over-allocating the
// keys or values themselves.
struct bpfj_const_map {
  __u32 max_entries;
  __u32 size;
  __u32 capacity;
  __u32 key_size;
  __u32 val_size;
  __u32 key_stride;
  __u32 val_stride;
  __u32 keys_offset;
  __u32 values_offset;
  __u32 probe_limit;
  __u32 sealed;
  __u32 total_size;
};

#define BPFJ_CONST_MAP_LOAD_SHIFT 2
#define BPFJ_CONST_MAP_MIN_CAPACITY 4
#define BPFJ_CONST_MAP_MAX_PROBES 16
#define BPFJ_CONST_MAP_HASH_MULT 0x9e3779b97f4a7c15ULL

enum {
  BPFJ_CONST_MAP_EXISTING = 0,
  BPFJ_CONST_MAP_INSERTED = 1,
};

#define BPFJ_CONST_MAP_PLAN(_kind, _idx) (((long)(_kind) << 32) | (long)(_idx))
#define BPFJ_CONST_MAP_PLAN_KIND(_plan) ((__u32)((__u64)(_plan) >> 32))
#define BPFJ_CONST_MAP_PLAN_INDEX(_plan) \
  ((__u32)((__u64)(_plan) & 0xffffffffULL))

static __always_inline __u32 bpfj_const_map_align(__u32 size) {
  return (size + sizeof(__u64) - 1) & ~(sizeof(__u64) - 1);
}

static __always_inline __u32 bpfj_const_map_round_capacity(__u32 capacity) {
  --capacity;
  capacity |= capacity >> 1;
  capacity |= capacity >> 2;
  capacity |= capacity >> 4;
  capacity |= capacity >> 8;
  capacity |= capacity >> 16;
  return capacity + 1;
}

// Exact bytes required for one map slab, or zero for invalid dimensions.
static __always_inline __u32 bpfj_const_map_allocation_size(
    __u32 max_entries,
    __u32 key_size,
    __u32 val_size) {
  if (max_entries == 0 || key_size == 0 || val_size == 0 ||
      key_size % sizeof(__u64) != 0) {
    return 0;
  }
  if (max_entries > ((__u32)-1 >> BPFJ_CONST_MAP_LOAD_SHIFT)) {
    return 0;
  }

  __u32 wanted = max_entries << BPFJ_CONST_MAP_LOAD_SHIFT;
  if (wanted < BPFJ_CONST_MAP_MIN_CAPACITY) {
    wanted = BPFJ_CONST_MAP_MIN_CAPACITY;
  }
  __u32 capacity = bpfj_const_map_round_capacity(wanted);
  if (capacity == 0) {
    return 0;
  }

  __u32 key_stride = bpfj_const_map_align(key_size);
  __u32 val_stride = bpfj_const_map_align(val_size);
  if (key_stride < key_size || val_stride < val_size) {
    return 0;
  }

  __u64 bytes = sizeof(struct bpfj_const_map);
  bytes += (__u64)capacity * sizeof(__u32);
  if (bytes > BPFJ_HEAP_MAX_ARENA_SIZE) {
    return 0;
  }
  bytes = bpfj_const_map_align((__u32)bytes);
  bytes += (__u64)max_entries * key_stride;
  if (bytes > BPFJ_HEAP_MAX_ARENA_SIZE) {
    return 0;
  }
  bytes = bpfj_const_map_align((__u32)bytes);
  bytes += (__u64)max_entries * val_stride;
  if (bytes > BPFJ_HEAP_MAX_ARENA_SIZE) {
    return 0;
  }
  return (__u32)bytes;
}
