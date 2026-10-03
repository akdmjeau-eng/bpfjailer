// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include <errno.h>
#include "bpfj/lib/bpf/heap.h"
#include "bpfj/lib/bpf/types_const_map.h"

static __always_inline __u32 __arena* bpfj_const_map_slots(
    struct bpfj_const_map __arena* map) {
  return (__u32 __arena*)((char __arena*)map + sizeof(struct bpfj_const_map));
}

static __always_inline __u64 __arena* bpfj_const_map_key_at(
    struct bpfj_const_map __arena* map,
    __u32 index) {
  if (index >= map->size) {
    return NULL;
  }
  __u32 off = bpfj_heap_clamp_off(map->keys_offset + index * map->key_stride);
  return (__u64 __arena*)((char __arena*)map + off);
}

static __always_inline void __arena* bpfj_const_map_value_at(
    struct bpfj_const_map __arena* map,
    __u32 index) {
  if (index >= map->size) {
    return NULL;
  }
  __u32 off = bpfj_heap_clamp_off(map->values_offset + index * map->val_stride);
  return (void __arena*)((char __arena*)map + off);
}

static __always_inline __u64 bpfj_const_map_hash_finish(__u64 hash) {
  hash ^= hash >> 30;
  hash *= BPFJ_CONST_MAP_HASH_MULT;
  hash ^= hash >> 32;
  return hash;
}

static __noinline __u64
bpfj_const_map_hash(const __u64 __arena* key, __u32 words) {
  __u64 hash = BPFJ_CONST_MAP_HASH_MULT;
  __u32 i = 0;
  bpf_for(i, 0, words) {
    hash = (hash ^ key[i]) * BPFJ_CONST_MAP_HASH_MULT;
  }
  return bpfj_const_map_hash_finish(hash);
}

static __always_inline __u64 bpfj_const_map_hash_u64(__u64 key) {
  return bpfj_const_map_hash_finish(
      (BPFJ_CONST_MAP_HASH_MULT ^ key) * BPFJ_CONST_MAP_HASH_MULT);
}

static __always_inline bool bpfj_const_map_key_equal(
    const __u64 __arena* left,
    const __u64 __arena* right,
    __u32 words) {
  if (left == NULL || right == NULL) {
    return false;
  }
  bool equal = true;
  __u32 i = 0;
  bpf_for(i, 0, words) {
    if (left[i] != right[i]) {
      equal = false;
      break;
    }
  }
  return equal;
}

// Initialize a caller-allocated slab of bpfj_const_map_allocation_size()
// bytes. Nothing may read the map until bpfj_const_map_seal().
static __noinline long bpfj_const_map_init(
    struct bpfj_const_map __arena* map __arg_arena,
    __u32 max_entries,
    __u32 key_size,
    __u32 val_size) {
  __u32 total_size =
      bpfj_const_map_allocation_size(max_entries, key_size, val_size);
  if (total_size == 0) {
    return -EINVAL;
  }

  __u32 capacity =
      bpfj_const_map_round_capacity(max_entries << BPFJ_CONST_MAP_LOAD_SHIFT);
  __u32 key_stride = bpfj_const_map_align(key_size);
  __u32 val_stride = bpfj_const_map_align(val_size);
  __u32 keys_offset =
      bpfj_const_map_align(sizeof(*map) + capacity * (__u32)sizeof(__u32));
  __u32 values_offset =
      bpfj_const_map_align(keys_offset + max_entries * key_stride);

  map->max_entries = max_entries;
  map->size = 0;
  map->capacity = capacity;
  map->key_size = key_size;
  map->val_size = val_size;
  map->key_stride = key_stride;
  map->val_stride = val_stride;
  map->keys_offset = keys_offset;
  map->values_offset = values_offset;
  map->probe_limit = 0;
  map->sealed = 0;
  map->total_size = total_size;
  bpfj_heap_zero_arena(
      bpfj_const_map_slots(map), capacity * (__u32)sizeof(__u32));
  return 0;
}

// Reserve a dense entry for an arena key. A new entry's value is zeroed;
// callers fill it through bpfj_const_map_value_at(). A duplicate returns its
// existing entry unchanged so callers can merge values during construction.
static __noinline long bpfj_const_map_insert(
    struct bpfj_const_map __arena* map __arg_arena,
    const __u64 __arena* key __arg_arena) {
  if (map->sealed) {
    return -EPERM;
  }
  __u32 words = map->key_size / (__u32)sizeof(__u64);
  __u64 hash = bpfj_const_map_hash(key, words);
  __u32 off = (__u32)hash & (map->capacity - 1);
  __u32 __arena* slots = bpfj_const_map_slots(map);

  __u32 p = 0;
#pragma unroll
  for (p = 0; p < BPFJ_CONST_MAP_MAX_PROBES; ++p) {
    __u32 entry_plus_one = slots[off];
    if (entry_plus_one == 0) {
      if (map->size >= map->max_entries) {
        return -ENOSPC;
      }
      __u32 index = map->size++;
      __u64 __arena* stored_key = bpfj_const_map_key_at(map, index);
      void __arena* stored_value = bpfj_const_map_value_at(map, index);
      if (stored_key == NULL || stored_value == NULL) {
        map->size--;
        return -EINVAL;
      }
      bpfj_heap_copy_arena(stored_key, key, map->key_size);
      bpfj_heap_zero_arena(stored_value, map->val_size);
      slots[off] = index + 1;
      if (p + 1 > map->probe_limit) {
        map->probe_limit = p + 1;
      }
      return BPFJ_CONST_MAP_PLAN(BPFJ_CONST_MAP_INSERTED, index);
    }

    __u32 index = entry_plus_one - 1;
    if (bpfj_const_map_key_equal(
            bpfj_const_map_key_at(map, index), key, words)) {
      return BPFJ_CONST_MAP_PLAN(BPFJ_CONST_MAP_EXISTING, index);
    }
    off = (off + 1) & (map->capacity - 1);
  }
  return -EOVERFLOW;
}

// Scalar-key fast path, used by pointer-keyed maps without allocating arena
// scratch merely to stage one word.
static __noinline long bpfj_const_map_insert_u64(
    struct bpfj_const_map __arena* map __arg_arena,
    __u64 key) {
  if (map->sealed) {
    return -EPERM;
  }
  if (map->key_size != sizeof(key)) {
    return -EINVAL;
  }
  __u32 off = (__u32)bpfj_const_map_hash_u64(key) & (map->capacity - 1);
  __u32 __arena* slots = bpfj_const_map_slots(map);
  __u32 p = 0;
#pragma unroll
  for (p = 0; p < BPFJ_CONST_MAP_MAX_PROBES; ++p) {
    __u32 entry_plus_one = slots[off];
    if (entry_plus_one == 0) {
      if (map->size >= map->max_entries) {
        return -ENOSPC;
      }
      __u32 index = map->size++;
      __u64 __arena* stored_key = bpfj_const_map_key_at(map, index);
      void __arena* stored_value = bpfj_const_map_value_at(map, index);
      if (stored_key == NULL || stored_value == NULL) {
        map->size--;
        return -EINVAL;
      }
      *stored_key = key;
      bpfj_heap_zero_arena(stored_value, map->val_size);
      slots[off] = index + 1;
      if (p + 1 > map->probe_limit) {
        map->probe_limit = p + 1;
      }
      return BPFJ_CONST_MAP_PLAN(BPFJ_CONST_MAP_INSERTED, index);
    }

    __u32 index = entry_plus_one - 1;
    __u64 __arena* stored_key = bpfj_const_map_key_at(map, index);
    if (stored_key != NULL && *stored_key == key) {
      return BPFJ_CONST_MAP_PLAN(BPFJ_CONST_MAP_EXISTING, index);
    }
    off = (off + 1) & (map->capacity - 1);
  }
  return -EOVERFLOW;
}

// Finish construction. Every successful insertion recorded the longest probe
// an existing key can require, so publication needs no table walk.
static __noinline long bpfj_const_map_seal(
    struct bpfj_const_map __arena* map __arg_arena) {
  if (map->sealed) {
    return -EPERM;
  }

  map->sealed = 1;
  return 0;
}

// Lookups return a dense value index, or a negative errno. The caller obtains
// the immutable value through bpfj_const_map_value_at().
static __noinline long bpfj_const_map_lookup(
    struct bpfj_const_map __arena* map __arg_arena,
    const __u64 __arena* key __arg_arena) {
  if (!map->sealed) {
    return -EPERM;
  }

  __u32 words = map->key_size / (__u32)sizeof(__u64);
  __u32 off = (__u32)bpfj_const_map_hash(key, words) & (map->capacity - 1);
  __u32 __arena* slots = bpfj_const_map_slots(map);
  __u32 p = 0;
#pragma unroll
  for (p = 0; p < BPFJ_CONST_MAP_MAX_PROBES; ++p) {
    if (p >= map->probe_limit) {
      break;
    }
    __u32 entry_plus_one = slots[off];
    if (entry_plus_one == 0) {
      return -ENOENT;
    }
    __u32 index = entry_plus_one - 1;
    if (bpfj_const_map_key_equal(
            bpfj_const_map_key_at(map, index), key, words)) {
      return index;
    }
    off = (off + 1) & (map->capacity - 1);
  }
  return -ENOENT;
}

static __noinline long bpfj_const_map_lookup_u64(
    struct bpfj_const_map __arena* map __arg_arena,
    __u64 key) {
  if (!map->sealed) {
    return -EPERM;
  }
  if (map->key_size != sizeof(key)) {
    return -EINVAL;
  }

  __u32 off = (__u32)bpfj_const_map_hash_u64(key) & (map->capacity - 1);
  __u32 __arena* slots = bpfj_const_map_slots(map);
  __u32 p = 0;
#pragma unroll
  for (p = 0; p < BPFJ_CONST_MAP_MAX_PROBES; ++p) {
    if (p >= map->probe_limit) {
      break;
    }
    __u32 entry_plus_one = slots[off];
    if (entry_plus_one == 0) {
      return -ENOENT;
    }
    __u32 index = entry_plus_one - 1;
    __u64 __arena* stored_key = bpfj_const_map_key_at(map, index);
    if (stored_key != NULL && *stored_key == key) {
      return index;
    }
    off = (off + 1) & (map->capacity - 1);
  }
  return -ENOENT;
}
