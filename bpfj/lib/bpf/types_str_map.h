// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#ifdef __cplusplus
#include <linux/types.h>
#include <cstring>
#endif

#include "bpfj/lib/bpf/types_heap.h"

#define BPFJ_STR_MAP_MAX_ATTEMPTS 32
#define BPFJ_STR_MAP_MAX_STR_LEN 256

struct bpfj_str_map_entry {
  __arena char* key;
  // An arena pointer, like `key` and `vec` below, both sides seeing the block
  // at the same address, so a lookup hands back something dereferenceable.
  __arena void* val;
  __u32 key_len;
};

struct bpfj_str_map {
  __arena struct bpfj_str_map_entry* vec;
  __u32 size;
  __u32 capacity;
};

#define BPFJ_STR_MAP_HASH_MULT 0x9e3779b97f4a7c15ULL

#ifdef __cplusplus

// max_len is the compile-time sizeof of the key buffer, unused here and masked
// against by the BPF variant's reads; the masks are no-ops whenever
// max_len >= size, so the two hashes agree.
static inline __u32
bpfj_str_map_hash(const char* key, __u32 size, __u32 capacity, __u32 max_len) {
  (void)max_len;
  __u64 hash = 0;
  std::size_t i = 0;
  for (; i + 8 <= size; i += 8) {
    __u64 chunk;
    __builtin_memcpy(&chunk, key + i, sizeof(chunk));
    hash ^= chunk;
    hash *= BPFJ_STR_MAP_HASH_MULT;
  }
  for (; i < size; ++i) {
    hash ^= (__u64)(unsigned char)key[i];
    hash *= BPFJ_STR_MAP_HASH_MULT;
  }
  return (__u32)(hash % capacity);
}

#else

// max_len is the caller's compile-time power-of-two sizeof of the key buffer,
// which may be non-arena and smaller than BPFJ_STR_MAP_MAX_STR_LEN. Read
// indices are masked against it rather than against size, whose bound is
// fragile across the surrounding loops, or against BPFJ_STR_MAP_MAX_STR_LEN,
// which left a caller with a 64-byte buffer getting reads the verifier could
// only bound to 256. The masks are no-ops on real data.
static __always_inline __u32
bpfj_str_map_hash(const char* key, __u32 size, __u32 capacity, __u32 max_len) {
  // Bound the length to the buffer. Keys are null-terminated within it by
  // construction, so this is a runtime no-op.
  if (size > max_len) {
    size = max_len;
  }
  u64 hash = 0;
  u32 full = size >> 3;
  u32 i = 0;
  bpf_for(i, 0, BPFJ_STR_MAP_MAX_STR_LEN / 8) {
    if (i >= full) {
      break;
    }
    // Mask the offset so the verifier can prove the 8-byte read stays in the
    // buffer, 6.19+ not propagating the bpf_for bound to the load;
    // barrier_var() stops Clang deleting the mask as redundant.
    u32 off = i << 3;
    barrier_var(off);
    off &= (max_len - 8);
    u64 chunk = *(const u64*)(key + off);
    hash ^= chunk;
    hash *= BPFJ_STR_MAP_HASH_MULT;
  }
  u32 tail = full << 3;
  bpf_for(i, 0, 8) {
    u32 pos = tail + i;
    if (pos >= size) {
      break;
    }
    barrier_var(pos);
    pos &= (max_len - 1);
    hash ^= (u64)(unsigned char)key[pos];
    hash *= BPFJ_STR_MAP_HASH_MULT;
  }
  return (u32)(hash % capacity);
}

#endif
