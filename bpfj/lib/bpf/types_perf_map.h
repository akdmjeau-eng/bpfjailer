// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#ifdef __cplusplus
#include <linux/types.h>
#endif

#include "bpfj/lib/bpf/types_heap.h"

// Perfect hash map for fixed sets of u64 keys, built from userspace and read
// only from BPF. Two-level: the key hashes to a bucket index, whose seed is
// read from the seeds array, and (key, seed) hashes to the slot the stored key
// is compared at.

struct bpfj_perf_map_slot {
  __u64 key;
  __u64 val;
  __u32 occupied;
  __u32 _pad;
};

struct bpfj_perf_map {
  __arena __u32* seeds; // arena pointer to __u32[num_buckets]
  __arena struct bpfj_perf_map_slot* slots; // arena ptr to slot[num_slots]
  __u32 num_buckets;
  __u32 num_slots;
};

#define BPFJ_PERF_MAP_HASH_MULT 0x9e3779b97f4a7c15ULL

static __always_inline __u32
bpfj_perf_map_hash(__u64 key, __u32 seed, __u32 mod) {
  __u64 h = key;
  h ^= (__u64)seed;
  h *= BPFJ_PERF_MAP_HASH_MULT;
  h ^= h >> 32;
  return (__u32)(h % mod);
}
