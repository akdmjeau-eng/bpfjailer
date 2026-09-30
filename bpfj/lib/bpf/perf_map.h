// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include <errno.h>
#include "bpfj/lib/bpf/heap.h"
#include "bpfj/lib/bpf/types_perf_map.h"

static __always_inline __arena const struct bpfj_perf_map_slot*
bpfj_perf_map_slot_at(
    __arena const struct bpfj_perf_map_slot* slots,
    __u32 idx) {
  return slots + idx;
}

static __always_inline __u32
bpfj_perf_map_seed_at(__arena const __u32* seeds, __u32 idx) {
  return seeds[idx];
}

// `map` is the arena-resident header (see PerfMap.h). A NULL header means the
// owner never built this map: treat it as empty rather than dereferencing arena
// offset 0, the heap control struct, which reads rather than faults.
static __noinline long bpfj_perf_map_lookup(
    __arena const struct bpfj_perf_map* map,
    __u64 key,
    __u64* val) {
  if (map == NULL || map->num_slots == 0) {
    return -ENOENT;
  }

  __u32 bucket = bpfj_perf_map_hash(key, 0, map->num_buckets);
  __u32 seed = bpfj_perf_map_seed_at(map->seeds, bucket);
  __u32 slot_idx = bpfj_perf_map_hash(key, seed, map->num_slots);

  __arena const struct bpfj_perf_map_slot* slot =
      bpfj_perf_map_slot_at(map->slots, slot_idx);

  if (!slot->occupied || slot->key != key) {
    return -ENOENT;
  }

  *val = slot->val;
  return 0;
}
