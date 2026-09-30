// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include <errno.h>
#include "bpfj/lib/bpf/heap.h"
#include "bpfj/lib/bpf/types_heap.h"
#include "bpfj/lib/bpf/types_str_map.h"

// The str map stores arena pointers rather than heap offsets, and the header
// lives on the arena too (userspace allocates it; see StrMap.h), the arena
// being mmap'd at the same fixed address in both worlds. An empty slot is a
// zeroed entry, i.e. a NULL key.

static __always_inline __arena const struct bpfj_str_map_entry*
bpfj_str_map_entry_at(__arena const struct bpfj_str_map_entry* vec, __u32 idx) {
  return vec + idx;
}

// Recover the heap offset of an arena pointer, spelled as a pointer
// difference because that is the one arena-pointer-to-scalar conversion the
// verifier takes (as BPFJ_HEAP_FREE does).
static __always_inline __u32
bpfj_str_map_ptr_off(void __arena* base, __arena const void* ptr) {
  return (__u32)((__arena const char*)ptr - (__arena const char*)base);
}

// max_len is the caller's compile-time sizeof of the lhs search buffer, which
// may live in a non-arena map value and so must be provably in range. The
// index is masked to max_len rather than len, whose bound is fragile across
// the surrounding probe loop. An 8-byte-chunk variant does not work: the
// chunk offset (i << 3) folds back into an unbounded register.
static __always_inline long bpfj_str_map_memcmp(
    const char* lhs,
    __arena const char* rhs,
    size_t len,
    u32 max_len) {
  u32 i = 0;
  bpf_for(i, 0, BPFJ_STR_MAP_MAX_STR_LEN) {
    if (i >= len) {
      return 0;
    }
    u32 pos = i;
    asm volatile("%0 &= %1" : "+r"(pos) : "r"(max_len - 1));
    if ((unsigned char)lhs[pos] != (unsigned char)rhs[pos]) {
      return 1;
    }
  }
  return 0;
}

static __always_inline long bpfj_str_map_lookup_internal(
    __arena const struct bpfj_str_map* str_map,
    const char* str,
    size_t len,
    void __arena** val,
    u32 max_len) {
  // A NULL or empty header means the owner never built this map; arena offset
  // 0 is the heap control struct, which reads rather than faults.
  if (str_map == NULL || str_map->capacity == 0) {
    return -ENOENT;
  }

  u32 hash = bpfj_str_map_hash(str, len, str_map->capacity, max_len);

  u32 off = hash;
  u32 i = 0;
  bpf_for(i, 0, BPFJ_STR_MAP_MAX_ATTEMPTS) {
    __arena const struct bpfj_str_map_entry* entry =
        bpfj_str_map_entry_at(str_map->vec, off);
    __arena const char* key = entry->key;
    if (key == NULL) {
      return -ENOENT;
    }

    if (entry->key_len != len) {
      ++off;
      if (off >= str_map->capacity) {
        off = 0;
      }
      continue;
    }

    if (bpfj_str_map_memcmp(str, key, len, max_len) == 0) {
      *val = entry->val;
      return 0;
    }

    ++off;

    if (off >= str_map->capacity) {
      off = 0;
    }
  }

  return -EOVERFLOW;
}

static long bpfj_str_map_lookup_strlen(
    __arena const struct bpfj_str_map* str_map,
    const char* str,
    size_t max_strlen,
    void __arena** val) {
  u32 len = 0;
  bpf_for(len, 0, max_strlen) {
    if (str[len] == '\0') {
      break;
    }
  }

  // Bound len to the caller's search buffer: the bpf_for break loses the
  // len < max_strlen bound and a plain clamp is elided as redundant, so an
  // inline-asm mask is what the verifier will take. Keys are null-terminated
  // within their buffers, so it is a no-op at runtime.
  asm volatile("%0 &= %1" : "+r"(len) : "r"((u32)(max_strlen - 1)));

  return bpfj_str_map_lookup_internal(str_map, str, len, val, (u32)max_strlen);
}

// static, not a global subprogram: the pointer it writes back must keep its
// arena provenance, and a global function's stores land as plain scalars.
static __noinline long bpfj_str_map_lookup(
    __arena const struct bpfj_str_map* str_map,
    const char* str,
    size_t len,
    void __arena** val) {
  // The explicit-length API's callers pass a buffer of at least
  // BPFJ_STR_MAP_MAX_STR_LEN bytes, so bound the compare index to that.
  return bpfj_str_map_lookup_internal(
      str_map, str, len, val, BPFJ_STR_MAP_MAX_STR_LEN);
}
