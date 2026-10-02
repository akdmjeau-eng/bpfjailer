// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

// Scratch buffers too large for the 512 byte BPF stack, claimed out of a
// shared pool by setting a bit in a bitmap with an atomic, so two CPUs racing
// for one slot cannot both win.
//
// Not a per-CPU array, the obvious place: a sleepable hook can be suspended
// mid-call and another program sharing the map takes the same entry on the
// same CPU, silently rewriting the first one's buffer. Not a ring buffer,
// whose space only comes back when the *consumer* position advances, which
// only userspace moves. Not task storage, which could not allocate a 16KB
// value on 6.19, nor the arena, whose pointers bpf_dynptr_from_mem will not
// take.
//
// The pool is fixed, so it can be exhausted; every caller has to handle a
// NULL, and the ones here deny rather than continue. See types_scratch.h for
// the two size classes.

#include <bpf/bpf_helpers.h>

#include "bpfj/lib/bpf/types_scratch.h"

struct bpfj_scratch_small_slot {
  char bytes[BPFJ_SCRATCH_SMALL_SIZE];
};

struct bpfj_scratch_large_slot {
  char bytes[BPFJ_SCRATCH_LARGE_SIZE];
};

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, BPFJ_SCRATCH_SMALL_SLOTS);
  __type(key, __u32);
  __type(value, struct bpfj_scratch_small_slot);
} bpfj_scratch_small SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, BPFJ_SCRATCH_LARGE_SLOTS);
  __type(key, __u32);
  __type(value, struct bpfj_scratch_large_slot);
} bpfj_scratch_large SEC(".maps");

// One bit per slot, set while the slot is claimed.
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, BPFJ_SCRATCH_SMALL_WORDS);
  __type(key, __u32);
  __type(value, __u64);
} bpfj_scratch_small_claimed SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, BPFJ_SCRATCH_LARGE_WORDS);
  __type(key, __u32);
  __type(value, __u64);
} bpfj_scratch_large_claimed SEC(".maps");

/// Claim a slot from one class, or NULL when that class is full. bpf_for
/// rather than a plain bounded loop, which the verifier walks iteration by
/// iteration until the instruction budget rather than the memory caps the pool
/// -- at 2048 small slots bpfj_jailer_exec stopped verifying with "BPF program
/// is too large". Claiming from inside a caller's bpf_for is safe even though
/// this is __always_inline, since bpf_for declares its iterator in the
/// for-init clause and a nested one shadows the outer.
static __always_inline void* bpfj_scratch_claim(
    void* slots,
    void* claimed,
    __u32 count,
    __u32 tag,
    __u32* slot) {
  if (count == 0) {
    return NULL;
  }
  // Spread concurrent callers across the bitmap instead of its first word.
  const __u32 start = bpf_get_prandom_u32() % count;
  int i;
  bpf_for(i, 0, count) {
    __u32 idx = start + (__u32)i;
    if (idx >= count) {
      idx -= count;
    }
    const __u32 w = idx / 64;
    __u64* word = bpf_map_lookup_elem(claimed, &w);
    if (!word) {
      break;
    }

    // Set and test in one step, or two CPUs could both see the bit clear.
    const __u64 mask = 1ULL << (idx % 64);
    if (__sync_fetch_and_or(word, mask) & mask) {
      continue;
    }

    void* mem = bpf_map_lookup_elem(slots, &idx);
    if (!mem) {
      // Unreachable, but a claim not handed out loses the slot for good.
      __sync_fetch_and_and(word, ~mask);
      break;
    }

    *slot = idx | tag;
    return mem;
  }

  return NULL;
}

/// Claim a slot big enough for `size`, or NULL when that class is full, with
/// `slot` receiving the handle to hand bpfj_scratch_free (BPFJ_SCRATCH_NONE if
/// nothing was claimed). Prefer BPFJ_SCRATCH_GUARD, which pairs the two.
static __always_inline void* bpfj_scratch_alloc(__u32 size, __u32* slot) {
  *slot = BPFJ_SCRATCH_NONE;

  if (size <= BPFJ_SCRATCH_SMALL_SIZE) {
    return bpfj_scratch_claim(
        &bpfj_scratch_small,
        &bpfj_scratch_small_claimed,
        BPFJ_SCRATCH_SMALL_SLOTS,
        0,
        slot);
  }

  return bpfj_scratch_claim(
      &bpfj_scratch_large,
      &bpfj_scratch_large_claimed,
      BPFJ_SCRATCH_LARGE_SLOTS,
      BPFJ_SCRATCH_LARGE_TAG,
      slot);
}

/// Give a slot back. BPFJ_SCRATCH_NONE is accepted and does nothing.
static __always_inline void bpfj_scratch_free(__u32 slot) {
  if (slot == BPFJ_SCRATCH_NONE) {
    return;
  }

  const __u32 index = slot & ~BPFJ_SCRATCH_LARGE_TAG;
  if (slot & BPFJ_SCRATCH_LARGE_TAG) {
    if (index >= BPFJ_SCRATCH_LARGE_SLOTS) {
      return;
    }

    const __u32 w = index / 64;
    __u64* word = bpf_map_lookup_elem(&bpfj_scratch_large_claimed, &w);
    if (word) {
      __sync_fetch_and_and(word, ~(1ULL << (index % 64)));
    }
    return;
  }

  if (index >= BPFJ_SCRATCH_SMALL_SLOTS) {
    return;
  }

  const __u32 w = index / 64;
  __u64* word = bpf_map_lookup_elem(&bpfj_scratch_small_claimed, &w);
  if (word) {
    __sync_fetch_and_and(word, ~(1ULL << (index % 64)));
  }
}

static void bpfj_scratch_release(__u32* slot) {
  bpfj_scratch_free(*slot);
}

/// Claim a slot as `_type* _name`, freed however the scope is left. `_name`
/// may be NULL, the pool being finite. Modelled on BPFJ_HEAP_ALLOC_GUARD, with
/// the same rule: `_name` is an alias to a hidden handle, so never free it by
/// hand, assign to it, or hand the slot out of the scope.
#define BPFJ_SCRATCH_GUARD(_type, _name)                                       \
  _Static_assert(                                                              \
      sizeof(_type) <= BPFJ_SCRATCH_LARGE_SIZE,                                \
      #_type " does not fit a scratch slot; raise BPFJ_SCRATCH_LARGE_SIZE");   \
  __attribute__((cleanup(bpfj_scratch_release))) __u32 _name##_scratch_guard = \
      BPFJ_SCRATCH_NONE;                                                       \
  _type* _name = bpfj_scratch_alloc(sizeof(_type), &_name##_scratch_guard)
