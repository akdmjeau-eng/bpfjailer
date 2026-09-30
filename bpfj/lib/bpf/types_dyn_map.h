// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#ifdef __cplusplus
#include <linux/types.h>
#endif

#include "bpfj/lib/bpf/types_heap.h"
#include "bpfj/lib/bpf/types_lock.h"
#include "bpfj/lib/bpf/types_shared_ptr.h"

// Dynamic open-addressing hash map for fixed-width keys -> fixed-width values,
// mutated from BPF and grown as keys are inserted: a single flat slot buffer on
// the arena heap, resolved via linear probing.
//
// Both halves of an entry live outside that buffer in arena blocks of their
// own, so freeing the slot buffer alone leaks every entry in it (see
// bpfj_dyn_map_destroy and its userspace mirror in DynLru.h). Keys are hashed
// and compared a __u64 at a time, so key_size must be a whole number of words;
// the map never reads values, so val_size is unconstrained.
//
// Concurrency. Inserts, deletes and lookups may run at once; only init,
// destroy and the userspace mirror require the map to themselves. Nothing
// blocks -- every lock is a trylock, so a contended operation reports -EBUSY
// -- and three things make that work:
//
//   - a lock per slot, held only while that slot's fields are read or written.
//     A probe walks the table one locked slot at a time, and hands the slot it
//     settles on back to its caller still locked.
//   - a reference count on the slot buffer, so a grow can publish a bigger one
//     while lookups still walk the old. `slots_ptr` is what a lookup reads and
//     `growing_slots_ptr` is where inserts go meanwhile, so nothing lands in a
//     buffer about to be dropped.
//   - a reference count on each value block, so the pointer a lookup hands
//     back outlives a concurrent delete or overwrite.
//
// The key block is not refcounted, being read only under the slot's lock.

// A dedicated state field, because an empty slot is indistinguishable from one
// holding an all-zero key (unlike str_map's key_off or perf_map's flag).
enum {
  BPFJ_DYN_SLOT_EMPTY = 0,
  BPFJ_DYN_SLOT_OCCUPIED = 1,
  BPFJ_DYN_SLOT_TOMB = 2, // deleted; reclaimed on the next grow-rehash
};

struct bpfj_dyn_map_slot {
  // key_size bytes of arena heap, owned outright by the slot; a slot that is
  // not OCCUPIED owns nothing.
  __u64 __arena* key;

  // A reference to val_size bytes of arena heap, shared with whoever a lookup
  // has handed one to.
  struct bpfj_shared_ptr val_ptr;

  // bpfj_dyn_map_key_hash of `key`, cached because re-deriving it in a rehash
  // would nest the key's word loop inside the walk over the slots, past the
  // verifier's budget. It also settles most probe steps without the key.
  __u64 hash;

  // Guards every field above and `state`, held only for the few instructions a
  // probe spends on this slot or the write that follows one.
  struct bpfj_lock lock;

  __u32 state;
};

// An entry taken out of a slot, which bpfj_dyn_map_do_delete hands back to be
// released once the slot's lock is out of the way.
struct bpfj_dyn_map_entry {
  __u64 __arena* key;
  struct bpfj_shared_ptr val;
};

struct bpfj_dyn_map {
  // The slot buffer, capacity slots, refcounted so a grow can retire one while
  // lookups are still walking it.
  struct bpfj_shared_ptr slots_ptr;

  // The buffer a grow is filling, growing_capacity slots, or null when no grow
  // is in flight; inserts go here while it is set.
  struct bpfj_shared_ptr growing_slots_ptr;

  // Guards the two pointers above and the counters below, so a grow swapping
  // buffers cannot cross an operation taking a reference to one. Not held
  // while the table itself is walked.
  struct bpfj_lock lock;

  // Extra storage for user, used in file matching to store locks
  __u64 extra;

  __u32 size; // live (OCCUPIED) entries
  __u32 tombstones; // TOMB slots awaiting reclaim
  __u32 capacity; // number of slots; always a power of two
  __u32 growing_capacity; // slots in growing_slots_ptr; 0 when it is null
  __u32 key_size; // bytes per key; a non-zero multiple of sizeof(__u64)
  __u32 val_size; // bytes per value; non-zero

  // Set when a grow gave up but could not take the map lock to unpublish its
  // buffer, so the next grow can tell that apart from a grow still running.
  __u32 grow_abandoned;
};

// Bound on a single linear-probe walk, well above the chains a load factor
// below 3/4 (see bpfj_dyn_map_should_grow) produces.
#define BPFJ_DYN_MAP_MAX_PROBES 16

// Upper bound on capacity, which bounds the rehash loop so a full-table grow
// stays within the verifier's complexity budget; tune against the VM test.
#define BPFJ_DYN_MAP_MAX_CAPACITY 1048576

// Smallest (and default) initial capacity. Must be a power of two.
#define BPFJ_DYN_MAP_MIN_CAPACITY 8

// A read or write that races a concurrent writer or grow this many times
// returns -EBUSY.
#define BPFJ_DYN_MAP_MAX_RETRIES 64

#define BPFJ_DYN_MAP_HASH_MULT 0x9e3779b97f4a7c15ULL

// The helpers below compile into BPF programs as well as userspace, and BPF
// needs them inlined rather than left as callable symbols.
// NOLINTBEGIN(facebook-hte-NamespaceScopedStaticDeclaration)

// Map a key's hash to a starting slot index, capacity being a power of two so
// the modulo reduces to a mask. Identical in BPF and userspace, so entries
// placed by one are found by the other.
static __always_inline __u32 bpfj_dyn_map_index(__u64 hash, __u32 capacity) {
  __u64 h = hash;
  h ^= h >> 30;
  h *= BPFJ_DYN_MAP_HASH_MULT;
  h ^= h >> 32;
  return (__u32)h & (capacity - 1);
}

// Round a capacity up to the next power of two; above 2^31 the result wraps to
// 0, so callers must reject a capacity past MAX_CAPACITY *before* calling.
static __always_inline __u32 bpfj_dyn_map_round_capacity(__u32 capacity) {
  --capacity;
  capacity |= capacity >> 1;
  capacity |= capacity >> 2;
  capacity |= capacity >> 4;
  capacity |= capacity >> 8;
  capacity |= capacity >> 16;
  return capacity + 1;
}

// Rehash when one more entry would push live+tombstone occupancy past 3/4 of
// capacity, so tombstones are reclaimed before probe chains grow long.
static __always_inline int
bpfj_dyn_map_should_grow(__u32 size, __u32 tombstones, __u32 capacity) {
  return (size + tombstones + 1) * 4 > capacity * 3;
}

// Target capacity for a rehash, decided by LIVE size alone: double past a 1/2
// live load, otherwise keep capacity and purge tombstones in place, so
// delete-heavy churn reclaims rather than doubling.
static __always_inline __u32
bpfj_dyn_map_target_cap(__u32 size, __u32 capacity) {
  if ((size + 1) * 2 > capacity) {
    return capacity * 2;
  }
  return capacity;
}

// NOLINTEND(facebook-hte-NamespaceScopedStaticDeclaration)
