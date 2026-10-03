// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include <errno.h>
#include "bpfj/lib/bpf/heap.h"
#include "bpfj/lib/bpf/lock.h"
#include "bpfj/lib/bpf/shared_ptr.h"
#include "bpfj/lib/bpf/types_dyn_lru.h"

// Fixed-size LRU of opaque arena blocks keyed by caller-owned fixed-width byte
// strings. One waiting map lock protects the index and recency state, while
// allocation and free stay outside it.
static __noinline void bpfj_dyn_lookup_guard_cleanup(
    struct bpfj_shared_ptr* ptr) {
  bpfj_shared_ptr_release(ptr);
}

#define BPFJ_DYN_LRU_LOOKUP_GUARD(_val_name) \
  __attribute((cleanup(                      \
      bpfj_dyn_lookup_guard_cleanup))) struct bpfj_shared_ptr _val_name = {0};

#define BPFJ_DYN_LRU_LOOKUP(_val_name, _map, _key) \
  ({ bpfj_dyn_lru_lookup(_map, _key, &_val_name); })

// An entry off the free list, or NULL when every entry is live.
static __always_inline struct bpfj_dyn_lru_entry __arena* bpfj_dyn_lru_pool_pop(
    struct bpfj_dyn_lru __arena* map) {
  struct bpfj_dyn_lru_entry __arena* entry = map->free_list;
  if (!entry) {
    return NULL;
  }
  map->free_list = entry->next_free;
  entry->next_free = NULL;
  return entry;
}

// Give an entry back after moving its value out.
static __always_inline void bpfj_dyn_lru_pool_push(
    struct bpfj_dyn_lru __arena* map,
    struct bpfj_dyn_lru_entry __arena* entry) {
  entry->ref = 0;
  entry->home = 0;
  entry->slot = 0;
  entry->next_free = map->free_list;
  map->free_list = entry;
}

// Keys are copied word-wise because whole-buffer copies out of arena memory
// read back as scalars on 6.11 and are rejected.
static __always_inline void bpfj_dyn_lru_key_copy(
    __u64 __arena* dst,
    const __u64 __arena* src,
    __u32 key_words) {
  __u32 i = 0;
  bpf_for(i, 0, key_words) {
    dst[i] = src[i];
  }
}

static __always_inline struct bpfj_dyn_lru_slot __arena* bpfj_dyn_lru_slot_at(
    struct bpfj_dyn_lru __arena* map,
    __u32 idx) {
  return map->slots + idx;
}

// How far linear probing displaced an entry from its home slot.
static __always_inline __u32
bpfj_dyn_lru_dist(__u32 from, __u32 to, __u32 arr_size) {
  return (to - from) & (arr_size - 1);
}

static __always_inline __u32 bpfj_dyn_lru_key_words(__u32 key_size) {
  return key_size / (__u32)sizeof(__u64);
}

static __always_inline __u32
bpfj_dyn_lru_home(const __u64 __arena* key, __u32 key_words, __u32 arr_size) {
  __u64 hash = 0xcbf29ce484222325ULL;
  __u32 i = 0;
  bpf_for(i, 0, key_words) {
    hash ^= key[i];
    hash *= 0x100000001b3ULL;
  }
  return (__u32)hash & (arr_size - 1);
}

static __always_inline bool bpfj_dyn_lru_key_eq(
    const __u64 __arena* a,
    const __u64 __arena* b,
    __u32 key_words) {
  __u32 i = 0;
  bpf_for(i, 0, key_words) {
    if (a[i] != b[i]) {
      return false;
    }
  }
  return true;
}

// Whether the probe can use this header at all.
static __always_inline bool bpfj_dyn_lru_usable(
    struct bpfj_dyn_lru __arena* map) {
  return map != NULL && map->key_size != 0 && map->arr_size != 0;
}

// The slot holding `key`, or -ENOENT. On a miss, `free_out` receives the
// terminating empty slot. The caller holds map->lock throughout.
static __always_inline long bpfj_dyn_lru_probe(
    struct bpfj_dyn_lru __arena* map,
    const __u64 __arena* key,
    __u32 key_words,
    __u32* free_out) {
  __u32 mask = map->arr_size - 1;
  __u32 off = bpfj_dyn_lru_home(key, key_words, map->arr_size);

#pragma unroll
  for (__u32 p = 0; p < BPFJ_DYN_LRU_MAX_PROBES; ++p) {
    struct bpfj_dyn_lru_slot __arena* slot = bpfj_dyn_lru_slot_at(map, off);

    struct bpfj_dyn_lru_entry __arena* stored = slot->entry;
    if (!stored) {
      if (free_out) {
        *free_out = off;
      }
      return -ENOENT;
    }
    if (bpfj_dyn_lru_key_eq(stored->key, key, key_words)) {
      return off;
    }
    off = (off + 1) & mask;
  }
  return -ENOENT;
}

// Close the hole left at `start` by pulling back entries still on that probe
// chain. The caller holds map->lock, so the chain cannot move underneath it.
static __noinline void bpfj_dyn_lru_close_hole(
    struct bpfj_dyn_lru __arena* map,
    __u32 start) {
  __u32 mask = map->arr_size - 1;
  __u32 hole = start & mask;
  __u32 probe = hole;

  __u32 i = 0;
  bpf_for(i, 0, map->arr_size) {
    probe = (probe + 1) & mask;
    struct bpfj_dyn_lru_slot __arena* from = bpfj_dyn_lru_slot_at(map, probe);

    struct bpfj_dyn_lru_entry __arena* stored = from->entry;
    if (!stored) {
      return; // end of the run; everything after it is already reachable
    }

    __u32 home = stored->home;
    if (bpfj_dyn_lru_dist(home, hole, map->arr_size) <
        bpfj_dyn_lru_dist(home, probe, map->arr_size)) {
      // The hole is still on this entry's probe path, so it can move back.
      struct bpfj_dyn_lru_slot __arena* to = bpfj_dyn_lru_slot_at(map, hole);
      to->entry = stored;
      stored->slot = hole;
      from->entry = NULL;
      hole = probe;
    }
  }
}

// Take the clock hand's victim out of the index with second-chance semantics.
// A full map has no free pool entries, so scanning the dense entry pool finds
// a live candidate immediately instead of walking the sparse hash index.
static __noinline struct bpfj_dyn_lru_entry __arena* bpfj_dyn_lru_evict(
    struct bpfj_dyn_lru __arena* map) {
  const __u32 kNone = ~(__u32)0;
  __u32 hand = map->clock_hand;
  struct bpfj_dyn_lru_entry __arena* victim = NULL;
  __u32 taken = kNone;
  __u32 first_used = kNone;

  // A bpf_for, unlike the probe: the lock operations here inline, so no call
  // leaves the verifier a fresh state per step.
  __u32 i = 0;
  bpf_for(i, 0, BPFJ_DYN_LRU_CLOCK_SCAN) {
    __u32 pool_idx = (hand + i) & (map->capacity - 1);
    struct bpfj_dyn_lru_entry __arena* cand = map->entry_pool + pool_idx;

    __u32 credit = cand->ref;
    if (credit != 0) {
      cand->ref = credit - 1;
      if (first_used == kNone) {
        first_used = pool_idx;
      }
      continue;
    }

    victim = cand;
    __u32 off = cand->slot;
    struct bpfj_dyn_lru_slot __arena* slot = bpfj_dyn_lru_slot_at(map, off);
    slot->entry = NULL;
    taken = off;
    hand = pool_idx;
    break;
  }

  if (!victim && first_used != kNone) {
    // Every entry in the window still had credit, so take the first one anyway
    // or `size` could climb past capacity without bound; __bpf_lru_list_shrink
    // gives up on the reference bit the same way.
    victim = map->entry_pool + first_used;
    taken = victim->slot;
    bpfj_dyn_lru_slot_at(map, taken)->entry = NULL;
    hand = first_used;
  }

  if (!victim) {
    return NULL;
  }

  bpfj_dyn_lru_close_hole(map, taken);
  map->clock_hand = (hand + 1) & (map->capacity - 1);
  map->size--;
  return victim;
}

long bpfj_dyn_lru_insert(
    struct bpfj_dyn_lru __arena* map __arg_arena,
    __u64 __arena* key __arg_arena,
    void __arena* val __arg_arena) {
  // Before anything reads through `map` -- including the key_size below.
  if (!bpfj_dyn_lru_usable(map)) {
    BPFJ_HEAP_FREE(val);
    return -EINVAL;
  }

  __u32 key_words = bpfj_dyn_lru_key_words(map->key_size);

  // The one allocation left on this path, taken before the lock.
  struct bpfj_shared_ptr val_sp = bpfj_shared_ptr_adopt(val);
  if (!val_sp.refcount) {
    BPFJ_HEAP_FREE(val);
    return -ENOMEM;
  }

  const __u32 kNoSlot = ~(__u32)0;
  long rc = 0;
  struct bpfj_shared_ptr retired = {0};

  {
    BPFJ_LOCK_WAIT_GUARD(dlm, &map->lock);
    if (!BPFJ_LOCK_WAIT_HELD(dlm)) {
      rc = -EBUSY;
      goto unlocked;
    }

    __u32 free_slot = kNoSlot;
    long existing = bpfj_dyn_lru_probe(map, key, key_words, &free_slot);
    if (existing >= 0) {
      struct bpfj_dyn_lru_slot __arena* slot =
          bpfj_dyn_lru_slot_at(map, (__u32)existing);
      struct bpfj_dyn_lru_entry __arena* cur = slot->entry;

      retired.buf = cur->val.buf;
      retired.refcount = cur->val.refcount;
      cur->val.buf = val_sp.buf;
      cur->val.refcount = val_sp.refcount;
      val_sp.buf = NULL;
      val_sp.refcount = NULL;

      cur->ref = BPFJ_DYN_LRU_REF_LOOKUP; // a re-insert is a use
      goto unlocked;
    }

    if (free_slot == kNoSlot) {
      // The index clustered past the probe window.
      rc = -EOVERFLOW;
      goto unlocked;
    }

    struct bpfj_dyn_lru_entry __arena* entry = bpfj_dyn_lru_pool_pop(map);
    if (!entry) {
      entry = bpfj_dyn_lru_evict(map);
      if (!entry) {
        rc = -EBUSY;
        goto unlocked;
      }
      retired.buf = entry->val.buf;
      retired.refcount = entry->val.refcount;
      entry->val.buf = NULL;
      entry->val.refcount = NULL;

      // Backward-shift deletion may have moved the terminating empty slot.
      free_slot = kNoSlot;
      existing = bpfj_dyn_lru_probe(map, key, key_words, &free_slot);
      if (existing >= 0 || free_slot == kNoSlot) {
        bpfj_dyn_lru_pool_push(map, entry);
        rc = existing >= 0 ? -EEXIST : -EOVERFLOW;
        goto unlocked;
      }
    }

    bpfj_dyn_lru_key_copy(entry->key, key, key_words);
    entry->val.buf = val_sp.buf;
    entry->val.refcount = val_sp.refcount;
    val_sp.buf = NULL;
    val_sp.refcount = NULL;
    entry->home = bpfj_dyn_lru_home(key, key_words, map->arr_size);
    entry->slot = free_slot;
    entry->ref = BPFJ_DYN_LRU_REF_INSERT;

    struct bpfj_dyn_lru_slot __arena* slot =
        bpfj_dyn_lru_slot_at(map, free_slot);
    slot->entry = entry;
    map->size++;
  }

unlocked:
  // Past the lock, so heap frees do not serialize other callers.
  bpfj_shared_ptr_release(&retired);
  bpfj_shared_ptr_release(&val_sp);
  return rc;
}

long bpfj_dyn_lru_lookup(
    struct bpfj_dyn_lru __arena* map __arg_arena,
    __u64 __arena* key __arg_arena,

    struct bpfj_shared_ptr* val __arg_nonnull) {
  if (!bpfj_dyn_lru_usable(map)) {
    return -ENOENT;
  }

  BPFJ_LOCK_WAIT_GUARD(dlm, &map->lock);
  if (!BPFJ_LOCK_WAIT_HELD(dlm)) {
    return -EBUSY;
  }

  __u32 key_words = bpfj_dyn_lru_key_words(map->key_size);
  long idx = bpfj_dyn_lru_probe(map, key, key_words, NULL);
  if (idx < 0) {
    return idx;
  }

  struct bpfj_dyn_lru_slot __arena* slot =
      bpfj_dyn_lru_slot_at(map, (__u32)idx);
  struct bpfj_dyn_lru_entry __arena* entry = slot->entry;

  // Under the map lock, so replacement or eviction cannot drop the map's
  // reference at the same time.
  __sync_fetch_and_add(entry->val.refcount, 1);
  val->buf = entry->val.buf;
  val->refcount = entry->val.refcount;

  // Read before write, so a repeatedly hit key leaves the line alone after the
  // first time, as bpf_lru_node_set_ref() does.
  if (entry->ref != BPFJ_DYN_LRU_REF_LOOKUP) {
    entry->ref = BPFJ_DYN_LRU_REF_LOOKUP;
  }

  return 0;
}
