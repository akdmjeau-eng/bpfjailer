// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include <errno.h>
#include "bpfj/lib/bpf/dyn_map.h"
#include "bpfj/lib/bpf/heap.h"
#include "bpfj/lib/bpf/lock.h"
#include "bpfj/lib/bpf/types_dyn_lru.h"

// Fixed-size LRU of `bpfj_dyn_map`s keyed by caller-owned fixed-width byte
// strings; lookups lock one slot at a time, inserts and erases hold map->lock,
// and allocation or free stays outside those locks.
static __always_inline void bpfj_dyn_lru_destroy_val(void __arena* p) {
  struct bpfj_dyn_map __arena* dyn = (struct bpfj_dyn_map __arena*)p;
  if (!dyn) {
    return;
  }
  bpfj_dyn_map_destroy(dyn);
  BPFJ_HEAP_FREE(dyn);
}

static void bpfj_dyn_lookup_guard_cleanup(struct bpfj_shared_ptr* ptr) {
  BPFJ_SHARED_PTR_RELEASE(ptr, bpfj_dyn_lru_destroy_val);
}

#define BPFJ_DYN_LRU_LOOKUP_GUARD(_val_name) \
  __attribute((cleanup(                      \
      bpfj_dyn_lookup_guard_cleanup))) struct bpfj_shared_ptr _val_name = {0};

#define BPFJ_DYN_LRU_LOOKUP(_val_name, _map, _key) \
  ({ bpfj_dyn_lru_lookup(_map, _key, &_val_name); })

// An entry off the free list, or NULL if the pool is transiently empty.
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
  entry->next_free = map->free_list;
  map->free_list = entry;
}

// Move an entry's value into `out` and return the entry to the pool.
static __always_inline void bpfj_dyn_lru_retire(
    struct bpfj_dyn_lru __arena* map,
    struct bpfj_dyn_lru_entry __arena* entry,
    struct bpfj_shared_ptr* out) {
  // Field-wise: a whole-struct copy out of arena memory reads back as a scalar
  // on 6.11 and the verifier rejects the use that follows.
  out->buf = entry->val.buf;
  out->refcount = entry->val.refcount;
  entry->val.buf = NULL;
  entry->val.refcount = NULL;
  bpfj_dyn_lru_pool_push(map, entry);
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

// Whether the probe can use this header at all.
static __always_inline bool bpfj_dyn_lru_usable(
    struct bpfj_dyn_lru __arena* map) {
  return map != NULL && map->key_size != 0 && map->arr_size != 0;
}

// What one step of a walk found; the two actionable ones leave the slot locked.
enum {
  BPFJ_DYN_LRU_TRY_MATCH = 0, // holds this key -- LOCKED
  BPFJ_DYN_LRU_TRY_FREE = 1, // holds nothing, ends the chain -- LOCKED
  BPFJ_DYN_LRU_TRY_MISS = 2, // holds another key
};

// Lock one slot and say what is in it. A global subprogram so the verifier
// checks it once rather than per step of every walk.
__noinline long bpfj_dyn_lru_try_slot(
    struct bpfj_dyn_lru_slot __arena* slot __arg_arena,
    const __u64 __arena* key __arg_arena,
    __u32 key_words) {
  BPFJ_LOCK_GUARD(dl, &slot->lock);
  if (!BPFJ_LOCK_IS_ACQUIRED(dl)) {
    return -EBUSY;
  }

  struct bpfj_dyn_lru_entry __arena* stored = slot->entry;
  if (!stored) {
    BPFJ_LOCK_GUARD_RELEASE(dl);
    return BPFJ_DYN_LRU_TRY_FREE;
  }

  if (bpfj_dyn_map_key_eq(stored->key, key, key_words)) {
    BPFJ_LOCK_GUARD_RELEASE(dl);
    return BPFJ_DYN_LRU_TRY_MATCH;
  }
  return BPFJ_DYN_LRU_TRY_MISS;
}

// The slot holding `key`, or -ENOENT/-EBUSY; on a miss with `free_out`, the
// terminating empty slot is returned there still locked. Unrolled because the
// call in the body leaves the verifier a fresh state every step.
static __always_inline long bpfj_dyn_lru_probe(
    struct bpfj_dyn_lru __arena* map,
    const __u64 __arena* key,
    __u32 key_words,
    __u32* free_out) {
  __u32 mask = map->arr_size - 1;
  __u32 off = bpfj_dyn_map_home(key, key_words, map->arr_size);

#pragma unroll
  for (__u32 p = 0; p < BPFJ_DYN_LRU_MAX_PROBES; ++p) {
    struct bpfj_dyn_lru_slot __arena* slot = bpfj_dyn_lru_slot_at(map, off);

    long found = bpfj_dyn_lru_try_slot(slot, key, key_words);
    if (found < 0) {
      return found;
    }
    if (found == BPFJ_DYN_LRU_TRY_MATCH) {
      return off; // handed to the caller locked
    }
    if (found == BPFJ_DYN_LRU_TRY_FREE) {
      // An insert wants the terminating slot and keeps the lock.
      if (free_out) {
        *free_out = off;
      } else {
        bpfj_lock_unlock(&slot->lock);
      }
      return -ENOENT;
    }
    off = (off + 1) & mask;
  }
  return -ENOENT;
}

// Close the hole left at `start` by pulling back entries still on that probe
// chain; a contended slot stops the walk with the chain intact but less
// compact.
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

    if (!bpfj_lock_trylock(&from->lock)) {
      return; // a lookup is reading it; leave the rest of the run in place
    }

    struct bpfj_dyn_lru_entry __arena* stored = from->entry;
    if (!stored) {
      bpfj_lock_unlock(&from->lock);
      return; // end of the run; everything after it is already reachable
    }

    __u32 home = stored->home;
    if (bpfj_dyn_lru_dist(home, hole, map->arr_size) <
        bpfj_dyn_lru_dist(home, probe, map->arr_size)) {
      // The hole is still on this entry's probe path, so it can move back.
      struct bpfj_dyn_lru_slot __arena* to = bpfj_dyn_lru_slot_at(map, hole);
      if (!bpfj_lock_trylock(&to->lock)) {
        bpfj_lock_unlock(&from->lock);
        return;
      }
      to->entry = stored;
      from->entry = NULL;
      bpfj_lock_unlock(&to->lock);
      hole = probe;
    }

    bpfj_lock_unlock(&from->lock);
  }
}

// Take the clock hand's victim out of the index with second-chance semantics,
// or return NULL when the sweep found nothing; `skip` is the slot just filled.
static __noinline struct bpfj_dyn_lru_entry __arena* bpfj_dyn_lru_evict(
    struct bpfj_dyn_lru __arena* map,
    __u32 skip) {
  const __u32 kNone = ~(__u32)0;
  __u32 mask = map->arr_size - 1;
  __u32 hand = map->clock_hand;
  struct bpfj_dyn_lru_entry __arena* victim = NULL;
  __u32 taken = kNone;
  __u32 first_used = kNone;

  // A bpf_for, unlike the probe: the lock operations here inline, so no call
  // leaves the verifier a fresh state per step.
  __u32 i = 0;
  bpf_for(i, 0, BPFJ_DYN_LRU_CLOCK_SCAN) {
    __u32 off = (hand + i) & mask;
    if (off == skip) {
      continue;
    }

    struct bpfj_dyn_lru_slot __arena* slot = bpfj_dyn_lru_slot_at(map, off);
    if (!bpfj_lock_trylock(&slot->lock)) {
      continue; // mid-lookup; the hand has no reason to wait on it
    }

    struct bpfj_dyn_lru_entry __arena* cand = slot->entry;
    if (!cand) {
      bpfj_lock_unlock(&slot->lock);
      continue;
    }

    __u32 credit = cand->ref;
    if (credit != 0) {
      cand->ref = credit - 1;
      if (first_used == kNone) {
        first_used = off;
      }
      bpfj_lock_unlock(&slot->lock);
      continue;
    }

    victim = cand;
    slot->entry = NULL;
    bpfj_lock_unlock(&slot->lock);
    taken = off;
    break;
  }

  if (!victim && first_used != kNone) {
    // Every entry in the window still had credit, so take the first one anyway
    // or `size` could climb past capacity without bound; __bpf_lru_list_shrink
    // gives up on the reference bit the same way.
    struct bpfj_dyn_lru_slot __arena* slot =
        bpfj_dyn_lru_slot_at(map, first_used);
    if (bpfj_lock_trylock(&slot->lock)) {
      victim = slot->entry;
      if (victim) {
        slot->entry = NULL;
        taken = first_used;
      }
      bpfj_lock_unlock(&slot->lock);
    }
  }

  if (!victim) {
    // Advanced anyway, so a window of empty slots is not rescanned forever.
    map->clock_hand = (hand + BPFJ_DYN_LRU_CLOCK_SCAN) & mask;
    return NULL;
  }

  bpfj_dyn_lru_close_hole(map, taken);
  map->clock_hand = (taken + 1) & mask;
  map->size--;
  return victim;
}

long bpfj_dyn_lru_insert(
    struct bpfj_dyn_lru __arena* map __arg_arena,
    __u64 __arena* key __arg_arena,
    struct bpfj_dyn_map __arena* val __arg_arena) {
  // Before anything reads through `map` -- including the key_size below.
  if (!bpfj_dyn_lru_usable(map)) {
    bpfj_dyn_lru_destroy_val(val);
    return -EINVAL;
  }

  __u32 key_words = bpfj_dyn_map_key_words(map->key_size);

  // The one allocation left on this path, taken before the lock.
  struct bpfj_shared_ptr val_sp = bpfj_shared_ptr_adopt(val);
  if (!val_sp.refcount) {
    bpfj_dyn_lru_destroy_val(val);
    return -ENOMEM;
  }

  const __u32 kNoSlot = ~(__u32)0;
  long rc = 0;

  {
    BPFJ_LOCK_GUARD(dlm, &map->lock);
    if (!BPFJ_LOCK_IS_ACQUIRED(dlm)) {
      rc = -EBUSY;
      goto unlocked;
    }

    // Popped before the walk so the value and key move into arena memory before
    // the unrolled probe path.
    struct bpfj_dyn_lru_entry __arena* entry = bpfj_dyn_lru_pool_pop(map);
    if (!entry) {
      // Only an eviction sweep that found no victim gets here; the next insert
      // sweeps again.
      rc = -EBUSY;
      goto unlocked;
    }

    // Field-wise because a whole-struct copy through arena memory loses the
    // address space.
    bpfj_dyn_lru_key_copy(entry->key, key, key_words);
    entry->val.buf = val_sp.buf;
    entry->val.refcount = val_sp.refcount;
    val_sp.buf = NULL;
    val_sp.refcount = NULL;
    entry->home = bpfj_dyn_map_home(key, key_words, map->arr_size);
    entry->ref = BPFJ_DYN_LRU_REF_INSERT;

    __u32 free_slot = kNoSlot;
    long existing = bpfj_dyn_lru_probe(map, key, key_words, &free_slot);
    if (existing == -EBUSY) {
      bpfj_dyn_lru_retire(map, entry, &val_sp);
      rc = -EBUSY;
      goto unlocked;
    }

    if (existing >= 0) {
      struct bpfj_dyn_lru_slot __arena* slot =
          bpfj_dyn_lru_slot_at(map, (__u32)existing);
      struct bpfj_dyn_lru_entry __arena* cur = slot->entry;

      void __arena* displaced_buf = cur->val.buf;
      __u32 __arena* displaced_rc = cur->val.refcount;
      cur->val.buf = entry->val.buf;
      cur->val.refcount = entry->val.refcount;
      entry->val.buf = displaced_buf;
      entry->val.refcount = displaced_rc;

      cur->ref = BPFJ_DYN_LRU_REF_LOOKUP; // a re-insert is a use

      bpfj_lock_unlock(&slot->lock);
      bpfj_dyn_lru_retire(map, entry, &val_sp);
      goto unlocked;
    }

    if (free_slot == kNoSlot) {
      // The index clustered past the probe window.
      bpfj_dyn_lru_retire(map, entry, &val_sp);
      rc = -EOVERFLOW;
      goto unlocked;
    }

    // The probe handed the empty slot over locked.
    struct bpfj_dyn_lru_slot __arena* slot =
        bpfj_dyn_lru_slot_at(map, free_slot);
    slot->entry = entry;
    bpfj_lock_unlock(&slot->lock);
    map->size++;

    // Enforced only now the new entry is in: evicting first would drop a live
    // entry for a slot this walk may never find.
    if (map->size > map->capacity) {
      struct bpfj_dyn_lru_entry __arena* victim =
          bpfj_dyn_lru_evict(map, free_slot);
      if (victim) {
        bpfj_dyn_lru_retire(map, victim, &val_sp);
      }
    }
  }

unlocked:
  // Past the lock, so the inner-map teardown costs other callers nothing.
  BPFJ_SHARED_PTR_RELEASE(&val_sp, bpfj_dyn_lru_destroy_val);
  return rc;
}

// Remove `key`, returning 0 on a miss and -EBUSY on contention.
long bpfj_dyn_lru_erase(
    struct bpfj_dyn_lru __arena* map __arg_arena,
    __u64 __arena* key __arg_arena) {
  if (!bpfj_dyn_lru_usable(map)) {
    return 0;
  }

  __u32 key_words = bpfj_dyn_map_key_words(map->key_size);
  struct bpfj_shared_ptr dead = {0};

  {
    BPFJ_LOCK_GUARD(dlm, &map->lock);
    if (!BPFJ_LOCK_IS_ACQUIRED(dlm)) {
      return -EBUSY;
    }

    long idx = bpfj_dyn_lru_probe(map, key, key_words, NULL);
    if (idx == -ENOENT) {
      return 0;
    }
    if (idx < 0) {
      return idx;
    }

    struct bpfj_dyn_lru_slot __arena* slot =
        bpfj_dyn_lru_slot_at(map, (__u32)idx);
    struct bpfj_dyn_lru_entry __arena* entry = slot->entry;
    slot->entry = NULL;
    bpfj_lock_unlock(&slot->lock);

    bpfj_dyn_lru_close_hole(map, (__u32)idx);
    bpfj_dyn_lru_retire(map, entry, &dead);
    map->size--;
  }

  BPFJ_SHARED_PTR_RELEASE(&dead, bpfj_dyn_lru_destroy_val);
  return 0;
}

long bpfj_dyn_lru_lookup(
    struct bpfj_dyn_lru __arena* map __arg_arena,
    __u64 __arena* key __arg_arena,

    struct bpfj_shared_ptr* val __arg_nonnull) {
  if (!bpfj_dyn_lru_usable(map)) {
    return -ENOENT;
  }

  __u32 key_words = bpfj_dyn_map_key_words(map->key_size);
  long idx = bpfj_dyn_lru_probe(map, key, key_words, NULL);
  if (idx < 0) {
    return idx;
  }

  struct bpfj_dyn_lru_slot __arena* slot =
      bpfj_dyn_lru_slot_at(map, (__u32)idx);
  struct bpfj_dyn_lru_entry __arena* entry = slot->entry;

  // Under the lock the probe left held, so an erase or eviction cannot be
  // dropping the map's reference at the same time.
  __sync_fetch_and_add(entry->val.refcount, 1);
  val->buf = entry->val.buf;
  val->refcount = entry->val.refcount;

  // Read before write, so a repeatedly hit key leaves the line alone after the
  // first time, as bpf_lru_node_set_ref() does.
  if (entry->ref != BPFJ_DYN_LRU_REF_LOOKUP) {
    entry->ref = BPFJ_DYN_LRU_REF_LOOKUP;
  }

  bpfj_lock_unlock(&slot->lock);
  return 0;
}
