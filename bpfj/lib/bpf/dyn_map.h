// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include <errno.h>
#include "bpfj/lib/bpf/heap.h"
#include "bpfj/lib/bpf/lock.h"
#include "bpfj/lib/bpf/shared_ptr.h"
#include "bpfj/lib/bpf/types_dyn_map.h"

// Open-addressing map of fixed-width arena-owned keys and values; insert
// consumes them, lookup borrows the key and returns a reference, and every
// lock is a trylock so a collision reports -EBUSY. Inlining here is mostly
// verifier budget management.

#ifndef BPFJ_DYN_READ_ONCE
#define BPFJ_DYN_READ_ONCE(x) (*(const volatile __typeof__(x)*)&(x))
#endif
#ifndef BPFJ_DYN_WRITE_ONCE
#define BPFJ_DYN_WRITE_ONCE(x, v) (*(volatile __typeof__(x)*)&(x) = (v))
#endif

enum {
  BPFJ_DYN_PLAN_NEW = 0, // insert at an empty slot
  BPFJ_DYN_PLAN_TOMB = 1, // insert reusing a tombstone
  BPFJ_DYN_PLAN_UPDATE = 2, // key exists; overwrite value only
};

// A probe packs the slot kind with the slot index because BPF's argument
// registers leave no room for an out-parameter.
#define BPFJ_DYN_PLAN(_kind, _idx) (((long)(_kind) << 32) | (long)(_idx))
#define BPFJ_DYN_PLAN_KIND(_plan) ((__u32)((__u64)(_plan) >> 32))
#define BPFJ_DYN_PLAN_IDX(_plan) ((__u32)((__u64)(_plan) & 0xffffffffULL))

static __always_inline __arena struct bpfj_dyn_map_slot* bpfj_dyn_map_slot_at(
    __arena struct bpfj_dyn_map_slot* slots,
    __u32 idx) {
  return slots + idx;
}

// For a header whose location reached BPF as a scalar heap offset.
static __always_inline __arena struct bpfj_dyn_map* bpfj_dyn_map_at(__u32 off) {
  return (__arena struct bpfj_dyn_map*)(bpfj_heap_ptr() + off);
}

// Keys are a whole number of __u64s (bpfj_dyn_map_init rejects anything else).
static __always_inline __u32 bpfj_dyn_map_key_words(__u32 key_size) {
  return key_size / (__u32)sizeof(__u64);
}

// Fold a key to the value its slot index derives from. __noinline saves caller
// stack, and static keeps the key's arena provenance intact.
static __noinline __u64
bpfj_dyn_map_key_hash(const __u64 __arena* key, __u32 key_words) {
  __u64 h = 0;
  __u32 i = 0;
  bpf_for(i, 0, key_words) {
    h = (h ^ key[i]) * BPFJ_DYN_MAP_HASH_MULT;
    h ^= h >> 32;
  }
  return h;
}

// Word-wise with a flag rather than an early return, because a whole-buffer
// compare out of arena memory reads back as a scalar on 6.11.
static __always_inline bool bpfj_dyn_map_key_eq(
    const __u64 __arena* a,
    const __u64 __arena* b,
    __u32 key_words) {
  bool eq = true;
  __u32 i = 0;
  bpf_for(i, 0, key_words) {
    if (a[i] != b[i]) {
      eq = false;
      break;
    }
  }
  return eq;
}

// The slot a key hashes to, before any linear probing.
static __always_inline __u32
bpfj_dyn_map_home(const __u64 __arena* key, __u32 key_words, __u32 capacity) {
  return bpfj_dyn_map_index(bpfj_dyn_map_key_hash(key, key_words), capacity);
}

// Release an entry not yet stored in the table.
static __always_inline void bpfj_dyn_map_free_entry(
    __u64 __arena* key,
    void __arena* val) {
  if (key) {
    BPFJ_HEAP_FREE(key);
  }
  if (val) {
    BPFJ_HEAP_FREE(val);
  }
}

// Free a slot's key and drop the map's reference to its value.
static __always_inline void bpfj_dyn_map_release_slot(
    struct bpfj_dyn_map_slot __arena* slot) {
  __u64 __arena* key = slot->key;
  slot->key = NULL;
  if (key) {
    BPFJ_HEAP_FREE(key);
  }
  bpfj_shared_ptr_release_arena(&slot->val_ptr);
}

// Release every occupied entry in a buffer; this runs only when the map is no
// longer shared.
static __always_inline void bpfj_dyn_map_release_entries(
    struct bpfj_dyn_map_slot __arena* slots,
    __u32 cap) {
  __u32 i = 0;
  bpf_for(i, 0, BPFJ_DYN_MAP_MAX_CAPACITY) {
    if (i >= cap) {
      break;
    }

    struct bpfj_dyn_map_slot __arena* slot = bpfj_dyn_map_slot_at(slots, i);
    if (slot->state != BPFJ_DYN_SLOT_OCCUPIED) {
      continue;
    }

    bpfj_dyn_map_release_slot(slot);
    slot->state = BPFJ_DYN_SLOT_EMPTY;
  }
}

struct bpfj_dyn_map_slots_guard {
  struct bpfj_shared_ptr sp;
};

// static, so this does not collide at link time across including objects.
static __always_inline void bpfj_dyn_map_slots_guard_cleanup(
    struct bpfj_dyn_map_slots_guard* guard) {
  // The buffer only: a grow moves the entries to the buffer replacing it.
  bpfj_shared_ptr_release(&guard->sp);
}

// Hold a reference to a slot buffer for the enclosing scope.
#define BPFJ_DYN_MAP_SLOTS_GUARD(_name)                                   \
  __attribute__((cleanup(                                                 \
      bpfj_dyn_map_slots_guard_cleanup))) struct bpfj_dyn_map_slots_guard \
      _name = {0}

#define BPFJ_DYN_MAP_SLOTS_ADOPT(_name, _map_sp) \
  ((_name).sp = bpfj_shared_ptr_acquire_arena(_map_sp))

#define BPFJ_DYN_MAP_SLOTS(_name) \
  ((struct bpfj_dyn_map_slot __arena*)(_name).sp.buf)

// What one step of a walk found; the two actionable ones leave the slot locked.
enum {
  BPFJ_DYN_TRY_MATCH = 0, // holds this key -- LOCKED
  BPFJ_DYN_TRY_FREE = 1, // holds nothing, ends the chain -- LOCKED
  BPFJ_DYN_TRY_MISS = 2, // holds another key
  BPFJ_DYN_TRY_DEAD = 3, // a tombstone
};

// Lock one slot and say what is in it; global so the verifier checks it once.
__noinline long bpfj_dyn_map_try_slot(
    struct bpfj_dyn_map_slot __arena* slot __arg_arena,
    const __u64 __arena* key __arg_arena,
    __u32 key_words,
    __u64 hash) {
  BPFJ_LOCK_GUARD(dm, &slot->lock);
  if (!BPFJ_LOCK_IS_ACQUIRED(dm)) {
    return -EBUSY;
  }

  __u32 state = slot->state;
  if (state == BPFJ_DYN_SLOT_EMPTY) {
    BPFJ_LOCK_GUARD_RELEASE(dm);
    return BPFJ_DYN_TRY_FREE;
  }
  if (state != BPFJ_DYN_SLOT_OCCUPIED) {
    return BPFJ_DYN_TRY_DEAD;
  }

  // The hash first, to settle most slots without walking two keys word by word.
  if (slot->hash == hash && bpfj_dyn_map_key_eq(slot->key, key, key_words)) {
    BPFJ_LOCK_GUARD_RELEASE(dm);
    return BPFJ_DYN_TRY_MATCH;
  }
  return BPFJ_DYN_TRY_MISS;
}

// The slot holding `key`, or a negative error; success returns it locked.
static __noinline long bpfj_dyn_map_probe_lookup(
    struct bpfj_dyn_map_slot __arena* slots,
    __u32 cap,
    const __u64 __arena* key,
    __u32 key_words) {
  if (cap == 0 || !slots) {
    // At capacity zero the walk runs off the buffer, which in the arena reads
    // the base rather than faulting.
    return -ENOENT;
  }

  __u64 hash = bpfj_dyn_map_key_hash(key, key_words);
  __u32 off = bpfj_dyn_map_index(hash, cap);

  // Unrolled because the call in this body leaves the verifier a fresh state
  // every step.
#pragma unroll
  for (__u32 p = 0; p < BPFJ_DYN_MAP_MAX_PROBES; ++p) {
    struct bpfj_dyn_map_slot __arena* slot = bpfj_dyn_map_slot_at(slots, off);

    long found = bpfj_dyn_map_try_slot(slot, key, key_words, hash);
    if (found < 0) {
      return found;
    }
    if (found == BPFJ_DYN_TRY_MATCH) {
      return off; // handed to the caller locked
    }
    if (found == BPFJ_DYN_TRY_FREE) {
      // An empty slot ends the chain, and a miss has no use for it.
      bpfj_lock_unlock(&slot->lock);
      return -ENOENT;
    }
    off = (off + 1) & (cap - 1);
  }
  return -EOVERFLOW;
}

// Take `idx` if it is still a tombstone and stamp the arriving hash there;
// success returns the slot locked.
__noinline long bpfj_dyn_map_claim_tomb(
    struct bpfj_dyn_map_slot __arena* slots __arg_arena,
    __u32 idx,
    __u64 hash) {
  struct bpfj_dyn_map_slot __arena* slot = bpfj_dyn_map_slot_at(slots, idx);

  BPFJ_LOCK_GUARD(dm, &slot->lock);
  if (!BPFJ_LOCK_IS_ACQUIRED(dm)) {
    return -EBUSY;
  }
  if (slot->state != BPFJ_DYN_SLOT_TOMB) {
    return -EAGAIN; // filled since the walk passed it
  }

  slot->hash = hash;
  BPFJ_LOCK_GUARD_RELEASE(dm);
  return BPFJ_DYN_PLAN(BPFJ_DYN_PLAN_TOMB, idx);
}

// Choose an insert slot for `key`: an update target, an empty slot or the
// earliest tombstone; success returns a packed locked-slot plan.
static __always_inline long bpfj_dyn_map_probe_plan(
    struct bpfj_dyn_map_slot __arena* slots,
    __u32 cap,
    const __u64 __arena* key,
    __u32 key_words,
    __u64 hash) {
  __u32 off = bpfj_dyn_map_index(hash, cap);

  // The first tombstone the walk passes and the empty slot ending the chain,
  // packed into one word because every extra live value spills on this frame.
  const __u32 kNone = ~(__u32)0;
  __u64 marks = ((__u64)kNone << 32) | kNone;
#define BPFJ_DYN_MARK_TOMB(_m) ((__u32)((_m) >> 32))
#define BPFJ_DYN_MARK_FREE(_m) ((__u32)(_m))

  // Unrolled for the reason in bpfj_dyn_map_probe_lookup.
#pragma unroll
  for (__u32 p = 0; p < BPFJ_DYN_MAP_MAX_PROBES; ++p) {
    long found = bpfj_dyn_map_try_slot(
        bpfj_dyn_map_slot_at(slots, off), key, key_words, hash);
    if (found < 0) {
      return found;
    }
    if (found == BPFJ_DYN_TRY_MATCH) {
      return BPFJ_DYN_PLAN(BPFJ_DYN_PLAN_UPDATE, off);
    }
    if (found == BPFJ_DYN_TRY_FREE) {
      marks = (marks & 0xffffffff00000000ULL) | off; // locked; chain ends here
      break;
    }
    if (found == BPFJ_DYN_TRY_DEAD && BPFJ_DYN_MARK_TOMB(marks) == kNone) {
      marks = (marks & 0x00000000ffffffffULL) | ((__u64)off << 32);
    }
    off = (off + 1) & (cap - 1);
  }

  // A tombstone earlier in the chain is the better home, but is claimed only
  // after the walk because the verifier explores the body once per step.
  if (BPFJ_DYN_MARK_TOMB(marks) != kNone) {
    long plan = bpfj_dyn_map_claim_tomb(slots, BPFJ_DYN_MARK_TOMB(marks), hash);
    if (plan >= 0 || plan == -EBUSY) {
      if (BPFJ_DYN_MARK_FREE(marks) != kNone) {
        bpfj_lock_unlock(
            &bpfj_dyn_map_slot_at(slots, BPFJ_DYN_MARK_FREE(marks))->lock);
      }
      return plan;
    }

    // -EAGAIN: filled since the walk passed it, possibly with this same key, so
    // falling through would put the key in the table twice.
    long refill = bpfj_dyn_map_try_slot(
        bpfj_dyn_map_slot_at(slots, BPFJ_DYN_MARK_TOMB(marks)),
        key,
        key_words,
        hash);
    if (refill == BPFJ_DYN_TRY_MATCH) {
      // Locked, and it is ours to update.
      if (BPFJ_DYN_MARK_FREE(marks) != kNone) {
        bpfj_lock_unlock(
            &bpfj_dyn_map_slot_at(slots, BPFJ_DYN_MARK_FREE(marks))->lock);
      }
      return BPFJ_DYN_PLAN(BPFJ_DYN_PLAN_UPDATE, BPFJ_DYN_MARK_TOMB(marks));
    }
    if (refill < 0) {
      if (BPFJ_DYN_MARK_FREE(marks) != kNone) {
        bpfj_lock_unlock(
            &bpfj_dyn_map_slot_at(slots, BPFJ_DYN_MARK_FREE(marks))->lock);
      }
      return refill;
    }
    // Somebody else's key. The empty slot it is.
  }

  if (BPFJ_DYN_MARK_FREE(marks) != kNone) {
    // Stamped here because the hash is in hand; handing it back would keep it
    // live across the walk.
    struct bpfj_dyn_map_slot __arena* slot =
        bpfj_dyn_map_slot_at(slots, BPFJ_DYN_MARK_FREE(marks));
    slot->hash = hash;
    return BPFJ_DYN_PLAN(BPFJ_DYN_PLAN_NEW, BPFJ_DYN_MARK_FREE(marks));
  }

  return -EOVERFLOW;
#undef BPFJ_DYN_MARK_TOMB
#undef BPFJ_DYN_MARK_FREE
}

// What bpfj_dyn_map_move_slot did with the slot it was pointed at.
enum {
  BPFJ_DYN_MOVE_DONE = 0, // the entry is in the new buffer
  BPFJ_DYN_MOVE_EMPTY = 1, // the slot held nothing
  BPFJ_DYN_MOVE_TOMB = 2, // a tombstone, dropped rather than moved
};

// Move one entry into the buffer a grow is filling, taking the first empty slot
// on its chain. A global subprogram, so the verifier checks it once rather than
// per step of bpfj_dyn_map_grow's walk.
__noinline long bpfj_dyn_map_move_slot(
    struct bpfj_dyn_map_slot __arena* src __arg_arena,
    struct bpfj_dyn_map_slot __arena* dst_slots __arg_arena,
    __u32 dst_cap) {
  BPFJ_LOCK_GUARD(src_lock, &src->lock);
  if (!BPFJ_LOCK_IS_ACQUIRED(src_lock)) {
    return -EBUSY;
  }

  __u32 state = src->state;
  if (state != BPFJ_DYN_SLOT_OCCUPIED) {
    return state == BPFJ_DYN_SLOT_TOMB ? BPFJ_DYN_MOVE_TOMB
                                       : BPFJ_DYN_MOVE_EMPTY;
  }

  __u64 hash = src->hash;
  __u32 off = bpfj_dyn_map_index(hash, dst_cap);

  // Unrolled for the reason in bpfj_dyn_map_probe_lookup.
#pragma unroll
  for (__u32 p = 0; p < BPFJ_DYN_MAP_MAX_PROBES; ++p) {
    struct bpfj_dyn_map_slot __arena* dst =
        bpfj_dyn_map_slot_at(dst_slots, off);

    BPFJ_LOCK_GUARD(dst_lock, &dst->lock);
    if (!BPFJ_LOCK_IS_ACQUIRED(dst_lock)) {
      return -EBUSY;
    }

    if (dst->state != BPFJ_DYN_SLOT_EMPTY) {
      // Skipped without comparing keys, so a concurrent insert of the same key
      // can be double-counted in map->size and leave the older copy reachable
      // after a delete; a compare here costs stack the budget has not got.
      off = (off + 1) & (dst_cap - 1);
      continue;
    }

    // The blocks do not move, only the slot's hold on them: copied with no
    // count taken, so whichever buffer survives owns them and a half-migrated
    // grow leaks nothing when retracted.
    dst->key = src->key;
    dst->val_ptr.buf = src->val_ptr.buf;
    dst->val_ptr.refcount = src->val_ptr.refcount;
    dst->hash = hash;
    dst->state = BPFJ_DYN_SLOT_OCCUPIED;

    // Left occupied rather than tombstoned, so an entry is never in neither
    // buffer; the old buffer is discarded whole anyway.
    return BPFJ_DYN_MOVE_DONE;
  }

  return -EOVERFLOW;
}

// Insert

// Place an entry in `slots`, which the caller holds a reference to. Returns a
// BPFJ_DYN_PLAN_* kind, or a negative error with nothing touched; `key` is
// stored only for a NEW or TOMB plan. `*val_sp` goes in and whatever it
// displaces comes back, so the caller releases exactly one value however this
// turns out. Nothing here allocates: the frame has room for the probe or the
// allocator, not both.
__noinline long bpfj_dyn_map_do_insert(
    struct bpfj_dyn_map_slot __arena* slots __arg_arena,
    __u32 cap,
    __u64 __arena* key __arg_arena,
    __u32 key_words,
    struct bpfj_shared_ptr* val_sp __arg_nonnull) {
  __u64 hash = bpfj_dyn_map_key_hash(key, key_words);

  long plan = bpfj_dyn_map_probe_plan(slots, cap, key, key_words, hash);
  if (plan < 0) {
    return plan;
  }

  __u32 kind = BPFJ_DYN_PLAN_KIND(plan);
  struct bpfj_dyn_map_slot __arena* slot =
      bpfj_dyn_map_slot_at(slots, BPFJ_DYN_PLAN_IDX(plan));

  // The probe handed the slot over locked; hold it until the entry is whole.
  BPFJ_LOCK_GUARD_TAKE_OVER(slot_lock, &slot->lock);

  struct bpfj_shared_ptr displaced = bpfj_shared_ptr_take_arena(&slot->val_ptr);
  slot->val_ptr.buf = val_sp->buf;
  slot->val_ptr.refcount = val_sp->refcount;
  *val_sp = displaced; // the value an update replaced, or nothing

  if (kind != BPFJ_DYN_PLAN_UPDATE) {
    // The probe stamped the hash already; an update keeps the key it holds.
    slot->key = key;
    slot->state = BPFJ_DYN_SLOT_OCCUPIED;
  }
  return kind;
}

// Grow

// Give up a grow that could not finish: unpublish the half-filled buffer so
// inserts go back to the live one. Its entries are NOT released here, though
// they should be -- neither shape of the reclaiming walk fits in the stack
// budget -- so userspace (DynLru::releaseSlots) does it.
static __always_inline void bpfj_dyn_map_retract_grow(
    __arena struct bpfj_dyn_map* map) {
  struct bpfj_shared_ptr sp = {0};
  {
    BPFJ_LOCK_GUARD(map_lock, &map->lock);
    if (!BPFJ_LOCK_IS_ACQUIRED(map_lock)) {
      // Leaving growing_slots_ptr published would wedge the map, and BPF cannot
      // spin, so mark it abandoned and let the next grow finish.
      BPFJ_DYN_WRITE_ONCE(map->grow_abandoned, 1);
      return;
    }
    sp = bpfj_shared_ptr_take_arena(&map->growing_slots_ptr);
    map->growing_capacity = 0;
    BPFJ_DYN_WRITE_ONCE(map->grow_abandoned, 0);
  }
  bpfj_shared_ptr_release(&sp);
}

// Move every entry into a bigger buffer and publish it. `growing_slots_ptr` is
// published before the walk starts, so inserts land in the new buffer, and
// lookups consult both for the duration.
static __noinline long bpfj_dyn_map_grow(__arena struct bpfj_dyn_map* map) {
  __u32 new_cap = bpfj_dyn_map_target_cap(map->size, map->capacity);
  if (new_cap > BPFJ_DYN_MAP_MAX_CAPACITY) {
    return -ENOMEM;
  }

  // Before the lock, since the heap has a lock of its own.
  struct bpfj_dyn_map_slot __arena* new_slots =
      BPFJ_HEAP_CALLOC(new_cap * sizeof(struct bpfj_dyn_map_slot));
  if (!new_slots) {
    return -ENOMEM;
  }

  // We keep a ref while growing in case the map is wiped
  __attribute__((
      cleanup(bpfj_shared_ptr_release))) struct bpfj_shared_ptr growing_ptr =
      bpfj_shared_ptr_adopt(new_slots);
  if (!bpfj_shared_ptr_valid(growing_ptr)) {
    BPFJ_HEAP_FREE(new_slots);
    return -ENOMEM;
  }

  // Neither buffer is held through a reference of its own, unlike every other
  // operation: publishing growing_slots_ptr makes this the only grow that can
  // run, so nobody can retire either buffer meanwhile. A buffer left published
  // by a retract that lost the lock must come down first.
  if (BPFJ_DYN_READ_ONCE(map->grow_abandoned)) {
    bpfj_dyn_map_retract_grow(map);
  }

  struct bpfj_dyn_map_slot __arena* old_slots = NULL;
  __u32 old_cap = 0;
  {
    BPFJ_LOCK_GUARD(map_lock, &map->lock);
    if (!BPFJ_LOCK_IS_ACQUIRED(map_lock)) {
      // No explicit free here or below: growing_ptr's cleanup frees the buffer.
      return -EBUSY;
    }

    if (map->growing_slots_ptr.refcount) {
      // Still set after the retract above means a grow is genuinely running and
      // inserts already go to its buffer, which is all this caller wanted.
      return 0;
    }

    map->growing_slots_ptr = bpfj_shared_ptr_acquire(growing_ptr);
    map->growing_capacity = new_cap;

    old_slots = map->slots_ptr.buf;
    old_cap = map->capacity;
  }

  // Nothing but the call and its two outcomes belongs in this body: the
  // verifier explores it once per step over BPFJ_DYN_MAP_MAX_CAPACITY steps.
  long failed = 0;
  __u32 i = 0;
  bpf_for(i, 0, old_cap) {
    // The verifier follows `i` into the pointer made from it, making every step
    // its own state ("BPF program is too large"); an arena access needs no
    // verifier bound, so forgetting the index lets the walk converge.
    __u32 idx = i;
    barrier_var(idx);

    long moved = bpfj_dyn_map_move_slot(
        bpfj_dyn_map_slot_at(old_slots, idx), new_slots, new_cap);
    if (moved < 0) {
      failed = moved;
      break;
    }
    if (moved == BPFJ_DYN_MOVE_TOMB) {
      __sync_fetch_and_sub(&map->tombstones, 1);
    }
  }

  if (failed != 0) {
    // Committing now would publish a table missing an entry.
    bpfj_dyn_map_retract_grow(map);
    return failed;
  }

  // Commit. The counters are not recomputed from the walk, since concurrent
  // inserts and deletes have been maintaining them all along.
  struct bpfj_shared_ptr retired = {0};
  {
    BPFJ_LOCK_GUARD(map_lock, &map->lock);
    if (!BPFJ_LOCK_IS_ACQUIRED(map_lock)) {
      bpfj_dyn_map_retract_grow(map);
      return -EBUSY;
    }

    if (!map->growing_slots_ptr.refcount) {
      // We were wiped during the grow and need to abort
      map->growing_capacity = 0;
      return -EBUSY;
    }

    retired = bpfj_shared_ptr_take_arena(&map->slots_ptr);
    map->slots_ptr.buf = map->growing_slots_ptr.buf;
    map->slots_ptr.refcount = map->growing_slots_ptr.refcount;
    map->growing_slots_ptr.buf = NULL;
    map->growing_slots_ptr.refcount = NULL;
    map->capacity = new_cap;
    map->growing_capacity = 0;
  }

  // The map's reference; the buffer goes once the last walker releases its own.
  bpfj_shared_ptr_release(&retired);
  return 0;
}

// Public operations.

// Borrows `key` and hands back a reference: `*val_ptr` owns a count on the
// block, which the caller releases when done.
__noinline long bpfj_dyn_map_lookup(
    __arena struct bpfj_dyn_map* map __arg_arena,
    __u64 __arena* key __arg_arena,
    struct bpfj_shared_ptr* val_ptr __arg_nonnull) {
  BPFJ_DYN_MAP_SLOTS_GUARD(published);
  BPFJ_DYN_MAP_SLOTS_GUARD(growing);
  __u32 cap = 0;
  __u32 growing_cap = 0;
  {
    BPFJ_LOCK_GUARD(map_lock, &map->lock);
    if (!BPFJ_LOCK_IS_ACQUIRED(map_lock)) {
      return -EBUSY;
    }

    BPFJ_DYN_MAP_SLOTS_ADOPT(published, &map->slots_ptr);
    cap = map->capacity;
    BPFJ_DYN_MAP_SLOTS_ADOPT(growing, &map->growing_slots_ptr);
    growing_cap = map->growing_capacity;
  }

  __u32 key_words = bpfj_dyn_map_key_words(map->key_size);

  // Newest buffer first: during a grow an entry can be in both, and an update
  // lands only in the new one.
  long idx = -ENOENT;
  struct bpfj_dyn_map_slot __arena* slots = NULL;
  if (BPFJ_DYN_MAP_SLOTS(growing)) {
    slots = BPFJ_DYN_MAP_SLOTS(growing);
    idx = bpfj_dyn_map_probe_lookup(slots, growing_cap, key, key_words);
  }
  if (idx == -ENOENT) {
    slots = BPFJ_DYN_MAP_SLOTS(published);
    idx = bpfj_dyn_map_probe_lookup(slots, cap, key, key_words);
  }
  if (idx < 0) {
    return idx;
  }

  struct bpfj_dyn_map_slot __arena* slot =
      bpfj_dyn_map_slot_at(slots, (__u32)idx);

  // Under the lock the probe left held, so a delete cannot be dropping the
  // map's reference at the same time.
  *val_ptr = bpfj_shared_ptr_acquire_arena(&slot->val_ptr);
  bpfj_lock_unlock(&slot->lock);
  return 0;
}

// Look `key` up and copy the first word of its value out, for callers whose
// value is a single word; the slot's own lock makes the copy safe without the
// reference bpfj_dyn_map_lookup would cost.
__noinline long bpfj_dyn_map_lookup_word(
    __arena struct bpfj_dyn_map* map __arg_arena,
    __u64 __arena* key __arg_arena,
    __u64* out __arg_nonnull) {
  BPFJ_DYN_MAP_SLOTS_GUARD(published);
  BPFJ_DYN_MAP_SLOTS_GUARD(growing);
  __u32 cap = 0;
  __u32 growing_cap = 0;
  {
    BPFJ_LOCK_GUARD(map_lock, &map->lock);
    if (!BPFJ_LOCK_IS_ACQUIRED(map_lock)) {
      return -EBUSY;
    }

    BPFJ_DYN_MAP_SLOTS_ADOPT(published, &map->slots_ptr);
    cap = map->capacity;
    BPFJ_DYN_MAP_SLOTS_ADOPT(growing, &map->growing_slots_ptr);
    growing_cap = map->growing_capacity;
  }

  __u32 key_words = bpfj_dyn_map_key_words(map->key_size);

  // Newest buffer first, for the reason on bpfj_dyn_map_lookup.
  long idx = -ENOENT;
  struct bpfj_dyn_map_slot __arena* slots = NULL;
  if (BPFJ_DYN_MAP_SLOTS(growing)) {
    slots = BPFJ_DYN_MAP_SLOTS(growing);
    idx = bpfj_dyn_map_probe_lookup(slots, growing_cap, key, key_words);
  }
  if (idx == -ENOENT) {
    slots = BPFJ_DYN_MAP_SLOTS(published);
    idx = bpfj_dyn_map_probe_lookup(slots, cap, key, key_words);
  }
  if (idx < 0) {
    return idx;
  }

  struct bpfj_dyn_map_slot __arena* slot =
      bpfj_dyn_map_slot_at(slots, (__u32)idx);

  // Under the lock the probe left held, so a delete cannot free the block.
  *out = *(__u64 __arena*)slot->val_ptr.buf;
  bpfj_lock_unlock(&slot->lock);
  return 0;
}

// Store `word` as the value of a live `key`, under the slot's lock as
// bpfj_dyn_map_lookup_word reads it.
__noinline long bpfj_dyn_map_update_word(
    __arena struct bpfj_dyn_map* map __arg_arena,
    __u64 __arena* key __arg_arena,
    __u64 word) {
  BPFJ_DYN_MAP_SLOTS_GUARD(published);
  BPFJ_DYN_MAP_SLOTS_GUARD(growing);
  __u32 cap = 0;
  __u32 growing_cap = 0;
  {
    BPFJ_LOCK_GUARD(map_lock, &map->lock);
    if (!BPFJ_LOCK_IS_ACQUIRED(map_lock)) {
      return -EBUSY;
    }

    BPFJ_DYN_MAP_SLOTS_ADOPT(published, &map->slots_ptr);
    cap = map->capacity;
    BPFJ_DYN_MAP_SLOTS_ADOPT(growing, &map->growing_slots_ptr);
    growing_cap = map->growing_capacity;
  }

  __u32 key_words = bpfj_dyn_map_key_words(map->key_size);

  // Newest buffer first, for the reason on bpfj_dyn_map_lookup.
  long idx = -ENOENT;
  struct bpfj_dyn_map_slot __arena* slots = NULL;
  if (BPFJ_DYN_MAP_SLOTS(growing)) {
    slots = BPFJ_DYN_MAP_SLOTS(growing);
    idx = bpfj_dyn_map_probe_lookup(slots, growing_cap, key, key_words);
  }
  if (idx == -ENOENT) {
    slots = BPFJ_DYN_MAP_SLOTS(published);
    idx = bpfj_dyn_map_probe_lookup(slots, cap, key, key_words);
  }
  if (idx < 0) {
    return idx;
  }

  struct bpfj_dyn_map_slot __arena* slot =
      bpfj_dyn_map_slot_at(slots, (__u32)idx);

  *(__u64 __arena*)slot->val_ptr.buf = word;
  bpfj_lock_unlock(&slot->lock);
  return 0;
}

// The body of bpfj_dyn_map_insert and bpfj_dyn_map_insert_shared. `out` is
// NULL for the plain insert, a constant at both call sites, so that one
// compiles to what it was before `out` existed.
static __always_inline long bpfj_dyn_map_insert_impl(
    __arena struct bpfj_dyn_map* map,
    __u64 __arena* key,
    void __arena* val,
    struct bpfj_shared_ptr* out) {
  if (map->capacity == 0) {
    bpfj_dyn_map_free_entry(key, val);
    return -EINVAL;
  }

  if (bpfj_dyn_map_should_grow(
          BPFJ_DYN_READ_ONCE(map->size),
          BPFJ_DYN_READ_ONCE(map->tombstones),
          BPFJ_DYN_READ_ONCE(map->capacity))) {
    // Best effort: the rehash is maintenance, and a buffer really out of room
    // says so through do_insert.
    bpfj_dyn_map_grow(map);
  }

  // Before the map's lock, since the allocator has a lock of its own.
  struct bpfj_shared_ptr val_sp = bpfj_shared_ptr_adopt(val);
  if (!val_sp.refcount) {
    bpfj_dyn_map_free_entry(key, val);
    return -ENOMEM;
  }

  // Taken before the value is published, so the caller's reference is to the
  // value this call stored even if another CPU replaces it right after.
  if (out) {
    *out = bpfj_shared_ptr_acquire(val_sp);
  }

  BPFJ_DYN_MAP_SLOTS_GUARD(slots);
  long kind = 0;
  {
    // Held across the write, not just the choice of buffer: otherwise a grow
    // publishing in that window can pass the still-empty slot and commit,
    // discarding the entry's blocks as raw memory while insert returns 0.
    BPFJ_LOCK_GUARD(map_lock, &map->lock);
    if (!BPFJ_LOCK_IS_ACQUIRED(map_lock)) {
      BPFJ_HEAP_FREE(key);
      bpfj_shared_ptr_release(&val_sp);
      if (out) {
        bpfj_shared_ptr_release(out);
      }
      return -EBUSY;
    }

    // Into the buffer a grow is filling, when there is one, since it is about
    // to be published.
    __u32 cap = 0;
    if (map->growing_slots_ptr.refcount) {
      // Unless this key is still in the retiring buffer waiting for the walk,
      // in which case writing here would put it in the table twice. Refused
      // rather than merged: updating the retiring copy needs a second write
      // path this frame has no stack for.
      struct bpfj_dyn_map_slot __arena* retiring =
          (struct bpfj_dyn_map_slot __arena*)map->slots_ptr.buf;
      long live = bpfj_dyn_map_probe_lookup(
          retiring, map->capacity, key, bpfj_dyn_map_key_words(map->key_size));
      if (live >= 0) {
        // probe_lookup hands a match back locked.
        bpfj_lock_unlock(&bpfj_dyn_map_slot_at(retiring, (__u32)live)->lock);
      }
      if (live != -ENOENT) {
        BPFJ_HEAP_FREE(key);
        bpfj_shared_ptr_release(&val_sp);
        if (out) {
          bpfj_shared_ptr_release(out);
        }
        return live >= 0 ? -EBUSY : live;
      }

      BPFJ_DYN_MAP_SLOTS_ADOPT(slots, &map->growing_slots_ptr);
      cap = map->growing_capacity;
    } else {
      BPFJ_DYN_MAP_SLOTS_ADOPT(slots, &map->slots_ptr);
      cap = map->capacity;
    }

    kind = bpfj_dyn_map_do_insert(
        BPFJ_DYN_MAP_SLOTS(slots),
        cap,
        key,
        bpfj_dyn_map_key_words(map->key_size),
        &val_sp);
  }
  if (kind < 0) {
    // Nothing was stored, so both blocks are still ours.
    BPFJ_HEAP_FREE(key);
    bpfj_shared_ptr_release(&val_sp);
    if (out) {
      bpfj_shared_ptr_release(out);
    }
    return kind;
  }

  if (kind == BPFJ_DYN_PLAN_UPDATE) {
    // The slot kept its own key, so the equal one handed over is a duplicate.
    BPFJ_HEAP_FREE(key);
  } else {
    // Atomics rather than map->lock: an insert that has placed its entry has
    // nowhere to put a lock failure.
    __sync_fetch_and_add(&map->size, 1);
    if (kind == BPFJ_DYN_PLAN_TOMB) {
      __sync_fetch_and_sub(&map->tombstones, 1);
    }
  }

  // What the slot gave up: the value an update replaced, or nothing at all.
  bpfj_shared_ptr_release(&val_sp);
  return 0;
}

// Takes ownership of the `key` and `val` blocks, which must be arena
// allocations of the map's key_size and val_size; re-inserting a live key
// replaces its value, and every failure releases both.
__noinline long bpfj_dyn_map_insert(
    __arena struct bpfj_dyn_map* map __arg_arena,
    __u64 __arena* key __arg_arena,
    void __arena* val __arg_arena) {
  return bpfj_dyn_map_insert_impl(map, key, val, NULL);
}

// bpfj_dyn_map_insert, also handing back in `*out` a reference to the value
// stored. That is what a lookup afterwards would give. It saves the second
// probe and its chance of -EBUSY. `*out` is left invalid on failure.
__noinline long bpfj_dyn_map_insert_shared(
    __arena struct bpfj_dyn_map* map __arg_arena,
    __u64 __arena* key __arg_arena,
    void __arena* val __arg_arena,
    struct bpfj_shared_ptr* out __arg_nonnull) {
  out->buf = NULL;
  out->refcount = NULL;
  return bpfj_dyn_map_insert_impl(map, key, val, out);
}

// Empty the slot holding `key` in one buffer, handing the entry back rather
// than releasing it, since mid-grow it may be reachable through the other.
static __noinline long bpfj_dyn_map_do_delete(
    struct bpfj_dyn_map_slot __arena* slots,
    __u32 cap,
    const __u64 __arena* key,
    __u32 key_words,
    struct bpfj_dyn_map_entry* out __arg_nonnull) {
  long idx = bpfj_dyn_map_probe_lookup(slots, cap, key, key_words);
  if (idx < 0) {
    return idx;
  }

  struct bpfj_dyn_map_slot __arena* slot =
      bpfj_dyn_map_slot_at(slots, (__u32)idx);

  // Emptied under the lock the probe left held; the blocks are released after
  // unlocking, since the heap takes a lock of its own.
  out->key = slot->key;
  out->val = bpfj_shared_ptr_take_arena(&slot->val_ptr);
  slot->key = NULL;
  slot->state = BPFJ_DYN_SLOT_TOMB;
  bpfj_lock_unlock(&slot->lock);
  return 0;
}

// bpfj_dyn_map_do_delete, but only if the map holds the value's last
// reference. It returns 1, with the entry left in place, when anyone else
// still holds one. Decided under the slot's lock, which every lookup takes to
// acquire. No lookup through this buffer can take a reference between the
// check and the delete. A holder that already had one keeps its copy valid
// either way.
static __noinline long bpfj_dyn_map_do_delete_unique(
    struct bpfj_dyn_map_slot __arena* slots,
    __u32 cap,
    const __u64 __arena* key,
    __u32 key_words,
    struct bpfj_dyn_map_entry* out __arg_nonnull) {
  long idx = bpfj_dyn_map_probe_lookup(slots, cap, key, key_words);
  if (idx < 0) {
    return idx;
  }

  struct bpfj_dyn_map_slot __arena* slot =
      bpfj_dyn_map_slot_at(slots, (__u32)idx);

  // A plain read suffices: anyone taking a reference without this lock
  // already holds one, so the count was never 1 to begin with.
  __u32 __arena* refcount = slot->val_ptr.refcount;
  if (refcount && BPFJ_DYN_READ_ONCE(*refcount) != 1) {
    bpfj_lock_unlock(&slot->lock);
    return 1;
  }

  out->key = slot->key;
  out->val = bpfj_shared_ptr_take_arena(&slot->val_ptr);
  slot->key = NULL;
  slot->state = BPFJ_DYN_SLOT_TOMB;
  bpfj_lock_unlock(&slot->lock);
  return 0;
}

// Whether `key` is present in `slots`. Success returns 1 and unlocks the slot
// the lookup matched, since the caller is only checking reachability.
static __always_inline long bpfj_dyn_map_lookup_exists(
    struct bpfj_dyn_map_slot __arena* slots,
    __u32 cap,
    const __u64 __arena* key,
    __u32 key_words) {
  long idx = bpfj_dyn_map_probe_lookup(slots, cap, key, key_words);
  if (idx < 0) {
    return idx;
  }

  bpfj_lock_unlock(&bpfj_dyn_map_slot_at(slots, (__u32)idx)->lock);
  return 1;
}

// The body of bpfj_dyn_map_delete and bpfj_dyn_map_delete_if_unique, `unique`
// a constant at both call sites.
static __always_inline long bpfj_dyn_map_delete_impl(
    __arena struct bpfj_dyn_map* map,
    __u64 __arena* key,
    bool unique) {
  BPFJ_DYN_MAP_SLOTS_GUARD(published);
  BPFJ_DYN_MAP_SLOTS_GUARD(growing);
  __u32 cap = 0;
  __u32 growing_cap = 0;
  {
    BPFJ_LOCK_GUARD(map_lock, &map->lock);
    if (!BPFJ_LOCK_IS_ACQUIRED(map_lock)) {
      return -EBUSY;
    }

    BPFJ_DYN_MAP_SLOTS_ADOPT(published, &map->slots_ptr);
    cap = map->capacity;
    BPFJ_DYN_MAP_SLOTS_ADOPT(growing, &map->growing_slots_ptr);
    growing_cap = map->growing_capacity;
  }

  __u32 key_words = bpfj_dyn_map_key_words(map->key_size);

  // Mid-grow the same value may be reachable through both buffers without a
  // second counted reference. A unique delete waits that out.
  if (unique && BPFJ_DYN_MAP_SLOTS(growing)) {
    long live = bpfj_dyn_map_lookup_exists(
        BPFJ_DYN_MAP_SLOTS(growing), growing_cap, key, key_words);
    if (live == -ENOENT) {
      live = bpfj_dyn_map_lookup_exists(
          BPFJ_DYN_MAP_SLOTS(published), cap, key, key_words);
    }
    return live;
  }

  // One buffer only: a grow leaves the entry in both, so deleting from both
  // would free it twice.
  struct bpfj_dyn_map_entry dead = {0};
  long ret = -ENOENT;
  if (BPFJ_DYN_MAP_SLOTS(growing)) {
    ret = unique
        ? bpfj_dyn_map_do_delete_unique(
              BPFJ_DYN_MAP_SLOTS(growing), growing_cap, key, key_words, &dead)
        : bpfj_dyn_map_do_delete(
              BPFJ_DYN_MAP_SLOTS(growing), growing_cap, key, key_words, &dead);
  }
  if (ret == -ENOENT) {
    ret = unique
        ? bpfj_dyn_map_do_delete_unique(
              BPFJ_DYN_MAP_SLOTS(published), cap, key, key_words, &dead)
        : bpfj_dyn_map_do_delete(
              BPFJ_DYN_MAP_SLOTS(published), cap, key, key_words, &dead);
  }
  if (ret != 0) {
    // A negative errno, or 1 from a unique delete that found the value shared.
    return ret;
  }

  __sync_fetch_and_sub(&map->size, 1);
  __sync_fetch_and_add(&map->tombstones, 1);

  if (dead.key) {
    BPFJ_HEAP_FREE(dead.key);
  }
  bpfj_shared_ptr_release(&dead.val);
  return 0;
}

// Borrows `key`; the entry it finds is the map's to release.
__noinline long bpfj_dyn_map_delete(
    __arena struct bpfj_dyn_map* map __arg_arena,
    __u64 __arena* key __arg_arena) {
  return bpfj_dyn_map_delete_impl(map, key, false);
}

// Delete `key` only if nothing but the map holds its value: 0 once deleted, 1
// if some other reference kept it in place, or a negative errno. For a map
// that indexes values held elsewhere, an entry nobody else holds is one to
// reclaim. Mid-grow it returns 1 for any reachable entry and waits for the
// grow to settle before deciding uniqueness.
__noinline long bpfj_dyn_map_delete_if_unique(
    __arena struct bpfj_dyn_map* map __arg_arena,
    __u64 __arena* key __arg_arena) {
  return bpfj_dyn_map_delete_impl(map, key, true);
}

// `key_size` and `val_size` fix the width of every entry for the map's
// lifetime, and a key size that is not a whole number of __u64s is rejected.
// The map must be all its own until this returns.
__noinline long bpfj_dyn_map_init(
    __arena struct bpfj_dyn_map* map __arg_arena,
    __u32 capacity,
    __u32 key_size,
    __u32 val_size) {
  if (key_size == 0 || key_size % sizeof(__u64) != 0 || val_size == 0) {
    return -EINVAL;
  }

  // Bounded before rounding, which overflows to 0 above 2^31.
  if (capacity > BPFJ_DYN_MAP_MAX_CAPACITY) {
    return -EINVAL;
  }

  if (capacity < BPFJ_DYN_MAP_MIN_CAPACITY) {
    capacity = BPFJ_DYN_MAP_MIN_CAPACITY;
  }
  capacity = bpfj_dyn_map_round_capacity(capacity);

  __u32 bytes = capacity * (__u32)sizeof(struct bpfj_dyn_map_slot);
  struct bpfj_dyn_map_slot __arena* slots =
      BPFJ_HEAP_CALLOC(bytes); // zeroed => all slots EMPTY, all locks free
  if (!slots) {
    return -ENOMEM;
  }

  // Before anything reads them, since a heap block comes back dirty.
  bpfj_lock_init(&map->lock);
  map->slots_ptr.buf = NULL;
  map->slots_ptr.refcount = NULL;
  map->growing_slots_ptr.buf = NULL;
  map->growing_slots_ptr.refcount = NULL;

  long ret = bpfj_shared_ptr_reset(&map->slots_ptr, slots);
  if (ret != 0) {
    BPFJ_HEAP_FREE(slots);
    return ret;
  }

  map->extra = 0;
  map->grow_abandoned = 0;
  map->size = 0;
  map->tombstones = 0;
  map->capacity = capacity;
  map->growing_capacity = 0;
  map->key_size = key_size;
  map->val_size = val_size;
  return 0;
}

static __always_inline long bpfj_dyn_map_wipe(
    __arena struct bpfj_dyn_map* map) {
  BPFJ_DYN_MAP_SLOTS_GUARD(published);
  __u32 cap = 0;
  {
    BPFJ_LOCK_GUARD(map_lock, &map->lock);
    if (!BPFJ_LOCK_IS_ACQUIRED(map_lock)) {
      return -EBUSY;
    }

    BPFJ_DYN_MAP_SLOTS_ADOPT(published, &map->slots_ptr);
    cap = map->capacity;
  }

  bpfj_dyn_map_release_entries(BPFJ_DYN_MAP_SLOTS(published), cap);

  // The counters go with the entries, or a wiped map would keep growing as
  // though full.
  map->size = 0;
  map->tombstones = 0;

  // Wiped so the growing thread frees it.
  bpfj_shared_ptr_release_arena(&map->growing_slots_ptr);
  map->growing_capacity = 0;

  return 0;
}

// Release everything the map holds; like init, requires the map to itself.
static __always_inline void bpfj_dyn_map_destroy(
    __arena struct bpfj_dyn_map* map) {
  if (map->capacity == 0) {
    return;
  }

  struct bpfj_dyn_map_slot __arena* slots = map->slots_ptr.buf;
  if (slots) {
    bpfj_dyn_map_release_entries(slots, map->capacity);
  }
  bpfj_shared_ptr_release_arena(&map->slots_ptr);

  // Dropped without walking its entries: a grow either commits or retracts, so
  // on the quiescent map this requires it is empty.
  bpfj_shared_ptr_release_arena(&map->growing_slots_ptr);

  map->size = 0;
  map->tombstones = 0;
  map->capacity = 0;
  map->growing_capacity = 0;
}
