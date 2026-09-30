// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#ifdef __cplusplus
#include <linux/types.h>
#endif

#include "bpfj/lib/bpf/types_dyn_map.h"
#include "bpfj/lib/bpf/types_shared_ptr.h"

// Fixed-size, thread-safe LRU map: fixed-width key -> bpfj_dyn_map value. A
// key is bpfj_dyn_lru::key_size bytes, fixed by DynLru::init, and is hashed,
// compared and copied a __u64 at a time, so the size must be a whole number of
// words.
//
// Concurrency, which is the whole shape of this thing:
//
//   - lookup takes one slot's lock and nothing else, since it runs on every
//     file access on every CPU and every arena lock is a trylock.
//
//   - insert, erase and eviction take bpfj_dyn_lru::lock. Serializing the only
//     three things that move an entry between slots is what lets removal close
//     its hole by backshift (bpfj_dyn_lru_close_hole); this index never
//     rehashes, so tombstones would accumulate until inserts failed.
//
//   - a slot's lock is still taken for every read and write of that slot.
//
// Recency is approximate, which is what keeps a lookup off the map-wide lock:
// a hit restores the entry's `ref` credit rather than moving it, and eviction
// spends it down as a clock hand sweeps -- kernel/bpf/bpf_lru_list.c's trade
// reduced to one sweep. The only thing a lookup can then observe is a removal
// shifting an entry back past its cursor, reading as a miss for a resident
// key; keys are compared under the slot's lock, so it can never read a wrong
// entry.

// Upper bound on capacity, which bounds the destroy loop for the verifier and
// caps the arena footprint.
#define BPFJ_DYN_LRU_MAX_CAPACITY 4096

// Index slots per live entry; the table never grows, so this is what keeps the
// load factor and the linear-probe chains low for the map's lifetime.
#define BPFJ_DYN_LRU_INDEX_SLACK 4

// Bound on a single linear-probe walk, far above the chains a 1/4 load factor
// actually produces.
#define BPFJ_DYN_LRU_MAX_PROBES 16

// Slots one eviction sweep looks at before giving up, bounded rather than a
// full pass because it runs under bpfj_dyn_lru::lock and arr_size reaches
// 16384, as the kernel bounds its rotation (bpf_lru::nr_scans).
#define BPFJ_DYN_LRU_CLOCK_SCAN 64

// Eviction credit: a sweep evicts an entry with none left and spends a unit
// off the rest, so a hit outranks a fresh insert. Keep the maximum small, it
// being also how many sweeps eviction may take to make progress.
#define BPFJ_DYN_LRU_REF_LOOKUP 2
#define BPFJ_DYN_LRU_REF_INSERT 1

// Entries the pool holds over `capacity`, covering the one an overflowing
// insert is briefly over by plus slack against a sweep that finds no victim.
#define BPFJ_DYN_LRU_POOL_SLACK 32

struct bpfj_dyn_lru_entry {
  // A slice of bpfj_dyn_lru::key_pool assigned at init and kept across
  // recycles, so an insert copies its key in rather than allocating.
  __u64 __arena* key;

  // Pointer to bpfj_dyn_map
  struct bpfj_shared_ptr val;

  // Eviction credit; see BPFJ_DYN_LRU_REF_LOOKUP. Read and written under the
  // lock of the slot pointing at this entry.
  __u32 ref;

  // The slot `key` hashes to, cached because re-deriving it would nest the
  // key's word loop inside bpfj_dyn_lru_close_hole's walk.
  __u32 home;

  // Next free entry while this one is in the pool, NULL while it is live.
  struct bpfj_dyn_lru_entry __arena* next_free;
};

struct bpfj_dyn_lru_slot {
  // The entry in this slot, or NULL. There is no tombstone state: removal
  // closes its hole, so an empty slot always ends a probe chain.
  struct bpfj_dyn_lru_entry __arena* entry;

  // Guards `entry` and the fields it reaches, held only for the few
  // instructions a probe spends here or the write that follows.
  struct bpfj_lock lock;
};

struct bpfj_dyn_lru {
  // slot[arr_size], one flat arena block.
  struct bpfj_dyn_lru_slot __arena* slots;

  // entry[pool_size] and pool_size * key_size bytes, each one flat arena block
  // owned for the map's lifetime, leaving an insert to allocate only the
  // reference count on its value. Preallocated for the reason
  // kernel/bpf/hashtab.c prealloc_init() is: the map's size is fixed, so the
  // steady state is the whole of it.
  struct bpfj_dyn_lru_entry __arena* entry_pool;
  __u64 __arena* key_pool;

  // Head of the free entries, threaded through bpfj_dyn_lru_entry::next_free.
  // Popped and pushed under `lock`.
  struct bpfj_dyn_lru_entry __arena* free_list;

  __u32 arr_size; // index slots; power of two, capacity * INDEX_SLACK
  __u32 capacity; // N; fixed
  __u32 pool_size; // entries in entry_pool; capacity + POOL_SLACK
  __u32 size; // live entries; changed only under `lock`
  __u32 key_size; // bytes per key; a non-zero multiple of sizeof(__u64)
  __u32 clock_hand; // where the next eviction sweep starts

  // Serializes insert, erase and eviction, the three operations that move
  // entries between slots; a lookup never takes it.
  struct bpfj_lock lock;
};

// Test scaffolding shared by DynLruTests.cpp and tests/bpf/dyn_lru_map.bpf.c:
// order matters for an LRU, so tests drive a scripted sequence against one map
// rather than one op per run.

enum lru_ins_type {
  LRU_NONE, // end of script
  LRU_INSERT,
  LRU_LOOKUP,
};

// Length of the instruction stream and of the result arrays BPF writes back.
#define BPFJ_DYN_LRU_TEST_MAX_INS 32

// Every inner bpfj_dyn_map the script inserts holds one entry under this key,
// so a lookup can prove it got the map stored under that LRU key.
#define BPFJ_DYN_LRU_TEST_PROBE_KEY 0x5eedULL

// One word, which the BPF side stages into an arena scratch buffer per op.
#define BPFJ_DYN_LRU_TEST_KEY_SIZE ((__u32)sizeof(__u64))

struct lru_ins {
  enum lru_ins_type ins;
  __u64 key;
  // LRU_INSERT: tagged into the inserted map under
  // BPFJ_DYN_LRU_TEST_PROBE_KEY.
  __u64 val;
};
