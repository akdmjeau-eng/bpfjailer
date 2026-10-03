// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <utility>
#include <vector>
#include "bpfj/err/StdExpected.h"
#include "bpfj/lib/Heap.h"
#include "bpfj/lib/Lock.h"
#include "bpfj/lib/SharedPtr.h"
#include "bpfj/lib/bpf/types_dyn_lru.h"
#include "bpfj/lib/bpf/types_dyn_map.h"

namespace bpfjailer {

// Every method touching the arena-resident header is no_sanitize("address"),
// as in PerfMap, StrMap and GlobMap: the arena is mmap'd behind the
// sanitizer's back, and without it the writes below do not reliably land.
template <heap::BpfSkelWithHeap Skel>
class DynLru {
 public:
  DynLru(std::shared_ptr<Skel> skel, struct bpfj_dyn_lru*& map)
      : skel_{std::move(skel)}, hdr_{map} {}

  // Standalone: the header pointer lives here rather than in a slot BPF reads
  // it from, for a map several owners each copy get() into their own slot.
  explicit DynLru(std::shared_ptr<Skel> skel)
      : skel_{std::move(skel)}, hdr_{ownedHdr_} {}

  // Sole owner of everything the header reaches, so share one through a
  // shared_ptr rather than a second DynLru.
  DynLru(const DynLru&) = delete;
  DynLru& operator=(const DynLru&) = delete;
  DynLru(DynLru&&) = delete;
  DynLru& operator=(DynLru&&) = delete;

  ~DynLru() {
    if (destroyOnDestruct_) {
      destroy();
    }
  }

  // Leave the arena allocation published for a pinned BPF object. The map pin
  // owns its lifetime after the loading process exits.
  void release() noexcept {
    destroyOnDestruct_ = false;
  }

  // Release everything the map owns: the bpfj_dyn_map every live entry holds,
  // which is an allocation of its own that freeing the entry pool would not
  // reach, then the four blocks the map is made of. Idempotent, and unlocked
  // since this runs where the map is no longer shared.
  __attribute__((no_sanitize("address"))) void destroy() {
    if (hdr_ == nullptr) {
      return;
    }

    for (__u32 i = 0; i < hdr_->arr_size; ++i) {
      auto& slot = hdr_->slots[i];
      if (slot.entry == nullptr) {
        continue;
      }
      releaseVal(&slot.entry->val);
    }

    heap::free(skel_, hdr_->key_pool);
    heap::free(skel_, hdr_->entry_pool);
    heap::free(skel_, hdr_->slots);
    heap::free(skel_, hdr_);
    hdr_ = nullptr;
  }

  // `keySize` fixes the width of every key for the map's lifetime, and one
  // that is not a whole number of __u64s is rejected here rather than
  // truncated in BPF.
  __attribute__((no_sanitize("address"))) err::Expected<> init(
      __u32 capacity,
      __u32 keySize) {
    if (capacity == 0 || capacity > BPFJ_DYN_LRU_MAX_CAPACITY) {
      return err::Error(
          std::errc::invalid_argument, "dyn lru capacity out of range");
    }

    if (keySize == 0 || keySize % sizeof(__u64) != 0) {
      return err::Error(
          std::errc::invalid_argument,
          "dyn lru key size must be a non-zero multiple of 8 bytes");
    }

    capacity = roundUpPow2(capacity);
    const __u32 arrSize = capacity * BPFJ_DYN_LRU_INDEX_SLACK;

    auto* hdr = heap::alloc<struct bpfj_dyn_lru>(skel_);
    if (hdr == nullptr) {
      return err::Error(
          std::errc::not_enough_memory, "dyn lru header allocation failed");
    }

    // Value-initialized, so every slot starts empty with its lock free; a heap
    // block otherwise comes back dirty and the lock reads as held.
    auto* slots = heap::allocArray<struct bpfj_dyn_lru_slot>(skel_, arrSize);
    if (slots == nullptr) {
      heap::free(skel_, hdr);
      return err::Error(
          std::errc::not_enough_memory, "dyn lru index allocation failed");
    }

    // Every entry and key buffer in one block each, so BPF takes them off a
    // free list and keeps the shared arena heap off the insert path.
    const __u32 poolSize = capacity + BPFJ_DYN_LRU_POOL_SLACK;
    auto* entries =
        heap::allocArray<struct bpfj_dyn_lru_entry>(skel_, poolSize);
    if (entries == nullptr) {
      heap::free(skel_, slots);
      heap::free(skel_, hdr);
      return err::Error(
          std::errc::not_enough_memory, "dyn lru entry pool allocation failed");
    }

    // As __u64, which is what an entry's key is walked as.
    const __u32 keyWords = keySize / sizeof(__u64);
    auto* keys =
        heap::allocArray<__u64>(skel_, std::size_t{poolSize} * keyWords);
    if (keys == nullptr) {
      heap::free(skel_, entries);
      heap::free(skel_, slots);
      heap::free(skel_, hdr);
      return err::Error(
          std::errc::not_enough_memory, "dyn lru key pool allocation failed");
    }

    // Hand each entry its slice of the key block and thread the free list; an
    // entry keeps that slice across every recycle.
    for (__u32 i = 0; i < poolSize; ++i) {
      entries[i].key = keys + (std::size_t{i} * keyWords);
      entries[i].next_free = (i + 1 < poolSize) ? &entries[i + 1] : nullptr;
    }

    hdr->slots = slots;
    hdr->entry_pool = entries;
    hdr->key_pool = keys;
    hdr->free_list = &entries[0];
    hdr->capacity = capacity;
    hdr->arr_size = arrSize;
    hdr->pool_size = poolSize;
    hdr->size = 0;
    hdr->key_size = keySize;
    hdr->clock_hand = 0;
    lock::init(hdr->lock);

    // Published last, so BPF never sees the header half-initialized.
    hdr_ = hdr;
    return err::unit;
  }

  // The arena header as BPF sees it, null until the first successful init()
  // and again after destroy().
  __attribute__((no_sanitize("address"))) struct bpfj_dyn_lru* get() const {
    return hdr_;
  }

  template <typename K>
  struct Entry {
    K key;
    // bpfj_dyn_map::extra of the value stored under `key`, or zero if the
    // entry holds no map.
    __u64 extra;
  };

  // Snapshot of the entries currently resident, in index rather than recency
  // order, the LRU keeping no recency list. This is diagnostic-only and must
  // not run while BPF is attached: BPF waits with interrupts disabled, so it
  // must never wait for a userspace holder that can be descheduled.
  template <typename K>
  err::Expected<std::vector<Entry<K>>> entries() const {
    if (hdr_ == nullptr) {
      return err::Error(
          std::errc::invalid_argument, "dyn lru is not initialized");
    }

    // Reading key_size bytes back as a wider K would walk off each key block.
    if (sizeof(K) != hdr_->key_size) {
      return err::Error(
          std::errc::invalid_argument,
          "dyn lru key size is " + std::to_string(hdr_->key_size) +
              " bytes, not " + std::to_string(sizeof(K)));
    }

    std::vector<Entry<K>> out;
    out.reserve(hdr_->size);

    lock::Guard guard{hdr_->lock, heap::kLockTimeout};
    if (!guard.owns()) {
      return err::Error(std::errc::timed_out, "timed out taking dyn lru lock");
    }

    for (__u32 i = 0; i < hdr_->arr_size; ++i) {
      auto& slot = hdr_->slots[i];

      if (slot.entry == nullptr || slot.entry->key == nullptr) {
        continue;
      }

      Entry<K> e{};
      std::memcpy(&e.key, slot.entry->key, sizeof(K));
      const auto* dyn =
          static_cast<const struct bpfj_dyn_map*>(slot.entry->val.buf);
      e.extra = dyn != nullptr ? dyn->extra : 0;
      out.emplace_back(e);
    }

    return out;
  }

 private:
  // Drop one reference to an entry's map, releasing the slot buffers the last
  // reference owns first, as bpfj_dyn_lru_destroy_val does on the BPF side.
  __attribute__((no_sanitize("address"))) void releaseVal(
      struct bpfj_shared_ptr* val) {
    if (val->refcount == nullptr) {
      return;
    }

    if (shared_ptr::useCount(*val) == 1) {
      auto* dyn = static_cast<struct bpfj_dyn_map*>(val->buf);
      if (dyn != nullptr) {
        releaseSlots(dyn->slots_ptr, dyn->capacity);
        // Set only mid-grow, which cannot happen here: nothing is walking a
        // map the LRU is dropping.
        releaseSlots(dyn->growing_slots_ptr, dyn->growing_capacity);
        dyn->capacity = 0;
        dyn->growing_capacity = 0;
      }
    }

    shared_ptr::release(skel_, val);
  }

  // Release one of a map's slot buffers and the key block and value reference
  // each entry holds, which freeing the buffer reaches neither of. Mirrors
  // bpfj_dyn_map_release_entries and bpfj_dyn_map_destroy on the BPF side.
  void releaseSlots(struct bpfj_shared_ptr& slotsPtr, __u32 capacity) {
    auto* slots = static_cast<struct bpfj_dyn_map_slot*>(slotsPtr.buf);
    if (slots == nullptr) {
      return;
    }

    for (__u32 i = 0; i < capacity; ++i) {
      auto& slot = slots[i];
      if (slot.state != BPFJ_DYN_SLOT_OCCUPIED) {
        continue;
      }
      heap::free(skel_, slot.key);
      shared_ptr::release(skel_, &slot.val_ptr);
    }

    shared_ptr::release(skel_, &slotsPtr);
  }

  static __u32 roundUpPow2(__u32 v) {
    if (v <= 8) {
      return 8;
    }
    v--;
    v |= v >> 1;
    v |= v >> 2;
    v |= v >> 4;
    v |= v >> 8;
    v |= v >> 16;
    v++;
    return v;
  }

  std::shared_ptr<Skel> skel_;
  // Only the standalone constructor uses this, and it is declared before hdr_
  // so it is alive when the reference binds.
  struct bpfj_dyn_lru* ownedHdr_ = nullptr;
  struct bpfj_dyn_lru*& hdr_;
  bool destroyOnDestruct_ = true;
};

} // namespace bpfjailer
