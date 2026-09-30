// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include <algorithm>
#include <cstdint>
#include <memory>
#include <optional>
#include <utility>
#include <vector>

#include "bpfj/lib/Heap.h"
#include "bpfj/lib/Log.h"
#include "bpfj/lib/ScopeGuard.h"
#include "bpfj/lib/bpf/types_perf_map.h"

namespace bpfjailer {

// The header lives on the arena: init() allocates it and publishes the pointer
// through `slot`, which is how BPF finds the map, and destroy() frees it.
//
// The slot must outlive the PerfMap, being held by reference and read by the
// destructor's leak check, so caller-owned storage has to be declared first --
// which is why FileMatchCached orders innerHdrs_ ahead of nodesMaps_.
template <heap::BpfSkelWithHeap Skel>
class PerfMap {
 public:
  PerfMap(
      std::shared_ptr<Skel> skel,
      struct bpfj_perf_map*& slot,
      bool checkDestroy = true)
      : skel_{std::move(skel)}, slot_(&slot), checkDestroy_(checkDestroy) {}

  ~PerfMap() {
    // Null for a moved-from instance; nothing to check or free.
    if (slot_ == nullptr) {
      return;
    }
    // checkDestroy_ == false opts out, for maps handed off deliberately.
    BPFJ_CHECK(!checkDestroy_ || *slot_ == nullptr) << "PerfMap not destroyed";
  }

  void swap(PerfMap& other) noexcept {
    std::swap(skel_, other.skel_);
    std::swap(slot_, other.slot_);
    std::swap(checkDestroy_, other.checkDestroy_);
  }

  PerfMap(PerfMap&& other) noexcept {
    swap(other);
  }

  PerfMap& operator=(PerfMap&& other) noexcept {
    swap(other);
    return *this;
  }

  PerfMap(const PerfMap&) = delete;
  PerfMap& operator=(const PerfMap&) = delete;

  template <typename Map>
  err::Expected<> init(Map&& entries) {
    // Release a prior init()'s header and tables, so re-compiling into the
    // same PerfMap does not strand the old seeds and slots, as GlobMap::init
    // and StrMap::init do.
    destroy();

    *slot_ = heap::alloc<struct bpfj_perf_map>(skel_);
    if (hdr() == nullptr) {
      return err::Error(
          std::errc::not_enough_memory, "Failed to allocate perf map header");
    }

    // Explicitly, despite heap::alloc value-initializing the block: the header
    // does not reliably read back as zero, so every failure path below would
    // unwind through a destroy() that frees whatever `seeds` and `slots`
    // happened to hold. StrMap::init zeroes up front for the same reason.
    clearHeader();

    // Callers do not destroy() a failed init(), and the destructor's
    // BPFJ_CHECK would abort on a still-published slot; this also reclaims the
    // tables the perfect-hash search can fail after allocating.
    auto headerGuard = makeGuard([this] { destroy(); });

    if (entries.empty()) {
      headerGuard.dismiss();
      return err::unit;
    }

    std::vector<std::pair<__u64, __u64>> kvs;
    kvs.reserve(entries.size());
    for (auto&& [k, v] : entries) {
      __u64 key = 0;
      static_assert(sizeof(key) >= sizeof(k));
      std::memcpy(&key, &k, sizeof(k));
      __u64 val = 0;
      static_assert(sizeof(val) >= sizeof(v));
      std::memcpy(&val, &v, sizeof(v));
      kvs.emplace_back(key, val);
    }

    __u32 numBuckets = static_cast<__u32>(kvs.size());
    // Over-provision slots (load factor ~0.5) so the greedy displacement below
    // reliably finds a perfect hash; a minimal table fails to place the last
    // buckets once the policy is large enough. The bound guards against a key
    // count overflowing the computation and silently shrinking the table.
    if (numBuckets > (0xFFFFFFFFU - 16U) / 2U) {
      return err::Error(
          std::errc::no_space_on_device,
          "Too many keys for perfect-hash table");
    }
    __u32 numSlots = (numBuckets * 2) + 16;

    auto seedsSize = numBuckets * sizeof(__u32);
    auto* seeds = heap::allocArray<__u32>(skel_, numBuckets);
    if (seeds == nullptr) {
      return err::Error(
          std::errc::not_enough_memory, "Failed to allocate seeds");
    }

    auto slotsSize = numSlots * sizeof(struct bpfj_perf_map_slot);
    auto* slots = heap::allocArray<struct bpfj_perf_map_slot>(skel_, numSlots);
    if (slots == nullptr) {
      heap::free(skel_, seeds);
      return err::Error(
          std::errc::not_enough_memory, "Failed to allocate slots");
    }

    zeroMemory(seeds, seedsSize);
    zeroMemory(slots, slotsSize);

    setHeader(
        bpfj_perf_map{
            .seeds = seeds,
            .slots = slots,
            .num_buckets = numBuckets,
            .num_slots = numSlots,
        });

    // Group keys by bucket (level-1 hash with seed=0)
    std::vector<Bucket> buckets(numBuckets);
    for (auto& [k, v] : kvs) {
      __u32 b = bpfj_perf_map_hash(k, 0, numBuckets);
      buckets[b].emplace_back(k, v);
    }

    // Sort buckets largest-first for greedy placement
    std::vector<__u32> order(numBuckets);
    for (__u32 i = 0; i < numBuckets; ++i) {
      order[i] = i;
    }
    std::sort(order.begin(), order.end(), [&](auto a, auto b) {
      return buckets[a].size() > buckets[b].size();
    });

    std::vector<bool> slotUsed(numSlots, false);

    std::vector<__u32> positions;
    for (__u32 bi : order) {
      const auto& bucket = buckets[bi];
      if (bucket.empty()) {
        continue;
      }

      auto seed = findBucketSeed(bucket, numSlots, slotUsed, positions);
      if (!seed) {
        return err::Error(
            std::errc::no_space_on_device,
            "Failed to find perfect hash for bucket");
      }

      setSeed(bi, *seed);
      for (std::size_t i = 0; i < bucket.size(); ++i) {
        setSlot(positions[i], bucket[i].first, bucket[i].second);
        slotUsed[positions[i]] = true;
      }
    }

    headerGuard.dismiss();
    return err::unit;
  }

  // The arena header as published to BPF, null until the first successful
  // init() and again after destroy().
  struct bpfj_perf_map* get() const {
    return hdr();
  }

  // The header's heap offset, for callers recording it as a scalar rather than
  // a pointer.
  std::uint32_t offset() const {
    return heap::ptrToOffset(heap::base(skel_), hdr());
  }

  void destroy() {
    if (slot_ == nullptr || hdr() == nullptr) {
      return;
    }
    // Not cleared first: the arena overwrites the header with its own
    // free-list bookkeeping.
    heap::free(skel_, headerSeeds());
    heap::free(skel_, headerSlots());
    heap::free(skel_, hdr());
    *slot_ = nullptr;
  }

 private:
  using Bucket = std::vector<std::pair<__u64, __u64>>;

  // Copy a fully-populated header into the arena-backed map in one shot,
  // taking the assembled struct so the fields stay named and unswappable.
  // Private because it dereferences hdr() unchecked.
  __attribute__((no_sanitize("address"))) void setHeader(
      const struct bpfj_perf_map& hdr) {
    *this->hdr() = hdr;
  }

  // Hash every key in `bucket` with `seed`, filling `positions`, and false as
  // soon as one lands on a slot already taken.
  static bool bucketPositions(
      const Bucket& bucket,
      __u32 seed,
      __u32 numSlots,
      const std::vector<bool>& slotUsed,
      std::vector<__u32>& positions) {
    positions.clear();
    for (const auto& [k, v] : bucket) {
      __u32 pos = bpfj_perf_map_hash(k, seed, numSlots);
      if (slotUsed[pos]) {
        return false;
      }
      if (std::find(positions.begin(), positions.end(), pos) !=
          positions.end()) {
        return false;
      }
      positions.push_back(pos);
    }
    return true;
  }

  // The level-2 seed mapping `bucket` onto free, distinct slots, left in
  // `positions`. Nullopt once the search window is exhausted, which the caller
  // reports rather than retrying: the table only gets fuller from here.
  static std::optional<__u32> findBucketSeed(
      const Bucket& bucket,
      __u32 numSlots,
      const std::vector<bool>& slotUsed,
      std::vector<__u32>& positions) {
    for (__u32 seed = 1; seed <= numSlots * 4; ++seed) {
      if (bucketPositions(bucket, seed, numSlots, slotUsed, positions)) {
        return seed;
      }
    }
    return std::nullopt;
  }

  struct bpfj_perf_map* hdr() const {
    return *slot_;
  }

  __attribute__((no_sanitize("address"))) void clearHeader() {
    hdr()->num_buckets = 0;
    hdr()->num_slots = 0;
    hdr()->seeds = nullptr;
    hdr()->slots = nullptr;
  }

  __attribute__((no_sanitize("address"))) __u32* headerSeeds() const {
    return hdr()->seeds;
  }

  __attribute__((no_sanitize("address"))) struct bpfj_perf_map_slot*
  headerSlots() const {
    return hdr()->slots;
  }

  __attribute__((no_sanitize("address"))) void zeroMemory(
      void* ptr,
      std::size_t len) {
    auto* dst = static_cast<unsigned char*>(ptr);
    for (std::size_t i = 0; i < len; ++i) {
      dst[i] = 0;
    }
  }

  __attribute__((no_sanitize("address"))) void setSeed(
      __u32 bucketIdx,
      __u32 seed) {
    auto* seeds = headerSeeds();
    seeds[bucketIdx] = seed;
  }

  __attribute__((no_sanitize("address"))) void
  setSlot(__u32 slotIdx, __u64 key, __u64 val) {
    auto* slots = headerSlots();
    slots[slotIdx].key = key;
    slots[slotIdx].val = val;
    slots[slotIdx].occupied = 1;
  }

  std::shared_ptr<Skel> skel_;
  // Where the caller wants the arena header pointer recorded.
  struct bpfj_perf_map** slot_ = nullptr;
  bool checkDestroy_ = true;
};

} // namespace bpfjailer
