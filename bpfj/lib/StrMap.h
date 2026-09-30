// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include <cstdint>
#include <limits>
#include <memory>
#include <utility>

#include "bpfj/lib/Heap.h"
#include "bpfj/lib/ScopeGuard.h"
#include "bpfj/lib/bpf/types_str_map.h"

namespace bpfjailer {

// The header lives on the arena: init() allocates it and publishes the arena
// pointer through `slot`, which is how BPF finds the map, and destroy() frees
// it. The slot itself may live on the arena, so every access goes through the
// no_sanitize accessors below. An entry's value is an arena pointer the map
// neither owns nor reads through.
template <heap::BpfSkelWithHeap Skel>
class StrMap {
 public:
  StrMap(
      std::shared_ptr<Skel> skel,
      struct bpfj_str_map*& slot,
      bool checkDestroy = true)
      : skel_{std::move(skel)}, slot_(&slot), checkDestroy_(checkDestroy) {}

  ~StrMap() {
    // Null for a moved-from instance; nothing to check or free.
    if (slot_ == nullptr) {
      return;
    }
    // checkDestroy_ == false opts out, for maps handed off deliberately.
    BPFJ_CHECK(!checkDestroy_ || hdr() == nullptr) << "StrMap not destroyed";
  }

  void swap(StrMap& other) noexcept {
    std::swap(skel_, other.skel_);
    std::swap(slot_, other.slot_);
    std::swap(checkDestroy_, other.checkDestroy_);
  }

  StrMap(StrMap&& other) noexcept {
    swap(other);
  }

  StrMap& operator=(StrMap&& other) noexcept {
    swap(other);
    return *this;
  }

  StrMap(const StrMap&) = delete;
  StrMap& operator=(const StrMap&) = delete;

  err::Expected<> init(std::size_t capacity) {
    // The header holds capacity as a __u32 and both hashes reduce modulo it,
    // so anything that does not fit is a table neither side could index.
    if (capacity == 0 || capacity > std::numeric_limits<__u32>::max()) {
      return err::Error(
          std::errc::invalid_argument, "str map capacity out of range");
    }

    // Release a prior init()'s header, vector and keys, or initHeader
    // replaces hdr()->vec outright and strands them. GlobMap::init and
    // PerfMap::init do the same.
    destroy();

    setHdr(heap::alloc<struct bpfj_str_map>(skel_));
    if (hdr() == nullptr) {
      return err::Error(
          std::errc::not_enough_memory, "Failed to allocate str map header");
    }

    // Emptied before anything below can fail: heap::alloc's block does not
    // reliably read as zero (as in PerfMap::init), so unwinding through
    // destroy() would walk a garbage capacity freeing garbage pointers.
    initHeader(0, nullptr);

    // A failure below leaves the header allocated and published in the slot,
    // which callers do not destroy() and the destructor aborts on.
    auto headerGuard = makeGuard([this] { destroy(); });

    auto* vec = heap::allocArray<struct bpfj_str_map_entry>(skel_, capacity);
    if (vec == nullptr) {
      return err::Error(
          std::errc::not_enough_memory, "Failed to allocate str map vector");
    }

    zeroMemory(vec, sizeof(struct bpfj_str_map_entry) * capacity);
    initHeader(static_cast<__u32>(capacity), vec);

    headerGuard.dismiss();
    return err::unit;
  }
  template <typename T>
  err::Expected<> addString(T&& str, void* val) {
    if (size() >= headerCapacity()) {
      return err::Error(std::errc::argument_list_too_long, "Too many strings");
    }

    auto* key = heap::allocArray<char>(skel_, str.size() + 1);
    if (key == nullptr) {
      return err::Error(
          std::errc::not_enough_memory, "Failed to allocate string");
    }

    copyString(key, str.data(), str.size());

    auto hash = bpfj_str_map_hash(
        str.data(), str.size(), headerCapacity(), BPFJ_STR_MAP_MAX_STR_LEN);

    std::uint32_t off = hash;

    const struct bpfj_str_map_entry entry{
        .key = key,
        .val = val,
        .key_len = static_cast<__u32>(str.size()),
    };

    std::size_t i = 0;
    for (; i < BPFJ_STR_MAP_MAX_ATTEMPTS; ++i) {
      if (tryInsert(off, entry)) {
        break;
      }

      ++off;

      if (off >= headerCapacity()) {
        off = 0;
      }
    }

    if (i == BPFJ_STR_MAP_MAX_ATTEMPTS) {
      return err::Error(std::errc::no_space_on_device, "Could not add string");
    }

    incrementSize();
    return err::unit;
  }

  template <typename T>
  err::Expected<> init(T&& map) {
    auto capacity = map.size() * 4;
    if (capacity == 0) {
      capacity = 1;
    }

    // Round up to a power of 2. The empty-map guard matters: __builtin_clzl(0)
    // is undefined, and a zero capacity divides by zero in the BPF-side hash.
    capacity = capacity == 0 ? 1 : (1 << (64 - __builtin_clzl(capacity)));

    // Captured before init() fills the slot, so this tears down only what
    // this call is responsible for: the addString loop below, init() having
    // unwound its own failures already.
    const bool allocatedHere = hdr() == nullptr;
    if (auto res = init(capacity); !res) {
      return res.error();
    }

    auto headerGuard = makeGuard([this, allocatedHere] {
      if (allocatedHere) {
        destroy();
      }
    });

    // The mapped type must be a pointer: a value that is not a block on the
    // arena is nothing BPF can use.
    for (auto&& [k, v] : map) {
      if (auto res = addString(k, v); !res) {
        return res.error();
      }
    }

    headerGuard.dismiss();
    return err::unit;
  }

  // The arena header as published to BPF, null until the first successful
  // init() and again after destroy().
  struct bpfj_str_map* get() const {
    return hdr();
  }

  void destroy() {
    if (slot_ == nullptr || hdr() == nullptr) {
      return;
    }

    std::uint32_t cap = headerCapacity();
    struct bpfj_str_map_entry* vec_base = headerVec();

    for (std::uint32_t i = 0; i < cap; ++i) {
      if (auto* key = entryKey(vec_base, i); key != nullptr) {
        heap::free(skel_, key);
      }
    }

    heap::free(skel_, vec_base);
    clearHeader();
    heap::free(skel_, hdr());
    setHdr(nullptr);
  }

 private:
  __attribute__((no_sanitize("address"))) struct bpfj_str_map* hdr() const {
    return *slot_;
  }

  __attribute__((no_sanitize("address"))) void setHdr(
      struct bpfj_str_map* hdr) {
    *slot_ = hdr;
  }

  __attribute__((no_sanitize("address"))) void clearHeader() {
    hdr()->size = 0;
    hdr()->capacity = 0;
    hdr()->vec = nullptr;
  }

  __attribute__((no_sanitize("address"))) struct bpfj_str_map_entry* headerVec()
      const {
    return hdr()->vec;
  }

  __attribute__((no_sanitize("address"))) static char* entryKey(
      const struct bpfj_str_map_entry* vec,
      std::uint32_t idx) {
    return vec[idx].key;
  }

  __attribute__((no_sanitize("address"))) void initHeader(
      __u32 capacity,
      struct bpfj_str_map_entry* vec) {
    hdr()->size = 0;
    hdr()->capacity = capacity;
    hdr()->vec = vec;
  }

  __attribute__((no_sanitize("address"))) __u32 size() const {
    return hdr()->size;
  }

  __attribute__((no_sanitize("address"))) __u32 headerCapacity() const {
    return hdr()->capacity;
  }

  __attribute__((no_sanitize("address"))) void zeroMemory(
      void* ptr,
      std::size_t len) {
    auto* dst = static_cast<unsigned char*>(ptr);
    for (std::size_t i = 0; i < len; ++i) {
      dst[i] = 0;
    }
  }

  __attribute__((no_sanitize("address"))) void
  copyString(char* dst, const char* data, std::size_t len) {
    for (std::size_t i = 0; i < len; ++i) {
      dst[i] = data[i];
    }
    dst[len] = '\0';
  }

  // Claim slot `idx` for `entry` if it is still free, taking the assembled
  // entry so key_len and val stay named rather than swappable.
  __attribute__((no_sanitize("address"))) bool tryInsert(
      __u32 idx,
      const struct bpfj_str_map_entry& entry) {
    auto* slot = hdr()->vec + idx;

    if (slot->key != nullptr) {
      return false;
    }

    *slot = entry;
    return true;
  }

  __attribute__((no_sanitize("address"))) void incrementSize() {
    ++hdr()->size;
  }

  std::shared_ptr<Skel> skel_;
  // Where the caller wants the arena header pointer recorded.
  struct bpfj_str_map** slot_ = nullptr;
  bool checkDestroy_ = true;
};

} // namespace bpfjailer
