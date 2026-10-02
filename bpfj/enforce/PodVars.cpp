// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "bpfj/enforce/PodVars.h"

#include <bpf/bpf.h>
#include <sys/mman.h>

#include <array>
#include <cstring>
#include <mutex>

#include "bpfj/enforce/ArenaMap.h"
#include "bpfj/enforce/bpf/types.h"
#include "bpfj/lib/Heap.h"
#include "bpfj/var/bpf/types_var.h"

namespace bpfjailer {

namespace {

constexpr std::string_view kVarMap = "bpfj_var_map";
constexpr std::string_view kArenaMap = "bpfj_heap_arena";

std::mutex& openMutex() noexcept {
  static std::mutex mutex;
  return mutex;
}

std::array<std::size_t, arena::kSlotCount>& openCounts() noexcept {
  static std::array<std::size_t, arena::kSlotCount> counts{};
  return counts;
}

std::size_t slotIndex(std::uint64_t extra) noexcept {
  return static_cast<std::size_t>(
      (extra - arena::kWindowBase) / arena::kSlotSize);
}

} // namespace

Expected<Fd> openVarMap(const PinConfig& cfg) noexcept {
  return pins::openPinnedMap(cfg, kVarMap);
}

Expected<> publishVarNames(
    const PinConfig& cfg,
    std::span<const std::string> names) noexcept {
  // Slot 0 means "no name", so the names need one more slot than there are
  // names.
  if (names.size() + 1 > BPFJ_VAR_MAP_SIZE) {
    return makeUnexpected(makeError(
        std::errc::value_too_large,
        "a policy may declare at most ",
        std::to_string(BPFJ_VAR_MAP_SIZE - 1),
        " vars, got ",
        std::to_string(names.size())));
  }

  auto varMap = openVarMap(cfg);
  if (!varMap) {
    return makeUnexpected(varMap.error());
  }

  for (std::uint32_t i = 0; i < names.size(); ++i) {
    const std::string_view name = names[i];
    if (name.size() >= BPFJ_VAR_NAME_LEN) {
      return makeUnexpected(makeError(
          std::errc::value_too_large,
          "variable name ",
          name,
          " must be at most ",
          std::to_string(BPFJ_VAR_NAME_LEN - 1),
          " characters"));
    }

    bpfj_var_name entry{};
    std::memcpy(entry.name, name.data(), name.size());

    const std::uint32_t id = i + 1;
    if (::bpf_map_update_elem(varMap->get(), &id, &entry, BPF_ANY) != 0) {
      return makeUnexpected(
          makeErrnoError("failed to publish variable name ", name));
    }
  }

  return unit;
}

Expected<std::vector<std::string>> readVarNames(const Fd& varMap) noexcept {
  std::vector<std::string> names(BPFJ_VAR_MAP_SIZE);
  for (std::uint32_t id = 1; id < BPFJ_VAR_MAP_SIZE; ++id) {
    bpfj_var_name entry{};
    if (::bpf_map_lookup_elem(varMap.get(), &id, &entry) != 0) {
      return makeUnexpected(makeErrnoError(
          "failed to read the name of variable ", std::to_string(id)));
    }

    names[id].assign(entry.name, ::strnlen(entry.name, BPFJ_VAR_NAME_LEN));
  }

  return names;
}

Expected<std::uint32_t> lookupVarId(
    const Fd& varMap,
    std::string_view name) noexcept {
  if (name.empty()) {
    return makeUnexpected(
        makeError(std::errc::invalid_argument, "a variable name is empty"));
  }

  // bpfj_var_map is an array, so every slot reads back whether or not anything
  // was ever published to it, and an empty name is what an unused one holds.
  for (std::uint32_t id = 1; id < BPFJ_VAR_MAP_SIZE; ++id) {
    bpfj_var_name entry{};
    if (::bpf_map_lookup_elem(varMap.get(), &id, &entry) != 0) {
      continue;
    }

    const std::string_view published(
        entry.name, ::strnlen(entry.name, BPFJ_VAR_NAME_LEN));
    if (!published.empty() && published == name) {
      return id;
    }
  }

  return makeUnexpected(makeError(
      std::errc::invalid_argument,
      "no variable named ",
      name,
      " is published in this jail"));
}

PodArena::~PodArena() noexcept {
  reset();
}

PodArena::PodArena(PodArena&& other) noexcept
    : owner_{std::move(other.owner_)},
      base_{other.base_},
      mapExtra_{other.mapExtra_} {
  other.base_ = nullptr;
  other.mapExtra_ = 0;
}

PodArena& PodArena::operator=(PodArena&& other) noexcept {
  if (this != &other) {
    reset();
    owner_ = std::move(other.owner_);
    base_ = other.base_;
    mapExtra_ = other.mapExtra_;
    other.base_ = nullptr;
    other.mapExtra_ = 0;
  }
  return *this;
}

Expected<PodArena> PodArena::open(const PinConfig& cfg) noexcept {
  if (auto res = arena::ensureWindowReserved(); !res) {
    return makeUnexpected(res.error());
  }

  auto fd = pins::openPinnedMap(cfg, kArenaMap);
  if (!fd) {
    return makeUnexpected(fd.error());
  }

  auto extra = arena::pinnedMapExtra(*fd);
  if (!extra) {
    return makeUnexpected(extra.error());
  }

  const std::size_t index = slotIndex(*extra);
  {
    std::lock_guard<std::mutex> guard(openMutex());
    if (openCounts()[index] == 0) {
      void* const mapped = ::mmap(
          reinterpret_cast<void*>(*extra),
          arena::kSlotSize,
          PROT_READ | PROT_WRITE,
          MAP_SHARED | MAP_FIXED,
          fd->get(),
          0);
      if (mapped == MAP_FAILED) {
        return makeUnexpected(
            makeErrnoError("failed to mmap pinned arena at fixed address"));
      }
    }
    ++openCounts()[index];
  }

  PodArena arena;
  arena.owner_ = std::shared_ptr<void>(
      reinterpret_cast<void*>(*extra), [extra = *extra](void*) {
        std::lock_guard<std::mutex> guard(openMutex());
        auto& counts = openCounts();
        const std::size_t slot = slotIndex(extra);
        if (counts[slot] == 0) {
          return;
        }
        --counts[slot];
        if (counts[slot] == 0) {
          (void)::munmap(reinterpret_cast<void*>(extra), arena::kSlotSize);
          (void)arena::restorePlaceholder(extra);
        }
      });
  arena.base_ = reinterpret_cast<void*>(*extra);
  arena.mapExtra_ = *extra;
  return arena;
}

Expected<void*> PodArena::alloc(std::uint32_t size) noexcept {
  const long offset = heap::alloc(base_, size);
  if (offset <= BPFJ_HEAP_NULL) {
    return makeUnexpected(
        makeError(std::errc::not_enough_memory, "failed to allocate pod vars"));
  }

  void* const ptr = heap::offsetToPtr(base_, static_cast<__u32>(offset));
  if (ptr == nullptr) {
    return makeUnexpected(makeError(
        std::errc::bad_address, "pod vars allocation lies outside the arena"));
  }
  return ptr;
}

Expected<> PodArena::free(void* ptr) noexcept {
  const long res = heap::free(base_, ptr);
  if (res != 0) {
    return makeUnexpected(
        makeError(std::errc(-res), "failed to free pod vars from arena"));
  }
  return unit;
}

void PodArena::reset() noexcept {
  owner_.reset();
  base_ = nullptr;
  mapExtra_ = 0;
}

} // namespace bpfjailer
