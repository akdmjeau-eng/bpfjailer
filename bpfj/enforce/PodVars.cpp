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

constexpr std::string_view kVarCatalogMap = "bpfj_var_catalog_map";
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

[[nodiscard]] Expected<Fd> openVarCatalogMap(const PinConfig& cfg) noexcept {
  return pins::openPinnedMap(cfg, kVarCatalogMap);
}

[[nodiscard]] std::uint32_t varCatalogAllocSize(
    std::span<const std::string> names) noexcept {
  std::uint32_t size = bpfj_var_align_up(sizeof(struct bpfj_var_catalog));
  for (const auto& name : names) {
    size += bpfj_var_align_up(static_cast<__u32>(name.size()) + 1);
  }
  return size;
}

[[nodiscard]] Expected<const struct bpfj_var_catalog*> readVarCatalogPointer(
    const Fd& catalogMap) noexcept {
  const std::uint32_t slot = 0;
  struct bpfj_var_catalog* catalog = nullptr;
  if (::bpf_map_lookup_elem(catalogMap.get(), &slot, &catalog) != 0) {
    return makeUnexpected(makeErrnoError(
        "failed to read the running jail's variable catalog pointer"));
  }
  return catalog;
}

Expected<> publishVarNames(
    const PinConfig& cfg,
    std::span<const std::string> names) noexcept {
  // Slot 0 means "no name", so the names need one more slot than there are
  // names.
  if (names.size() + 1 > BPFJ_VAR_ID_SLOTS) {
    return makeUnexpected(makeError(
        std::errc::value_too_large,
        "a policy may declare at most ",
        std::to_string(BPFJ_VAR_ID_SLOTS - 1),
        " vars, got ",
        std::to_string(names.size())));
  }

  auto arena = PodArena::open(cfg);
  if (!arena) {
    return makeUnexpected(arena.error());
  }

  auto catalogMap = openVarCatalogMap(cfg);
  if (!catalogMap) {
    return makeUnexpected(catalogMap.error());
  }

  auto oldCatalog = readVarCatalogPointer(*catalogMap);
  if (!oldCatalog) {
    return makeUnexpected(oldCatalog.error());
  }

  struct bpfj_var_catalog* published = nullptr;
  if (!names.empty()) {
    auto blob = arena->alloc(varCatalogAllocSize(names));
    if (!blob) {
      return makeUnexpected(blob.error());
    }

    auto* catalog = static_cast<struct bpfj_var_catalog*>(*blob);
    *catalog = {};
    catalog->count = static_cast<__u32>(names.size());

    std::uint32_t nameOff = bpfj_var_align_up(sizeof(struct bpfj_var_catalog));
    for (std::size_t i = 0; i < names.size(); ++i) {
      const auto& name = names[i];
      auto* stored = static_cast<char*>(*blob) + nameOff;
      std::memcpy(stored, name.data(), name.size());
      stored[name.size()] = '\0';
      catalog->names[i + 1] = stored;
      nameOff += bpfj_var_align_up(static_cast<__u32>(name.size()) + 1);
    }

    published = catalog;
  }

  const std::uint32_t slot = 0;
  if (::bpf_map_update_elem(catalogMap->get(), &slot, &published, BPF_ANY) !=
      0) {
    if (published != nullptr) {
      (void)arena->free(published);
    }
    return makeUnexpected(
        makeErrnoError("failed to publish variable allowlist catalog"));
  }

  if (*oldCatalog != nullptr) {
    (void)arena->free(const_cast<struct bpfj_var_catalog*>(*oldCatalog));
  }

  return unit;
}

Expected<const struct bpfj_var_catalog*> readVarCatalog(
    const PinConfig& cfg,
    const PodArena& arena) noexcept {
  if (!arena.valid()) {
    return makeUnexpected(makeError(
        std::errc::bad_address, "variable catalog read needs an open arena"));
  }

  auto catalogMap = openVarCatalogMap(cfg);
  if (!catalogMap) {
    return makeUnexpected(catalogMap.error());
  }

  return readVarCatalogPointer(*catalogMap);
}

Expected<ResolvedPolicyVar> lookupVar(
    const struct bpfj_var_catalog* catalog,
    std::string_view name) noexcept {
  if (name.empty()) {
    return makeUnexpected(
        makeError(std::errc::invalid_argument, "a variable name is empty"));
  }

  const std::uint32_t count = catalog == nullptr
      ? 0
      : std::min<std::uint32_t>(catalog->count, BPFJ_VAR_ID_SLOTS - 1);
  for (std::uint32_t id = 1; id <= count; ++id) {
    const char* published = catalog->names[id];
    if (published != nullptr && std::string_view(published) == name) {
      return ResolvedPolicyVar{.id = id, .name = published};
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
