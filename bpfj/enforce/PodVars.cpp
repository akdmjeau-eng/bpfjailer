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

[[nodiscard]] std::uint32_t varCatalogAllocSize(
    std::span<const std::string> names) noexcept {
  std::uint32_t size = bpfj_var_align_up(
      offsetof(struct bpfj_var_catalog, names) +
      sizeof(struct bpfj_var_name*) * names.size());
  for (const auto& name : names) {
    size += bpfj_var_align_up(
        offsetof(struct bpfj_var_name, str) + static_cast<__u32>(name.size()) +
        1);
  }
  return size;
}

[[nodiscard]] const struct bpfj_var_catalog* readVarCatalogPointer(
    const PodArena& arena) noexcept {
  const auto* ctrl = arena.ctrl();
  return ctrl == nullptr
      ? nullptr
      : static_cast<const struct bpfj_var_catalog*>(ctrl->var_catalog);
}

Expected<> publishVarNames(
    const PinConfig& cfg,
    std::span<const std::string> names) noexcept {
  auto arena = PodArena::open(cfg);
  if (!arena) {
    return makeUnexpected(arena.error());
  }

  auto* oldCatalog =
      const_cast<struct bpfj_var_catalog*>(readVarCatalogPointer(*arena));

  struct bpfj_var_catalog* published = nullptr;
  if (!names.empty()) {
    auto blob = arena->alloc(varCatalogAllocSize(names));
    if (!blob) {
      return makeUnexpected(blob.error());
    }

    auto* catalog = static_cast<struct bpfj_var_catalog*>(*blob);
    *catalog = {};
    catalog->count = static_cast<__u32>(names.size());
    auto* publishedNames = bpfj_var_catalog_names_mut(catalog);

    std::uint32_t nameOff = bpfj_var_align_up(
        offsetof(struct bpfj_var_catalog, names) +
        sizeof(struct bpfj_var_name*) * names.size());
    for (std::size_t i = 0; i < names.size(); ++i) {
      const auto& name = names[i];
      auto* stored = reinterpret_cast<struct bpfj_var_name*>(
          static_cast<char*>(*blob) + nameOff);
      stored->id = static_cast<__u32>(i + 1);
      stored->len = static_cast<__u32>(name.size());
      std::memcpy(stored->str, name.data(), name.size());
      stored->str[name.size()] = '\0';
      publishedNames[i] = stored;
      nameOff += bpfj_var_align_up(
          offsetof(struct bpfj_var_name, str) + stored->len + 1);
    }

    published = catalog;
  }

  arena->ctrl()->var_catalog = published;

  if (oldCatalog != nullptr) {
    (void)arena->free(oldCatalog);
  }

  return unit;
}

Expected<const struct bpfj_var_catalog*> readVarCatalog(
    const PodArena& arena) noexcept {
  if (!arena.valid()) {
    return makeUnexpected(makeError(
        std::errc::bad_address, "variable catalog read needs an open arena"));
  }

  return readVarCatalogPointer(arena);
}

Expected<ResolvedPolicyVar> lookupVar(
    const struct bpfj_var_catalog* catalog,
    std::string_view name) noexcept {
  if (name.empty()) {
    return makeUnexpected(
        makeError(std::errc::invalid_argument, "a variable name is empty"));
  }

  const std::uint32_t count = catalog == nullptr ? 0 : catalog->count;
  const auto* publishedNames = bpfj_var_catalog_names(catalog);
  for (std::uint32_t at = 0; at < count; ++at) {
    const auto* published = publishedNames[at];
    if (published != nullptr && published->len == name.size() &&
        std::string_view(published->str, published->len) == name) {
      return ResolvedPolicyVar{.id = published->id, .name = published};
    }
  }

  return makeUnexpected(makeError(
      std::errc::invalid_argument,
      "no variable named ",
      name,
      " is published in this jail"));
}

struct bpfj_heap_control* PodArena::ctrl() noexcept {
  return reinterpret_cast<struct bpfj_heap_control*>(base_);
}

const struct bpfj_heap_control* PodArena::ctrl() const noexcept {
  return reinterpret_cast<const struct bpfj_heap_control*>(base_);
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
