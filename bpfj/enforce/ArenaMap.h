// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include <cstdint>
#include <filesystem>

#include "bpfj/err/Error.h"
#include "bpfj/lib/Fd.h"
#include "bpfj/lib/bpf/types_heap.h"
#include "bpfj/libbpf-cpp/BpfSkelBase.h"

namespace bpfjailer::arena {

inline constexpr std::uint64_t kWindowBase = 0x500000000000ULL;
inline constexpr std::uint64_t kSlotSize =
    static_cast<std::uint64_t>(BPFJ_HEAP_ARENA_MAP_PAGES) * BPFJ_HEAP_PAGE_SIZE;
inline constexpr std::size_t kSlotCount = 8;
inline constexpr std::uint64_t kWindowSize = kSlotSize * kSlotCount;

/// Reserve the whole arena window in this process with a PROT_NONE mapping.
[[nodiscard]] Expected<> ensureWindowReserved() noexcept;

/// Validate that `extra` is one of the reserved slot base addresses.
[[nodiscard]] Expected<std::uint64_t> validateMapExtra(
    std::uint64_t extra) noexcept;

/// Read and validate the fixed mmap address recorded in a pinned arena map.
[[nodiscard]] Expected<std::uint64_t> pinnedMapExtra(const Fd& fd) noexcept;

/// Set bpfj_heap_arena's map_extra to the existing pin's slot, or pick a new
/// free slot inside the reserved window if this load is creating the map.
[[nodiscard]] Expected<> prepareMap(
    bpfj::libbpf::BpfSkelBase& skel,
    const std::filesystem::path& mapDir) noexcept;

/// Reinstall the PROT_NONE placeholder for a slot after a helper unmaps it.
[[nodiscard]] Expected<> restorePlaceholder(std::uint64_t extra) noexcept;

} // namespace bpfjailer::arena
