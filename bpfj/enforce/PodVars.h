// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "bpfj/enforce/Pins.h"
#include "bpfj/err/Error.h"
#include "bpfj/lib/Fd.h"

namespace bpfjailer {

/// @brief A pod variable as a caller spells it, before its id is resolved.
struct PodVar {
  std::string name;
  std::string value;
};

/// @brief Open the pinned bpfj_var_map.
[[nodiscard]] Expected<Fd> openVarMap(const PinConfig& cfg) noexcept;

/// @brief Publish the policy's `vars` into the pinned bpfj_var_map. A name's id
/// is its 1-based position in `names`, so an unused slot reads back as the
/// empty name. The published list is the whole allowlist: an enrollment that
/// names anything else fails to resolve. A bpfj_var carries the id, not the
/// name, and this map lets processes that never talk to each other agree on
/// what id 1 means. bpfjsrv is a fresh process for each connection. Ids are
/// positions, so a different policy can renumber them. A replace therefore
/// translates ids by name (see readVarNames()).
[[nodiscard]] Expected<> publishVarNames(
    const PinConfig& cfg,
    std::span<const std::string> names) noexcept;

/// @brief Every name in `varMap`, indexed by id. An unused id reads back
/// empty.
[[nodiscard]] Expected<std::vector<std::string>> readVarNames(
    const Fd& varMap) noexcept;

/// @brief The id `name` was published under in `varMap`, read back from the
/// map so the answer is the running jail's rather than whatever policy this
/// binary last saw.
[[nodiscard]] Expected<std::uint32_t> lookupVarId(
    const Fd& varMap,
    std::string_view name) noexcept;

/// @brief mmap of the jail's pinned arena map, at the fixed slot its map_extra
/// records, for the pod-owned flat var blobs stored by pointer in bpfj_pod.
class PodArena {
 public:
  PodArena() noexcept = default;
  ~PodArena() noexcept;

  PodArena(const PodArena&) = delete;
  PodArena& operator=(const PodArena&) = delete;
  PodArena(PodArena&& other) noexcept;
  PodArena& operator=(PodArena&& other) noexcept;

  [[nodiscard]] static Expected<PodArena> open(const PinConfig& cfg) noexcept;

  [[nodiscard]] void* base() const noexcept {
    return base_;
  }

  [[nodiscard]] bool valid() const noexcept {
    return base_ != nullptr;
  }

  [[nodiscard]] Expected<void*> alloc(std::uint32_t size) noexcept;
  [[nodiscard]] Expected<> free(void* ptr) noexcept;

 private:
  void reset() noexcept;

  std::shared_ptr<void> owner_;
  void* base_ = nullptr;
  std::uint64_t mapExtra_ = 0;
};

} // namespace bpfjailer
