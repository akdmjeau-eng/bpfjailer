// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <string_view>

#include "bpfj/enforce/Pins.h"
#include "bpfj/enforce/bpf/types.h"
#include "bpfj/err/Error.h"
#include "bpfj/lib/Fd.h"
#include "bpfj/policy/Policy.h"
#include "bpfj/var/bpf/types_var.h"

namespace bpfjailer {

class PodArena;

/// @brief A pod variable as a caller spells it, before its id is resolved.
struct PodVar {
  std::string name;
  std::string value;
};

/// @brief A policy variable resolved against the running jail's allowlist.
struct ResolvedPolicyVar {
  std::uint32_t id = 0;
  const struct bpfj_var_name* name = nullptr;
};

/// @brief Publish every role and variable as one immutable arena policy graph.
[[nodiscard]] Expected<> publishPolicyCatalog(
    const PinConfig& cfg,
    const Policy& policy) noexcept;

[[nodiscard]] Expected<const struct bpfj_policy_catalog*> readPolicyCatalog(
    const PodArena& arena) noexcept;

[[nodiscard]] Expected<const struct bpfj_role_policy*> lookupRolePolicy(
    const Fd& rolePolicies,
    std::string_view role) noexcept;

[[nodiscard]] Expected<const struct bpfj_role_policy*> lookupRolePolicy(
    const Fd& rolePolicies,
    const struct bpfj_role_id& role) noexcept;

/// @brief The running jail's shared variable allowlist, or null when the
/// policy published no variables.
[[nodiscard]] Expected<const struct bpfj_var_catalog*> readVarCatalog(
    const PodArena& arena) noexcept;

/// @brief The id and shared name pointer `name` was published under in
/// `catalog`.
[[nodiscard]] Expected<ResolvedPolicyVar> lookupVar(
    const struct bpfj_var_catalog* catalog,
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

  [[nodiscard]] struct bpfj_heap_control* ctrl() noexcept;
  [[nodiscard]] const struct bpfj_heap_control* ctrl() const noexcept;

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
