// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

#include "bpfj/enforce/RoleId.h"
#include "bpfj/err/Error.h"
#include "bpfj/libbpf-cpp/BpfSkelBase.h"
#include "bpfj/policy/Policy.h"

namespace bpfjailer {

/// @brief The key of a gate's access map. Mirrors `bpfj_role_pair`.
struct RolePair {
  struct bpfj_role_id actor;
  struct bpfj_role_id target;
};

/// @brief Which maps a role-pair gate lives in, and which policy field fills
/// them, so an enforcer need only name its two maps and the two `RolePolicy`
/// members holding its list; `bpfj/enforce/bpf/role_gate.h` is the BPF side.
struct RoleGate {
  /// @brief The map holding one entry per role that wrote its list.
  std::string_view rolesMap;

  /// @brief The map holding one entry per permitted (actor, target) pair.
  std::string_view accessMap;

  /// @brief Whether the role wrote the list at all, e.g. `hasKill`.
  bool RolePolicy::* configured;

  /// @brief The list itself, e.g. `kill`.
  std::vector<std::string> RolePolicy::* targets;
};

namespace gate {

/// @brief Size and pin the gate's two maps. Must run before load(), like any
/// pinned map: libbpf creates the pin as part of map creation.
[[nodiscard]] Expected<> pinMaps(
    bpfj::libbpf::BpfSkelBase& skel,
    const RoleGate& gate,
    const std::filesystem::path& mapDir) noexcept;

/// @brief Fill the gate's maps from `policy`. A role appears in the roles map
/// only if it wrote its list at all, the BPF side reading absence as
/// unrestricted, and an empty list writes the entry with no pairs. Must run
/// after load() and before attach(), so no hook reads a half-written policy.
[[nodiscard]] Expected<> writePolicy(
    bpfj::libbpf::BpfSkelBase& skel,
    const RoleGate& gate,
    const Policy& policy) noexcept;

} // namespace gate
} // namespace bpfjailer
