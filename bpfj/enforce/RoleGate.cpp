// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "bpfj/enforce/RoleGate.h"

#include <cstdint>

#include "bpfj/enforce/Pins.h"
#include "bpfj/libbpf-cpp/BpfMap.h"

namespace bpfjailer {

namespace {

// Role-keyed, so bounded by the host's roles rather than the processes under
// them. The access map holds one entry per permitted (actor, target) pair,
// bounded by the roles squared but in practice by how much policy is written.
constexpr std::uint32_t kMaxRoles = 1024;
constexpr std::uint32_t kMaxAccessPairs = 4096;

// Presence is the whole signal on both maps, so the value is a placeholder.
constexpr std::uint8_t kSet = 1;

} // namespace

namespace gate {

Expected<> pinMaps(
    bpfj::libbpf::BpfSkelBase& skel,
    const RoleGate& gate,
    const std::filesystem::path& mapDir) noexcept {
  if (auto res = pins::pinMap(skel, gate.rolesMap, mapDir, kMaxRoles); !res) {
    return res;
  }

  return pins::pinMap(skel, gate.accessMap, mapDir, kMaxAccessPairs);
}

Expected<> writePolicy(
    bpfj::libbpf::BpfSkelBase& skel,
    const RoleGate& gate,
    const Policy& policy) noexcept {
  auto roles = skel.getMap(gate.rolesMap.data());
  auto access = skel.getMap(gate.accessMap.data());
  if (!roles || !access) {
    return makeUnexpected(makeError(
        std::errc::no_such_file_or_directory,
        "gate maps ",
        gate.rolesMap,
        " and ",
        gate.accessMap,
        " are missing"));
  }

  for (const auto& [name, rolePolicy] : policy.roles) {
    if (!(rolePolicy.*gate.configured)) {
      continue;
    }

    auto actor = makeRoleId(name);
    if (!actor) {
      return makeUnexpected(actor.error());
    }

    if (auto res = roles->updateElem(*actor, kSet); !res) {
      return res;
    }

    for (const auto& targetRole : rolePolicy.*gate.targets) {
      auto target = makeRoleId(targetRole);
      if (!target) {
        return makeUnexpected(target.error());
      }

      RolePair key{};
      key.actor = *actor;
      key.target = *target;

      if (auto res = access->updateElem(key, kSet); !res) {
        return res;
      }
    }
  }

  return unit;
}

} // namespace gate
} // namespace bpfjailer
