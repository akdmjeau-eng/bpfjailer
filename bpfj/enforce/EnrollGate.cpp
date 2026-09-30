// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "bpfj/enforce/EnrollGate.h"

#include <bpf/bpf.h>

#include <cerrno>
#include <cstdint>
#include <string>

#include "bpfj/enforce/Pods.h"
#include "bpfj/enforce/RoleGate.h"

namespace bpfjailer {

namespace {

constexpr std::string_view kEnrollRoles = "bpfj_enroll_roles";
constexpr std::string_view kEnrollAccess = "bpfj_enroll_access";
constexpr std::string_view kOverrideMap = "bpfj_pod_override_map";

/// @brief Whether `map` holds a non-zero entry under `key`.
template <typename Key>
[[nodiscard]] Expected<bool>
holds(const Fd& map, const Key& key, std::string_view name) noexcept {
  std::uint8_t value = 0;
  if (::bpf_map_lookup_elem(map.get(), &key, &value) == 0) {
    return value != 0;
  }

  if (errno == ENOENT) {
    return false;
  }

  return makeUnexpected(makeErrnoError("failed to read ", name));
}

} // namespace

Expected<bool> enrollPermitted(
    const PinConfig& cfg,
    pid_t pid,
    std::string_view role) noexcept {
  auto target = makeRoleId(std::string(role));
  if (!target) {
    return makeUnexpected(target.error());
  }

  auto roles = pins::openPinnedMap(cfg, kEnrollRoles);
  if (!roles) {
    return makeUnexpected(roles.error());
  }

  auto access = pins::openPinnedMap(cfg, kEnrollAccess);
  if (!access) {
    return makeUnexpected(access.error());
  }

  auto overrides = pins::openPinnedMap(cfg, kOverrideMap);
  if (!overrides) {
    return makeUnexpected(overrides.error());
  }

  auto pods = listPods(cfg, pid);
  if (!pods) {
    return makeUnexpected(pods.error());
  }

  // Oldest first, as bpfj_pid_data holds them, so walked backwards to match
  // the order every enforcer reads a task's roles in.
  for (auto pod = pods->rbegin(); pod != pods->rend(); ++pod) {
    auto configured = holds(*roles, pod->role_id, kEnrollRoles);
    if (!configured) {
      return makeUnexpected(configured.error());
    }

    if (*configured) {
      RolePair key{};
      key.actor = pod->role_id;
      key.target = *target;

      auto listed = holds(*access, key, kEnrollAccess);
      if (!listed) {
        return makeUnexpected(listed.error());
      }

      if (!*listed) {
        return false;
      }
    }

    auto overriding = holds(*overrides, pod->role_id, kOverrideMap);
    if (!overriding) {
      return makeUnexpected(overriding.error());
    }

    if (*overriding) {
      break;
    }
  }

  return true;
}

} // namespace bpfjailer
