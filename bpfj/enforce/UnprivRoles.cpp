// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "bpfj/enforce/UnprivRoles.h"

#include <cstring>
#include <string>

#include "bpfj/enforce/PodVars.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#include "bpfj/enforce/bpf/types.h"
#pragma GCC diagnostic pop

namespace bpfjailer {

/// @brief `name` as a map key, rejecting one too long to be represented.
[[nodiscard]] Expected<bpfj_role_id> makeRoleKey(
    std::string_view name) noexcept {
  if (name.empty()) {
    return makeUnexpected(
        makeError(std::errc::invalid_argument, "a role id is empty"));
  }

  // Truncating instead would silently map two different roles onto one key,
  // and the shorter of them would inherit the other's access.
  if (name.size() >= ROLE_ID_LEN) {
    return makeUnexpected(makeError(
        std::errc::value_too_large,
        "role '",
        name,
        "' must be at most ",
        std::to_string(ROLE_ID_LEN - 1),
        " characters"));
  }

  bpfj_role_id key{};
  std::memcpy(key.id, name.data(), name.size());
  return key;
}

Expected<bool> unprivEnrollAllowed(
    const PinConfig& cfg,
    std::string_view role) noexcept {
  auto key = makeRoleKey(role);
  if (!key) {
    return makeUnexpected(key.error());
  }

  auto arena = PodArena::open(cfg);
  if (!arena) {
    return makeUnexpected(arena.error());
  }
  auto rolePolicies = pins::openPinnedMap(cfg, "bpfj_role_policies");
  if (!rolePolicies) {
    return makeUnexpected(rolePolicies.error());
  }
  auto policy = lookupRolePolicy(*rolePolicies, *key);
  if (!policy) {
    return makeUnexpected(policy.error());
  }
  return *policy && ((*policy)->flags & BPFJ_POLICY_UNPRIV_ENROLL);
}

} // namespace bpfjailer
