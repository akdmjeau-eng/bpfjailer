// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "bpfj/enforce/UnprivRoles.h"

#include "bpfj/enforce/PodVars.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#include "bpfj/enforce/bpf/types.h"
#pragma GCC diagnostic pop

namespace bpfjailer {

Expected<bool> unprivEnrollAllowed(
    const PinConfig& cfg,
    std::string_view role) noexcept {
  auto arena = PodArena::open(cfg);
  if (!arena) {
    return makeUnexpected(arena.error());
  }
  auto policies = readRolePolicies(*arena);
  if (!policies) {
    return makeUnexpected(policies.error());
  }
  auto policy = lookupRolePolicy(*policies, role);
  if (!policy) {
    return makeUnexpected(policy.error());
  }
  return *policy && ((*policy)->flags & BPFJ_POLICY_UNPRIV_ENROLL);
}

} // namespace bpfjailer
