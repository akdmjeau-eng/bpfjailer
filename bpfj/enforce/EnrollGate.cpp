// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "bpfj/enforce/EnrollGate.h"

#include "bpfj/enforce/PodVars.h"
#include "bpfj/enforce/Pods.h"

namespace bpfjailer {

namespace {

bool contains(
    const struct bpfj_role_set* set,
    const struct bpfj_role_policy* policy) noexcept {
  if (!set) {
    return false;
  }
  for (std::size_t i = 0; i < set->count; ++i) {
    if (set->policies[i] == policy) {
      return true;
    }
  }
  return false;
}

} // namespace

Expected<bool> enrollPermitted(
    const PinConfig& cfg,
    pid_t pid,
    std::string_view role) noexcept {
  auto arena = PodArena::open(cfg);
  if (!arena) {
    return makeUnexpected(arena.error());
  }
  auto policies = readRolePolicies(*arena);
  if (!policies) {
    return makeUnexpected(policies.error());
  }
  auto targetPolicy = lookupRolePolicy(*policies, role);
  if (!targetPolicy) {
    return makeUnexpected(targetPolicy.error());
  }
  if (!*targetPolicy) {
    return false;
  }

  auto pods = listPods(cfg, pid);
  if (!pods) {
    return makeUnexpected(pods.error());
  }

  // Oldest first, as bpfj_pid_data holds them, so walked backwards to match
  // the order every enforcer reads a task's roles in.
  for (auto pod = pods->rbegin(); pod != pods->rend(); ++pod) {
    const auto* policy = pod->policy;
    if (!policy) {
      return false;
    }
    if (policy->enroll_mode == BPFJ_POLICY_DENY) {
      return false;
    }
    if (policy->enroll_mode == BPFJ_POLICY_ROLES) {
      const auto* set = policy->gates[BPFJ_POLICY_GATE_ENROLL];
      if (!contains(set, *targetPolicy)) {
        return false;
      }
    }

    if (policy->flags & BPFJ_POLICY_OVERRIDE_STACKED) {
      break;
    }
  }

  return true;
}

} // namespace bpfjailer
