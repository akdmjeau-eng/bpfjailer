// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include "bpfj/enforce/bpf/maps.h"
#include "bpfj/enforce/bpf/role_gate.h"
#include "bpfj/enforce/bpf/types.h"

static __always_inline bool bpfj_mq_uuid_equal(
    const struct bpfj_uuid* a,
    const struct bpfj_uuid* b) {
  const __u64* aw = (const __u64*)a->uuid;
  const __u64* bw = (const __u64*)b->uuid;
  return aw[0] == bw[0] && aw[1] == bw[1];
}

/// Snapshot the creator's newest pod into an owner record. An unjailed task
/// deliberately produces no owner: restricted actors subsequently treat the
/// missing record as unknown, while unconfigured actors remain unrestricted.
static __always_inline bool bpfj_mq_current_owner(struct bpfj_mq_owner* owner) {
  struct bpfj_pid_data* pid_data = bpfj_get_current_pid_data();
  if (!pid_data || pid_data->num_pods == 0) {
    return false;
  }

  __u32 index = pid_data->num_pods - 1;
  if (index >= BPFJ_MAX_POD_PER_PID) {
    index = BPFJ_MAX_POD_PER_PID - 1;
  }
  void* pod_pointer = (void*)pid_data->pods[index];
  if (!pod_pointer) {
    return false;
  }
  barrier_var(pod_pointer);
  struct bpfj_pod __arena* pod =
      (struct bpfj_pod __arena*)(uintptr_t)pod_pointer;

  bpfj_pod_read_role_id(&owner->role, pod);
  bpfj_pod_read_uuid(&owner->pod, pod);
  owner->policy = bpfj_pod_policy(pod);
  if (!owner->policy) {
    return false;
  }
  return true;
}

/// Apply one of the independent mq-sysv/mq-posix gates. Every configured
/// actor role must permit the owner; an empty list therefore permits only the
/// exact creating pod. Roles absent from the map abstain, unless an override
/// role ends the walk. Missing ownership is denied whenever any applicable
/// role is configured, and allowed when none is.
static __always_inline bool bpfj_mq_allowed(
    enum bpfj_policy_gate gate,
    struct bpfj_pid_data* actor,
    const struct bpfj_mq_owner* owner) {
  if (!actor) {
    return true;
  }

  const __u32 num_pods = bpfj_gate_num_pods(actor);
  for (int i = BPFJ_MAX_POD_PER_PID - 1; i >= 0; --i) {
    if (i >= num_pods) {
      continue;
    }

    struct bpfj_pod __arena* pod = actor->pods[i];
    if (!pod) {
      continue;
    }

    struct bpfj_uuid actor_pod = {};
    bpfj_pod_read_uuid(&actor_pod, pod);
    const struct bpfj_role_policy __arena* policy = bpfj_pod_policy(pod);
    if (!policy) {
      return false;
    }
    const __u8 mode = gate == BPFJ_POLICY_GATE_MQ_SYSV ? policy->mq_sysv_mode
                                                       : policy->mq_posix_mode;
    if (mode != BPFJ_POLICY_UNCONFIGURED) {
      if (mode == BPFJ_POLICY_DENY || !owner) {
        return false;
      }

      if (!bpfj_mq_uuid_equal(&actor_pod, &owner->pod) &&
          !bpfj_role_set_contains(policy->gates[gate], owner->policy)) {
        return false;
      }
    }

    if (bpfj_is_override(pod)) {
      break;
    }
  }

  return true;
}
