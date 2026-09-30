// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

// May a process in these roles act on a process in those roles? The signal
// enforcer asks it of `kill` and the ptrace enforcer of `ptrace`, so the rule
// lives here and each enforcer supplies its own two maps:
//
//   roles    one entry per role that wrote its list, an empty list included.
//   access   one entry per (actor, target) role pair the lists permit.
//
// Which gives a role three states:
//
//   list absent    unrestricted
//   list empty     may act only inside its own pod
//   list [a, b]    that, and on a process whose roles are all in {a, b}
//
// Acting inside the restricting role's *own* pod is always allowed, a pod
// being one jail instance -- not any pod the two share, since a base role puts
// the whole host in one and the list would then never deny anything.
//
// Where the actor holds several roles, every configured one has to permit,
// walking newest first and stopping after the first override role; an
// unconfigured role abstains rather than granting or denying. The target is
// read the other way round, every role it holds having to be listed, or
// picking up a listed role alongside the one protecting it is an escalation --
// which is also why a restricted actor cannot reach a target in no pod at all.

#include "bpfj/enforce/bpf/maps.h"
#include "bpfj/enforce/bpf/types.h"

// The access map's key, flat rather than a map of maps keyed on the actor so
// userspace fills it with the update call it already has.
struct bpfj_role_pair {
  struct bpfj_role_id actor;
  struct bpfj_role_id target;
};

static __always_inline __u32
bpfj_gate_num_pods(const struct bpfj_pid_data* pid_data) {
  const __u32 num_pods = pid_data->num_pods;
  return num_pods > BPFJ_MAX_POD_PER_PID ? BPFJ_MAX_POD_PER_PID : num_pods;
}

/// Whether `pid_data` names the pod `uuid`.
static __always_inline bool bpfj_gate_in_pod(
    struct bpfj_pid_data* pid_data,
    const struct bpfj_uuid* uuid) {
  const __u32 num_pods = bpfj_gate_num_pods(pid_data);

  for (int i = 0; i < BPFJ_MAX_POD_PER_PID; ++i) {
    if (i >= num_pods) {
      break;
    }

    if (bpfj_uuid_cmp(&pid_data->pod_uuids[i], uuid) == 0) {
      return true;
    }
  }

  return false;
}

/// Whether `actor_role`'s list names every role the target holds. A pod
/// missing from the pod map leaves a role this cannot check, so it denies.
/// Deliberately does not stop on bpfj_is_override(): every role here has to be
/// covered, and breaking early would let a target escape a gate by holding an
/// override role.
static __always_inline bool bpfj_gate_covers(
    void* access,
    const struct bpfj_role_id* actor_role,
    struct bpfj_pid_data* target) {
  const __u32 num_pods = bpfj_gate_num_pods(target);
  if (num_pods == 0) {
    return false;
  }

  for (int i = 0; i < BPFJ_MAX_POD_PER_PID; ++i) {
    if (i >= num_pods) {
      break;
    }

    struct bpfj_pod* pod =
        bpf_map_lookup_elem(&bpfj_pod_map, &target->pod_uuids[i]);
    if (!pod) {
      return false;
    }

    struct bpfj_role_pair key = {};
    __builtin_memcpy(&key.actor, actor_role, sizeof(key.actor));
    __builtin_memcpy(&key.target, &pod->role_id, sizeof(key.target));

    if (!bpf_map_lookup_elem(access, &key)) {
      return false;
    }
  }

  return true;
}

/// Whether the actor may act on something `owner` owns, under the gate
/// `roles`/`access`. The object form of bpfj_gate_allowed(): the target
/// belongs to exactly one role, so naming that role is the whole test and the
/// own-pod exemption becomes an own-role one.
static __always_inline bool bpfj_gate_allowed_owner(
    void* roles,
    void* access,
    struct bpfj_pid_data* actor,
    const struct bpfj_role_id* owner) {
  if (!actor) {
    return true;
  }

  const __u32 num_pods = bpfj_gate_num_pods(actor);
  // Newest role first, down to the base. See bpfj_is_override() in maps.h.
  for (int i = BPFJ_MAX_POD_PER_PID - 1; i >= 0; --i) {
    if (i >= num_pods) {
      continue;
    }

    struct bpfj_pod* pod =
        bpf_map_lookup_elem(&bpfj_pod_map, &actor->pod_uuids[i]);
    if (!pod) {
      continue;
    }

    if (bpf_map_lookup_elem(roles, &pod->role_id) &&
        bpfj_role_id_cmp(&pod->role_id, owner) != 0) {
      struct bpfj_role_pair key = {};
      __builtin_memcpy(&key.actor, &pod->role_id, sizeof(key.actor));
      __builtin_memcpy(&key.target, owner, sizeof(key.target));

      if (!bpf_map_lookup_elem(access, &key)) {
        return false;
      }
    }

    // Checked for every pod, configured or not: an override role that wrote no
    // list still answers for the task, and the answer is "unrestricted".
    if (bpfj_is_override(&pod->role_id)) {
      break;
    }
  }

  return true;
}

/// Whether any role the actor holds wrote a list.
static __always_inline bool bpfj_gate_restricted(
    void* roles,
    struct bpfj_pid_data* actor) {
  const __u32 num_pods = bpfj_gate_num_pods(actor);

  // Newest role first, down to the base. See bpfj_is_override() in maps.h.
  for (int i = BPFJ_MAX_POD_PER_PID - 1; i >= 0; --i) {
    if (i >= num_pods) {
      continue;
    }

    struct bpfj_pod* pod =
        bpf_map_lookup_elem(&bpfj_pod_map, &actor->pod_uuids[i]);
    if (!pod) {
      continue;
    }

    if (bpf_map_lookup_elem(roles, &pod->role_id)) {
      return true;
    }

    if (bpfj_is_override(&pod->role_id)) {
      break;
    }
  }

  return false;
}

/// Whether the actor may act on the target, under the gate `roles`/`access`.
/// Either side may be NULL, meaning a process the jailer knows nothing about:
/// no policy applies to such an actor, and such a target is reachable only by
/// an unrestricted one.
static __always_inline bool bpfj_gate_allowed(
    void* roles,
    void* access,
    struct bpfj_pid_data* actor,
    struct bpfj_pid_data* target) {
  if (!actor) {
    return true;
  }

  // Answered here rather than inside the walk below: clang hoists the address
  // of the target's uuids out of that loop, above a nested null test, and the
  // verifier rejects arithmetic on an unchecked pointer.
  if (!target) {
    return !bpfj_gate_restricted(roles, actor);
  }

  const __u32 num_pods = bpfj_gate_num_pods(actor);
  // Newest role first, down to the base. See bpfj_is_override() in maps.h.
  for (int i = BPFJ_MAX_POD_PER_PID - 1; i >= 0; --i) {
    if (i >= num_pods) {
      continue;
    }

    struct bpfj_pod* pod =
        bpf_map_lookup_elem(&bpfj_pod_map, &actor->pod_uuids[i]);
    if (!pod) {
      continue;
    }

    if (bpf_map_lookup_elem(roles, &pod->role_id) &&
        !bpfj_gate_in_pod(target, &actor->pod_uuids[i]) &&
        !bpfj_gate_covers(access, &pod->role_id, target)) {
      return false;
    }

    // As above: an override role that wrote no list still answers.
    if (bpfj_is_override(&pod->role_id)) {
      break;
    }
  }

  return true;
}
