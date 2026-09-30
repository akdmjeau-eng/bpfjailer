// Copyright (c) Meta Platforms, Inc. and affiliates.

// The backfill half of `bpfjctl replace`. Userspace copies the pods, but task
// storage answers get_next_key with ENOTSUPP, so a task iterator is the only
// way to reach every task's entry. It runs after the new jailer seeded its
// base role, and merges the old membership into that rather than replacing
// it, a base role being a floor rather than an alternative.

#include <bpf/vmlinux/vmlinux.h>

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "bpfj/enforce/bpf/maps.h"
#include "bpfj/enforce/bpf/types.h"
#include "bpfj/lib/bpf/types_heap.h"

// The task map of the jailer being replaced, a second definition of maps.h's
// bpfj_task_map that must stay identical to it; libbpf compares the two before
// adopting, so drift fails the load.
struct {
  __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
  __uint(map_flags, BPF_F_NO_PREALLOC);
  __type(key, int);
  __type(value, struct bpfj_pid_data);
} bpfj_old_task_map SEC(".maps");

// Tasks that came across with their whole membership intact.
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, __u64);
} bpfj_replace_migrated SEC(".maps");

// Tasks that did not, because the entry could not be allocated or the
// membership did not fit; a non-zero count fails the replace.
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, __u64);
} bpfj_replace_failed SEC(".maps");

static __always_inline void bpfj_replace_count(void* counter) {
  const __u32 zero = 0;
  __u64* n = bpf_map_lookup_elem(counter, &zero);
  if (n) {
    __sync_fetch_and_add(n, 1);
  }
}

/// Whether `pid_data` already names `uuid`.
static __always_inline bool bpfj_replace_holds(
    struct bpfj_pid_data* pid_data,
    const struct bpfj_uuid* uuid) {
  __u32 num_pods = pid_data->num_pods;
  if (num_pods > BPFJ_MAX_POD_PER_PID) {
    num_pods = BPFJ_MAX_POD_PER_PID;
  }
  barrier_var(num_pods);

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

/// Add `uuid` to `pid_data` and take a reference on the pod it names.
/// @return false if there was no room, the caller's cue to fail the replace
///         rather than let the task through with a narrower jail.
static __always_inline bool bpfj_replace_add(
    struct bpfj_pid_data* pid_data,
    const struct bpfj_uuid* uuid,
    struct bpfj_pod* pod) {
  __u32 slot = pid_data->num_pods;
  if (slot >= BPFJ_MAX_POD_PER_PID) {
    return false;
  }
  barrier_var(slot);

  for (int i = 0; i < BPFJ_UUID_BYTES; ++i) {
    pid_data->pod_uuids[slot].uuid[i] = uuid->uuid[i];
  }
  pid_data->num_pods = slot + 1;

  // After the write, so the reference is only taken once the entry naming
  // the pod is holding it.
  bpfj_pod_refs_inc(pod);
  return true;
}

// Sleepable so creating a task storage entry allocates with GFP_KERNEL; a
// non-sleepable iterator uses kmalloc_nolock, which can fail on trylock
// contention alone and leave a task unjailed.
SEC("iter.s/task")
int bpfj_replace_backfill(struct bpf_iter__task* ctx) {
  struct task_struct* task = ctx->task;
  if (!task) {
    // The final call of the walk carries no task.
    return 0;
  }

  struct bpfj_pid_data* old = bpfj_get_pid_data_from(&bpfj_old_task_map, task);
  if (!old) {
    return 0;
  }

  // Usually already there holding the base role this tree seeded, and
  // created empty for a task the new base role does not cover.
  struct bpfj_pid_data* new_data =
      bpfj_set_pid_data_in(&bpfj_task_map, task, NULL);
  if (!new_data) {
    bpfj_replace_count(&bpfj_replace_failed);
    return 0;
  }

  __u32 num_pods = old->num_pods;
  if (num_pods > BPFJ_MAX_POD_PER_PID) {
    num_pods = BPFJ_MAX_POD_PER_PID;
  }
  barrier_var(num_pods);

  bool lost = false;
  for (int i = 0; i < BPFJ_MAX_POD_PER_PID; ++i) {
    if (i >= num_pods) {
      break;
    }

    // An unresolvable uuid is one userspace deliberately left behind, the
    // old base role; carrying it would give the task two.
    struct bpfj_pod* pod =
        bpf_map_lookup_elem(&bpfj_pod_map, &old->pod_uuids[i]);
    if (!pod) {
      continue;
    }

    if (bpfj_replace_holds(new_data, &old->pod_uuids[i])) {
      continue;
    }

    if (!bpfj_replace_add(new_data, &old->pod_uuids[i], pod)) {
      lost = true;
    }
  }

  // Not a ternary: each map is its own anonymous struct type.
  if (lost) {
    bpfj_replace_count(&bpfj_replace_failed);
  } else {
    bpfj_replace_count(&bpfj_replace_migrated);
  }
  return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
