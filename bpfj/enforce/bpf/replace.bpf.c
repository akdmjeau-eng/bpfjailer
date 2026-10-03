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

struct bpfj_replace_pod {
  struct bpfj_pod __arena* pod;
};

struct bpfj_replace_pod_key {
  struct bpfj_pod __arena* old_pod;
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 4096);
  __type(key, struct bpfj_replace_pod_key);
  __type(value, struct bpfj_replace_pod);
} bpfj_replace_pods SEC(".maps");

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

// Persisted pod references for which userspace supplied no translation.
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, __u64);
} bpfj_replace_unmapped SEC(".maps");

// Task-storage entries whose persisted value layout this build cannot read.
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, __u64);
} bpfj_replace_incompatible SEC(".maps");

static __always_inline void bpfj_replace_count(void* counter) {
  const __u32 zero = 0;
  __u64* n = bpf_map_lookup_elem(counter, &zero);
  if (n) {
    __sync_fetch_and_add(n, 1);
  }
}

/// Whether `pid_data` already names `pod`.
static __always_inline bool bpfj_replace_holds(
    struct bpfj_pid_data* pid_data,
    struct bpfj_pod __arena* pod) {
  __u32 num_pods = pid_data->num_pods;
  if (num_pods > BPFJ_MAX_POD_PER_PID) {
    num_pods = BPFJ_MAX_POD_PER_PID;
  }
  barrier_var(num_pods);

  for (int i = 0; i < BPFJ_MAX_POD_PER_PID; ++i) {
    if (i >= num_pods) {
      break;
    }

    if (bpfj_pod_ptr_cmp(pid_data->pods[i], pod) == 0) {
      return true;
    }
  }

  return false;
}

/// Add `pod` to `pid_data` and take a reference on it.
/// @return false if there was no room, the caller's cue to fail the replace
///         rather than let the task through with a narrower jail.
static __always_inline bool bpfj_replace_add(
    struct bpfj_pid_data* pid_data,
    struct bpfj_pod __arena* pod) {
  __u32 slot = pid_data->num_pods;
  if (slot >= BPFJ_MAX_POD_PER_PID) {
    return false;
  }
  barrier_var(slot);
  pid_data->pods[slot] = pod;
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

  if (old->version != BPFJ_PID_DATA_VERSION) {
    bpfj_replace_count(&bpfj_replace_incompatible);
    bpfj_replace_count(&bpfj_replace_failed);
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

    struct bpfj_pod __arena* old_pod = old->pods[i];
    if (!old_pod) {
      continue;
    }

    struct bpfj_replace_pod_key key = {.old_pod = old_pod};
    struct bpfj_replace_pod* translated =
        bpf_map_lookup_elem(&bpfj_replace_pods, &key);
    if (!translated) {
      bpfj_replace_count(&bpfj_replace_unmapped);
      lost = true;
      continue;
    }
    // Userspace records the old base-role pod as an intentional tombstone:
    // the new tree has already seeded its replacement.
    if (!translated->pod) {
      continue;
    }

    if (bpfj_replace_holds(new_data, translated->pod)) {
      continue;
    }

    if (!bpfj_replace_add(new_data, translated->pod)) {
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
