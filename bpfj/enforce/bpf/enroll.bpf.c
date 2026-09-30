// Copyright (c) Meta Platforms, Inc. and affiliates.

// Enroll a running process as one unpinned program the enrolling process
// loads, runs and throws away over maps adopted from the jailer's pins.
// `bpfjctl enroll` cannot do it through the pinned maps alone: bpfj_task_map
// is keyed by pidfd and pidfd_open() only accepts a thread group leader, while
// every thread is checked against its own entry.
//
// The link narrows the walk rather than this program -- the loader sets
// `link_info.task.pid`, so the tgid check below is a guard rather than a
// filter -- and the process, pod and thread mode are compiled in rather than
// read from a map, which is what makes two concurrent enrollments safe.

#include <bpf/vmlinux/vmlinux.h>

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <errno.h>

#include "bpfj/enforce/bpf/maps.h"
#include "bpfj/enforce/bpf/types.h"
#include "bpfj/lib/bpf/logging_bpf.h"

// The process to enroll, and the pod to put it in. Set before load.
volatile const pid_t bpfj_enroll_tgid = 0;
volatile const pid_t bpfj_enroll_caller_pid = 0;
volatile const __u8 bpfj_enroll_all_threads = 0;
volatile const struct bpfj_uuid bpfj_enroll_uuid;

// How many threads took it. Read back by the loader once the walk is done; it
// is what separates an enrollment that reached nothing from one that worked.
__u32 bpfj_enroll_count = 0;

// Sleepable, because a thread that has never been jailed needs an entry
// allocated; a non-sleepable iterator uses kmalloc_nolock, which can fail on
// trylock contention alone and leave a thread out of the jail.
SEC("iter.s/task")
int bpfj_enroll_threads(struct bpf_iter__task* ctx) {
  struct task_struct* task = ctx->task;
  if (!task) {
    // The final call of the walk carries no task; drop the marker that made a
    // concurrent replace wait for this enrollment to finish.
    if (bpfj_enroll_caller_pid > 0) {
      __u32 caller = (__u32)bpfj_enroll_caller_pid;
      bpf_map_delete_elem(&bpfj_active_enrolls, &caller);
    }
    return 0;
  }

  // The link already scoped this to one thread group; see the note above.
  if (bpfj_enroll_tgid == 0 || task->tgid != bpfj_enroll_tgid) {
    return 0;
  }

  if (!bpfj_enroll_all_threads && task->pid != task->tgid) {
    return 0;
  }

  struct bpfj_uuid uuid;
#pragma clang loop unroll(full)
  for (int i = 0; i < BPFJ_UUID_BYTES; ++i) {
    uuid.uuid[i] = bpfj_enroll_uuid.uuid[i];
  }

  // Looked up before the entry is created, so a pod that went away does not
  // leave an empty entry behind on a task that is not jailed.
  struct bpfj_pod* pod = bpf_map_lookup_elem(&bpfj_pod_map, &uuid);
  if (!pod) {
    BPFJ_LOG_ERR(ENOENT, "Enroll skipped for pid %d: pod missing", task->pid);
    return 0;
  }

  struct bpfj_pid_data* pid_data = bpf_task_storage_get(
      &bpfj_task_map, task, NULL, BPF_LOCAL_STORAGE_GET_F_CREATE);
  if (!pid_data) {
    BPFJ_LOG_ERR(
        ENOMEM, "Enroll skipped for pid %d: no task storage", task->pid);
    return 0;
  }

  // Already named, or no room for another. Either way nothing is owed.
  if (!bpfj_pid_data_add_uuid(pid_data, &uuid)) {
    return 0;
  }

  bpfj_pod_refs_inc(pod);

  // Atomic because the walk is not serialised against itself across CPUs.
  __sync_fetch_and_add(&bpfj_enroll_count, 1);

  return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
