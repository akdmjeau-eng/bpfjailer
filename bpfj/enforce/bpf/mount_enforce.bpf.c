// Copyright (c) Meta Platforms, Inc. and affiliates.

#include <bpf/vmlinux/vmlinux.h>

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <errno.h>

#include "bpfj/enforce/bpf/maps.h"
#include "bpfj/enforce/bpf/types_mount_enforce.h"
#include "bpfj/lib/bpf/logging_bpf.h"
#include "bpfj/lib/bpf/scratch.h"
#include "bpfj/match/bpf/file_match_cached.h"
#include "bpfj/match/bpf/glob_var_bindings.h"

#define MS_REMOUNT 32
#define MS_MOVE 8192
#define BPFJ_REMOUNT_RELAY_NS (100ULL * 1000 * 1000)

struct bpfj_dyn_lru __arena* bpfj_mount_match_lru;
struct bpfj_mount_cache __arena bpfj_mount_cache;

struct bpfj_remount_relay {
  __u64 sb;
  __u64 root;
  __u64 type;
  __u64 dev;
  __u64 magic;
  __u64 when;
};

struct bpfj_mount_scratch {
  struct bpfj_role_id role;
  struct bpfj_uuid uuid;
  char type[BPFJ_MOUNT_FS_TYPE_LEN];
  bool has_type;
};

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 1024);
  __type(key, __u64);
  __type(value, struct bpfj_remount_relay);
} bpfj_remount_relays SEC(".maps");

static __noinline int bpfj_mount_deny(
    struct bpfj_pod __arena* pod,
    struct task_struct* task,
    const struct bpfj_role_id* role,
    const char* operation) {
  struct bpfj_event* event = bpfj_event_reserve(BPFJ_EVENT_MOUNT, pod, task);
  bpfj_event_submit(event);
  BPFJ_LOG("Denied %s for role %s", operation, role->id);
  return -EACCES;
}

// Keep scratch-pool iteration out of the already-deep path matcher call
// chain. The claimed slot remains live in the caller until its cleanup runs.
static __noinline struct bpfj_mount_scratch* bpfj_mount_scratch_claim(
    __u32* slot) {
  return bpfj_scratch_alloc(sizeof(struct bpfj_mount_scratch), slot);
}

static __noinline bool bpfj_mount_match_allowed(
    struct bpfj_file_match_cached_state __arena* state,
    long count,
    struct bpfj_mount_scratch* scratch) {
  __s32 best_pos = -1;
  __u8 best_specificity = 0;
  struct bpfj_mount_path_entry* best = NULL;
  __u32 i;
  bpf_for(i, 0, BPFJ_FILE_MATCH_MAX_ITERS) {
    if (i >= count) {
      break;
    }
    struct bpfj_mount_path_entry* entry =
        BPFJ_FILE_MATCH_CACHED_LOOKUP(state, i);
    if (!entry) {
      continue;
    }
    const __s32 pos = BPFJ_FILE_MATCH_CACHED_GET_POS(state, i);
    if (pos > best_pos ||
        (pos == best_pos && entry->specificity > best_specificity) ||
        (pos == best_pos && entry->specificity == best_specificity &&
         !entry->types)) {
      best_pos = pos;
      best_specificity = entry->specificity;
      best = entry;
    }
  }
  if (!best) {
    return true;
  }
  if (!best->types || !scratch->has_type) {
    return false;
  }

  void __arena* found = NULL;
  return bpfj_str_map_lookup_strlen(
             best->types, scratch->type, sizeof(scratch->type), &found) == 0;
}

// The pod loop is deliberately ordinary: file_match_cached uses bpf_for,
// whose iterator state must not be nested.
static __always_inline int bpfj_mount_enforce_path(
    uintptr_t dentry,
    const char* type) {
  struct task_struct* task = bpf_get_current_task_btf();
  struct bpfj_pid_data* pid_data = bpfj_get_current_pid_data();
  if (!task || !pid_data || !dentry) {
    return 0;
  }

  __attribute__((cleanup(bpfj_scratch_release))) __u32 scratch_guard =
      BPFJ_SCRATCH_NONE;
  struct bpfj_mount_scratch* scratch = bpfj_mount_scratch_claim(&scratch_guard);
  if (!scratch) {
    return -EACCES;
  }
  __builtin_memset(scratch->type, 0, sizeof(scratch->type));
  scratch->has_type = type &&
      bpf_probe_read_kernel_str(scratch->type, sizeof(scratch->type), type) > 0;

  BPFJ_FILE_MATCH_CACHED_ALLOC(state);
  if (!state) {
    return 0;
  }
  __u32 num_pods = pid_data->num_pods;
  if (num_pods > BPFJ_MAX_POD_PER_PID) {
    num_pods = BPFJ_MAX_POD_PER_PID;
  }
  for (int index = BPFJ_MAX_POD_PER_PID - 1; index >= 0; --index) {
    if (index >= num_pods || !pid_data->pods[index]) {
      continue;
    }
    void* pod_pointer = (void*)pid_data->pods[index];
    barrier_var(pod_pointer);
    struct bpfj_pod __arena* pod =
        (struct bpfj_pod __arena*)(uintptr_t)pod_pointer;
    bpfj_pod_read_role_id(&scratch->role, pod);
    bpfj_pod_read_uuid(&scratch->uuid, pod);
    const struct bpfj_role_policy __arena* policy = bpfj_pod_policy(pod);
    struct bpfj_file_matcher __arena* matcher =
        policy ? policy->mount_matcher : NULL;
    if (matcher) {
      const long count = BPFJ_FILE_MATCH_CACHED(
          state,
          matcher,
          &bpfj_mount_cache,
          dentry,
          &scratch->uuid,
          bpfj_file_match_cached_bind_var_array,
          &pod->var_array);
      if (count > 0 && !bpfj_mount_match_allowed(state, count, scratch)) {
        return bpfj_mount_deny(pod, task, &scratch->role, "mount");
      }
      if (count < 0 && count != -EXDEV) {
        BPFJ_LOG_ERR(-count, "mount destination path match failed");
      }
    }
    if (bpfj_is_override(pod)) {
      break;
    }
  }
  return 0;
}

static __always_inline int bpfj_mount_enforce_umount(void) {
  struct task_struct* task = bpf_get_current_task_btf();
  struct bpfj_pid_data* pid_data = bpfj_get_current_pid_data();
  if (!task || !pid_data) {
    return 0;
  }
  __u32 num_pods = pid_data->num_pods;
  if (num_pods > BPFJ_MAX_POD_PER_PID) {
    num_pods = BPFJ_MAX_POD_PER_PID;
  }
  for (int index = BPFJ_MAX_POD_PER_PID - 1; index >= 0; --index) {
    if (index >= num_pods || !pid_data->pods[index]) {
      continue;
    }
    void* pod_pointer = (void*)pid_data->pods[index];
    barrier_var(pod_pointer);
    struct bpfj_pod __arena* pod =
        (struct bpfj_pod __arena*)(uintptr_t)pod_pointer;
    struct bpfj_role_id role = {};
    bpfj_pod_read_role_id(&role, pod);
    const struct bpfj_role_policy __arena* policy = bpfj_pod_policy(pod);
    if (policy && (policy->flags & BPFJ_POLICY_HAS_UMOUNT) &&
        !(policy->flags & BPFJ_POLICY_UMOUNT_ANY)) {
      return bpfj_mount_deny(pod, task, &role, "umount");
    }
    if (bpfj_is_override(pod)) {
      break;
    }
  }
  return 0;
}

static __always_inline bool bpfj_mount_has_path_policy(void) {
  struct bpfj_pid_data* pid_data = bpfj_get_current_pid_data();
  if (!pid_data) {
    return false;
  }
  __u32 num_pods = pid_data->num_pods;
  if (num_pods > BPFJ_MAX_POD_PER_PID) {
    num_pods = BPFJ_MAX_POD_PER_PID;
  }
  for (int index = BPFJ_MAX_POD_PER_PID - 1; index >= 0; --index) {
    if (index >= num_pods || !pid_data->pods[index]) {
      continue;
    }
    void* pod_pointer = (void*)pid_data->pods[index];
    barrier_var(pod_pointer);
    struct bpfj_pod __arena* pod =
        (struct bpfj_pod __arena*)(uintptr_t)pod_pointer;
    const struct bpfj_role_policy __arena* policy = bpfj_pod_policy(pod);
    if (policy && policy->mount_matcher) {
      return true;
    }
    if (bpfj_is_override(pod)) {
      break;
    }
  }
  return false;
}

static __always_inline const char* bpfj_mount_path_type(
    const struct path* path) {
  if (!path) {
    return NULL;
  }
  return BPF_CORE_READ(path, mnt, mnt_sb, s_type, name);
}

// A remount path names the mounted root. Match the covered mountpoint instead,
// which is the destination the policy author wrote and remains visible in the
// host mount snapshot used by file_match_cached.
static __always_inline struct dentry* bpfj_mount_destination(
    const struct path* path) {
  if (!path) {
    return NULL;
  }
  struct vfsmount* vfsmount = BPF_CORE_READ(path, mnt);
  if (!vfsmount) {
    return NULL;
  }
  const long offset = bpf_core_field_offset(struct mount, mnt);
  struct mount* mount = (struct mount*)((void*)vfsmount - offset);
  struct mount* parent = BPF_CORE_READ(mount, mnt_parent);
  if (parent && parent != mount) {
    return BPF_CORE_READ(mount, mnt_mountpoint);
  }
  return BPF_CORE_READ(path, dentry);
}

SEC("lsm/sb_mount")
int BPF_PROG(
    bpfj_mount_new,
    const char* dev_name,
    const struct path* path,
    const char* type,
    unsigned long flags,
    void* data,
    int lsm_ret) {
  if (lsm_ret || !path || (flags & MS_REMOUNT)) {
    return lsm_ret;
  }
  return bpfj_mount_enforce_path((uintptr_t)BPF_CORE_READ(path, dentry), type);
}

SEC("lsm/sb_mount")
int BPF_PROG(
    bpfj_mount_remount,
    const char* dev_name,
    const struct path* path,
    const char* type,
    unsigned long flags,
    void* data,
    int lsm_ret) {
  if (lsm_ret || !path || !(flags & MS_REMOUNT)) {
    return lsm_ret;
  }
  return bpfj_mount_enforce_path(
      (uintptr_t)bpfj_mount_destination(path), bpfj_mount_path_type(path));
}

SEC("lsm/sb_mount")
int BPF_PROG(
    bpfj_mount_move_source,
    const char* dev_name,
    const struct path* path,
    const char* type,
    unsigned long flags,
    void* data,
    int lsm_ret) {
  return lsm_ret || !(flags & MS_MOVE) ? lsm_ret : bpfj_mount_enforce_umount();
}

SEC("lsm/sb_mount")
int BPF_PROG(
    bpfj_mount_remount_relay,
    const char* dev_name,
    const struct path* path,
    const char* type,
    unsigned long flags,
    void* data,
    int lsm_ret) {
  if (lsm_ret || !(flags & MS_REMOUNT) || !path) {
    return lsm_ret;
  }

  struct super_block* sb = BPF_CORE_READ(path, mnt, mnt_sb);
  if (!sb) {
    return 0;
  }
  const __u64 pid_tgid = bpf_get_current_pid_tgid();
  const struct bpfj_remount_relay relay = {
      .sb = (__u64)sb,
      .root = (__u64)BPF_CORE_READ(sb, s_root),
      .type = (__u64)BPF_CORE_READ(sb, s_type),
      .dev = BPF_CORE_READ(sb, s_dev),
      .magic = BPF_CORE_READ(sb, s_magic),
      .when = bpf_ktime_get_ns(),
  };
  bpf_map_update_elem(&bpfj_remount_relays, &pid_tgid, &relay, BPF_ANY);
  return 0;
}

SEC("lsm/sb_remount")
int BPF_PROG(
    bpfj_remount,
    struct super_block* sb,
    void* mnt_opts,
    int lsm_ret) {
  if (lsm_ret || !sb || !bpfj_mount_has_path_policy()) {
    return lsm_ret;
  }
  const __u64 pid_tgid = bpf_get_current_pid_tgid();
  struct bpfj_remount_relay* relay =
      bpf_map_lookup_elem(&bpfj_remount_relays, &pid_tgid);
  const bool allowed = relay && relay->sb == (__u64)sb &&
      relay->root == (__u64)BPF_CORE_READ(sb, s_root) &&
      relay->type == (__u64)BPF_CORE_READ(sb, s_type) &&
      relay->dev == BPF_CORE_READ(sb, s_dev) &&
      relay->magic == BPF_CORE_READ(sb, s_magic) &&
      bpf_ktime_get_ns() - relay->when < BPFJ_REMOUNT_RELAY_NS;
  bpf_map_delete_elem(&bpfj_remount_relays, &pid_tgid);
  if (allowed) {
    return 0;
  }
  struct task_struct* task = bpf_get_current_task_btf();
  struct bpfj_pid_data* pid_data = bpfj_get_current_pid_data();
  if (!task || !pid_data) {
    return 0;
  }
  __u32 num_pods = pid_data->num_pods;
  if (num_pods > BPFJ_MAX_POD_PER_PID) {
    num_pods = BPFJ_MAX_POD_PER_PID;
  }
  for (int index = BPFJ_MAX_POD_PER_PID - 1; index >= 0; --index) {
    if (index >= num_pods || !pid_data->pods[index]) {
      continue;
    }
    void* pod_pointer = (void*)pid_data->pods[index];
    barrier_var(pod_pointer);
    struct bpfj_pod __arena* pod =
        (struct bpfj_pod __arena*)(uintptr_t)pod_pointer;
    struct bpfj_role_id role = {};
    bpfj_pod_read_role_id(&role, pod);
    const struct bpfj_role_policy __arena* policy = bpfj_pod_policy(pod);
    if (policy && policy->mount_matcher) {
      return bpfj_mount_deny(pod, task, &role, "remount");
    }
    if (bpfj_is_override(pod)) {
      break;
    }
  }
  return 0;
}

SEC("lsm/sb_umount")
int BPF_PROG(bpfj_umount, struct vfsmount* mnt, int flags, int lsm_ret) {
  return lsm_ret ? lsm_ret : bpfj_mount_enforce_umount();
}

SEC("lsm/move_mount")
int BPF_PROG(
    bpfj_move_mount_destination,
    const struct path* from_path,
    const struct path* to_path,
    int lsm_ret) {
  if (lsm_ret || !from_path || !to_path) {
    return lsm_ret;
  }
  return bpfj_mount_enforce_path(
      (uintptr_t)BPF_CORE_READ(to_path, dentry),
      bpfj_mount_path_type(from_path));
}

SEC("lsm/move_mount")
int BPF_PROG(
    bpfj_move_mount_source,
    const struct path* from_path,
    const struct path* to_path,
    int lsm_ret) {
  return lsm_ret ? lsm_ret : bpfj_mount_enforce_umount();
}

SEC("lsm/sb_pivotroot")
int BPF_PROG(
    bpfj_pivot_root_new,
    const struct path* old_path,
    const struct path* new_path,
    int lsm_ret) {
  if (lsm_ret || !new_path) {
    return lsm_ret;
  }
  return bpfj_mount_enforce_path(
      (uintptr_t)bpfj_mount_destination(new_path),
      bpfj_mount_path_type(new_path));
}

SEC("lsm/sb_pivotroot")
int BPF_PROG(
    bpfj_pivot_root_old,
    const struct path* old_path,
    const struct path* new_path,
    int lsm_ret) {
  return lsm_ret ? lsm_ret : bpfj_mount_enforce_umount();
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
