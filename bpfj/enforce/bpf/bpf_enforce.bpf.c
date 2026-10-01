// Copyright (c) Meta Platforms, Inc. and affiliates.

// BPF object ownership. CAP_BPF is all or nothing, so every map and program a
// *configured* role creates is recorded as owned by it and checked against the
// opener's policy afterwards. A role becomes configured by writing `bpf` or
// setting `no-bpf`, which makes this safe to turn on one role at a time:
//
//   bpf absent    may call bpf(2), may open anything unowned, may not open
//                 what a configured role owns
//   bpf empty     may call bpf(2); reaches only what its own role owns
//   bpf [a, b]    that, and what a and b own
//   no-bpf: true  may not call bpf(2) at all
//
// `untracked-bpf: true` modifies the two middle states, keeping the role held
// to its list while leaving what it creates unowned -- which is what a base
// role needs, since it would otherwise own every object on the host.

#include <bpf/vmlinux/vmlinux.h>

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <errno.h>

#include "bpfj/enforce/bpf/maps.h"
#include "bpfj/enforce/bpf/types.h"
#include "bpfj/lib/bpf/logging_bpf.h"

extern void bpf_prog_fops __ksym;
extern void bpf_map_fops __ksym;

#define BPFJ_BPF_DENY 0
#define BPFJ_BPF_ALLOW 1
#define BPFJ_BPF_ALLOW_UNTRACKED 2

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1);
  __type(key, struct bpfj_role_id);
  __type(value, __u8);
} bpfj_bpf_syscall_roles SEC(".maps");

struct bpfj_bpf_access_key {
  struct bpfj_role_id opener;
  struct bpfj_role_id owner;
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1);
  __type(key, struct bpfj_bpf_access_key);
  __type(value, __u8);
} bpfj_bpf_access SEC(".maps");

// Keyed on the kernel address of the object rather than its id; see struct
// bpfj_bpf_owner in types.h. A replace carries both maps across, since the
// seeding walk below only sees objects some task holds an fd to and a pinned
// map is held by its pin, and bpfj_bpf_owner_version says whether it can.
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1);
  __type(key, __u64);
  __type(value, struct bpfj_bpf_owner);
} bpfj_bpf_map_owners SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1);
  __type(key, __u64);
  __type(value, struct bpfj_bpf_owner);
} bpfj_bpf_prog_owners SEC(".maps");

// BPFJ_BPF_OWNER_VERSION, written by userspace at load. A map rather than
// rodata because the reader is the next build's replace, reaching in through
// the pin from another process.
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, __u32);
} bpfj_bpf_owner_version SEC(".maps");

/// Whether the caller may call bpf(2) at all: denied when any role it holds
/// says so, since `no-bpf` outranks a role that said nothing.
static __always_inline bool bpfj_bpf_syscall_allowed(
    struct bpfj_pid_data* pid_data) {
  if (!pid_data) {
    // Not jailed, so no policy applies.
    return true;
  }

  __u32 num_pods = pid_data->num_pods;
  if (num_pods > BPFJ_MAX_POD_PER_PID) {
    num_pods = BPFJ_MAX_POD_PER_PID;
  }

  // Newest role first, down to the base. See bpfj_is_override() in maps.h.
  for (int i = BPFJ_MAX_POD_PER_PID - 1; i >= 0; --i) {
    if (i >= num_pods) {
      continue;
    }

    struct bpfj_pod* pod =
        bpf_map_lookup_elem(&bpfj_pod_map, &pid_data->pod_uuids[i]);
    if (!pod) {
      continue;
    }

    __u8* mode = bpf_map_lookup_elem(&bpfj_bpf_syscall_roles, &pod->role_id);
    if (mode && *mode == BPFJ_BPF_DENY) {
      return false;
    }

    if (bpfj_is_override(&pod->role_id)) {
      break;
    }
  }

  return true;
}

/// The role that owns what this caller creates, or NULL if nothing should be
/// recorded. ALLOW_UNTRACKED is skipped rather than returned, so the walk
/// carries on to the roles under it.
static __always_inline struct bpfj_role_id* bpfj_bpf_owning_role(
    struct bpfj_pid_data* pid_data) {
  if (!pid_data) {
    return NULL;
  }

  __u32 num_pods = pid_data->num_pods;
  if (num_pods > BPFJ_MAX_POD_PER_PID) {
    num_pods = BPFJ_MAX_POD_PER_PID;
  }

  // Newest role first, so a specific role owns what it creates rather than the
  // base role every process on the host also holds.
  for (int i = BPFJ_MAX_POD_PER_PID - 1; i >= 0; --i) {
    if (i >= num_pods) {
      continue;
    }

    struct bpfj_pod* pod =
        bpf_map_lookup_elem(&bpfj_pod_map, &pid_data->pod_uuids[i]);
    if (!pod) {
      continue;
    }

    __u8* mode = bpf_map_lookup_elem(&bpfj_bpf_syscall_roles, &pod->role_id);
    if (mode && *mode == BPFJ_BPF_ALLOW) {
      return &pod->role_id;
    }

    if (bpfj_is_override(&pod->role_id)) {
      break;
    }
  }

  return NULL;
}

/// Whether the caller may open an object owned by `owner`. Every configured
/// role the walk reaches has to reach the object and at least one has to,
/// since an unconfigured role abstains rather than grants -- otherwise a role
/// could reach a protected object by leaving itself out of the policy.
static __always_inline bool bpfj_bpf_access_allowed(
    struct bpfj_pid_data* pid_data,
    const struct bpfj_role_id* owner) {
  if (!pid_data) {
    return false;
  }

  __u32 num_pods = pid_data->num_pods;
  if (num_pods > BPFJ_MAX_POD_PER_PID) {
    num_pods = BPFJ_MAX_POD_PER_PID;
  }

  bool granted = false;
  // Newest role first, down to the base. See bpfj_is_override() in maps.h.
  for (int i = BPFJ_MAX_POD_PER_PID - 1; i >= 0; --i) {
    if (i >= num_pods) {
      continue;
    }

    struct bpfj_pod* pod =
        bpf_map_lookup_elem(&bpfj_pod_map, &pid_data->pod_uuids[i]);
    if (!pod) {
      continue;
    }

    if (bpf_map_lookup_elem(&bpfj_bpf_syscall_roles, &pod->role_id)) {
      struct bpfj_bpf_access_key key = {};
      __builtin_memcpy(&key.opener, &pod->role_id, sizeof(key.opener));
      __builtin_memcpy(&key.owner, owner, sizeof(key.owner));

      // A `no-bpf` role holds no pairs, so it lands here as a denial too.
      if (!bpf_map_lookup_elem(&bpfj_bpf_access, &key)) {
        return false;
      }
      granted = true;
    }

    if (bpfj_is_override(&pod->role_id)) {
      break;
    }
  }

  return granted;
}

/// Take ownership of a newly created object on behalf of its creator. Only
/// from the create hooks, since bpf_map_new_fd also runs for a GET_FD_BY_ID
/// and an open of a pin; the id is unassigned here, so the first fd fills it
/// in.
static __always_inline void bpfj_bpf_take_ownership(void* owners, __u64 addr) {
  struct bpfj_role_id* role = bpfj_bpf_owning_role(bpfj_get_current_pid_data());
  if (!role) {
    // Unjailed, or a role that did not configure itself. Nothing to track.
    return;
  }

  struct bpfj_bpf_owner record = {};
  __builtin_memcpy(&record.role, role, sizeof(record.role));

  if (bpf_map_update_elem(owners, &addr, &record, BPF_NOEXIST) < 0) {
    // Loud, because the object stays unowned and so openable by anyone.
    BPFJ_LOG_ERR(ENOSPC, "No room to record the owner of a new BPF object");
  }
}

/// @brief Check an fd being created for an object against the caller's policy;
/// an unowned object is not gated.
static __always_inline int
bpfj_bpf_check_object(void* owners, __u64 addr, __u32 id) {
  struct bpfj_bpf_owner* owner = bpf_map_lookup_elem(owners, &addr);
  if (!owner) {
    return 0;
  }

  if (!bpfj_bpf_access_allowed(bpfj_get_current_pid_data(), &owner->role)) {
    struct bpfj_event* ev = bpfj_event_reserve_current(BPFJ_EVENT_BPF);
    bpfj_event_submit(ev);
    BPFJ_LOG("Denied BPF object %u owned by %s", id, owner->role.id);
    return -EPERM;
  }

  // The id exists by the first fd, so record it for userspace.
  if (owner->id == 0) {
    owner->id = id;
  }

  return 0;
}

// Every program below that can refuse takes a trailing `lsm_ret`, the verdict
// the hook has collected so far, and returns early when it is set; ignoring it
// would turn another module's denial into an allow. It only is the return
// value at the hook's real arity, so every argument ahead of it has to be
// declared even where it is unused.
SEC("lsm/bpf")
int BPF_PROG(
    bpfj_bpf_syscall,
    int cmd,
    union bpf_attr* attr,
    unsigned int size,
    bool kernel,
    int lsm_ret) {
  if (lsm_ret) {
    return lsm_ret;
  }

  if (bpfj_bpf_syscall_allowed(bpfj_get_current_pid_data())) {
    return 0;
  }

  struct bpfj_event* ev = bpfj_event_reserve_current(BPFJ_EVENT_BPF);
  bpfj_event_submit(ev);
  BPFJ_LOG("Denied bpf(2) cmd %d", cmd);
  return -EPERM;
}

// The only place ownership is taken. The id is not allocated until after this
// returns, so only the address is usable.
SEC("lsm/bpf_map_create")
int BPF_PROG(
    bpfj_bpf_map_created,
    struct bpf_map* map,
    union bpf_attr* attr,
    struct bpf_token* token,
    bool kernel,
    int lsm_ret) {
  if (lsm_ret) {
    // The creation is being refused, so there will be no object to own.
    return lsm_ret;
  }

  if (map) {
    bpfj_bpf_take_ownership(&bpfj_bpf_map_owners, (__u64)map);
  }
  return 0;
}

SEC("lsm/bpf_prog_load")
int BPF_PROG(
    bpfj_bpf_prog_loaded,
    struct bpf_prog* prog,
    union bpf_attr* attr,
    struct bpf_token* token,
    bool kernel,
    int lsm_ret) {
  if (lsm_ret) {
    return lsm_ret;
  }

  if (prog) {
    bpfj_bpf_take_ownership(&bpfj_bpf_prog_owners, (__u64)prog);
  }
  return 0;
}

SEC("lsm/bpf_map")
int BPF_PROG(
    bpfj_bpf_map_check,
    struct bpf_map* map,
    fmode_t fmode,
    int lsm_ret) {
  if (lsm_ret) {
    return lsm_ret;
  }

  if (!map) {
    return 0;
  }

  return bpfj_bpf_check_object(&bpfj_bpf_map_owners, (__u64)map, map->id);
}

// No fmode here, unlike bpf_map: security_bpf_prog() takes the program alone.
SEC("lsm/bpf_prog")
int BPF_PROG(bpfj_bpf_prog_check, struct bpf_prog* prog, int lsm_ret) {
  if (lsm_ret) {
    return lsm_ret;
  }

  if (!prog || !prog->aux) {
    return 0;
  }

  return bpfj_bpf_check_object(
      &bpfj_bpf_prog_owners, (__u64)prog, prog->aux->id);
}

// Cleanup. Both hooks return void, so there is nothing to decide here.

static __always_inline void bpfj_bpf_forget(void* owners, __u64 addr) {
  bpf_map_delete_elem(owners, &addr);
}

SEC("lsm/bpf_map_free")
int BPF_PROG(bpfj_bpf_map_free, struct bpf_map* map) {
  bpfj_bpf_forget(&bpfj_bpf_map_owners, (__u64)map);
  return 0;
}

SEC("lsm/bpf_prog_free")
int BPF_PROG(bpfj_bpf_prog_free, struct bpf_prog* prog) {
  bpfj_bpf_forget(&bpfj_bpf_prog_owners, (__u64)prog);
  return 0;
}

// Record what is already open: the hooks above only see an object as its fd is
// created, so this walks every open file on the host once at load. First
// writer wins, the creator not being recoverable after the fact.
SEC("iter/task_file")
int bpfj_bpf_seed_owners(struct bpf_iter__task_file* ctx) {
  struct task_struct* task = ctx->task;
  struct file* file = ctx->file;
  if (!task || !file) {
    return 0;
  }

  // A process's jail lives on its thread-group leader.
  if (task->pid != task->tgid) {
    return 0;
  }

  struct bpfj_pid_data* pid_data =
      bpf_task_storage_get(&bpfj_task_map, task, NULL, 0);
  struct bpfj_role_id* role = bpfj_bpf_owning_role(pid_data);
  if (!role) {
    return 0;
  }

  struct bpfj_bpf_owner record = {};
  __builtin_memcpy(&record.role, role, sizeof(record.role));

  if (file->f_op == &bpf_map_fops) {
    struct bpf_map* map = bpf_core_cast(file->private_data, struct bpf_map);
    if (map) {
      const __u64 addr = (__u64)map;
      record.id = map->id;
      bpf_map_update_elem(&bpfj_bpf_map_owners, &addr, &record, BPF_NOEXIST);
    }
  } else if (file->f_op == &bpf_prog_fops) {
    struct bpf_prog* prog = bpf_core_cast(file->private_data, struct bpf_prog);
    if (prog && prog->aux) {
      const __u64 addr = (__u64)prog;
      record.id = prog->aux->id;
      bpf_map_update_elem(&bpfj_bpf_prog_owners, &addr, &record, BPF_NOEXIST);
    }
  }

  return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
