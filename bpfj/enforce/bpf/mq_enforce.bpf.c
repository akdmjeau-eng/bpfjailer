// Copyright (c) Meta Platforms, Inc. and affiliates.

// System V message queues name kernel objects with integer ids that can be
// copied freely, so every operation is checked. POSIX queues are file-backed:
// file_open gates mq_open(), file_receive gates SCM_RIGHTS acquisition, and
// possession of an already-authorized descriptor remains the capability.

#include <bpf/vmlinux/vmlinux.h>

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <errno.h>

#include "bpfj/enforce/bpf/maps.h"
#include "bpfj/enforce/bpf/mq_gate.h"
#include "bpfj/enforce/bpf/role_gate.h"
#include "bpfj/enforce/bpf/types.h"
#include "bpfj/lib/bpf/logging_bpf.h"

#define BPFJ_MQUEUE_MAGIC 0x19800202

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1);
  __type(key, __u64);
  __type(value, struct bpfj_mq_owner);
} bpfj_mq_sysv_owners SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1);
  __type(key, struct bpfj_posix_mq_key);
  __type(value, struct bpfj_mq_owner);
} bpfj_mq_posix_owners SEC(".maps");

struct bpfj_mq_pending_owner {
  struct bpfj_mq_owner owner;
  __u8 owned;
};

// Creation starts before mqueuefs has a stable inode number. Remember the
// inode pointer until file_open can resolve it to the persistent key. This is
// deliberately ephemeral rather than pinned: inode allocation and file open
// are one in-flight operation, and two trees attached during replacement each
// observe both hooks.
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 16384);
  __type(key, __u64);
  __type(value, struct bpfj_mq_pending_owner);
} bpfj_mq_posix_pending SEC(".maps");

#define BPFJ_MQ_VERSION_MAP(name)     \
  struct {                            \
    __uint(type, BPF_MAP_TYPE_ARRAY); \
    __uint(max_entries, 1);           \
    __type(key, __u32);               \
    __type(value, __u32);             \
  } name SEC(".maps")

BPFJ_MQ_VERSION_MAP(bpfj_mq_sysv_owner_version);
BPFJ_MQ_VERSION_MAP(bpfj_mq_posix_owner_version);

static __always_inline int bpfj_mq_deny(const char* kind) {
  BPFJ_LOG("Denied %s message queue access", kind);
  return -EPERM;
}

static __always_inline int bpfj_mq_sysv_check(
    struct kern_ipc_perm* msq,
    struct task_struct* actor) {
  if (!msq) {
    return 0;
  }

  const __u64 key = (__u64)msq;
  const struct bpfj_mq_owner* owner =
      bpf_map_lookup_elem(&bpfj_mq_sysv_owners, &key);
  struct bpfj_pid_data* pid_data =
      actor ? bpfj_get_task_pid_data(actor) : bpfj_get_current_pid_data();
  return bpfj_mq_allowed(BPFJ_POLICY_GATE_MQ_SYSV, pid_data, owner)
      ? 0
      : bpfj_mq_deny("System V");
}

SEC("lsm/msg_queue_alloc_security")
int BPF_PROG(bpfj_mq_sysv_alloc, struct kern_ipc_perm* msq, int lsm_ret) {
  if (lsm_ret || !msq) {
    return lsm_ret;
  }

  struct bpfj_mq_owner owner = {};
  const bool owned = bpfj_mq_current_owner(&owner);
  if (!bpfj_mq_allowed(
          BPFJ_POLICY_GATE_MQ_SYSV,
          bpfj_get_current_pid_data(),
          owned ? &owner : NULL)) {
    return bpfj_mq_deny("System V");
  }

  if (owned) {
    const __u64 key = (__u64)msq;
    if (bpf_map_update_elem(&bpfj_mq_sysv_owners, &key, &owner, BPF_NOEXIST) !=
        0) {
      return -ENOMEM;
    }
  }
  return 0;
}

SEC("lsm/msg_queue_free_security")
int BPF_PROG(bpfj_mq_sysv_free, struct kern_ipc_perm* msq) {
  if (msq) {
    const __u64 key = (__u64)msq;
    bpf_map_delete_elem(&bpfj_mq_sysv_owners, &key);
  }
  return 0;
}

SEC("lsm/msg_queue_associate")
int BPF_PROG(
    bpfj_mq_sysv_associate,
    struct kern_ipc_perm* msq,
    int msqflg,
    int lsm_ret) {
  return lsm_ret ? lsm_ret : bpfj_mq_sysv_check(msq, NULL);
}

SEC("lsm/msg_queue_msgctl")
int BPF_PROG(
    bpfj_mq_sysv_msgctl,
    struct kern_ipc_perm* msq,
    int cmd,
    int lsm_ret) {
  return lsm_ret ? lsm_ret : bpfj_mq_sysv_check(msq, NULL);
}

SEC("lsm/msg_queue_msgsnd")
int BPF_PROG(
    bpfj_mq_sysv_send,
    struct kern_ipc_perm* msq,
    struct msg_msg* msg,
    int msqflg,
    int lsm_ret) {
  return lsm_ret ? lsm_ret : bpfj_mq_sysv_check(msq, NULL);
}

SEC("lsm/msg_queue_msgrcv")
int BPF_PROG(
    bpfj_mq_sysv_receive,
    struct kern_ipc_perm* msq,
    struct msg_msg* msg,
    struct task_struct* target,
    long type,
    int mode,
    int lsm_ret) {
  return lsm_ret ? lsm_ret : bpfj_mq_sysv_check(msq, target);
}

static __always_inline bool bpfj_posix_mq_key(
    struct file* file,
    struct bpfj_posix_mq_key* key) {
  struct inode* inode = file ? BPF_CORE_READ(file, f_inode) : NULL;
  struct super_block* sb = inode ? BPF_CORE_READ(inode, i_sb) : NULL;
  if (!sb || BPF_CORE_READ(sb, s_magic) != BPFJ_MQUEUE_MAGIC) {
    return false;
  }

  key->dev = BPF_CORE_READ(sb, s_dev);
  key->ino = BPF_CORE_READ(inode, i_ino);
  return key->ino != 0;
}

static __always_inline bool bpfj_is_mqueue_inode(struct inode* inode) {
  struct super_block* sb = inode ? BPF_CORE_READ(inode, i_sb) : NULL;
  return sb && BPF_CORE_READ(sb, s_magic) == BPFJ_MQUEUE_MAGIC;
}

SEC("lsm/inode_alloc_security")
int BPF_PROG(bpfj_mq_posix_alloc, struct inode* inode, int lsm_ret) {
  if (lsm_ret || !bpfj_is_mqueue_inode(inode)) {
    return lsm_ret;
  }

  struct bpfj_mq_pending_owner pending = {};
  pending.owned = bpfj_mq_current_owner(&pending.owner);
  if (!bpfj_mq_allowed(
          BPFJ_POLICY_GATE_MQ_POSIX,
          bpfj_get_current_pid_data(),
          pending.owned ? &pending.owner : NULL)) {
    return bpfj_mq_deny("POSIX");
  }

  const __u64 key = (__u64)inode;
  return bpf_map_update_elem(&bpfj_mq_posix_pending, &key, &pending, BPF_ANY) ==
          0
      ? 0
      : -ENOMEM;
}

static __always_inline int bpfj_mq_posix_check(struct file* file) {
  struct bpfj_posix_mq_key key = {};
  if (!bpfj_posix_mq_key(file, &key)) {
    return 0;
  }

  const struct bpfj_mq_owner* owner =
      bpf_map_lookup_elem(&bpfj_mq_posix_owners, &key);
  return bpfj_mq_allowed(
             BPFJ_POLICY_GATE_MQ_POSIX, bpfj_get_current_pid_data(), owner)
      ? 0
      : bpfj_mq_deny("POSIX");
}

SEC("lsm/file_open")
int BPF_PROG(bpfj_mq_posix_open, struct file* file, int lsm_ret) {
  if (lsm_ret) {
    return lsm_ret;
  }

  struct bpfj_posix_mq_key key = {};
  if (!bpfj_posix_mq_key(file, &key)) {
    return 0;
  }

  struct inode* inode = BPF_CORE_READ(file, f_inode);
  const __u64 pending_key = (__u64)inode;
  const struct bpfj_mq_pending_owner* pending =
      bpf_map_lookup_elem(&bpfj_mq_posix_pending, &pending_key);
  if (!pending) {
    return bpfj_mq_posix_check(file);
  }

  if (!bpfj_mq_allowed(
          BPFJ_POLICY_GATE_MQ_POSIX,
          bpfj_get_current_pid_data(),
          pending->owned ? &pending->owner : NULL)) {
    return bpfj_mq_deny("POSIX");
  }

  if (pending->owned &&
      bpf_map_update_elem(
          &bpfj_mq_posix_owners, &key, &pending->owner, BPF_ANY) != 0) {
    return -ENOMEM;
  }
  bpf_map_delete_elem(&bpfj_mq_posix_pending, &pending_key);
  return 0;
}

SEC("lsm/file_receive")
int BPF_PROG(bpfj_mq_posix_receive_fd, struct file* file, int lsm_ret) {
  return lsm_ret ? lsm_ret : bpfj_mq_posix_check(file);
}

SEC("lsm/inode_free_security")
int BPF_PROG(bpfj_mq_posix_free, struct inode* inode) {
  const __u64 pending_key = (__u64)inode;
  bpf_map_delete_elem(&bpfj_mq_posix_pending, &pending_key);

  struct super_block* sb = inode ? BPF_CORE_READ(inode, i_sb) : NULL;
  if (sb && BPF_CORE_READ(sb, s_magic) == BPFJ_MQUEUE_MAGIC) {
    struct bpfj_posix_mq_key key = {
        .dev = BPF_CORE_READ(sb, s_dev),
        .ino = BPF_CORE_READ(inode, i_ino),
    };
    if (key.ino != 0) {
      bpf_map_delete_elem(&bpfj_mq_posix_owners, &key);
    }
  }
  return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
