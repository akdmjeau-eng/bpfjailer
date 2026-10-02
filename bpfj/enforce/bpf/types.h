// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include "bpfj/fsverity/bpf/types_fsverity.h"
#include "bpfj/lib/bpf/types_role.h"
#include "bpfj/lib/bpf/types_uuid.h"
#include "bpfj/var/bpf/types_var.h"

// The types the open source jailer needs, and nothing else; the internal tree
// keeps its own, much larger one at bpfjailer/enforce/bpf/types.h, and what is
// shared is what this header includes. The pod layout is now OSS-specific: pod
// variables live in the shared arena and the pod carries only arena pointers.

// Sized for long service/tenant identity strings (255 chars plus NUL). Never
// put a bpfj_user_id on the BPF stack -- even at 64 bytes it pushed the
// internal scan chain past the 512-byte budget.
#define POD_USER_ID_LEN 256

// Ceiling on the roles a policy may flag, and so on the entries in
// bpfj_unpriv_enroll_map and bpfj_pod_override_map, both keyed by role. Sizes
// a map rather than a struct, so raising it costs memory and nothing else.
#define BPFJ_MAX_UNPRIV_ROLES 1024

// Versioning
#define BPFJ_PID_DATA_VERSION 2

// The layout of the bpfj_bpf_owner records below, which a replace reads
// through the running tree's pin to decide whether it can carry them across;
// bump it whenever bpfj_bpf_owner changes shape. Pin adoption does not cover
// this: it catches a change of size but not a reordering, and the replace
// copies between two maps rather than adopting one.
#define BPFJ_BPF_OWNER_VERSION 1

// Layout of both message-queue ownership maps. The maps have distinct keys,
// but intentionally share this value and version so replacement can validate
// and carry both atomically.
#define BPFJ_MQ_OWNER_VERSION 1

// Layout of both shared-memory ownership maps and the POSIX mount classifier.
#define BPFJ_SHM_OWNER_VERSION 1

#define BPFJ_EXEC_POLICY_XATTR "user.bpfj.policy.exec"

// How a pod came to exist, numbered to match the internal tree's.
#define BPFJ_ENROLL_UNKNOWN 0
#define BPFJ_ENROLL_CLIENT 1
#define BPFJ_ENROLL_EXE 2
#define BPFJ_ENROLL_EXE_SCAN 3
#define BPFJ_ENROLL_CGROUP 4
#define BPFJ_ENROLL_CGROUP_SCAN 5
#define BPFJ_ENROLL_XATTR 6
#define BPFJ_ENROLL_DBUS 7
#define BPFJ_ENROLL_FFC_TCP 8
#define BPFJ_ENROLL_FFC_UDS 9
#define BPFJ_ENROLL_BASE_ROLE 10
#define BPFJ_ENROLL_FFC_PTY 11

enum bpfj_event_type {
  BPFJ_EVENT_UNKNOWN = 0,
  BPFJ_EVENT_JAILER = 1,
  BPFJ_EVENT_ENROLL = 2,
  BPFJ_EVENT_VERITY = 3,
  BPFJ_EVENT_KILL = 4,
  BPFJ_EVENT_PTRACE = 5,
  BPFJ_EVENT_BPF = 6,
  BPFJ_EVENT_LKM = 7,
};

struct bpfj_role_id {
  // null terminated. String role id.
  char id[ROLE_ID_LEN];
};

struct bpfj_user_id {
  // null terminated. String user id.
  char id[POD_USER_ID_LEN];
};

struct bpfj_pod {
  struct bpfj_role_id role_id;
  struct bpfj_user_id user_id;
  struct bpfj_uuid uuid;
  struct bpfj_var_array var_array;

  // Number of processes referencing this pod
  __s64 refs;

  // bpf_ktime_get_ns() at enrollment, so CLOCK_MONOTONIC.
  __s64 creation_time_ns;

  // How many attempts before we decide a pod is stale
  __u16 gc_removal_attempts;
  __u8 enrollment_source;
};

struct bpfj_event {
  enum bpfj_event_type type;
  struct bpfj_pod pod;
  __u32 pid;
  __u32 tid;
  __u64 timestamp_ns;
};

// Which role owns a BPF map or program, keyed in bpfj_bpf_map_owners and
// bpfj_bpf_prog_owners by the object's kernel address. The id cannot be the
// key -- bpf_map_put() zeroes map->id before queueing the work that runs the
// free hook -- so it is carried in the value for userspace instead. Here
// rather than in bpf_enforce.bpf.c because a replace carries these records
// between two trees' maps and so needs the layout from C++ too.
struct bpfj_bpf_owner {
  struct bpfj_role_id role;
  __u32 id;
};

struct bpfj_mq_owner {
  struct bpfj_role_id role;
  struct bpfj_uuid pod;
};

// mqueuefs inode identity. s_dev separates mounts/filesystems and i_ino names
// the queue within one of them; unlike an fd, the pair survives close/open.
struct bpfj_posix_mq_key {
  __u64 dev;
  __u64 ino;
};

struct bpfj_shm_owner {
  struct bpfj_role_id role;
  struct bpfj_uuid pod;
};

struct bpfj_posix_shm_key {
  __u64 dev;
  __u64 ino;
};

// A mount id is unique only within its mount namespace.
struct bpfj_shm_mount_key {
  __u64 namespace_ino;
  __u64 mount_id;
};

struct bpfj_pid_data {
  __s8 version;
  __u8 num_pods;
  __u32 flags; // currently unused
  __u64 reserved; // currently unused
  struct bpfj_pod __arena* pods[BPFJ_MAX_POD_PER_PID];
};

// Pinned so widening a member is a compile error rather than a silent change
// to the task-storage records shared by every BPF object in the jail.
#ifdef __cplusplus
#define BPFJ_POD_STATIC_ASSERT(condition) static_assert(condition)
#else
#define BPFJ_POD_STATIC_ASSERT(condition) \
  _Static_assert(condition, "pod layout is shared through pinned jail maps")
#endif

BPFJ_POD_STATIC_ASSERT(sizeof(struct bpfj_var) == 24);
BPFJ_POD_STATIC_ASSERT(sizeof(struct bpfj_var_array) == 16);
BPFJ_POD_STATIC_ASSERT(sizeof(struct bpfj_pod) == 328);
BPFJ_POD_STATIC_ASSERT(sizeof(struct bpfj_pid_data) == 48);

// Same reasoning for the records a replace copies between two trees; a change
// this catches is one BPFJ_BPF_OWNER_VERSION has to be bumped for.
BPFJ_POD_STATIC_ASSERT(sizeof(struct bpfj_bpf_owner) == 20);
BPFJ_POD_STATIC_ASSERT(sizeof(struct bpfj_mq_owner) == 32);
BPFJ_POD_STATIC_ASSERT(sizeof(struct bpfj_posix_mq_key) == 16);
BPFJ_POD_STATIC_ASSERT(sizeof(struct bpfj_shm_owner) == 32);
BPFJ_POD_STATIC_ASSERT(sizeof(struct bpfj_posix_shm_key) == 16);
BPFJ_POD_STATIC_ASSERT(sizeof(struct bpfj_shm_mount_key) == 16);

#undef BPFJ_POD_STATIC_ASSERT
