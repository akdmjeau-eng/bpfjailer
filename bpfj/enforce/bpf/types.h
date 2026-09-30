// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include "bpfj/fsverity/bpf/types_fsverity.h"
#include "bpfj/lib/bpf/types_role.h"
#include "bpfj/lib/bpf/types_uuid.h"
#include "bpfj/var/bpf/types_var.h"

// The types the open source jailer needs, and nothing else; the internal tree
// keeps its own, much larger one at bpfjailer/enforce/bpf/types.h, and what is
// shared is what this header includes. The pod layout matches the internal one
// apart from child_role_id, which this tree has no policy to populate, so
// bpfj_pod is 512 bytes rather than 528 and the two cannot share a map.

// Sized for long service/tenant identity strings (255 chars plus NUL). Never
// put a bpfj_user_id on the BPF stack -- even at 64 bytes it pushed the
// internal scan chain past the 512-byte budget.
#define POD_USER_ID_LEN 256

// Ceiling on the roles a policy may flag, and so on the entries in
// bpfj_unpriv_enroll_map and bpfj_pod_override_map, both keyed by role. Sizes
// a map rather than a struct, so raising it costs memory and nothing else.
#define BPFJ_MAX_UNPRIV_ROLES 1024

// Versioning
#define BPFJ_PID_DATA_VERSION 1

// The layout of the bpfj_bpf_owner records below, which a replace reads
// through the running tree's pin to decide whether it can carry them across;
// bump it whenever bpfj_bpf_owner changes shape. Pin adoption does not cover
// this: it catches a change of size but not a reordering, and the replace
// copies between two maps rather than adopting one.
#define BPFJ_BPF_OWNER_VERSION 1

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

struct __attribute__((packed)) bpfj_pid_data {
  __s8 version;
  __u8 num_pods;
  __u32 flags; // currently unused
  __u64 reserved; // currently unused
  struct bpfj_uuid pod_uuids[BPFJ_MAX_POD_PER_PID];
};

// Pinned so widening a member is a compile error rather than a silent change
// to bpfj_pod_map, which outlives the process that created it.
#ifdef __cplusplus
#define BPFJ_POD_STATIC_ASSERT(condition) static_assert(condition)
#else
#define BPFJ_POD_STATIC_ASSERT(condition) \
  _Static_assert(condition, "pod layout is shared through bpfj_pod_map")
#endif

BPFJ_POD_STATIC_ASSERT(sizeof(struct bpfj_var) == 48);
BPFJ_POD_STATIC_ASSERT(sizeof(struct bpfj_var_array) == 196);
BPFJ_POD_STATIC_ASSERT(sizeof(struct bpfj_pod) == 512);

// Same reasoning for the records a replace copies between two trees; a change
// this catches is one BPFJ_BPF_OWNER_VERSION has to be bumped for.
BPFJ_POD_STATIC_ASSERT(sizeof(struct bpfj_bpf_owner) == 20);

#undef BPFJ_POD_STATIC_ASSERT
