// Copyright (c) Meta Platforms, Inc. and affiliates.

// Who may signal whom. A signal is a way out of a jail -- SIGKILL the daemon
// holding something you want, or SIGSTOP the watchdog that would have noticed
// -- and the uid check in check_kill_permission() says nothing between two
// processes of the same user.
//
// `kill` names the roles a role may signal and is a role-pair gate like any
// other; role_gate.h has the rule and this is the hook it is read at. Nothing
// here distinguishes one signal from another.

#include <bpf/vmlinux/vmlinux.h>

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <errno.h>

#include "bpfj/enforce/bpf/maps.h"
#include "bpfj/enforce/bpf/role_gate.h"
#include "bpfj/enforce/bpf/types.h"
#include "bpfj/lib/bpf/logging_bpf.h"

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1);
  __type(key, struct bpfj_role_id);
  __type(value, __u8);
} bpfj_kill_roles SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1);
  __type(key, struct bpfj_role_pair);
  __type(value, __u8);
} bpfj_kill_access SEC(".maps");

// The trailing `lsm_ret` is the verdict the hook has collected so far;
// ignoring it would turn another module's denial into an allow. It only is the
// return value at the hook's real arity, so every argument ahead of it has to
// be declared even where it is unused.
SEC("lsm/task_kill")
int BPF_PROG(
    bpfj_kill_check,
    struct task_struct* p,
    struct kernel_siginfo* info,
    int sig,
    const struct cred* cred,
    int lsm_ret) {
  if (lsm_ret) {
    return lsm_ret;
  }

  if (!p) {
    return 0;
  }

  if (bpfj_gate_allowed(
          &bpfj_kill_roles,
          &bpfj_kill_access,
          bpfj_get_current_pid_data(),
          bpfj_get_task_pid_data(p))) {
    return 0;
  }

  BPFJ_LOG("Denied signal %d to pid %d", sig, p->tgid);
  return -EPERM;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
