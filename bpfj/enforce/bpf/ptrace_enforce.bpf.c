// Copyright (c) Meta Platforms, Inc. and affiliates.

// Who may ptrace whom. A tracer owns its tracee's memory, registers and
// syscalls, so attaching across a jail boundary hands over everything the jail
// was holding back, and the kernel's ptrace_may_access() says nothing between
// processes of the same user.
//
// `ptrace` names the roles a role may attach to and is a role-pair gate like
// `kill`; role_gate.h has the rule and these are the two hooks it is read at.
// Only an attach is gated, since gating the read-only modes would break `ps`,
// and PTRACE_TRACEME is asked the same question with the roles reversed --
// consent from the tracee is not the jail's to give.

#include <bpf/vmlinux/vmlinux.h>

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <errno.h>

#include "bpfj/enforce/bpf/maps.h"
#include "bpfj/enforce/bpf/role_gate.h"
#include "bpfj/enforce/bpf/types.h"
#include "bpfj/lib/bpf/logging_bpf.h"

// From the kernel's ptrace.h. PTRACE_SEIZE reaches ptrace_attach() as
// PTRACE_MODE_ATTACH_REALCREDS, so this bit covers it.
#define PTRACE_MODE_ATTACH 0x02

// Both programs take a trailing `lsm_ret`, the verdict the hook has collected
// so far, and return early when it is set; ignoring it would turn another
// module's denial into an allow. It only is the return value at the hook's
// real arity, so every argument ahead of it has to be declared.
SEC("lsm/ptrace_access_check")
int BPF_PROG(
    bpfj_ptrace_check,
    struct task_struct* child,
    unsigned int mode,
    int lsm_ret) {
  if (lsm_ret) {
    return lsm_ret;
  }

  if (!child || !(mode & PTRACE_MODE_ATTACH)) {
    return 0;
  }

  if (bpfj_gate_allowed(
          BPFJ_POLICY_GATE_PTRACE,
          bpfj_get_current_pid_data(),
          bpfj_get_task_pid_data(child))) {
    return 0;
  }

  struct bpfj_event* ev = bpfj_event_reserve_current(BPFJ_EVENT_PTRACE);
  bpfj_event_submit(ev);
  BPFJ_LOG("Denied ptrace attach to pid %d", child->tgid);
  return -EPERM;
}

SEC("lsm/ptrace_traceme")
int BPF_PROG(bpfj_ptrace_traceme, struct task_struct* parent, int lsm_ret) {
  if (lsm_ret) {
    return lsm_ret;
  }

  if (!parent) {
    return 0;
  }

  // Inverted against the hook above: the caller is the tracee, so the parent is
  // the actor the gate is asked about.
  if (bpfj_gate_allowed(
          BPFJ_POLICY_GATE_PTRACE,
          bpfj_get_task_pid_data(parent),
          bpfj_get_current_pid_data())) {
    return 0;
  }

  struct bpfj_event* ev = bpfj_event_reserve_current(BPFJ_EVENT_PTRACE);
  bpfj_event_submit(ev);
  BPFJ_LOG("Denied PTRACE_TRACEME by pid %d", parent->tgid);
  return -EPERM;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
