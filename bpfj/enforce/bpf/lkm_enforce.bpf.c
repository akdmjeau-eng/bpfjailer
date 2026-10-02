// Copyright (c) Meta Platforms, Inc. and affiliates.

// `no-lkm` denies module autoload, module insertion and kexec loading through
// the kernel's three kernel-data LSM hooks.

#include <bpf/vmlinux/vmlinux.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <errno.h>

#include "bpfj/enforce/bpf/maps.h"
#include "bpfj/enforce/bpf/types.h"
#include "bpfj/lib/bpf/logging_bpf.h"

static __always_inline bool bpfj_lkm_allowed(void) {
  struct bpfj_pid_data* pid_data = bpfj_get_current_pid_data();
  if (!pid_data) {
    return true;
  }

  __u32 num_pods = pid_data->num_pods;
  if (num_pods > BPFJ_MAX_POD_PER_PID) {
    num_pods = BPFJ_MAX_POD_PER_PID;
  }

  for (int i = BPFJ_MAX_POD_PER_PID - 1; i >= 0; --i) {
    if (i >= num_pods) {
      continue;
    }

    struct bpfj_pod __arena* pod = pid_data->pods[i];
    if (!pod) {
      continue;
    }

    const struct bpfj_role_policy __arena* policy = bpfj_pod_policy(pod);
    if (!policy || (policy->flags & BPFJ_POLICY_NO_LKM)) {
      return false;
    }

    if (bpfj_is_override(pod)) {
      break;
    }
  }

  return true;
}

static __always_inline int bpfj_lkm_check(int lsm_ret) {
  if (lsm_ret) {
    return lsm_ret;
  }
  if (bpfj_lkm_allowed()) {
    return 0;
  }

  struct bpfj_event* ev = bpfj_event_reserve_current(BPFJ_EVENT_LKM);
  bpfj_event_submit(ev);
  BPFJ_LOG("Denied kernel module or kexec load");
  return -EPERM;
}

static __always_inline bool bpfj_lkm_load_data_id(enum kernel_load_data_id id) {
  return id == LOADING_MODULE || id == LOADING_KEXEC_IMAGE ||
      id == LOADING_KEXEC_INITRAMFS;
}

static __always_inline bool bpfj_lkm_read_file_id(enum kernel_read_file_id id) {
  return id == READING_MODULE || id == READING_KEXEC_IMAGE ||
      id == READING_KEXEC_INITRAMFS;
}

SEC("lsm/kernel_module_request")
int BPF_PROG(bpfj_kernel_module_request, char* kmod_name, int lsm_ret) {
  return bpfj_lkm_check(lsm_ret);
}

SEC("lsm/kernel_load_data")
int BPF_PROG(
    bpfj_kernel_load_data,
    enum kernel_load_data_id id,
    bool contents,
    int lsm_ret) {
  return bpfj_lkm_load_data_id(id) ? bpfj_lkm_check(lsm_ret) : lsm_ret;
}

SEC("lsm/kernel_read_file")
int BPF_PROG(
    bpfj_kernel_read_file,
    struct file* file,
    enum kernel_read_file_id id,
    bool contents,
    int lsm_ret) {
  return bpfj_lkm_read_file_id(id) ? bpfj_lkm_check(lsm_ret) : lsm_ret;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
