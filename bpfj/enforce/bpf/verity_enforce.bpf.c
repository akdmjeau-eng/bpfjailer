// Copyright (c) Meta Platforms, Inc. and affiliates.

// fs-verity signature enforcement: a jailed task may only bring in code whose
// fs-verity digest carries a PKCS#7 signature from a key its role trusts, and
// a role with no key in bpfj_key_map is not checked at all. A file is checked
// against every pod the task belongs to, and a failed check is a silent denial
// until the event pipeline is ported.
//
// Two hooks, because neither reaches every way code is loaded:
//
//   mmap_file catches the dynamic loader and every shared object it maps, but
//   a statically linked binary maps nothing.
//
//   bprm_check_security closes that gap, and is the first exec hook after
//   jailer.bpf.c's bprm_creds_from_file enrollment, so a binary enrolling
//   itself from its policy xattr is checked against the role it just claimed.
//
// The third hook, bpfj_keyring_check below, guards the keyrings the other two
// verify against, which nothing but this enforcer creates.

#include <bpf/vmlinux/vmlinux.h>

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <errno.h>

#include "bpfj/enforce/bpf/maps.h"
#include "bpfj/enforce/bpf/role_gate.h"
#include "bpfj/enforce/bpf/types.h"
#include "bpfj/fsverity/bpf/fsverity.h"
#include "bpfj/lib/bpf/logging_bpf.h"

// From <sys/mman.h>, which cannot be pulled into a translation unit that has
// already included vmlinux.h.
#define PROT_EXEC 0x4

// Checks `file` against the signing key of every role the calling task is
// jailed under, returning -EPERM if any role that has one refuses.
static int bpfj_verity_check(struct file* file, bool is_exec) {
  struct task_struct* task = bpf_get_current_task_btf();

  struct bpfj_pid_data* pid_data =
      bpf_task_storage_get(&bpfj_task_map, task, NULL, 0);
  if (!pid_data) {
    // Not jailed, so there is no role to demand a signature.
    return 0;
  }

  // Newest role first, down to the base. See bpfj_is_override() in maps.h.
  for (int i = BPFJ_MAX_POD_PER_PID - 1; i >= 0; i--) {
    if (i >= pid_data->num_pods) {
      continue;
    }

    // Read in place, a bpfj_pod filling the 512 byte stack on its own.
    struct bpfj_uuid uuid = pid_data->pod_uuids[i];
    struct bpfj_pod* pod = bpf_map_lookup_elem(&bpfj_pod_map, &uuid);
    if (!pod) {
      // The pod was removed, so nothing names a key and no policy applies.
      continue;
    }

    enum bpfj_fsverity_reason reason = BPFJ_FSVERITY_REASON_NONE;
    if (bpfj_check_fsverity_pkcs7(file, pod->role_id.id, is_exec, &reason) <
        0) {
      return -EPERM;
    }

    if (bpfj_is_override(&pod->role_id)) {
      break;
    }
  }

  return 0;
}

// Every program here takes a trailing `lsm_ret`, the verdict the hook has
// collected so far, and returns early when it is set; ignoring it would turn
// another module's denial into an allow. It only is the return value at the
// hook's real arity, so every argument ahead of it has to be declared even
// where it is unused.

// `prot`, the third argument, is what the kernel installs, which under
// READ_IMPLIES_EXEC carries a PROT_EXEC `reqprot` never asked for.
SEC("lsm.s/mmap_file")
int BPF_PROG(
    bpfj_verity_mmap_file,
    struct file* file,
    unsigned long reqprot,
    unsigned long prot,
    unsigned long flags,
    int lsm_ret) {
  if (lsm_ret) {
    return lsm_ret;
  }

  if (!file || !(prot & PROT_EXEC)) {
    return 0;
  }

  // Not the exec path, so a sequence number is read where the file carries one
  // but never demanded of a shared object that does not.
  return bpfj_verity_check(file, false);
}

// Runs once per binfmt attempt, so an interpreted script is seen twice -- as
// the script and as its interpreter -- and both are checked.
SEC("lsm.s/bprm_check_security")
int BPF_PROG(bpfj_verity_bprm_check, struct linux_binprm* bprm, int lsm_ret) {
  if (lsm_ret) {
    return lsm_ret;
  }

  struct file* file = bprm->file;
  if (!file) {
    return 0;
  }

  return bpfj_verity_check(file, true);
}

// Who may write the keyrings the two hooks above verify against: one more
// certificate in bpfj:webserver runs anything you sign yourself as webserver,
// and the kernel cannot prevent it, since the mode verification needs is also
// the mode that leaves the keyring writable (see Keyring::persist()).
//
// `keyring` is a role-pair gate like `kill` and `ptrace`, but over a keyring
// rather than a process, so the owner side comes from bpfj_keyring_owner and
// role_gate.h's object form. Writes only, since denying search and read would
// deny every binary under the role instead of protecting it.

// Every keyring this enforcer built, by serial; any other serial is none of
// the jailer's business.
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct bpfj_role_id);
} bpfj_keyring_owner SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1);
  __type(key, struct bpfj_role_id);
  __type(value, __u8);
} bpfj_keyring_roles SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1);
  __type(key, struct bpfj_role_pair);
  __type(value, __u8);
} bpfj_keyring_access SEC(".maps");

// From enum key_need_perm, spelled out because that enum is internal and only
// in vmlinux.h for as long as some built-in LSM keeps referencing it.
#define BPFJ_KEY_NEED_WRITE 3

// security_key_permission() takes (key_ref, cred, need_perm), so the collected
// verdict is the slot after those three.
#define BPFJ_KEY_PERMISSION_NARGS 3

// Takes the raw context rather than BPF_PROG's unpacked arguments: key_ref_t
// points at a type the kernel never defines, so it is a FWD in BTF and a read
// of context offset 0 is rejected outright on 6.16 and 6.19.
// bpf_get_func_arg() reaches it through the saved register array instead.
SEC("lsm/key_permission")
int bpfj_keyring_check(__u64* ctx) {
  // Read straight out of the context, bpf_get_func_ret() being inlined only
  // for fexit and fmod_ret programs.
  const int lsm_ret = (int)ctx[BPFJ_KEY_PERMISSION_NARGS];
  if (lsm_ret) {
    return lsm_ret;
  }

  __u64 need_perm = 0;
  if (bpf_get_func_arg(ctx, 2, &need_perm) != 0 ||
      need_perm != BPFJ_KEY_NEED_WRITE) {
    return 0;
  }

  __u64 key_ref = 0;
  if (bpf_get_func_arg(ctx, 0, &key_ref) != 0) {
    return 0;
  }

  // Bit 0 is the possession flag; see key_ref_to_ptr().
  struct key* key = bpf_core_cast((void*)(key_ref & ~1ULL), struct key);
  if (!key) {
    return 0;
  }

  __u32 serial = key->serial;
  struct bpfj_role_id* owner =
      bpf_map_lookup_elem(&bpfj_keyring_owner, &serial);
  if (!owner) {
    return 0;
  }

  if (bpfj_gate_allowed_owner(
          &bpfj_keyring_roles,
          &bpfj_keyring_access,
          bpfj_get_current_pid_data(),
          owner)) {
    return 0;
  }

  BPFJ_LOG("Denied write to keyring %u", serial);
  return -EPERM;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
