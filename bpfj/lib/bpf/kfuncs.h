// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

// The kernel functions this tree calls, declared for itself, every BPF object
// being built with -DBPF_NO_KFUNC_PROTOTYPES to stop vmlinux.h's derived
// prototypes colliding with the tree's and libbpf's.
//
// A header rather than per-file externs, because a kfunc used without a
// prototype is an implicit declaration returning int, so a pointer-returning
// one silently becomes a truncated integer. The signatures have to match the
// kernel's BTF exactly, and a mismatch is a verifier rejection at load rather
// than a compile error here.

struct bpf_dynptr;
struct file;
struct task_struct;

// Takes a reference on the task, which bpf_task_release() has to give back.
extern struct task_struct* bpf_task_from_pid(pid_t pid) __ksym;
extern void bpf_task_release(struct task_struct* task) __ksym;

// Here rather than beside the other fs-verity kfuncs in
// bpfj/fsverity/bpf/fsverity.h, which the enforcers reading xattrs do not
// include.
extern int bpf_get_file_xattr(
    struct file* file,
    const char* name__str,
    struct bpf_dynptr* value_p) __weak __ksym;

// Used by the arena spin lock bpfj/lib/bpf/lock.h pulls in from scx's
// libarena headers, which call the pair without declaring it.
extern void bpf_preempt_disable(void) __weak __ksym;
extern void bpf_preempt_enable(void) __weak __ksym;
