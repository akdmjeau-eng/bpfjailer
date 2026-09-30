// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

// struct bpfj_lock, shared between BPF and userspace so it can be embedded in
// arena data structures both sides touch: a single 32-bit word laid out
// exactly like libarena's arena_spinlock_t, with the locked byte in bits 0-7,
// the pending byte in 8-15 and the MCS queue tail in 16-31. Operations live in
// bpfj/lib/bpf/lock.h and bpfj/lib/Lock.h.
//
// Storage only, with no include of libarena's header, so structures embedding
// a lock stay usable by BPF objects with no arena -- that header defines a
// 64 KiB qnodes array libbpf rejects without an ARENA map.

#ifndef __arena
#ifdef __cplusplus
#define __arena
#else
#define __arena __attribute__((address_space(1)))
#endif
#endif

#ifdef __cplusplus

#include <atomic>

#include <linux/types.h>

struct bpfj_lock {
  std::atomic<__u32> val;
};

static_assert(
    sizeof(bpfj_lock) == sizeof(__u32) && alignof(bpfj_lock) == alignof(__u32),
    "bpfj_lock must stay a bare 32-bit word");
static_assert(
    std::atomic<__u32>::is_always_lock_free,
    "the lock word is shared with BPF, so it cannot be emulated with a mutex");

#else

struct bpfj_lock {
  __u32 val;
};

#endif
