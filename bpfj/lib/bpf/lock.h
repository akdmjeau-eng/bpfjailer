// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

// A spin lock that lives in the BPF arena, so the same lock word can be taken
// from BPF and from userspace (bpfj/lib/Lock.h). Only the uncontended path of
// the underlying qspinlock is used, so the word only ever holds 0 or LOCKED;
// arena_spin_lock()'s blocking slow path is unsafe against a userspace holder
// on two counts:
//
//   - it waits with preemption disabled, so a BPF program spinning on a
//     userspace holder parked on the same CPU keeps it from running, and
//   - its bail-out returns with the pending bit set and never cleared, which
//     wedges the lock for both sides.
//
// BPF must therefore treat acquisition as fallible: take the lock or move on.
// Userspace may wait, since it yields rather than spins and a BPF holder
// always releases before its program returns.
//
// types_lock.h first: it supplies the __arena qualifier libarena's header
// declares its own types with.
#include "bpfj/lib/bpf/kfuncs.h"
#include "bpfj/lib/bpf/types_lock.h"

// Angle-bracket include: the BPF build gets the libarena headers as an include
// directory, and arena_spinlock_t is gated on ENABLE_ATOMICS_TESTS -- both
// from bpfjailer/defs.bzl under Buck and from the Makefile's LIBARENA in the
// open source build. This also pulls in libarena's 64 KiB qnodes __arena
// global, so only objects declaring an ARENA map may use it.
#include <bpf_arena_spin_lock.h>

// Upstream libarena (the Makefile build) only declares the queue nodes its
// slow path uses, expecting libarena's own objects to be linked in. That slow
// path is emitted whether or not anything reaches it, so the declaration has
// to resolve. fbsource's vendored copy, which Buck uses, defines them itself.
#ifdef BPFJ_DEFINE_LIBARENA_QNODES
struct arena_qnode __weak __arena __hidden qnodes[_Q_MAX_CPUS][_Q_MAX_NODES];
#endif

_Static_assert(
    sizeof(arena_spinlock_t) == sizeof(__u32),
    "struct bpfj_lock must stay layout-compatible with arena_spinlock_t");

// The shared struct stores the bare word so types_heap.h can embed it without
// dragging libarena's header into arena-less objects.
static __always_inline arena_spinlock_t __arena* bpfj_lock_qspinlock(
    struct bpfj_lock __arena* l) {
  return (arena_spinlock_t __arena*)&l->val;
}

// Put a lock into the free state: required before first use, and not safe to
// run concurrently with any user. Acquire only succeeds on an all-zero word,
// and nothing clears the pending bit or tail outside the slow path we do not
// use, so residue -- the allocator's free-list links in a recycled heap block,
// say -- leaves the lock permanently held.
static void bpfj_lock_init(struct bpfj_lock __arena* l) {
  WRITE_ONCE(l->val, 0);
}

// Take the lock if it is free. Returns 1 on success, 0 if it is held. Unlike
// arena_spin_lock() this does not disable preemption, which costs waiters
// latency but cannot deadlock.
static int bpfj_lock_trylock(struct bpfj_lock __arena* l) {
  return arena_spin_trylock(bpfj_lock_qspinlock(l));
}

// Release a lock taken with bpfj_lock_trylock(): arena_spin_unlock() minus its
// bpf_preempt_enable(), which would unbalance the preempt count.
static void bpfj_lock_unlock(struct bpfj_lock __arena* l) {
  smp_store_release(&bpfj_lock_qspinlock(l)->locked, 0);
}

// Whether the lock is currently held, without attempting to take it.
static bool bpfj_lock_is_locked(struct bpfj_lock __arena* l) {
  return READ_ONCE(bpfj_lock_qspinlock(l)->locked) != 0;
}

struct bpfj_lock_guard {
  struct bpfj_lock __arena* lock;
};

// static, so this is not emitted as a global BPF subprog into every including
// object and collide at link time.
static void bpfj_lock_guard_cleanup(struct bpfj_lock_guard* guard) {
  struct bpfj_lock __arena* lock = guard->lock;
  if (lock) {
    bpfj_lock_unlock(lock);
    guard->lock = NULL;
  }
}

// RAII holder for a lock
#define BPFJ_LOCK_GUARD(_name, _lock_ptr)                                    \
  __attribute__((                                                            \
      cleanup(bpfj_lock_guard_cleanup))) struct bpfj_lock_guard _name = {0}; \
  {                                                                          \
    int _ret = bpfj_lock_trylock(_lock_ptr);                                 \
    if (_ret) {                                                              \
      _name.lock = _lock_ptr;                                                \
    }                                                                        \
  }

#define BPFJ_LOCK_IS_ACQUIRED(_name) ((_name).lock ? 1 : 0)

#define BPFJ_LOCK_UNLOCK(_name) bpfj_lock_guard_cleanup(&_name)

#define BPFJ_LOCK_GUARD_RELEASE(_name) _name.lock = NULL

// One declaration and no second statement: the guard must be declared in the
// caller's own scope for the cleanup to run there, and a following assignment
// would escape an unbraced if or loop body.
#define BPFJ_LOCK_GUARD_TAKE_OVER(_name, _lock_ptr)                       \
  __attribute__((                                                         \
      cleanup(bpfj_lock_guard_cleanup))) struct bpfj_lock_guard _name = { \
      .lock = (_lock_ptr)}
