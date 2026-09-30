// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

// Reference-counted pointer to a heap buffer in the BPF arena: the {buffer,
// reference count} pointer pair, two separate arena allocations, so the
// payload is handed back untouched. The count moves under atomic
// read-modify-write, so acquire and release may run concurrently across the
// BPF and userspace holders sharing this arena.
//
// BPFJ_SHARED_PTR_GUARD adopts a reference and releases it at scope exit,
// mirroring BPFJ_LOCK_GUARD in lock.h:
//
//   BPFJ_SHARED_PTR_GUARD(owner, bpfj_shared_ptr_make(size));  // count = 1
//   if (!BPFJ_SHARED_PTR_VALID(owner)) {
//     return;
//   }
//   ... write through BPFJ_SHARED_PTR_BUF(owner) ...
//   // scope exit: count -> 0, buffer and count freed.

#include "bpfj/lib/bpf/heap.h"
#include "bpfj/lib/bpf/types_shared_ptr.h"

// Allocate a 'size'-byte buffer and its reference count, the count set to 1,
// or an invalid pointer (buf == NULL) if either allocation fails.
static __always_inline struct bpfj_shared_ptr bpfj_shared_ptr_make(__u32 size) {
  struct bpfj_shared_ptr sp = {0};

  // Raw heap functions rather than the BPFJ_HEAP_* macros: those inline a
  // BPFJ_LOG_ERR block that these __always_inline helpers would duplicate into
  // every caller, past the verifier's instruction limit.
  long off = bpfj_heap_alloc(size);
  if (off <= 0) {
    return sp;
  }

  long rc_off = bpfj_heap_alloc(sizeof(__u32));
  if (rc_off <= 0) {
    bpfj_heap_free((__u32)off);
    return sp;
  }

  // No other reference exists yet, so a plain store is enough to publish 1.
  __u32 __arena* refcount = (__u32 __arena*)(bpfj_heap_ptr() + rc_off);
  *refcount = 1;
  sp.buf = (void __arena*)(bpfj_heap_ptr() + off);
  sp.refcount = refcount;
  return sp;
}

// bpfj_shared_ptr_make with a zeroed buffer, for callers whose buffer must
// read as all-zero before first use.
static __always_inline struct bpfj_shared_ptr bpfj_shared_ptr_calloc(
    __u32 size) {
  struct bpfj_shared_ptr sp = {0};

  // Raw heap functions, not the BPFJ_HEAP_* macros — see bpfj_shared_ptr_make.
  long off = bpfj_heap_calloc(size);
  if (off <= 0) {
    return sp;
  }

  long rc_off = bpfj_heap_alloc(sizeof(__u32));
  if (rc_off <= 0) {
    bpfj_heap_free((__u32)off);
    return sp;
  }

  __u32 __arena* refcount = (__u32 __arena*)(bpfj_heap_ptr() + rc_off);
  *refcount = 1;
  sp.buf = (void __arena*)(bpfj_heap_ptr() + off);
  sp.refcount = refcount;
  return sp;
}

// Wrap a buffer the caller already has in a fresh reference count, set to 1,
// or an invalid pointer (refcount == NULL) leaving the buffer the caller's. It
// costs one allocation, so a caller about to take a lock can take the count in
// advance and hand it on.
static __always_inline struct bpfj_shared_ptr bpfj_shared_ptr_adopt(
    void __arena* buf) {
  struct bpfj_shared_ptr sp = {0};

  // Raw heap function, not the BPFJ_HEAP_* macro -- see bpfj_shared_ptr_make.
  long rc_off = bpfj_heap_alloc(sizeof(__u32));
  if (rc_off <= 0) {
    return sp;
  }

  __u32 __arena* refcount = (__u32 __arena*)(bpfj_heap_ptr() + rc_off);
  *refcount = 1;
  sp.buf = buf;
  sp.refcount = refcount;
  return sp;
}

// Whether the pointer refers to a live buffer.
static __always_inline bool bpfj_shared_ptr_valid(struct bpfj_shared_ptr sp) {
  return sp.buf != NULL;
}

// The current reference count, 0 for an invalid pointer; observability only,
// the free decision being the atomic decrement in release().
static __always_inline __u32
bpfj_shared_ptr_use_count(struct bpfj_shared_ptr sp) {
  if (!sp.refcount) {
    return 0;
  }
  return *sp.refcount;
}

// Take an additional reference; the returned copy aliases the original.
static __always_inline struct bpfj_shared_ptr bpfj_shared_ptr_acquire(
    struct bpfj_shared_ptr sp) {
  if (sp.refcount) {
    __sync_fetch_and_add(sp.refcount, 1);
  }
  return sp;
}

// bpfj_shared_ptr_acquire for a pointer in the arena, field by field because a
// whole-struct load out of arena memory reads back as a scalar on 6.11. The
// caller must hold whatever guards '*sp' against replacement.
static __always_inline struct bpfj_shared_ptr bpfj_shared_ptr_acquire_arena(
    struct bpfj_shared_ptr __arena* sp) {
  struct bpfj_shared_ptr out = {0};
  out.buf = sp->buf;
  out.refcount = sp->refcount;
  if (out.refcount) {
    __sync_fetch_and_add(out.refcount, 1);
  }
  return out;
}

// Move a pointer out of the arena: the caller takes over the reference '*sp'
// held, with no count changing hands.
static __always_inline struct bpfj_shared_ptr bpfj_shared_ptr_take_arena(
    struct bpfj_shared_ptr __arena* sp) {
  struct bpfj_shared_ptr out = {0};
  out.buf = sp->buf;
  out.refcount = sp->refcount;
  sp->buf = NULL;
  sp->refcount = NULL;
  return out;
}

#define BPFJ_SHARED_PTR_RELEASE(_sp, _destructor)               \
  ({                                                            \
    void __arena* _p = (_sp)->buf;                              \
    __u32 __arena* _refcount = (_sp)->refcount;                 \
                                                                \
    if (_refcount && __sync_sub_and_fetch(_refcount, 1) == 0) { \
      BPFJ_HEAP_FREE(_refcount);                                \
      _destructor(_p);                                          \
    }                                                           \
                                                                \
    (_sp)->buf = NULL;                                          \
    (_sp)->refcount = NULL;                                     \
    0;                                                          \
  })

// Drop this reference, freeing the buffer and count at 0. Clears '*sp' so a
// second release is a no-op.
static __always_inline long bpfj_shared_ptr_release(
    struct bpfj_shared_ptr* sp) {
  return BPFJ_SHARED_PTR_RELEASE(sp, BPFJ_HEAP_FREE);
}

// __always_inline like bpfj_shared_ptr_release, a frame of its own sitting on
// the deepest release chains, which have none to spare.
static __always_inline long bpfj_shared_ptr_release_arena(
    __arena struct bpfj_shared_ptr* sp) {
  return BPFJ_SHARED_PTR_RELEASE(sp, BPFJ_HEAP_FREE);
}

// Drop whatever '*sp' held and make it the sole owner of 'ptr', count 1;
// -ENOMEM leaves '*sp' cleared and 'ptr' the caller's to free. Inlined rather
// than a global subprogram, because callers reach it holding a lock, where the
// arena pointers have decayed to scalars a global's contract would reject.
static __always_inline long bpfj_shared_ptr_reset(
    struct bpfj_shared_ptr __arena* sp,
    void __arena* ptr) {
  // Clears '*sp' and cannot fail.
  bpfj_shared_ptr_release_arena(sp);

  // Raw heap function, not the BPFJ_HEAP_* macro — see bpfj_shared_ptr_make.
  long rc_off = bpfj_heap_alloc(sizeof(__u32));
  if (rc_off <= 0) {
    return -ENOMEM;
  }

  // No other reference exists yet, so a plain store is enough to publish 1.
  __u32 __arena* refcount = (__u32 __arena*)(bpfj_heap_ptr() + rc_off);
  *refcount = 1;
  sp->buf = ptr;
  sp->refcount = refcount;
  return 0;
}

struct bpfj_shared_ptr_guard {
  struct bpfj_shared_ptr ptr;
};

// static, so this is not emitted as a global BPF subprog into every including
// object and collide at link time (as in lock.h).
static __always_inline void bpfj_shared_ptr_guard_cleanup(
    struct bpfj_shared_ptr_guard* guard) {
  bpfj_shared_ptr_release(&guard->ptr);
}

// RAII holder: adopts '_sp' without taking an extra reference and releases it
// at scope exit, so wrap bpfj_shared_ptr_make() to own the initial reference
// or bpfj_shared_ptr_acquire() to hold a scoped extra one.
#define BPFJ_SHARED_PTR_GUARD(_name, _sp)                                     \
  __attribute__((cleanup(                                                     \
      bpfj_shared_ptr_guard_cleanup))) struct bpfj_shared_ptr_guard _name = { \
      .ptr = (_sp)}

// The buffer held by a guard, and whether that buffer is live.
#define BPFJ_SHARED_PTR_BUF(_name) ((_name).ptr.buf)
#define BPFJ_SHARED_PTR_VALID(_name) bpfj_shared_ptr_valid((_name).ptr)
