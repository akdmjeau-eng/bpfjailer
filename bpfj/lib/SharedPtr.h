// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

// Userspace side of the arena reference-counted pointer (struct
// bpfj_shared_ptr, see bpfj/lib/bpf/shared_ptr.h). The buffer and its count
// both live in the arena, mapped at the same address in both worlds, and the
// count moves under lock-free atomics compatible with the BPF side's __sync
// builtins, so acquire and release may interleave.

#include <utility>

#include "bpfj/lib/Heap.h"
#include "bpfj/lib/bpf/types_shared_ptr.h"

namespace bpfjailer::shared_ptr {

// Allocate a 'size'-byte buffer and its reference count, set to 1, or an
// invalid pointer (buf == nullptr) if either allocation fails. The buffer is
// not zeroed, matching the BPF-side make.
template <typename Skel>
inline bpfj_shared_ptr make(Skel&& skel, __u32 size) {
  bpfj_shared_ptr sp{};

  // Bind the forwarding reference to an lvalue first, since this reaches the
  // heap up to three times and the first callee would move from an rvalue.
  auto& skelRef = skel;

  void* buf = heap::alloc(skelRef, size);
  if (buf == nullptr) {
    return sp;
  }

  auto* refcount = heap::alloc<__u32>(skelRef, __u32{1});
  if (refcount == nullptr) {
    heap::free(skelRef, buf);
    return sp;
  }

  sp.buf = buf;
  sp.refcount = refcount;
  return sp;
}

// Whether the pointer refers to a live buffer.
inline bool valid(bpfj_shared_ptr sp) {
  return sp.buf != nullptr;
}

// The current reference count, 0 for an invalid pointer. Observability only:
// the free decision is the atomic decrement in release().
inline __u32 useCount(bpfj_shared_ptr sp) {
  if (sp.refcount == nullptr) {
    return 0;
  }
  return __atomic_load_n(sp.refcount, __ATOMIC_ACQUIRE);
}

// Take an additional reference; the returned copy aliases the original.
inline bpfj_shared_ptr acquire(bpfj_shared_ptr sp) {
  if (sp.refcount != nullptr) {
    __atomic_add_fetch(sp.refcount, 1, __ATOMIC_ACQ_REL);
  }
  return sp;
}

// Drop this reference. At 0, free the count and hand the buffer to
// `destroy(skel, buf)`. That callback releases whatever the buffer owns and
// then the buffer itself. It is BPFJ_SHARED_PTR_RELEASE's destructor on this
// side. Clears `*sp` so a second release is a no-op.
template <typename Skel, typename Destroy>
inline void release(Skel&& skel, bpfj_shared_ptr* sp, Destroy&& destroy) {
  if (sp->refcount == nullptr) {
    return;
  }

  if (__atomic_sub_fetch(sp->refcount, 1, __ATOMIC_ACQ_REL) == 0) {
    // Bind to an lvalue before reaching the heap twice, as in make().
    auto& skelRef = skel;
    heap::free(skelRef, sp->refcount);
    std::forward<Destroy>(destroy)(skelRef, sp->buf);
  }

  sp->buf = nullptr;
  sp->refcount = nullptr;
}

// Drop this reference, freeing the buffer and count at 0, for a buffer that
// owns nothing else.
template <typename Skel>
inline void release(Skel&& skel, bpfj_shared_ptr* sp) {
  release(std::forward<Skel>(skel), sp, [](auto& skelRef, void* buf) {
    heap::free(skelRef, buf);
  });
}

} // namespace bpfjailer::shared_ptr
