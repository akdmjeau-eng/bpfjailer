// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#ifdef __cplusplus
#include <linux/types.h>
#endif

#include "bpfj/lib/bpf/types_heap.h"

// Layout of a reference-counted pointer to an arena heap buffer -- a pointer
// to the buffer and one to its count, both into the arena -- shared between
// the BPF ops (shared_ptr.h, which has the ownership model) and the userspace
// mirror (SharedPtr.h). A zeroed value (buf == NULL) is the invalid pointer.
struct bpfj_shared_ptr {
  void __arena* buf;
  __u32 __arena* refcount;
};
