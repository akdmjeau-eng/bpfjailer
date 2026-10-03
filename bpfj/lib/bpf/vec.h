// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include <errno.h>
#include "bpfj/lib/bpf/heap.h"
#include "bpfj/lib/bpf/types_heap.h"

// A growable array on the BPF arena, in the shape of a C++ vector: an empty
// vec owns nothing, and a push past the end doubles the buffer. BPF-only,
// unlike str_map, perf_map and dyn_lru, so whoever calls bpfj_vec_init calls
// bpfj_vec_destroy. The element type is not part of the type -- it stores
// elem_size bytes per slot and hands back void pointers -- so one
// implementation serves every element type for one instruction budget.

// Slots the first growth allocates, small because the point of a vec over a
// fixed array is not paying for slots nobody uses.
#define BPFJ_VEC_MIN_CAPACITY 4

// Round up to a power of two. Undefined for 0, which reserve never passes.
static __always_inline __u32 bpfj_vec_round_capacity(__u32 capacity) {
  --capacity;
  capacity |= capacity >> 1;
  capacity |= capacity >> 2;
  capacity |= capacity >> 4;
  capacity |= capacity >> 8;
  capacity |= capacity >> 16;
  return capacity + 1;
}

// Zero a vec and fix its element size. Owns nothing until the first push.
static __always_inline void bpfj_vec_init(
    struct bpfj_vec __arena* vec,
    __u32 elem_size) {
  // Field-wise: a whole-struct write to arena memory loses the address space.
  vec->buf = NULL;
  vec->elem_size = elem_size;
  vec->size = 0;
  vec->capacity = 0;
  vec->_pad = 0;
}

// Give the buffer back; elem_size survives, so a destroyed vec is a valid
// empty vec that can be pushed to again.
static __always_inline void bpfj_vec_destroy(struct bpfj_vec __arena* vec) {
  // Through a local, or the allocator reads a pointer it is returning.
  void __arena* buf = vec->buf;
  if (buf != NULL) {
    BPFJ_HEAP_FREE(buf);
  }
  vec->buf = NULL;
  vec->size = 0;
  vec->capacity = 0;
}

static __always_inline __u32 bpfj_vec_size(struct bpfj_vec __arena* vec) {
  return vec->size;
}

static __always_inline __u32 bpfj_vec_capacity(struct bpfj_vec __arena* vec) {
  return vec->capacity;
}

// Drop every element and keep the buffer; a vec holds plain bytes.
static __always_inline void bpfj_vec_clear(struct bpfj_vec __arena* vec) {
  vec->size = 0;
}

static __always_inline void bpfj_vec_pop_back(struct bpfj_vec __arena* vec) {
  __u32 size = vec->size;
  if (size != 0) {
    vec->size = size - 1;
  }
}

// Drop everything past `size`. Shorter only, since growing here would expose
// slots nobody wrote.
static __always_inline void bpfj_vec_truncate(
    struct bpfj_vec __arena* vec,
    __u32 size) {
  if (size < vec->size) {
    vec->size = size;
  }
}

// Element `index`, or NULL if it is past the end.
static __always_inline void __arena* bpfj_vec_at(
    struct bpfj_vec __arena* vec,
    __u32 index) {
  if (index >= vec->size) {
    return NULL;
  }

  void __arena* buf = vec->buf;
  if (buf == NULL) {
    return NULL;
  }

  // Clamped because index and stride both come out of the arena, so their
  // product is unknown at verification time.
  __u32 off = bpfj_heap_clamp_off(index * vec->elem_size);
  return (char __arena*)buf + off;
}

// Make room for at least `want` elements. Returns 0, or a negative errno.
// __noinline so its scratch and the growth copy's iterator sit in a frame of
// their own, its callers being on a chain already at the verifier's
// combined-stack limit.
static __noinline long bpfj_vec_reserve(
    struct bpfj_vec __arena* vec,
    __u32 want) {
  __u32 capacity = vec->capacity;
  if (want <= capacity) {
    return 0;
  }

  __u32 elem_size = vec->elem_size;
  if (elem_size == 0) {
    return -EINVAL;
  }

  // Doubling, unless the caller asked for more than doubling would give.
  __u32 new_capacity = capacity != 0 ? capacity * 2 : BPFJ_VEC_MIN_CAPACITY;
  if (new_capacity < want) {
    new_capacity = bpfj_vec_round_capacity(want);
  }

  // Both the doubling and the round-up can wrap, and the byte count can
  // overflow a __u32, so the ceiling is checked by dividing.
  if (new_capacity < want ||
      new_capacity > BPFJ_HEAP_MAX_ARENA_SIZE / elem_size) {
    return -E2BIG;
  }

  void __arena* buf = BPFJ_HEAP_ALLOC(new_capacity * elem_size);
  if (buf == NULL) {
    return -ENOMEM;
  }

  void __arena* old = vec->buf;
  if (old != NULL) {
    bpfj_heap_copy_arena(buf, old, vec->size * elem_size);
    BPFJ_HEAP_FREE(old);
  }

  vec->buf = buf;
  vec->capacity = new_capacity;
  return 0;
}

// Grow if needed and hand back the new last slot, uninitialized, or NULL if it
// could not grow. The cheapest one to use from inside a bpf_for: it has no
// iterator of its own, and the growth path's lives in bpfj_vec_reserve's frame
// rather than the caller's.
static __always_inline void __arena* bpfj_vec_emplace_back(
    struct bpfj_vec __arena* vec) {
  __u32 size = vec->size;
  if (size >= vec->capacity) {
    if (bpfj_vec_reserve(vec, size + 1) < 0) {
      return NULL;
    }
  }

  void __arena* buf = vec->buf;
  if (buf == NULL) {
    return NULL;
  }

  __u32 off = bpfj_heap_clamp_off(size * vec->elem_size);
  vec->size = size + 1;
  return (char __arena*)buf + off;
}

// Copy an element in from outside the arena -- a local, or a map value.
// `len` is the caller's sizeof, checked against vec->elem_size, because the
// byte-wise copy can only be bounded if the source's size is known at the call
// site. __always_inline so that constant survives to the copy, at the cost of
// the copy's iterator landing in the caller's frame -- on a chain near the
// verifier's combined-stack limit, prefer emplace_back plus
// bpfj_heap_copy_arena when the source is already on the arena.
static __always_inline long
bpfj_vec_push_back(struct bpfj_vec __arena* vec, const void* elem, __u32 len) {
  if (len != vec->elem_size) {
    return -EINVAL;
  }

  void __arena* slot = bpfj_vec_emplace_back(vec);
  if (slot == NULL) {
    return -ENOMEM;
  }

  bpfj_heap_write_arena(slot, len, elem);
  return 0;
}

// Push `_elem` (a pointer to the value) onto `_vec`, taking the length from the
// pointee's type so it stays a compile-time constant.
#define BPFJ_VEC_PUSH_BACK(_vec, _elem) \
  bpfj_vec_push_back(_vec, (_elem), (__u32)sizeof(*(_elem)))

// Replace the contents with `count` elements from `src`, which must be a heap
// block holding at least that many, so bpfj_heap_copy_arena's word-wise
// round-up lands inside it. The bulk counterpart to push_back, taking an arena
// source so the length need not be provable at the call site.
static __noinline long bpfj_vec_assign(
    struct bpfj_vec __arena* vec,
    const void __arena* src,
    __u32 count) {
  if (count != 0) {
    if (src == NULL) {
      return -EINVAL;
    }

    long res = bpfj_vec_reserve(vec, count);
    if (res < 0) {
      return res;
    }

    bpfj_heap_copy_arena(vec->buf, src, count * vec->elem_size);
  }

  vec->size = count;
  return 0;
}

// Deep copy: `dst` ends up holding its own copy of src's elements. Both must
// already be init'd to the same element size.
static __always_inline long bpfj_vec_copy(
    struct bpfj_vec __arena* dst,
    struct bpfj_vec __arena* src) {
  if (dst->elem_size != src->elem_size) {
    return -EINVAL;
  }

  return bpfj_vec_assign(dst, src->buf, src->size);
}

// Hand src's buffer to dst, releasing whatever dst held and leaving src as it
// was before its first push.
static __always_inline void bpfj_vec_move(
    struct bpfj_vec __arena* dst,
    struct bpfj_vec __arena* src) {
  bpfj_vec_destroy(dst);

  dst->buf = src->buf;
  dst->elem_size = src->elem_size;
  dst->size = src->size;
  dst->capacity = src->capacity;

  src->buf = NULL;
  src->size = 0;
  src->capacity = 0;
}
