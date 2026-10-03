#pragma once

#include <errno.h>
#include "bpfj/lib/bpf/heap.h"
#include "bpfj/lib/bpf/lock.h"
#include "bpfj/lib/bpf/shared_ptr.h"
#include "bpfj/match/bpf/types_mount.h"

extern const void mount_lock __ksym;

__noinline u32 bpfj_mount_seqcount() {
  return BPF_CORE_READ(
      ((const seqlock_t*)&mount_lock), seqcount.seqcount.sequence);
}

static __always_inline void bpfj_mount_task_cleanup(struct task_struct** task) {
  if (task && *task) {
    bpf_task_release(*task);
  }
}

static __always_inline struct bpfj_mount_snapshot_slot __arena*
bpfj_mount_snapshot_slot_at(
    struct bpfj_mount_snapshot __arena* snapshot,
    __u32 index) {
  __u32 off = bpfj_heap_clamp_off(
      index * (__u32)sizeof(struct bpfj_mount_snapshot_slot));
  return (
      struct bpfj_mount_snapshot_slot __arena*)((char __arena*)snapshot->slots +
                                                off);
}

static __always_inline long bpfj_mount_snapshot_insert(
    struct bpfj_mount_snapshot __arena* snapshot,
    __u64 root,
    __u64 parent_vfsmount,
    __u64 mountpoint,
    __u64 mount_id) {
  if (!root) {
    return -EINVAL;
  }
  if (snapshot->count >= snapshot->capacity) {
    return -ENOSPC;
  }
  struct bpfj_mount_snapshot_slot __arena* slot =
      bpfj_mount_snapshot_slot_at(snapshot, snapshot->count++);
  slot->root = root;
  slot->parent_vfsmount = parent_vfsmount;
  slot->mountpoint = mountpoint;
  slot->mount_id = mount_id;
  return 0;
}

__noinline long bpfj_mount_snapshot_visit(
    struct bpfj_mount_snapshot __arena* snapshot __arg_arena,
    struct rb_node * __arena * nodes __arg_arena,
    int depth) {
  int pos = depth - 1;
  struct rb_node* node = nodes[pos--];
  struct mount* mount = container_of(node, struct mount, mnt_node);
  struct rb_node* right = BPF_CORE_READ(node, rb_right);
  struct rb_node* left = BPF_CORE_READ(node, rb_left);

  if (right) {
    ++pos;
    barrier_var(pos);
    if (pos >= 0 && pos < BPFJ_MOUNT_MAX_TREE_BREADTH) {
      nodes[pos] = right;
    }
  }
  if (pos >= BPFJ_MOUNT_MAX_TREE_BREADTH) {
    return -E2BIG;
  }
  if (left) {
    ++pos;
    barrier_var(pos);
    if (pos >= 0 && pos < BPFJ_MOUNT_MAX_TREE_BREADTH) {
      nodes[pos] = left;
    }
  }
  if (pos >= BPFJ_MOUNT_MAX_TREE_BREADTH) {
    return -E2BIG;
  }

  struct mount* parent = BPF_CORE_READ(mount, mnt_parent);
  long ret = bpfj_mount_snapshot_insert(
      snapshot,
      (uintptr_t)BPF_CORE_READ(mount, mnt.mnt_root),
      parent ? (uintptr_t)&parent->mnt : 0,
      (uintptr_t)BPF_CORE_READ(mount, mnt_mountpoint),
      BPF_CORE_READ(mount, mnt_id_unique));
  return ret < 0 ? ret : pos + 1;
}

static __noinline long bpfj_mount_snapshot_build(
    uintptr_t namespace_i,
    __u32 generation,
    struct bpfj_shared_ptr* out) {
  struct mnt_namespace* ns = (struct mnt_namespace*)namespace_i;
  __u32 mounts = BPF_CORE_READ(ns, nr_mounts);
  if (mounts > BPFJ_MOUNT_MAX_MOUNTS) {
    return -E2BIG;
  }

  __u64 bytes = sizeof(struct bpfj_mount_snapshot) +
      (__u64)mounts * sizeof(struct bpfj_mount_snapshot_slot);
  if (bytes > BPFJ_HEAP_MAX_ARENA_SIZE) {
    return -E2BIG;
  }

  struct bpfj_shared_ptr snapshot_ptr = bpfj_shared_ptr_calloc((__u32)bytes);
  if (!bpfj_shared_ptr_valid(snapshot_ptr)) {
    return -ENOMEM;
  }
  struct bpfj_mount_snapshot __arena* snapshot = snapshot_ptr.buf;
  snapshot->mount_lock = generation;
  snapshot->capacity = mounts;

  __attribute((cleanup(bpfj_heap_free_ptr))) void __arena* stack_buf =
      BPFJ_HEAP_ALLOC(sizeof(struct rb_node*) * BPFJ_MOUNT_MAX_TREE_BREADTH);
  if (!stack_buf) {
    bpfj_shared_ptr_release(&snapshot_ptr);
    return -ENOMEM;
  }
  struct rb_node* __arena* nodes = stack_buf;
  nodes[0] = BPF_CORE_READ(ns, mounts.rb_node);
  long depth = nodes[0] ? 1 : 0;
  __u32 visited = 0;
  __u32 i = 0;
  bpf_for(i, 0, BPFJ_MOUNT_MAX_MOUNTS) {
    if (depth <= 0 || depth > BPFJ_MOUNT_MAX_TREE_BREADTH) {
      break;
    }
    depth = bpfj_mount_snapshot_visit(snapshot, nodes, (int)depth);
    if (depth < 0) {
      break;
    }
    ++visited;
  }

  long ret = depth < 0 ? depth : 0;
  // A concurrent mount-tree update can change both the traversal shape and
  // nr_mounts. Retry any result from a stale generation, including apparent
  // breadth overflow, rather than reporting a permanent policy error.
  if (generation != bpfj_mount_seqcount()) {
    ret = -EBUSY;
  } else if (ret == 0 && visited != mounts) {
    ret = -EIO;
  }
  if (ret < 0) {
    bpfj_shared_ptr_release(&snapshot_ptr);
    return ret;
  }
  *out = snapshot_ptr;
  return 0;
}

// Resolve the target namespace and acquire an immutable snapshot from the
// caller-owned cache, replacing a stale generation without disturbing walks
// that still hold it.
__noinline long bpfj_mount_load(
    struct bpfj_mount_cache __arena* cache __arg_arena,
    pid_t pid,
    struct bpfj_mount_descriptor __arena* descriptor __arg_arena,
    struct bpfj_shared_ptr __arena* out __arg_arena) {
  descriptor->ns_ino = 0;
  descriptor->namespace_addr = 0;
  descriptor->mount_lock = 0;
  out->buf = NULL;
  out->refcount = NULL;
  if (!cache) {
    return -EINVAL;
  }

  __attribute((cleanup(bpfj_mount_task_cleanup))) struct task_struct* task =
      bpf_task_from_pid(pid);
  if (!task) {
    return -ESRCH;
  }
  struct mnt_namespace* ns = BPF_CORE_READ(task, nsproxy, mnt_ns);
  if (!ns) {
    return -ESRCH;
  }

  __u64 ns_ino = BPF_CORE_READ(ns, ns.inum);
  __u32 generation = bpfj_mount_seqcount();
  {
    BPFJ_LOCK_GUARD(guard, &cache->lock);
    if (!BPFJ_LOCK_IS_ACQUIRED(guard)) {
      return -EBUSY;
    }
    struct bpfj_mount_snapshot __arena* snapshot = cache->snapshot.buf;
    if (cache->ns_ino == ns_ino && snapshot &&
        snapshot->mount_lock == generation) {
      struct bpfj_shared_ptr acquired =
          bpfj_shared_ptr_acquire_arena(&cache->snapshot);
      out->buf = acquired.buf;
      out->refcount = acquired.refcount;
      descriptor->ns_ino = ns_ino;
      descriptor->mount_lock = generation;
      descriptor->namespace_addr = (uintptr_t)ns;
      return (long)ns_ino;
    }
  }

  struct bpfj_shared_ptr built = {0};
  long ret = bpfj_mount_snapshot_build((uintptr_t)ns, generation, &built);
  if (ret < 0) {
    return ret;
  }

  struct bpfj_shared_ptr retired = {0};
  {
    BPFJ_LOCK_GUARD(guard, &cache->lock);
    if (!BPFJ_LOCK_IS_ACQUIRED(guard)) {
      bpfj_shared_ptr_release(&built);
      return -EBUSY;
    }
    struct bpfj_mount_snapshot __arena* current = cache->snapshot.buf;
    if (cache->ns_ino == ns_ino && current &&
        current->mount_lock == generation) {
      struct bpfj_shared_ptr acquired =
          bpfj_shared_ptr_acquire_arena(&cache->snapshot);
      out->buf = acquired.buf;
      out->refcount = acquired.refcount;
    } else {
      retired = bpfj_shared_ptr_take_arena(&cache->snapshot);
      cache->ns_ino = ns_ino;
      cache->snapshot.buf = built.buf;
      cache->snapshot.refcount = built.refcount;
      built.buf = NULL;
      built.refcount = NULL;
      struct bpfj_shared_ptr acquired =
          bpfj_shared_ptr_acquire_arena(&cache->snapshot);
      out->buf = acquired.buf;
      out->refcount = acquired.refcount;
    }
  }
  bpfj_shared_ptr_release(&retired);
  bpfj_shared_ptr_release(&built);

  descriptor->ns_ino = ns_ino;
  descriptor->mount_lock = generation;
  descriptor->namespace_addr = (uintptr_t)ns;
  return (long)ns_ino;
}

struct bpfj_mount_snapshot_lookup_ctx {
  struct bpfj_mount_snapshot __arena* snapshot;
  __u64 root;
  __u64 parent_vfsmount;
  __u64 mountpoint;
  __u64 mount_id;
  bool found;
};

static long bpfj_mount_snapshot_lookup(__u32 index, void* data) {
  struct bpfj_mount_snapshot_lookup_ctx* ctx = data;
  struct bpfj_mount_snapshot __arena* snapshot = ctx->snapshot;
  if (index >= snapshot->count) {
    return 1;
  }
  struct bpfj_mount_snapshot_slot __arena* slot =
      bpfj_mount_snapshot_slot_at(snapshot, index);
  if (slot->root != ctx->root) {
    return 0;
  }
  if (!ctx->found || slot->mount_id < ctx->mount_id) {
    ctx->parent_vfsmount = slot->parent_vfsmount;
    ctx->mountpoint = slot->mountpoint;
    ctx->mount_id = slot->mount_id;
    ctx->found = true;
  }
  return 0;
}

// Lookup the canonical transition for a true filesystem or subvolume root.
__noinline long bpfj_mount_find_parent(
    struct bpfj_mount_snapshot __arena* snapshot __arg_arena,
    uintptr_t root_i,
    struct bpfj_mount_fallback __arena* out __arg_arena) {
  out->parent_vfsmount = 0;
  out->mountpoint = 0;
  if (!snapshot || !root_i || snapshot->count == 0 ||
      snapshot->count > snapshot->capacity ||
      snapshot->capacity > BPFJ_MOUNT_MAX_MOUNTS) {
    return -EINVAL;
  }

  struct bpfj_mount_snapshot_lookup_ctx ctx = {
      .snapshot = snapshot,
      .root = root_i,
      .mount_id = ~0ULL,
  };
  bpf_loop(snapshot->count, bpfj_mount_snapshot_lookup, &ctx, 0);
  if (!ctx.found) {
    return -ENOENT;
  }
  out->parent_vfsmount = ctx.parent_vfsmount;
  out->mountpoint = ctx.mountpoint;
  return 0;
}
