// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

// Userspace heap initialization and allocation for the BPF arena heap: libbpf
// mmaps the arena during skeleton load(), and heap::init() then initializes
// the TLSF control structure and publishes the base into the bpfj_heap_ctrl
// BPF global, which is how both worlds find the arena.

#include <sys/mman.h>
#include <atomic>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <optional>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "bpfj/err/StdExpected.h"
#include "bpfj/lib/Lock.h"
#include "bpfj/lib/Log.h"
#include "bpfj/lib/bpf/types_heap.h"

namespace bpfjailer::heap {

// How long a userspace heap operation waits for the arena lock. BPF holders
// release within one program run, so reaching this means a wedged lock.
constexpr auto kLockTimeout = std::chrono::seconds{5};

template <typename T>
concept BpfSkelWithHeap = requires(T obj) { obj.bss().bpfj_heap_ctrl; };

template <typename Skel>
concept BpfSkelWithHeapSyscall = requires(Skel&& skel) {
  skel->rodata().bpfj_heap_enabled;
  skel->progs().bpfj_heap_syscall;
};

template <typename Skel>
err::Expected<> init(Skel& obj) {
  if (obj->bss().bpfj_heap_ctrl) {
    return err::unit;
  }

  size_t size = 0;
  void* ret = bpf_map__initial_value(obj->maps().bpfj_heap_arena, &size);
  if (!ret) {
    return err::Error(std::errc::invalid_argument, "No arena mmap");
  }

  // When the kernel exposes an arena address, replace libbpf's anonymous
  // staging mapping for a reused pinned arena with the map fd. Older kernels
  // report zero and libbpf's initial-value pointer is already the live map.
  constexpr std::size_t kArenaMapSize =
      BPFJ_HEAP_ARENA_MAP_PAGES * BPFJ_HEAP_PAGE_SIZE;
  const int mapFd = bpf_map__fd(obj->maps().bpfj_heap_arena);
  struct bpf_map_info info{};
  __u32 infoLen = sizeof(info);
  if (mapFd < 0 || bpf_obj_get_info_by_fd(mapFd, &info, &infoLen) != 0) {
    return err::Error::fromErrno("Failed to inspect arena map");
  }
  if (info.map_extra != 0) {
    void* const arenaBase = reinterpret_cast<void*>(info.map_extra);
    void* const mapped = ::mmap(
        arenaBase,
        kArenaMapSize,
        PROT_READ | PROT_WRITE,
        MAP_SHARED | MAP_FIXED,
        mapFd,
        0);
    if (mapped == MAP_FAILED) {
      return err::Error::fromErrno("Failed to mmap arena");
    }
    ret = mapped;
  }

  // For an arena map libbpf reports the size of the object's __arena globals,
  // which it places in the map's last pages; the map is oversized by
  // BPFJ_HEAP_ARENA_GLOBALS_SIZE to keep them clear of the heap.
  if (size > BPFJ_HEAP_ARENA_GLOBALS_SIZE) {
    BPFJ_LOG(ERR) << "arena globals (" << size << " bytes) exceed the "
                  << BPFJ_HEAP_ARENA_GLOBALS_SIZE << " reserved above the heap";
    return err::Error(
        std::errc::no_buffer_space, "Arena globals overflow their reservation");
  }

  auto* ctrl = static_cast<struct bpfj_heap_control*>(ret);
  if (ctrl->arena_size == 0) {
    constexpr __u32 arenaSize = BPFJ_HEAP_INIT_PAGES * BPFJ_HEAP_PAGE_SIZE;
    // Only the initial-value extent is backed here. init_arena writes its
    // control block and first free-block header inside that extent while
    // recording the logical size that later allocations may grow into.
    memset(ret, 0, arenaSize);
    bpfj_heap_init_arena(ctrl, arenaSize);
    // Redundant after the memset, but this is where the lock becomes usable
    // and bpfj_heap_init_arena() no-ops on an already-initialized arena.
    lock::init(ctrl->lock);
  }

  obj->bss().bpfj_heap_ctrl = ctrl;

  return err::unit;
}

// Address translation

// The arena base, published into the BPF global by init(), and null until then.
// The arena is mapped at the same address in both worlds.
template <typename Skel>
inline void* base(Skel&& skel) {
  return reinterpret_cast<void*>(skel->bss().bpfj_heap_ctrl);
}

// Translate a heap offset to an arena pointer, or nullptr if out of range.
inline void* offsetToPtr(void* base, __u32 offset) {
  if (offset >= BPFJ_HEAP_MAX_ARENA_PAGES * BPFJ_HEAP_PAGE_SIZE) {
    return nullptr;
  }

  return reinterpret_cast<char*>(base) + offset;
}

// Inverse of offsetToPtr; a nullptr maps to BPFJ_HEAP_NULL.
inline __u32 ptrToOffset(void* base, const void* ptr) {
  if (ptr == nullptr) {
    return BPFJ_HEAP_NULL;
  }
  return static_cast<__u32>(
      reinterpret_cast<std::uintptr_t>(ptr) -
      reinterpret_cast<std::uintptr_t>(base));
}

template <typename Skel>
inline long
runHeapSyscall(Skel&& skel, __u32 op, __u32 arg, __u32 expectedArenaSize = 0) {
  if (!skel->rodata().bpfj_heap_enabled) {
    return op == BPFJ_HEAP_SYSCALL_FREE ? 0 : BPFJ_HEAP_NULL;
  }

  const int progFd = bpf_program__fd(skel->progs().bpfj_heap_syscall);
  if (progFd < 0) {
    BPFJ_LOG(ERR) << "heap: bpfj_heap_syscall fd is invalid";
    return -EBADF;
  }

  bpfj_heap_syscall_req req{
      .op = op,
      .arg = arg,
      .expected_arena_size = expectedArenaSize,
  };
  LIBBPF_OPTS(
      bpf_test_run_opts, opts, .ctx_in = &req, .ctx_size_in = sizeof(req));

  const int err = bpf_prog_test_run_opts(progFd, &opts);
  if (err < 0) {
    BPFJ_LOG(ERR) << "heap: bpf_prog_test_run_opts failed: " << err;
    return err;
  }

  return static_cast<long>(static_cast<std::int32_t>(opts.retval));
}

inline long
prefaultGrowth(void* base, __u32 minBytes, __u32& expectedArenaSize) {
  auto* ctrl = reinterpret_cast<struct bpfj_heap_control*>(base);
  expectedArenaSize = ctrl->arena_size;
  if (expectedArenaSize >= BPFJ_HEAP_MAX_ARENA_SIZE) {
    return -ENOMEM;
  }

  const __u32 bytes = bpfj_heap_growth_size(minBytes, expectedArenaSize);

  auto* start = reinterpret_cast<std::uint8_t*>(base) + expectedArenaSize;
  for (__u64 offset = 0; offset < bytes; offset += BPFJ_HEAP_PAGE_SIZE) {
    std::uint8_t expected = 0;
    __atomic_compare_exchange_n(
        start + offset,
        &expected,
        0,
        false,
        __ATOMIC_RELAXED,
        __ATOMIC_RELAXED);
  }
  return 0;
}

// Userspace alloc/free (call after init)

// Grow the committed free space by at least 'minBytes' and insert it as one
// free block, the new pages faulted in and zeroed as init() does so they are
// backed for both worlds. False at BPFJ_HEAP_MAX_ARENA_SIZE, and the caller
// must hold the arena lock; bpfj_arena_double() is the BPF side.
inline bool growLocked(void* base, __u32 minBytes) {
  auto* ctrl = reinterpret_cast<struct bpfj_heap_control*>(base);
  __u32 oldSize = ctrl->arena_size;
  if (oldSize >= BPFJ_HEAP_MAX_ARENA_SIZE) {
    return false;
  }

  // Enough for the block header, alignment, and TLSF's good-fit rounding: a
  // request is rounded to the top of its sub-bucket before the search, so the
  // slack must cover a whole granule, 2^(fls(size) - SLI_LOG2). Two pages was
  // exactly enough at 128 KiB and two short at 256 KiB.
  __u64 want = bpfj_heap_adjust_size(minBytes);
  want += (__u64{1}
           << (bpfj_heap_fls(static_cast<__u32>(want)) - BPFJ_HEAP_SLI_LOG2)) -
      1;

  __u64 pages = (want + BPFJ_HEAP_PAGE_SIZE - 1) / BPFJ_HEAP_PAGE_SIZE;
  if (pages < BPFJ_HEAP_GROW_PAGES) {
    pages = BPFJ_HEAP_GROW_PAGES;
  }
  __u64 newBlockSize = pages * BPFJ_HEAP_PAGE_SIZE;
  __u64 newSize = static_cast<__u64>(oldSize) + newBlockSize;
  if (newSize > BPFJ_HEAP_MAX_ARENA_SIZE) {
    newSize = BPFJ_HEAP_MAX_ARENA_SIZE;
    newBlockSize = newSize - oldSize;
  }

  // Fault in and zero the region as init() does, bumping arena_size before
  // the insert so the new block is treated as the arena tail.
  memset(reinterpret_cast<char*>(base) + oldSize, 0, newBlockSize);
  ctrl->arena_size = static_cast<__u32>(newSize);

  auto* hdr = bpfj_heap_block_at(base, oldSize);
  hdr->size_and_flags = static_cast<__u32>(newBlockSize);
  hdr->prev_phys_offset = BPFJ_HEAP_NULL;

  __u32 fli = 0;
  __u32 sli = 0;
  bpfj_heap_mapping(static_cast<__u32>(newBlockSize), &fli, &sli);
  bpfj_heap_insert_free_block(base, ctrl, oldSize, fli, sli);
  ++ctrl->grow_gen;
  return true;
}

// Grow the arena, taking the arena lock. Returns false if the arena is already
// at BPFJ_HEAP_MAX_ARENA_SIZE or the lock could not be taken.
inline bool grow(void* base, __u32 minBytes) {
  auto* ctrl = reinterpret_cast<struct bpfj_heap_control*>(base);
  lock::Guard guard{ctrl->lock, kLockTimeout};
  if (!guard.owns()) {
    BPFJ_LOG(ERR) << "heap: timed out taking the arena lock to grow";
    return false;
  }
  return growLocked(base, minBytes);
}

// Allocate 'size' bytes, returning the heap offset or BPFJ_HEAP_NULL, and
// growing the arena when the free list cannot satisfy the request.
inline long alloc(void* base, __u32 size) {
  auto* ctrl = reinterpret_cast<struct bpfj_heap_control*>(base);
  lock::Guard guard{ctrl->lock, kLockTimeout};
  if (!guard.owns()) {
    BPFJ_LOG(ERR) << "heap: timed out taking the arena lock to allocate";
    return BPFJ_HEAP_NULL;
  }

  long offset = bpfj_heap_alloc_impl(base, ctrl, size);
  if (offset <= 0 && growLocked(base, size)) {
    offset = bpfj_heap_alloc_impl(base, ctrl, size);
  }
  return offset;
}

// Allocate through the BPF helper so userspace does not take the shared arena
// lock directly. On exhaustion, ask BPF to grow the arena and then retry once.
template <typename Skel>
inline long allocOffset(Skel&& skel, __u32 size) {
  if constexpr (!BpfSkelWithHeapSyscall<Skel>) {
    return alloc(base(std::forward<Skel>(skel)), size);
  } else {
    if (!skel->rodata().bpfj_heap_enabled) {
      return BPFJ_HEAP_NULL;
    }
    if (bpf_program__fd(skel->progs().bpfj_heap_syscall) < 0) {
      return alloc(base(std::forward<Skel>(skel)), size);
    }

    long offset =
        runHeapSyscall(std::forward<Skel>(skel), BPFJ_HEAP_SYSCALL_ALLOC, size);
    if (offset == BPFJ_HEAP_NULL || offset == -ENOMEM) {
      __u32 expectedArenaSize = 0;
      long ret = prefaultGrowth(
          base(std::forward<Skel>(skel)), size, expectedArenaSize);
      if (ret < 0) {
        BPFJ_LOG(ERR) << "heap: prefault growth failed: " << ret;
        return ret;
      }
      ret = runHeapSyscall(
          std::forward<Skel>(skel),
          BPFJ_HEAP_SYSCALL_GROW,
          size,
          expectedArenaSize);
      if (ret < 0) {
        BPFJ_LOG(ERR) << "heap: publishing prefaulted growth failed: " << ret;
        return ret;
      }
      offset = runHeapSyscall(
          std::forward<Skel>(skel), BPFJ_HEAP_SYSCALL_ALLOC, size);
    }
    return offset;
  }
}

// Allocate 'size' bytes, returning an arena pointer (nullptr on failure).
template <typename Skel>
inline void* alloc(Skel&& skel, __u32 size) {
  void* arena = base(std::forward<Skel>(skel));
  long offset = allocOffset(std::forward<Skel>(skel), size);
  if (offset <= 0) {
    return nullptr;
  }
  return offsetToPtr(arena, static_cast<__u32>(offset));
}

// Allocate a single T constructed from 'args' (nullptr on failure).
template <typename T, typename Skel, typename... Args>
inline T* alloc(Skel&& skel, Args&&... args) {
  T* ptr = static_cast<T*>(
      alloc(std::forward<Skel>(skel), static_cast<__u32>(sizeof(T))));
  if (ptr == nullptr) {
    return nullptr;
  }
  new (ptr) T{std::forward<Args>(args)...};

  return ptr;
}

// Allocate 'n' contiguous T, each constructed from 'args' (nullptr on
// failure). A distinct name rather than an 'alloc' overload, which would be
// ambiguous whenever T is constructible from an integer, and 'args' are const
// references, perfect-forwarding moving from an rvalue on the first element.
template <typename T, typename Skel, typename... Args>
inline T* allocArray(Skel&& skel, std::size_t n, const Args&... args) {
  T* ptr = static_cast<T*>(
      alloc(std::forward<Skel>(skel), static_cast<__u32>(sizeof(T) * n)));
  if (ptr == nullptr) {
    return nullptr;
  }
  for (std::size_t i = 0; i < n; ++i) {
    new (ptr + i) T{args...};
  }

  return ptr;
}

// Free a previously allocated block by heap offset.
inline long free(void* base, __u32 offset) {
  auto* ctrl = reinterpret_cast<struct bpfj_heap_control*>(base);
  lock::Guard guard{ctrl->lock, kLockTimeout};
  if (!guard.owns()) {
    BPFJ_LOG(ERR) << "heap: timed out taking the arena lock to free";
    return -EBUSY;
  }
  return bpfj_heap_free_impl(base, ctrl, offset);
}

// Free a previously allocated block by arena pointer. A nullptr is a no-op.
template <typename T>
inline long free(void* base, T* ptr) {
  if (ptr == nullptr) {
    return 0;
  }
  return free(base, ptrToOffset(base, ptr));
}

template <typename Skel>
inline long freeOffset(Skel&& skel, __u32 offset) {
  if (offset == BPFJ_HEAP_NULL) {
    return 0;
  }
  if constexpr (!BpfSkelWithHeapSyscall<Skel>) {
    return free(base(std::forward<Skel>(skel)), offset);
  } else {
    if (!skel->rodata().bpfj_heap_enabled) {
      return 0;
    }
    if (bpf_program__fd(skel->progs().bpfj_heap_syscall) < 0) {
      return free(base(std::forward<Skel>(skel)), offset);
    }
    return runHeapSyscall(
        std::forward<Skel>(skel), BPFJ_HEAP_SYSCALL_FREE, offset);
  }
}

// Free a previously allocated block by arena pointer. A nullptr is a no-op.
template <typename Skel, typename T>
inline long free(Skel&& skel, T* ptr) {
  if (ptr == nullptr) {
    return 0;
  }
  void* arena = base(std::forward<Skel>(skel));
  return freeOffset(std::forward<Skel>(skel), ptrToOffset(arena, ptr));
}

template <typename Skel>
inline __u32 currentUsed(Skel&& skel) {
  if (!skel->rodata().bpfj_heap_enabled) {
    return 0;
  }
  const auto* ctrl = skel->bss().bpfj_heap_ctrl;
  if (ctrl == nullptr) {
    return 0;
  }
  // The arena is capped at BPFJ_HEAP_MAX_ARENA_PAGES (32 MiB), so the __u64
  // count cannot reach 32 bits and the narrowing is safe.
  return static_cast<__u32>(ctrl->current_used);
}

// Heap usage stats read from the arena control structure, for ODS counters.
struct Stats {
  __u32 arenaSize;
  __u64 currentUsed;
  __u64 totalAlloc;
  __u64 totalFree;
};

/// Read heap usage stats for ODS reporting, or nullopt when the arena is not
/// readable here. bpfj_heap_ctrl is null until init() publishes the base, so
/// it doubles as the "initialized" gate and is never dereferenced unchecked.
template <typename Obj>
std::optional<Stats> readStats(Obj& obj) {
  if (!obj->rodata().bpfj_heap_enabled) {
    return std::nullopt;
  }
  const auto* ctrl = obj->bss().bpfj_heap_ctrl;
  if (ctrl == nullptr || ctrl->arena_size == 0) {
    return std::nullopt;
  }
  return Stats{
      ctrl->arena_size,
      ctrl->current_used,
      ctrl->total_alloc,
      ctrl->total_free};
}

} // namespace bpfjailer::heap
