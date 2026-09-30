// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

// Userspace side of the BPF arena spin lock (struct bpfj_lock, see
// bpfj/lib/bpf/lock.h). types_lock.h gives BPF libarena's arena_spinlock_t and
// userspace an equivalent single atomic word, and both sides are restricted to
// the same compare-exchange-from-zero acquire and locked-byte release, so they
// genuinely exclude.
//
// Waiting here is safe in a way waiting in BPF is not -- a BPF holder always
// releases before its program returns, and waiting yields rather than spinning
// with preemption disabled -- so keep critical sections short, a BPF program
// that fails to acquire having to skip its work.

#include <atomic>
#include <chrono>
#include <thread>

#include <linux/types.h>

#include "bpfj/lib/bpf/types_lock.h"

namespace bpfjailer::lock {

// Bit layout of the qspinlock value word, mirroring _Q_* in
// bpf_arena_spin_lock.h; positions rather than byte offsets, so they hold on
// either endianness.
constexpr __u32 kLockedMask = 0xFFU;
constexpr __u32 kLockedVal = 1U;

// Put a lock into the free state: required before first use, and not safe to
// run concurrently with any user. Acquire only succeeds on an all-zero word,
// so residue -- the allocator's free-list links in a recycled heap block, say
// -- leaves the lock permanently held. Relaxed, since initialization is
// unshared and the publishing store carries the release.
inline void init(bpfj_lock& lock) {
  lock.val.store(0, std::memory_order_relaxed);
}

// Take the lock if it is completely free, returning whether it was acquired.
inline bool tryLock(bpfj_lock& lock) {
  __u32 expected = 0;
  return lock.val.compare_exchange_strong(
      expected,
      kLockedVal,
      std::memory_order_acquire,
      std::memory_order_relaxed);
}

// Spin until the lock is acquired or 'timeout' elapses, yielding between
// attempts since there is nothing to wait on but the word.
inline bool tryLockFor(bpfj_lock& lock, std::chrono::nanoseconds timeout) {
  const auto deadline = std::chrono::steady_clock::now() + timeout;
  while (!tryLock(lock)) {
    if (std::chrono::steady_clock::now() >= deadline) {
      return false;
    }
    std::this_thread::yield();
  }
  return true;
}

// Clears only the locked byte, so this stays a correct release for the full
// qspinlock protocol.
inline void unlock(bpfj_lock& lock) {
  lock.val.fetch_and(~kLockedMask, std::memory_order_release);
}

inline bool isLocked(const bpfj_lock& lock) {
  return (lock.val.load(std::memory_order_relaxed) & kLockedMask) != 0;
}

// RAII holder for a bpfj_lock. Acquisition can fail, so callers must check
// owns() before entering the critical section.
class Guard {
 public:
  Guard(bpfj_lock& lock, std::chrono::nanoseconds timeout)
      : lock_{lock}, owns_{tryLockFor(lock, timeout)} {}

  ~Guard() {
    if (owns_) {
      unlock(lock_);
    }
  }

  Guard(const Guard&) = delete;
  Guard& operator=(const Guard&) = delete;

  bool owns() const {
    return owns_;
  }

  explicit operator bool() const {
    return owns_;
  }

 private:
  bpfj_lock& lock_;
  bool owns_;
};

} // namespace bpfjailer::lock
