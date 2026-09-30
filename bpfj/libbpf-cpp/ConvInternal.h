// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include <chrono>
#include <cstdint>
#include <functional>

#include <bpf/bpf.h>

#include "bpfj/libbpf-cpp/Err.h"

namespace bpfj::libbpf::conv::detail {

// Injectable syscall/clock seam, so the batch -> per-entry fallback -> ENOMEM
// backoff-retry orchestration can be unit-tested without a kernel.
struct BatchUpdateOps {
  // Mirrors bpf_map_update_batch: 0 on success, non-zero with errno set, and
  // *count (starting at the total) receives what the kernel processed.
  std::function<int(std::uint32_t* count)> updateBatch;
  // Mirrors bpf_map_update_elem for entry `i`: 0, or the failing errno.
  std::function<int(std::uint32_t i)> updateElem;
  // Backoff between retry rounds so kswapd can reclaim; injected so tests
  // advance time without real sleeps.
  std::function<void(std::chrono::milliseconds)> sleep;
  std::function<std::chrono::steady_clock::time_point()> now;
  std::chrono::milliseconds budget{};
  std::chrono::milliseconds initialBackoff{};
  // Ceiling on retry rounds, independent of the wall-clock budget; retries stop
  // at whichever is hit first.
  std::uint32_t maxRetryRounds = 0;
};

// True for errnos worth a bounded retry -- ENOMEM, where a brief sleep lets
// kswapd reclaim, plus EINTR and EAGAIN -- and false for everything else.
[[nodiscard]] bool isTransientErrno(int err) noexcept;

// Populate an inner map of `total` entries: one bpf_map_update_batch, a
// per-entry fallback for what did not land, then exponential-backoff retry
// bounded by both the wall-clock budget and the round count. Returns unit only
// when every entry is present; on terminal failure the caller closes the
// private FD and aborts publication.
[[nodiscard]] Expected<> batchUpdateWithFallback(
    const char* mapPrefix,
    bpf_map_type type,
    std::uint32_t total,
    const BatchUpdateOps& ops) noexcept;

} // namespace bpfj::libbpf::conv::detail
