// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "bpfj/libbpf-cpp/Conv.h"
#include "bpfj/lib/Log.h"
#include "bpfj/libbpf-cpp/ConvInternal.h"

#include <algorithm>
#include <cerrno>
#include <string>
#include <thread>
#include <vector>

#include <bpf/bpf.h>

namespace {

// Constants rather than flags, since the open source tree takes no
// flag-library dependency. Retuning means rebuilding.

// Wall-clock budget for retrying inner-map inserts that fail transiently
// during batch-update fallback, NO_PREALLOC nodes allocating lazily under the
// daemon memcg so a brief sleep lets kswapd reclaim. Non-positive disables
// retry, though one fallback pass still runs.
constexpr int kEnomemRetryBudgetMs = 3000;

// Initial backoff between transient retries, doubling each round up to 500ms.
constexpr int kEnomemBackoffMs = 20;

// Runaway guard on retry rounds, independent of the wall-clock budget; retries
// stop at whichever bound is hit first.
constexpr int kEnomemMaxRetryRounds = 100;

} // namespace

namespace bpfj::libbpf::conv::detail {

bool isTransientErrno(int err) noexcept {
  return err == ENOMEM || err == EINTR || err == EAGAIN;
}

Expected<> batchUpdateWithFallback(
    const char* mapPrefix,
    bpf_map_type type,
    std::uint32_t total,
    const BatchUpdateOps& ops) noexcept {
  if (total == 0) {
    return unit;
  }

  std::uint32_t landed = total;
  if (ops.updateBatch(&landed) == 0) {
    // Full batch success: return immediately, never rewrite entries per-entry.
    return unit;
  }
  const int batchErrno = errno;

  // The in/out count is trusted only to mark a leading prefix as done, so an
  // unchanged or out-of-range one falls back from 0 rather than skipping.
  const std::uint32_t landedPrefix = landed < total ? landed : 0;

  std::vector<std::uint32_t> pending;
  pending.reserve(total - landedPrefix);
  for (std::uint32_t i = landedPrefix; i < total; ++i) {
    pending.push_back(i);
  }

  const auto startTime = ops.now();
  const auto deadline = startTime + ops.budget;
  auto backoff = std::clamp(
      ops.initialBackoff,
      std::chrono::milliseconds(1),
      std::chrono::milliseconds(500));

  std::uint32_t retries = 0;
  int lastErrno = batchErrno;
  bool firstRound = true;
  while (!pending.empty()) {
    if (!firstRound) {
      // Bounded by both the round count and the wall-clock budget.
      if (retries >= ops.maxRetryRounds) {
        break;
      }
      const auto now = ops.now();
      if (now >= deadline) {
        break;
      }
      const auto remaining =
          std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);
      ops.sleep(std::min(backoff, remaining));
      backoff = std::min(backoff * 2, std::chrono::milliseconds(500));
      ++retries;
    }
    firstRound = false;

    // Compacted to the front of `pending` so retry rounds allocate nothing:
    // the shrink-only resize below never reallocates.
    std::size_t survivors = 0;
    for (std::size_t r = 0; r < pending.size(); ++r) {
      const std::uint32_t i = pending[r];
      const int err = ops.updateElem(i);
      if (err == 0) {
        continue;
      }
      lastErrno = err;
      if (isTransientErrno(err)) {
        pending[survivors++] = i;
      } else {
        // Permanent (EINVAL/EOPNOTSUPP/E2BIG/ENOSPC/...): fail closed with the
        // actual errno rather than retrying.
        return makeUnexpected(makeError(
            std::errc(err),
            "failed to populate inner map ",
            mapPrefix,
            " (type ",
            std::to_string(static_cast<int>(type)),
            ", ",
            std::to_string(total),
            " entries): permanent errno ",
            std::to_string(err),
            " on per-entry fallback after batch errno ",
            std::to_string(batchErrno),
            " (batch landed ",
            std::to_string(landedPrefix),
            ")"));
      }
    }
    pending.resize(survivors);
  }

  const auto elapsedMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                             ops.now() - startTime)
                             .count();

  if (!pending.empty()) {
    return makeUnexpected(makeError(
        std::errc(lastErrno),
        "failed to populate inner map ",
        mapPrefix,
        " (type ",
        std::to_string(static_cast<int>(type)),
        ", ",
        std::to_string(total),
        " entries): ",
        std::to_string(pending.size()),
        " still failing (errno ",
        std::to_string(lastErrno),
        ") after ",
        std::to_string(retries),
        " retry round(s) / ",
        std::to_string(elapsedMs),
        "ms elapsed (budget ",
        std::to_string(ops.budget.count()),
        "ms, max ",
        std::to_string(ops.maxRetryRounds),
        " rounds) (batch landed ",
        std::to_string(landedPrefix),
        ", batch errno ",
        std::to_string(batchErrno),
        ")"));
  }

  // One log per inner map, never per failed entry, so Scuba can tell
  // fallback-recovery from retry-recovery without a log storm.
  BPFJ_LOG(WARN) << "Recovered inner map " << mapPrefix << " (type "
                 << static_cast<int>(type) << ", " << total
                 << " entries) after batch errno " << batchErrno
                 << ": batch landed " << landedPrefix << ", "
                 << (total - landedPrefix)
                 << " entries via per-entry fallback, " << retries
                 << " retry round(s), " << elapsedMs << "ms elapsed";
  return unit;
}

Expected<> batchUpdateInnerMap(
    int fd,
    const char* mapPrefix,
    bpf_map_type type,
    unsigned char* keys,
    std::size_t keySize,
    unsigned char* vals,
    std::size_t valSize,
    std::uint32_t total) noexcept {
  DECLARE_LIBBPF_OPTS(
      bpf_map_batch_opts, batchOpts, .elem_flags = 0, .flags = 0);

  BatchUpdateOps ops;
  ops.updateBatch = [fd, keys, vals, &batchOpts](std::uint32_t* count) {
    return ::bpf_map_update_batch(fd, keys, vals, count, &batchOpts);
  };
  ops.updateElem = [fd, keys, keySize, vals, valSize](std::uint32_t i) -> int {
    const void* key = keys + (static_cast<std::size_t>(i) * keySize);
    const void* val = vals + (static_cast<std::size_t>(i) * valSize);
    return ::bpf_map_update_elem(fd, key, val, BPF_ANY) == 0 ? 0 : errno;
  };
  ops.sleep = [](std::chrono::milliseconds ms) {
    // NOLINTNEXTLINE(facebook-hte-BadCall-sleep_for)
    std::this_thread::sleep_for(ms);
  };
  ops.now = [] { return std::chrono::steady_clock::now(); };
  ops.budget = std::chrono::milliseconds(kEnomemRetryBudgetMs);
  ops.initialBackoff = std::chrono::milliseconds(kEnomemBackoffMs);
  ops.maxRetryRounds =
      static_cast<std::uint32_t>(std::max(0, kEnomemMaxRetryRounds));

  return batchUpdateWithFallback(mapPrefix, type, total, ops);
}

} // namespace bpfj::libbpf::conv::detail
