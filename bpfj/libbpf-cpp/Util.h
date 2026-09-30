// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include <cerrno>
#include <string>
#include <vector>

#include "bpfj/libbpf-cpp/Err.h"

namespace bpfj::libbpf {

namespace detail {

// Safety cap on read() calls while draining a BPF iterator, whose EAGAIN is a
// resume signal rather than an error -- bpf_seq_read yields it every ~1M
// objects -- so this only trips on an iterator that never terminates.
inline constexpr int kMaxBpfIterReads = 1'000'000;

// Drain a BPF iterator fd via readFn (ssize_t(char*, size_t)), retrying
// EAGAIN/EINTR as resume signals until EOF; an error on any other errno or
// past kMaxBpfIterReads.
template <typename ReadFn>
[[nodiscard]] Expected<std::vector<char>> drainBpfIter(
    ReadFn&& readFn) noexcept {
  char buf[4096];
  std::vector<char> result;
  for (int reads = 0; reads < kMaxBpfIterReads; ++reads) {
    ssize_t ret = readFn(buf, sizeof(buf));
    if (ret > 0) {
      result.insert(result.end(), buf, buf + ret);
    } else if (ret == 0) {
      return result; // EOF: iteration complete
    } else if (errno != EAGAIN && errno != EINTR) {
      return makeUnexpected(Error::fromErrno("failed to read BPF iterator"));
    }
    // EAGAIN/EINTR: re-issue read() to resume iteration.
  }
  return makeUnexpected(makeError(
      std::errc::timed_out,
      "BPF iterator did not terminate within ",
      std::to_string(kMaxBpfIterReads),
      " reads"));
}

template <typename F, typename... Args>
Expected<> call(const char* msg, F&& func, Args&&... args) noexcept {
  if (auto error = func(std::forward<Args>(args)...)) {
    return makeUnexpected(makeError(std::errc(-error), msg));
  }
  return unit;
}

template <typename T, typename F, typename... Args>
auto callRet(const char* msg, F&& func, Args&&... args) noexcept
    -> Expected<T> {
  if (auto ret = func(std::forward<Args>(args)...); ret) {
    return T(ret);
  } else {
    return makeUnexpected(makeErrnoError(msg));
  }
}

} // namespace detail

} // namespace bpfj::libbpf
