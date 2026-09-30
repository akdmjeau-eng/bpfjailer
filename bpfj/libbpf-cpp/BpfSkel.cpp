// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "bpfj/libbpf-cpp/BpfSkel.h"

#include <mutex>

namespace bpfj::libbpf {

std::mutex& skeletonOpenMutex() noexcept {
  static std::mutex m;
  return m;
}

} // namespace bpfj::libbpf
